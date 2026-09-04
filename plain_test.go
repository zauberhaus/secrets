package secrets

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSerializable struct {
	Data string
}

func (m *mockSerializable) MarshalText() ([]byte, error) {
	return []byte(m.Data), nil
}

func (m *mockSerializable) UnmarshalText(text []byte) error {
	m.Data = string(text)
	return nil
}

type mockJSON struct {
	Data string
}

func (m *mockJSON) UnmarshalJSON(text []byte) error {
	m.Data = string(text)
	return nil
}

func (m mockJSON) MarshalJSON() ([]byte, error) {
	return []byte(m.Data), nil
}

func TestSimpleSecret_ByteArray(t *testing.T) {
	sec := &PlainSecret[[]byte]{val: []byte("initial")}

	if string(sec.Secret()) != "initial" {
		t.Errorf("Expected 'initial', got '%s'", string(sec.Secret()))
	}

	b, err := sec.MarshalText()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if string(b) != "*****" { // fixed-width mask, independent of value length
		t.Errorf("Expected '*****', got '%s'", string(b))
	}

	err = sec.UnmarshalText([]byte("new-bytes"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Note: Currently UnmarshalText for []byte has a bug where it ignores the input text.
	// This assertion expects the correct behavior.
	if string(sec.Secret()) != "new-bytes" {
		t.Errorf("Expected 'new-bytes', got '%s'", string(sec.Secret()))
	}
}

func TestSimpleSecret_String(t *testing.T) {
	sec := &PlainSecret[string]{val: "hello there"}

	if sec.Secret() != "hello there" {
		t.Errorf("Expected 'hello there', got '%s'", sec.Secret())
	}

	b, err := sec.MarshalText()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if string(b) != "*****" { // fixed-width mask, independent of value length
		t.Errorf("Expected '*****', got '%s'", string(b))
	}

	err = sec.UnmarshalText([]byte("world"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Note: Currently UnmarshalText for string has a bug where it ignores the input text.
	if sec.Secret() != "world" {
		t.Errorf("Expected 'world', got '%s'", sec.Secret())
	}
}

func TestSimpleSecret_Serializable(t *testing.T) {
	mock := &mockSerializable{Data: "mock-data"}
	sec := NewSecret(mock)

	if sec.Secret().Data != "mock-data" {
		t.Errorf("Expected 'mock-data', got '%s'", sec.Secret().Data)
	}

	b, err := sec.MarshalText()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// For unrecognized dynamic types, MarshalText masks with "*****"
	if string(b) != "*****" {
		t.Errorf("Expected '*****', got '%s'", string(b))
	}

	err = sec.UnmarshalText([]byte("new-mock-data"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if sec.Secret().Data != "new-mock-data" {
		t.Errorf("Expected 'new-mock-data', got '%s'", sec.Secret().Data)
	}
}

func TestSimpleSecret_JSON(t *testing.T) {
	mock := &mockJSON{Data: "initial"}
	sec := NewSecret(mock)

	err := sec.UnmarshalText([]byte("new-json-data"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if sec.Secret().Data != "new-json-data" {
		t.Errorf("Expected 'new-json-data', got '%s'", sec.Secret().Data)
	}
}

func TestSimpleSecret_Empty(t *testing.T) {
	var nilSec *PlainSecret[string]
	if !nilSec.Empty() {
		t.Error("Expected nil string secret to be empty")
	}

	emptyStrSec := &PlainSecret[string]{val: ""}
	if !emptyStrSec.Empty() {
		t.Error("Expected empty string secret to be empty")
	}

	emptyBytesSec := &PlainSecret[[]byte]{val: []byte{}}
	if !emptyBytesSec.Empty() {
		t.Error("Expected empty bytes secret to be empty")
	}

	nonEmptyBytesSec := &PlainSecret[[]byte]{val: []byte("val")}
	if nonEmptyBytesSec.Empty() {
		t.Error("Expected non-empty bytes secret to not be empty")
	}
}

func TestSimpleSecret_JSONMarshaler(t *testing.T) {
	es := NewSecret("abc")
	assert.False(t, es.Empty())

	data, err := json.Marshal(es)
	assert.NoError(t, err)
	assert.Equal(t, `"*****"`, string(data))
}

func TestSimpleSecret_JSONUnmarshaler(t *testing.T) {
	var es PlainSecret[string]
	err := json.Unmarshal([]byte(`"abcdefg"`), &es)
	assert.NoError(t, err)
	assert.False(t, es.Empty())

	text := es.Secret()
	assert.Equal(t, `abcdefg`, text)
}

func TestSimpleSecret_Set(t *testing.T) {
	var s PlainSecret[string]
	err := s.Set("hello")
	assert.NoError(t, err)
	assert.Equal(t, "hello", s.Secret())
}

func TestSimpleSecret_Type(t *testing.T) {
	s := PlainSecret[string]{}
	assert.Equal(t, "string", s.Type())

	sb := PlainSecret[[]byte]{}
	assert.Equal(t, "[]uint8", sb.Type())
}

func TestSimpleSecret_Secret_NilReceiver(t *testing.T) {
	var s *PlainSecret[string]
	assert.Equal(t, "", s.Secret())
}

func TestSimpleSecret_UnmarshalText_NilReceiver(t *testing.T) {
	var s *PlainSecret[string]
	err := s.UnmarshalText([]byte("hello"))
	assert.NoError(t, err)
}

func TestSimpleSecret_UnmarshalJSON_NilReceiver(t *testing.T) {
	var s *PlainSecret[string]
	assert.NotPanics(t, func() {
		err := s.UnmarshalJSON([]byte(`"hello"`))
		assert.NoError(t, err)
	})
}

func TestSimpleSecret_ID_NilReceiver(t *testing.T) {
	var s *PlainSecret[string]
	assert.NotPanics(t, func() {
		id, err := s.ID()
		assert.NoError(t, err)
		assert.Empty(t, id)
	})
}

// plainStruct is a plain struct with no special marshaling interfaces.
type plainStruct struct {
	Name string `json:"name"`
}

func TestSimpleSecret_UnmarshalText_PlainStruct(t *testing.T) {
	var s PlainSecret[plainStruct]
	err := s.UnmarshalText([]byte(`{"name":"alice"}`))
	assert.NoError(t, err)
	assert.Equal(t, "alice", s.Secret().Name)
}

func TestSimpleSecret_UnmarshalText_NonPointerJSON(t *testing.T) {
	// mockGlobalJSON is a value type whose *T implements json.Unmarshaler.
	// This exercises the non-pointer json.Unmarshaler branch in UnmarshalText.
	var s PlainSecret[mockGlobalJSON]
	err := s.UnmarshalText([]byte(`"json-data"`))
	assert.NoError(t, err)
	assert.Equal(t, mockGlobalJSON("json-data"), s.Secret())
}

func TestSimpleSecret_UnmarshalText_NonPointerText(t *testing.T) {
	// mockGlobalText is a value type whose *T implements encoding.TextUnmarshaler.
	// This exercises the non-pointer TextUnmarshaler branch in UnmarshalText.
	var s PlainSecret[mockGlobalText]
	err := s.UnmarshalText([]byte("text-data"))
	assert.NoError(t, err)
	assert.Equal(t, mockGlobalText("text-data"), s.Secret())
}

func TestSimpleSecret_UnmarshalJSON_Error(t *testing.T) {
	var s PlainSecret[string]
	err := s.UnmarshalJSON([]byte(`not-valid-json`))
	assert.Error(t, err)
}

func TestSimpleSecret_UnmarshalText_NilPointerJSON(t *testing.T) {
	// s.val is a nil *mockJSON; the IsNil branch allocates a new instance.
	s := PlainSecret[*mockJSON]{val: nil}
	err := s.UnmarshalText([]byte("new-json-data"))
	assert.NoError(t, err)
	assert.Equal(t, "new-json-data", s.Secret().Data)
}

func TestSimpleSecret_UnmarshalText_NilPointerText(t *testing.T) {
	// s.val is a nil *mockSerializable; the IsNil branch allocates a new instance.
	s := PlainSecret[*mockSerializable]{val: nil}
	err := s.UnmarshalText([]byte("new-text-data"))
	assert.NoError(t, err)
	assert.Equal(t, "new-text-data", s.Secret().Data)
}

func TestSimpleSecret_UnmarshalText_PointerNoInterface(t *testing.T) {
	// *int does not implement json.Unmarshaler or TextUnmarshaler,
	// so UnmarshalText falls through to the reflect_utils.IsPointer branch
	// and calls json.Unmarshal directly on the pointer value.
	n := 0
	s := PlainSecret[*int]{val: &n}
	err := s.UnmarshalText([]byte("42"))
	assert.NoError(t, err)
	assert.Equal(t, 42, *s.Secret())
}

// errorTextMarshal implements encoding.TextMarshaler but always errors.
type errorTextMarshal struct{}

func (e errorTextMarshal) MarshalText() ([]byte, error) {
	return nil, errors.New("text marshal error")
}

func (e *errorTextMarshal) UnmarshalText([]byte) error { return nil }

func TestSimpleSecret_MarshalSecret_TextMarshalError(t *testing.T) {
	s := NewSecret(errorTextMarshal{})
	_, err := s.MarshalSecret()
	assert.Error(t, err)
	assert.Equal(t, "text marshal error", err.Error())
}

// jsonMarshalErrorType implements json.Marshaler but always errors,
// without implementing encoding.TextMarshaler, so MarshalSecret falls
// through to the default json.Marshal branch.
type jsonMarshalErrorType struct{}

func (j jsonMarshalErrorType) MarshalJSON() ([]byte, error) {
	return nil, errors.New("json marshal error")
}

func TestSimpleSecret_MarshalSecret_JSONMarshalError(t *testing.T) {
	s := NewSecret(jsonMarshalErrorType{})
	_, err := s.MarshalSecret()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "json marshal error")
}

func TestSimpleSecret_ID_String(t *testing.T) {
	s := NewSecret("my-secret")
	id, err := s.ID()
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestSimpleSecret_ID_Deterministic(t *testing.T) {
	s1 := NewSecret("same-value")
	s2 := NewSecret("same-value")
	id1, err1 := s1.ID()
	id2, err2 := s2.ID()
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, id1, id2)
}

func TestSimpleSecret_ID_DifferentValues(t *testing.T) {
	s1 := NewSecret("value-a")
	s2 := NewSecret("value-b")
	id1, _ := s1.ID()
	id2, _ := s2.ID()
	assert.NotEqual(t, id1, id2)
}

func TestSimpleSecret_ID_Bytes(t *testing.T) {
	s := NewSecret([]byte("byte-secret"))
	id, err := s.ID()
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestSimpleSecret_ID_MarshalError(t *testing.T) {
	s := NewSecret(errorTextMarshal{})
	_, err := s.ID()
	assert.Error(t, err)
	assert.Equal(t, "text marshal error", err.Error())
}

func TestSimpleSecret_Destroy_String(t *testing.T) {
	s := PlainSecret[string]{val: "sensitive"}
	assert.False(t, s.Empty())

	s.Destroy()

	assert.True(t, s.Empty())
	assert.Equal(t, "", s.String())
	assert.Equal(t, "", s.Secret())
}

func TestSimpleSecret_Destroy_Bytes(t *testing.T) {
	s := PlainSecret[[]byte]{val: []byte("sensitive")}
	assert.False(t, s.Empty())

	s.Destroy()

	assert.True(t, s.Empty())
	assert.Equal(t, []byte(nil), s.Secret())
}

func TestSimpleSecret_Destroy_NilReceiver(t *testing.T) {
	var s *PlainSecret[string]
	assert.NotPanics(t, func() { s.Destroy() })
}

func TestSimpleSecret_Destroy_ThenSet(t *testing.T) {
	s := PlainSecret[string]{val: "first"}
	s.Destroy()

	err := s.Set("second")
	assert.NoError(t, err)
	assert.Equal(t, "second", s.Secret())
}

func TestSimpleSecret_Destroy_Struct(t *testing.T) {
	s := PlainSecret[plainStruct]{val: plainStruct{Name: "alice"}}
	assert.False(t, s.Empty())

	s.Destroy()

	assert.True(t, s.Empty())
	assert.Equal(t, plainStruct{}, s.Secret())
}

// failingUnmarshalJSON serializes cleanly but always fails to decode.
type failingUnmarshalJSON struct {
	Data string
}

func (f failingUnmarshalJSON) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Data)
}

func (f *failingUnmarshalJSON) UnmarshalJSON([]byte) error {
	return errors.New("unmarshal json failed")
}

func TestSimpleSecret_UnmarshalText_PointerJSONError(t *testing.T) {
	s := PlainSecret[*failingUnmarshalJSON]{val: &failingUnmarshalJSON{}}
	err := s.UnmarshalText([]byte("anything"))
	assert.ErrorContains(t, err, "unmarshal json failed")
}

func TestSimpleSecret_UnmarshalText_ValueJSONError(t *testing.T) {
	var s PlainSecret[failingUnmarshalJSON]
	err := s.UnmarshalText([]byte("anything"))
	assert.ErrorContains(t, err, "unmarshal json failed")
}

func TestSimpleSecret_UnmarshalText_PointerTextError(t *testing.T) {
	s := PlainSecret[*failingUnmarshalText]{val: &failingUnmarshalText{}}
	err := s.UnmarshalText([]byte("anything"))
	assert.ErrorContains(t, err, "unmarshal text failed")
}

func TestSimpleSecret_UnmarshalText_ValueTextError(t *testing.T) {
	var s PlainSecret[failingUnmarshalText]
	err := s.UnmarshalText([]byte("anything"))
	assert.ErrorContains(t, err, "unmarshal text failed")
}

func TestSimpleSecret_UnmarshalText_PointerFallbackJSONError(t *testing.T) {
	// *plainStruct implements neither interface, so it falls through to
	// json.Unmarshal on the pointer.
	s := PlainSecret[*plainStruct]{val: &plainStruct{}}
	err := s.UnmarshalText([]byte("{not json"))
	assert.Error(t, err)
}

func TestSimpleSecret_UnmarshalText_NilPointerFallbackJSON(t *testing.T) {
	// *plainStruct implements neither interface and s.val starts nil, so
	// UnmarshalText must allocate a target before calling json.Unmarshal
	// on the pointer, instead of passing a nil pointer to json.Unmarshal.
	s := PlainSecret[*plainStruct]{val: nil}
	err := s.UnmarshalText([]byte(`{"name":"alice"}`))
	require.NoError(t, err)
	require.NotNil(t, s.Secret())
	assert.Equal(t, "alice", s.Secret().Name)
}

// mockSigner implements crypto.Signer but isn't one of the key types
// x509.MarshalPKCS8PrivateKey knows how to encode.
type mockSigner struct{}

func (mockSigner) Public() crypto.PublicKey { return nil }

func (mockSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestSimpleSecret_MarshalSecret_SignerError(t *testing.T) {
	s := NewSecret(mockSigner{})
	_, err := s.MarshalSecret()
	assert.Error(t, err)
}

func TestSimpleSecret_UnmarshalText_SignerInvalidDER(t *testing.T) {
	var s PlainSecret[*ecdsa.PrivateKey]
	err := s.UnmarshalText([]byte("not a valid PKCS8 key"))
	assert.Error(t, err)
}

func TestSimpleSecret_UnmarshalText_SignerTypeMismatch(t *testing.T) {
	// Encode an ed25519 key, then try to decode it as an *ecdsa.PrivateKey.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	//der = append(pkcs8Header, der...)

	var s PlainSecret[*ecdsa.PrivateKey]
	err = s.UnmarshalText(der)
	assert.ErrorContains(t, err, "unexpected key type")
}

func TestSimpleSecret_Signer_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	s := NewSecret(key)
	data, err := s.MarshalSecret()
	require.NoError(t, err)

	var got PlainSecret[*ecdsa.PrivateKey]
	require.NoError(t, got.UnmarshalText(data))
	assert.True(t, key.Equal(got.Secret()))
}

func TestSimpleSecret_MarshalSecret_PublicKeyIsTagged(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	s := NewSecret(key.Public())
	data, err := s.MarshalSecret()
	require.NoError(t, err)

	require.NotEmpty(t, data)
	assert.Equal(t, pkixHeader, data[:4])

	der, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	assert.Equal(t, der, data[4:])
}

func TestSimpleSecret_MarshalSecret_PublicKeyHeaderNotShared(t *testing.T) {
	// Regression test: MarshalSecret must build a fresh header per call.
	// Appending straight to a shared package-level header slice would let
	// one call's output alias, and later be overwritten by, another's.
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dataA, err := NewSecret(keyA.Public()).MarshalSecret()
	require.NoError(t, err)
	dataACopy := append([]byte(nil), dataA...)

	_, err = NewSecret(keyB.Public()).MarshalSecret()
	require.NoError(t, err)

	assert.Equal(t, dataACopy, dataA, "first MarshalSecret result was mutated by a later call")
}

func TestSimpleSecret_PublicKeyInterface_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	s := NewSecret[crypto.PublicKey](key.Public())
	data, err := s.MarshalSecret()
	require.NoError(t, err)

	var got PlainSecret[crypto.PublicKey]
	require.NoError(t, got.UnmarshalText(data))

	eq, ok := got.Secret().(interface{ Equal(x crypto.PublicKey) bool })
	require.True(t, ok)
	assert.True(t, eq.Equal(key.Public()))
}

func TestSimpleSecret_Hash_NilReceiver(t *testing.T) {
	var s *PlainSecret[string]
	hash, err := s.Hash()
	assert.NoError(t, err)
	assert.Equal(t, [32]byte{}, hash)
}
