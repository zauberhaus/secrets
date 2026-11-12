package secrets

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptedSecret_NewAndGet(t *testing.T) {
	plain := "my-super-secret"
	es := newEncrypted(plain)

	assert.False(t, es.Empty())

	decrypted := es.Secret()
	assert.Equal(t, plain, decrypted)
}

func TestEncryptedSecret_PointerStruct_RoundTrip(t *testing.T) {
	// *plainStruct has no marshaling interfaces, so Secret() must allocate
	// a fresh target when decrypting rather than passing a nil pointer to
	// json.Unmarshal.
	es := newEncrypted(&plainStruct{Name: "alice"})
	require.False(t, es.Empty())

	got := es.Secret()
	require.NotNil(t, got)
	assert.Equal(t, "alice", got.Name)
}

func TestEncryptedSecret_SetEmpty(t *testing.T) {
	es := newEncrypted("initial")
	err := es.Set("")
	assert.NoError(t, err)
	assert.True(t, es.Empty())
}

func TestEncryptedSecret_MarshalSecret(t *testing.T) {
	var es EncryptedSecret[string]
	err := es.UnmarshalText([]byte("unmarshaled-secret"))
	assert.NoError(t, err)

	b, err := es.MarshalSecret()
	assert.NoError(t, err)

	assert.Equal(t, []byte("unmarshaled-secret"), b)
}

func TestEncryptedSecret_StringAndMarshal(t *testing.T) {
	es := newEncrypted("test")

	assert.Equal(t, "*****", es.String())

	b, err := es.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "*****", string(b))

	empty := EncryptedSecret[string]{}
	assert.Equal(t, "", empty.String())

	eb, err := empty.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "", string(eb))
}

func TestEncryptedSecret_UnmarshalText(t *testing.T) {
	var es EncryptedSecret[string]
	err := es.UnmarshalText([]byte("unmarshaled-secret"))
	assert.NoError(t, err)
	assert.Equal(t, "unmarshaled-secret", es.Secret())
}

func TestEncryptedSecret_Secret(t *testing.T) {
	es := newEncrypted("another-secret")
	assert.Equal(t, "another-secret", es.Secret())
}

func TestEncryptedSecret_GetEmpty(t *testing.T) {
	var es EncryptedSecret[string]
	got := es.Secret()
	assert.Empty(t, got)
}

func TestEncryptedSecret_GetTooShort(t *testing.T) {
	var es EncryptedSecret[string]
	es.data = []byte("012345678912")

	assert.PanicsWithError(t, "cipher: message authentication failed", func() {
		_ = es.Secret()
	})
}

func TestEncryptedSecret_CorruptedData(t *testing.T) {
	es := newEncrypted("my-secret")

	// Corrupt the ciphertext
	es.data[len(es.data)-1] ^= 0xff

	assert.Panics(t, func() {
		_ = es.Secret()
	})
}

func TestEncryptedSecret_Set_InvalidKeySize(t *testing.T) {
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	// Force an invalid AES key size
	secKey.enclave = memguard.NewEnclave([]byte("invalid-size"))

	var es EncryptedSecret[string]
	err := es.Set("some-secret")
	assert.Error(t, err)
}

func TestEncryptedSecret_Get_InvalidKeySize(t *testing.T) {
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	var es EncryptedSecret[string]
	err := es.Set("some-secret")
	assert.NoError(t, err)

	// Force an invalid AES key size
	secKey.enclave = memguard.NewEnclave([]byte("invalid-size"))

	assert.PanicsWithError(t, "crypto/aes: invalid key size 12", func() {
		_ = es.Secret()
	})
}

func TestSetKey_Success(t *testing.T) {
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	secKey.enclave = nil
	const customKey = "12345678901234567890123456789012"
	SetKey([]byte(customKey)) // SetKey wipes its input, so pass a fresh copy

	buf, err := secKey.open()
	assert.NoError(t, err)
	defer buf.Destroy()
	assert.Equal(t, customKey, string(buf.Bytes()))
}

func TestSetKey_Panic(t *testing.T) {
	// Ensure the key is already initialized
	buf, err := secKey.open()
	assert.NoError(t, err)
	buf.Destroy()

	defer func() {
		if r := recover(); r == nil {
			assert.Fail(t, "Expected SetKey to panic because key is already initialized")
		}
	}()
	SetKey([]byte("some-key-that-is-32-bytes-long!!!"))
}

func TestSetKey_InvalidSize(t *testing.T) {
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	secKey.enclave = nil

	assert.Panics(t, func() {
		SetKey([]byte("too-short"))
	})
}

func TestSetKey_WipesSource(t *testing.T) {
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	secKey.enclave = nil
	key := []byte("12345678901234567890123456789012")
	SetKey(key)

	// The caller's slice is wiped once the key is sealed in the enclave.
	assert.Equal(t, make([]byte, 32), key)
}

// errorMarshalerText implements encoding.TextMarshaler but always returns an error.
type errorMarshalerText struct{}

func (e errorMarshalerText) MarshalText() ([]byte, error) {
	return nil, fmt.Errorf("text marshal error")
}

func (e *errorMarshalerText) UnmarshalText([]byte) error {
	return nil
}

type mockGlobalText []byte

func (m mockGlobalText) MarshalText() ([]byte, error) {
	return m, nil
}

func (m *mockGlobalText) UnmarshalText(text []byte) error {
	// The TextUnmarshaler contract requires copying the input; the library
	// wipes the decrypted buffer after unmarshaling.
	*m = append([]byte(nil), text...)
	return nil
}

type mockGlobalJSON string

func (m mockGlobalJSON) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, `"%s"`, m), nil
}

func (m *mockGlobalJSON) UnmarshalJSON(text []byte) error {
	v := strings.Trim(string(text), `"`)
	*m = mockGlobalJSON(v)
	return nil
}

func TestEncryptedSecret_ByteArray(t *testing.T) {
	plain := []byte("my-super-secret-bytes")
	es := newEncrypted(plain)

	assert.False(t, es.Empty())

	decrypted := es.Secret()
	assert.Equal(t, string(plain), string(decrypted))
}

func TestEncryptedSecret_TextMarshaler_Pointer(t *testing.T) {
	obj := mockGlobalText("text-marshaler-data")

	es := newEncrypted(&obj)

	assert.False(t, es.Empty())

	val := es.Secret()
	assert.Equal(t, "text-marshaler-data", string(*val))
}

func TestEncryptedSecret_TextMarshaler(t *testing.T) {
	obj := mockGlobalText("text-marshaler-data")

	es := newEncrypted(obj)

	assert.False(t, es.Empty())

	val := es.Secret()
	assert.Equal(t, "text-marshaler-data", string(val))
}

func TestEncryptedSecret_JSONMarshaler_Pointer(t *testing.T) {
	obj := mockGlobalJSON("text-marshaler-data")

	es := newEncrypted(&obj)

	assert.False(t, es.Empty())

	val := es.Secret()
	assert.Equal(t, "text-marshaler-data", string(*val))
}

func TestEncryptedSecret_JSONMarshaler_NoPointer(t *testing.T) {
	obj := mockGlobalJSON("text-marshaler-data")

	es := newEncrypted(obj)

	assert.False(t, es.Empty())

	val := es.Secret()
	assert.Equal(t, "text-marshaler-data", string(val))
}

func TestEncryptedSecret_JSONMarshaler(t *testing.T) {
	es := newEncrypted("abc")
	assert.False(t, es.Empty())

	data, err := json.Marshal(es)
	assert.NoError(t, err)
	assert.Equal(t, `"*****"`, string(data))
}

func TestEncryptedSecret_JSONUnmarshaler(t *testing.T) {
	var es EncryptedSecret[string]
	err := json.Unmarshal([]byte(`"abcdefg"`), &es)
	assert.NoError(t, err)
	assert.False(t, es.Empty())

	text := es.Secret()
	assert.Equal(t, `abcdefg`, text)
}

func TestEncryptedSecret_Type(t *testing.T) {
	es := newEncrypted("hello")
	assert.Equal(t, "string", es.Type())

	esBytes := newEncrypted([]byte("hello"))
	assert.Equal(t, "[]uint8", esBytes.Type())
}

func TestEncryptedSecret_MarshalSecret_Empty(t *testing.T) {
	var es EncryptedSecret[string]
	b, err := es.MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, b)
}

func TestEncryptedSecret_MarshalSecret_Bytes(t *testing.T) {
	plain := []byte("secret-bytes")
	es := newEncrypted(plain)

	b, err := es.MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, plain, b)
}

func TestEncryptedSecret_MarshalSecret_JSONMarshalerBranch(t *testing.T) {
	obj := mockGlobalJSON("json-data")
	es := newEncrypted(obj)

	b, err := es.MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, `"json-data"`, string(b))
}

func TestEncryptedSecret_MarshalSecret_MatchesPlain(t *testing.T) {
	es := newEncrypted(42)

	b, err := es.MarshalSecret()
	assert.NoError(t, err)

	want, err := NewSecret(42).MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, want, b)
	assert.True(t, Equal(Secret[int](es), NewSecret(42)))
}

func TestEncryptedSecret_Get_NilReceiver(t *testing.T) {
	var es *EncryptedSecret[string]
	val, err := es.get()
	assert.NoError(t, err)
	assert.Equal(t, "", val)
}

func TestEncryptedSecret_UnmarshalText_NilReceiver(t *testing.T) {
	var es *EncryptedSecret[string]
	assert.NotPanics(t, func() {
		err := es.UnmarshalText([]byte("hello"))
		assert.ErrorIs(t, err, ErrNilSecret)
	})
}

func TestEncryptedSecret_UnmarshalJSON_NilReceiver(t *testing.T) {
	var es *EncryptedSecret[string]
	assert.NotPanics(t, func() {
		err := es.UnmarshalJSON([]byte(`"hello"`))
		assert.ErrorIs(t, err, ErrNilSecret)
	})
}

func TestEncryptedSecret_ID_NilReceiver(t *testing.T) {
	var es *EncryptedSecret[string]
	assert.NotPanics(t, func() {
		id, err := es.ID()
		assert.NoError(t, err)
		assert.Empty(t, id)
	})
}

func TestEncryptedSecret_Get_DataTooShort(t *testing.T) {
	var es EncryptedSecret[string]
	es.data = []byte("short") // 5 bytes < 12 (AES-GCM nonce size)

	assert.PanicsWithError(t, "ciphertext too short", func() {
		_ = es.Secret()
	})
}

func TestEncryptedSecret_UnmarshalJSON_Error(t *testing.T) {
	var es EncryptedSecret[string]
	err := json.Unmarshal([]byte(`not-valid-json`), &es)
	assert.Error(t, err)
}

func TestEncryptedSecret_MarshalJSON_DoesNotDecrypt(t *testing.T) {
	var es EncryptedSecret[string]
	es.data = []byte("short") // would fail if MarshalJSON decrypted

	b, err := es.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, `"*****"`, string(b))
}

func TestEncryptedSecret_Set_MarshalSecretError(t *testing.T) {
	var es EncryptedSecret[errorMarshalerText]
	err := es.set(errorMarshalerText{})
	assert.Error(t, err)
	assert.Equal(t, "text marshal error", err.Error())
}

func TestEncryptedSecret_UnmarshalText_Error(t *testing.T) {
	// int requires valid JSON; passing non-JSON causes SimpleSecret.UnmarshalText
	// to return an error, which propagates through EncryptedSecret.UnmarshalText.
	var es EncryptedSecret[int]
	err := es.UnmarshalText([]byte("not-a-number"))
	assert.Error(t, err)
}

func TestEncryptedSecret_ID_String(t *testing.T) {
	es := newEncrypted("my-secret")
	id, err := es.ID()
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestEncryptedSecret_ID_Deterministic(t *testing.T) {
	es1 := newEncrypted("same-value")
	es2 := newEncrypted("same-value")
	id1, err1 := es1.ID()
	id2, err2 := es2.ID()
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, id1, id2)
}

func TestEncryptedSecret_ID_DifferentValues(t *testing.T) {
	es1 := newEncrypted("value-a")
	es2 := newEncrypted("value-b")
	id1, _ := es1.ID()
	id2, _ := es2.ID()
	assert.NotEqual(t, id1, id2)
}

func TestEncryptedSecret_ID_Bytes(t *testing.T) {
	es := newEncrypted([]byte("byte-secret"))
	id, err := es.ID()
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestEncryptedSecret_ID_MarshalError(t *testing.T) {
	es := newEncrypted(42)
	es.data[len(es.data)-1] ^= 0xff // corrupt so decryption fails
	_, err := es.ID()
	assert.Error(t, err)
}

func TestEncryptedSecret_UnmarshalJSON_SetError(t *testing.T) {
	// json.Unmarshal succeeds but set() fails due to an invalid AES key,
	// covering the "return s.set(val)" error path in UnmarshalJSON.
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	secKey.enclave = memguard.NewEnclave([]byte("bad-key-size"))

	var es EncryptedSecret[string]
	err := json.Unmarshal([]byte(`"hello"`), &es)
	assert.Error(t, err)
}

func TestEncryptedSecret_Destroy(t *testing.T) {
	es := newEncrypted("sensitive")
	assert.False(t, es.Empty())

	es.Destroy()

	assert.True(t, es.Empty())
	assert.Equal(t, "", es.String())
}

func TestEncryptedSecret_Destroy_WipesBytes(t *testing.T) {
	es := newEncrypted("wipe-me")

	// Hold a reference to the backing array before Destroy; it keeps the
	// memory alive so we can verify it was zeroed.
	original := es.data

	es.Destroy()

	assert.Equal(t, make([]byte, len(original)), original)
}

func TestEncryptedSecret_Destroy_NilReceiver(t *testing.T) {
	var es *EncryptedSecret[string]
	assert.NotPanics(t, func() { es.Destroy() })
}

func TestEncryptedSecret_Destroy_ThenSet(t *testing.T) {
	es := newEncrypted("first")
	es.Destroy()

	err := es.Set("second")
	assert.NoError(t, err)
	assert.Equal(t, "second", es.Secret())
}

func TestNewEncryptedSecret_PanicsOnUnserializableValue(t *testing.T) {
	// A channel cannot be JSON-encoded, so set fails and the constructor panics.
	assert.Panics(t, func() { _ = NewEncryptedSecret(make(chan int)) })
}

func TestEncryptedSecret_Get_UnmarshalError(t *testing.T) {
	es := newEncrypted(failingUnmarshalText{Data: "payload"})

	_, err := es.get()
	assert.ErrorIs(t, err, ErrInvalidValue)
	assert.NotContains(t, err.Error(), "payload")
}

func TestEncryptedSecret_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var es EncryptedSecret[string]
	err := es.UnmarshalJSON([]byte("{not json"))
	assert.Error(t, err)
	assert.True(t, es.Empty())
}

func TestEncryptedSecret_Hash_NilReceiver(t *testing.T) {
	var es *EncryptedSecret[string]
	hash, err := es.Hash()
	assert.NoError(t, err)
	assert.Equal(t, [32]byte{}, hash)
}

func TestEncryptedSecret_Empty_NilReceiver(t *testing.T) {
	var s *EncryptedSecret[string]
	assert.NotPanics(t, func() {
		assert.True(t, s.Empty())
	})

	var iface Secret[string] = s
	assert.NotPanics(t, func() {
		assert.True(t, iface.Empty())
	})
}

func TestEncryptedSecret_Empty_ZeroValue(t *testing.T) {
	var s EncryptedSecret[string]
	assert.True(t, s.Empty())
}
