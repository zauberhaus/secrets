package secrets

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptedSecret_NewAndGet(t *testing.T) {
	plain := "my-super-secret"
	es := NewEncryptedSecret(plain)

	assert.False(t, es.Empty())

	decrypted := es.Secret()
	assert.Equal(t, plain, decrypted)
}

func TestEncryptedSecret_SetEmpty(t *testing.T) {
	es := NewEncryptedSecret("initial")
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
	es := NewEncryptedSecret("test")

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
	es := NewEncryptedSecret("another-secret")
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
	es := NewEncryptedSecret("my-secret")

	// Corrupt the ciphertext
	es.data[len(es.data)-1] ^= 0xff

	assert.Panics(t, func() {
		_ = es.Secret()
	})
}

func TestEncryptedSecret_Set_InvalidKeySize(t *testing.T) {
	oldValue := secKey.value
	oldInit := secKey.init
	defer func() {
		secKey.value = oldValue
		secKey.init = oldInit
	}()

	// Force an invalid AES key size
	secKey.value = []byte("invalid-size")

	var es EncryptedSecret[string]
	err := es.Set("some-secret")
	assert.Error(t, err)
}

func TestEncryptedSecret_Get_InvalidKeySize(t *testing.T) {
	oldValue := secKey.value
	oldInit := secKey.init
	defer func() {
		secKey.value = oldValue
		secKey.init = oldInit
	}()

	// This call to Set will fail, but we ignore the error
	// because we want to test Get
	var es EncryptedSecret[string]
	err := es.Set("some-secret")
	assert.NoError(t, err)

	// Force an invalid AES key size
	secKey.value = []byte("invalid-size")

	assert.PanicsWithError(t, "crypto/aes: invalid key size 12", func() {
		_ = es.Secret()
	})
}

func TestSetKey_Success(t *testing.T) {
	oldValue := secKey.value
	oldInit := secKey.init
	defer func() {
		secKey.value = oldValue
		secKey.init = oldInit
	}()

	secKey.value = nil
	customKey := []byte("12345678901234567890123456789012")
	SetKey(customKey)

	assert.Equal(t, string(customKey), string(secKey.Get()))
}

func TestSetKey_Panic(t *testing.T) {
	// Ensure the key is already initialized
	_ = secKey.Get()

	defer func() {
		if r := recover(); r == nil {
			assert.Fail(t, "Expected SetKey to panic because key is already initialized")
		}
	}()
	SetKey([]byte("some-key-that-is-32-bytes-long!!!"))
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
	*m = text
	return nil
}

type mockGlobalJSON string

func (m mockGlobalJSON) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, m)), nil
}

func (m *mockGlobalJSON) UnmarshalJSON(text []byte) error {
	v := strings.Trim(string(text), `"`)
	*m = mockGlobalJSON(v)
	return nil
}

func TestEncryptedSecret_ByteArray(t *testing.T) {
	plain := []byte("my-super-secret-bytes")
	es := NewEncryptedSecret(plain)

	assert.False(t, es.Empty())

	decrypted := es.Secret()
	assert.Equal(t, string(plain), string(decrypted))
}

func TestEncryptedSecret_TextMarshaler_Pointer(t *testing.T) {
	obj := mockGlobalText("text-marshaler-data")

	es := NewEncryptedSecret(&obj)

	assert.False(t, es.Empty())

	val := es.Secret()
	assert.Equal(t, "text-marshaler-data", string(*val))
}

func TestEncryptedSecret_TextMarshaler(t *testing.T) {
	obj := mockGlobalText("text-marshaler-data")

	es := NewEncryptedSecret(obj)

	assert.False(t, es.Empty())

	val := es.Secret()
	assert.Equal(t, "text-marshaler-data", string(val))
}

func TestEncryptedSecret_JSONMarshaler_Pointer(t *testing.T) {
	obj := mockGlobalJSON("text-marshaler-data")

	es := NewEncryptedSecret(&obj)

	assert.False(t, es.Empty())

	val := es.Secret()
	assert.Equal(t, "text-marshaler-data", string(*val))
}

func TestEncryptedSecret_JSONMarshaler_NoPointer(t *testing.T) {
	obj := mockGlobalJSON("text-marshaler-data")

	es := NewEncryptedSecret(obj)

	assert.False(t, es.Empty())

	val := es.Secret()
	assert.Equal(t, "text-marshaler-data", string(val))
}

func TestEncryptedSecret_JSONMarshaler(t *testing.T) {
	es := NewEncryptedSecret("abc")
	assert.False(t, es.Empty())

	data, err := json.Marshal(es)
	assert.NoError(t, err)
	assert.Equal(t, `"***"`, string(data))
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
	es := NewEncryptedSecret("hello")
	assert.Equal(t, "string", es.Type())

	esBytes := NewEncryptedSecret([]byte("hello"))
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
	es := NewEncryptedSecret(plain)

	b, err := es.MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, plain, b)
}

func TestEncryptedSecret_MarshalSecret_JSONMarshalerBranch(t *testing.T) {
	obj := mockGlobalJSON("json-data")
	es := NewEncryptedSecret(obj)

	b, err := es.MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, `"json-data"`, string(b))
}

func TestEncryptedSecret_MarshalSecret_DefaultError(t *testing.T) {
	// int is not string, []byte, or json.Marshaler in the EncryptedSecret.MarshalSecret switch
	es := NewEncryptedSecret(42)

	_, err := es.MarshalSecret()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "can's serialize")
}

func TestEncryptedSecret_Get_NilReceiver(t *testing.T) {
	var es *EncryptedSecret[string]
	val, err := es.get()
	assert.NoError(t, err)
	assert.Equal(t, "", val)
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

func TestEncryptedSecret_MarshalJSON_Error(t *testing.T) {
	var es EncryptedSecret[string]
	es.data = []byte("short") // causes get() to return "ciphertext too short"

	_, err := es.MarshalJSON()
	assert.Error(t, err)
	assert.Equal(t, "ciphertext too short", err.Error())
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

func TestEncryptedSecret_UnmarshalJSON_SetError(t *testing.T) {
	// json.Unmarshal succeeds but set() fails due to an invalid AES key,
	// covering the "return s.set(val)" error path in UnmarshalJSON.
	oldValue := secKey.value
	oldInit := secKey.init
	defer func() {
		secKey.value = oldValue
		secKey.init = oldInit
	}()

	secKey.value = []byte("bad-key-size")

	var es EncryptedSecret[string]
	err := json.Unmarshal([]byte(`"hello"`), &es)
	assert.Error(t, err)
}
