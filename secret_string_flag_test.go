// Copyright 2026 Zauberhaus
// Licensed to Zauberhaus under one or more agreements.
// Zauberhaus licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package secrets

import (
	"encoding/json"
	"testing"

	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/assert"
)

func TestSecretStringSecret_NewAndGet(t *testing.T) {
	val := "my-super-secret"
	s := NewStringSecret(val)

	assert.False(t, s.Empty())
	assert.Equal(t, val, string(s.Secret()))
}

func TestSecretStringSecret_Empty(t *testing.T) {
	val := ""
	s := NewStringSecret(val)

	assert.True(t, s.Empty())
	assert.Equal(t, val, string(s.Secret()))
}

func TestSecretStringFlag_NewAndGet(t *testing.T) {
	val := "my-super-secret"
	s := NewStringFlag(&val)

	assert.False(t, s.Empty())
	assert.Equal(t, val, string(s.Secret()))
}

func TestSecretStringFlag_New_NilValue(t *testing.T) {
	s := NewStringFlag(nil)
	assert.True(t, s.Empty())
	assert.Equal(t, "", s.String())
}

func TestSecretStringFlag_New_EmptyValue(t *testing.T) {
	val := ""
	s := NewStringFlag(&val)
	assert.True(t, s.Empty())
}

func TestSecretStringFlag_ZeroValue_Empty(t *testing.T) {
	var s StringSecret
	assert.True(t, s.Empty())
	assert.Equal(t, "", s.String())
	assert.Equal(t, []byte{}, []byte(s.Secret()))
}

func TestSecretStringFlag_StringAndMarshalText(t *testing.T) {
	val := "hunter2"
	s := NewStringFlag(&val)

	assert.Equal(t, "*****", s.String())

	b, err := s.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "*****", string(b))
}

func TestSecretStringFlag_UnmarshalText(t *testing.T) {
	var s StringSecret
	err := s.UnmarshalText([]byte("unmarshaled-secret"))
	assert.NoError(t, err)
	assert.False(t, s.Empty())
	assert.Equal(t, "unmarshaled-secret", string(s.Secret()))
}

func TestSecretStringFlag_UnmarshalText_Empty(t *testing.T) {
	val := "initial"
	s := NewStringFlag(&val)

	err := s.UnmarshalText([]byte(""))
	assert.NoError(t, err)
	assert.True(t, s.Empty())
}

func TestSecretStringFlag_UnmarshalText_NilReceiver(t *testing.T) {
	var s *StringSecret
	assert.NotPanics(t, func() {
		err := s.UnmarshalText([]byte("hello"))
		assert.ErrorIs(t, err, ErrNilSecret)
	})
}

func TestSecretStringFlag_Set(t *testing.T) {
	var s StringSecret
	err := s.Set("from-flag")
	assert.NoError(t, err)
	assert.Equal(t, "from-flag", string(s.Secret()))
}

func TestSecretStringFlag_Set_Empty(t *testing.T) {
	val := "initial"
	s := NewStringFlag(&val)

	err := s.Set("")
	assert.NoError(t, err)
	assert.True(t, s.Empty())
}

func TestSecretStringFlag_Type(t *testing.T) {
	var s StringSecret
	assert.Equal(t, "string", s.Type())
}

func TestSecretStringFlag_MarshalSecret(t *testing.T) {
	var s StringSecret
	err := s.UnmarshalText([]byte("plaintext-bytes"))
	assert.NoError(t, err)

	b, err := s.MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, []byte("plaintext-bytes"), b)
}

func TestSecretStringFlag_MarshalSecret_Empty(t *testing.T) {
	var s StringSecret
	b, err := s.MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, b)
}

func TestSecretStringFlag_JSONMarshal(t *testing.T) {
	val := "abc"
	s := NewStringFlag(&val)

	data, err := json.Marshal(s)
	assert.NoError(t, err)
	assert.Equal(t, `"*****"`, string(data))
}

func TestSecretStringFlag_JSONUnmarshal(t *testing.T) {
	var s StringSecret
	err := json.Unmarshal([]byte(`"abcdefg"`), &s)
	assert.NoError(t, err)
	assert.False(t, s.Empty())
	assert.Equal(t, "abcdefg", string(s.Secret()))
}

func TestSecretStringFlag_UnmarshalJSON_NilReceiver(t *testing.T) {
	var s *StringSecret
	assert.NotPanics(t, func() {
		err := s.UnmarshalJSON([]byte(`"hello"`))
		assert.ErrorIs(t, err, ErrNilSecret)
	})
}

func TestSecretStringFlag_UnmarshalJSON_Error(t *testing.T) {
	var s StringSecret
	err := json.Unmarshal([]byte(`not-valid-json`), &s)
	assert.Error(t, err)
}

func TestSecretStringFlag_UnmarshalJSON_TypeMismatch(t *testing.T) {
	// Syntactically valid JSON (a number) that isn't a string, so the error
	// comes from json.Unmarshal(data, &val) inside UnmarshalJSON itself
	// rather than from json's outer syntax pre-check.
	var s StringSecret
	err := s.UnmarshalJSON([]byte(`123`))
	assert.Error(t, err)
}

func TestSecretStringFlag_ID_Deterministic(t *testing.T) {
	v1, v2 := "same-value", "same-value"
	s1 := NewStringFlag(&v1)
	s2 := NewStringFlag(&v2)

	id1, err1 := s1.ID()
	id2, err2 := s2.ID()
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, id1, id2)
}

func TestSecretStringFlag_ID_DifferentValues(t *testing.T) {
	va, vb := "value-a", "value-b"
	s1 := NewStringFlag(&va)
	s2 := NewStringFlag(&vb)

	id1, _ := s1.ID()
	id2, _ := s2.ID()
	assert.NotEqual(t, id1, id2)
}

func TestSecretStringFlag_ID_NilReceiver(t *testing.T) {
	var s *StringSecret
	assert.NotPanics(t, func() {
		id, err := s.ID()
		assert.NoError(t, err)
		assert.Empty(t, id)
	})
}

func TestSecretStringFlag_Hash_NilReceiver(t *testing.T) {
	var s *StringSecret
	hash, err := s.Hash()
	assert.NoError(t, err)
	assert.Equal(t, [32]byte{}, hash)
}

func TestSecretStringFlag_Destroy(t *testing.T) {
	val := "sensitive"
	s := NewStringFlag(&val)
	assert.False(t, s.Empty())

	s.Destroy()

	assert.True(t, s.Empty())
	assert.Equal(t, "", s.String())
}

func TestSecretStringFlag_Destroy_WipesBytes(t *testing.T) {
	var s StringSecret
	err := s.UnmarshalText([]byte("wipe-me"))
	assert.NoError(t, err)

	// Hold a reference to the backing array before Destroy; it keeps the
	// memory alive so we can verify it was zeroed.
	original := []byte(s)

	s.Destroy()

	assert.Equal(t, make([]byte, len(original)), original)
}

func TestSecretStringFlag_Destroy_NilReceiver(t *testing.T) {
	var s *StringSecret
	assert.NotPanics(t, func() { s.Destroy() })
}

func TestSecretStringFlag_Destroy_ThenSet(t *testing.T) {
	val := "first"
	s := NewStringFlag(&val)
	s.Destroy()

	err := s.Set("second")
	assert.NoError(t, err)
	assert.Equal(t, "second", string(s.Secret()))
}

func TestSecretStringFlag_Get_DataTooShort(t *testing.T) {
	s := StringSecret("short") // 5 bytes < 12 (AES-GCM nonce size)

	assert.PanicsWithError(t, "ciphertext too short", func() {
		_ = s.Secret()
	})
}

func TestSecretStringFlag_CorruptedData(t *testing.T) {
	var s StringSecret
	err := s.UnmarshalText([]byte("my-secret"))
	assert.NoError(t, err)

	// Corrupt the ciphertext
	s[len(s)-1] ^= 0xff

	assert.Panics(t, func() {
		_ = s.Secret()
	})
}

func TestSecretStringFlag_Set_InvalidKeySize(t *testing.T) {
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	// Force an invalid AES key size
	secKey.enclave = memguard.NewEnclave([]byte("invalid-size"))

	var s StringSecret
	err := s.Set("some-secret")
	assert.Error(t, err)
}

func TestNewStringFlag_PanicsOnInvalidKeySize(t *testing.T) {
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	// Force an invalid AES key size
	secKey.enclave = memguard.NewEnclave([]byte("invalid-size"))

	val := "some-secret"
	assert.Panics(t, func() { _ = NewStringFlag(&val) })
}

func TestSecretStringFlag_Hash_Error(t *testing.T) {
	s := StringSecret("short") // 5 bytes < 12 (AES-GCM nonce size)

	_, err := s.Hash()
	assert.Error(t, err)
}

func TestSecretStringFlag_ID_Error(t *testing.T) {
	s := StringSecret("short") // 5 bytes < 12 (AES-GCM nonce size)

	_, err := s.ID()
	assert.Error(t, err)
}

func TestSecretStringFlag_UnmarshalJSON_SetError(t *testing.T) {
	// json.Unmarshal succeeds but set() fails due to an invalid AES key,
	// covering the "return s.set(&val)" error path in UnmarshalJSON.
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	secKey.enclave = memguard.NewEnclave([]byte("bad-key-size"))

	var s StringSecret
	err := json.Unmarshal([]byte(`"hello"`), &s)
	assert.Error(t, err)
}

func TestSecretStringFlag_Empty_NilReceiver(t *testing.T) {
	var s *StringSecret
	assert.NotPanics(t, func() {
		assert.True(t, s.Empty())
	})

	var secret Secret[[]byte] = s
	assert.NotPanics(t, func() {
		assert.True(t, secret.Empty())
	})
}
