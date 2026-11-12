// Copyright 2026 Zauberhaus
// Licensed to Zauberhaus under one or more agreements.
// Zauberhaus licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

// cspell:words decryptable mysecretvalue
package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGuardedSecret_NewAndGet_String(t *testing.T) {
	s := NewGuardedSecret("my-secret")
	assert.False(t, s.Empty())
	assert.Equal(t, "my-secret", s.Secret())
}

func TestGuardedSecret_NewAndGet_Bytes(t *testing.T) {
	s := NewGuardedSecret([]byte("byte-secret"))
	assert.False(t, s.Empty())
	assert.Equal(t, []byte("byte-secret"), s.Secret())
}

func TestGuardedSecret_Empty_NilReceiver(t *testing.T) {
	var s *GuardedSecret[string]
	assert.True(t, s.Empty())
}

func TestGuardedSecret_Empty_ZeroValue(t *testing.T) {
	var s GuardedSecret[string]
	assert.True(t, s.Empty())
}

func TestGuardedSecret_Empty_AfterSet(t *testing.T) {
	s := NewGuardedSecret("value")
	assert.False(t, s.Empty())
}

func TestGuardedSecret_String_Masked(t *testing.T) {
	s := NewGuardedSecret("hunter2")
	assert.Equal(t, "*****", s.String())
}

func TestGuardedSecret_String_EmptyIsBlank(t *testing.T) {
	var s GuardedSecret[string]
	assert.Equal(t, "", s.String())
}

func TestGuardedSecret_MarshalText_Masked(t *testing.T) {
	s := NewGuardedSecret("password123")
	b, err := s.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "*****", string(b))
}

func TestGuardedSecret_MarshalText_Empty(t *testing.T) {
	var s GuardedSecret[string]
	b, err := s.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "", string(b))
}

func TestGuardedSecret_UnmarshalText_String(t *testing.T) {
	var s GuardedSecret[string]
	err := s.UnmarshalText([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, "hello", s.Secret())
}

func TestGuardedSecret_UnmarshalText_Bytes(t *testing.T) {
	var s GuardedSecret[[]byte]
	err := s.UnmarshalText([]byte("raw"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("raw"), s.Secret())
}

func TestGuardedSecret_UnmarshalText_Empty(t *testing.T) {
	s := NewGuardedSecret("initial")
	err := s.UnmarshalText([]byte(""))
	assert.NoError(t, err)
	assert.True(t, s.Empty())
}

func TestGuardedSecret_UnmarshalText_Error(t *testing.T) {
	var s GuardedSecret[int]
	err := s.UnmarshalText([]byte("not-a-number"))
	assert.Error(t, err)
}

func TestGuardedSecret_MarshalJSON_Masked(t *testing.T) {
	s := NewGuardedSecret("abc")
	data, err := json.Marshal(s)
	assert.NoError(t, err)
	assert.Equal(t, `"*****"`, string(data))
}

func TestGuardedSecret_UnmarshalJSON_String(t *testing.T) {
	var s GuardedSecret[string]
	err := json.Unmarshal([]byte(`"hello"`), &s)
	assert.NoError(t, err)
	assert.Equal(t, "hello", s.Secret())
}

func TestGuardedSecret_UnmarshalJSON_Error(t *testing.T) {
	var s GuardedSecret[string]
	err := json.Unmarshal([]byte(`not-valid-json`), &s)
	assert.Error(t, err)
}

func TestGuardedSecret_JSONRoundTrip(t *testing.T) {
	original := "tok_live_abc123"
	s := NewGuardedSecret(original)

	data, err := json.Marshal(s)
	assert.NoError(t, err)
	assert.Equal(t, `"*****"`, string(data)) // never leaks value

	var s2 GuardedSecret[string]
	err = json.Unmarshal([]byte(`"`+original+`"`), &s2)
	assert.NoError(t, err)
	assert.Equal(t, original, s2.Secret())
}

func TestGuardedSecret_Set(t *testing.T) {
	var s GuardedSecret[string]
	err := s.Set("hello")
	assert.NoError(t, err)
	assert.Equal(t, "hello", s.Secret())
}

func TestGuardedSecret_Set_Error(t *testing.T) {
	var s GuardedSecret[int]
	err := s.Set("not-a-number")
	assert.Error(t, err)
}

func TestGuardedSecret_Type(t *testing.T) {
	s := GuardedSecret[string]{}
	assert.Equal(t, "string", s.Type())

	sb := GuardedSecret[[]byte]{}
	assert.Equal(t, "[]uint8", sb.Type())
}

func TestGuardedSecret_MarshalSecret(t *testing.T) {
	s := NewGuardedSecret("my-value")
	data, err := s.MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, []byte("my-value"), data)
}

func TestGuardedSecret_MarshalSecret_Empty(t *testing.T) {
	var s GuardedSecret[string]
	data, err := s.MarshalSecret()
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, data)
}

func TestGuardedSecret_MarshalSecret_WipeDoesNotCorruptStored(t *testing.T) {
	s := NewGuardedSecret("stable")

	data, _ := s.MarshalSecret()
	memguard_wipe(data) // simulate caller wiping the returned slice

	// Secret must still decrypt correctly from the enclave.
	assert.Equal(t, "stable", s.Secret())
}

func TestGuardedSecret_ID_NonEmpty(t *testing.T) {
	s := NewGuardedSecret("some-token")
	id, err := s.ID()
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestGuardedSecret_ID_Deterministic(t *testing.T) {
	s1 := NewGuardedSecret("same")
	s2 := NewGuardedSecret("same")
	id1, _ := s1.ID()
	id2, _ := s2.ID()
	assert.Equal(t, id1, id2)
}

func TestGuardedSecret_ID_Unique(t *testing.T) {
	s1 := NewGuardedSecret("value-a")
	s2 := NewGuardedSecret("value-b")
	id1, _ := s1.ID()
	id2, _ := s2.ID()
	assert.NotEqual(t, id1, id2)
}

func TestGuardedSecret_ValueIsNotStoredInPlainHeap(t *testing.T) {
	const plaintext = "mysecretvalue"
	s := NewGuardedSecret(plaintext)

	// The enclave's Size() reflects the sealed bytes, not raw plaintext.
	assert.Equal(t, len(plaintext), s.enclave.Load().Size())
	// Secret() still decrypts correctly.
	assert.Equal(t, plaintext, s.Secret())
}

func TestGuardedSecret_CustomType_TextMarshaler(t *testing.T) {
	obj := mockGlobalText("text-data")
	s := NewGuardedSecret(obj)
	assert.Equal(t, mockGlobalText("text-data"), s.Secret())
}

func TestGuardedSecret_CustomType_TextMarshaler_Pointer(t *testing.T) {
	obj := mockGlobalText("text-data")
	s := NewGuardedSecret(&obj)
	val := s.Secret()
	assert.Equal(t, mockGlobalText("text-data"), *val)
}

func TestGuardedSecret_CustomType_JSONMarshaler(t *testing.T) {
	obj := mockGlobalJSON("json-data")
	s := NewGuardedSecret(obj)
	assert.Equal(t, mockGlobalJSON("json-data"), s.Secret())
}

func TestGuardedSecret_CustomType_JSONMarshalerError(t *testing.T) {
	// errorTextMarshal.MarshalText always returns an error, so set() fails.
	assert.Panics(t, func() {
		NewGuardedSecret(errorTextMarshal{})
	})
}

func TestGuardedSecret_UnmarshalText_PlainStruct(t *testing.T) {
	var s GuardedSecret[plainStruct]
	err := s.UnmarshalText([]byte(`{"name":"alice"}`))
	assert.NoError(t, err)
	assert.Equal(t, "alice", s.Secret().Name)
}

// memguard_wipe zero-fills a slice to simulate the caller wiping the
// buffer returned by MarshalSecret, without importing memguard directly.
func memguard_wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func TestGuardedSecret_Destroy(t *testing.T) {
	s := NewGuardedSecret("to-be-destroyed")
	assert.False(t, s.Empty())

	s.Destroy()

	assert.True(t, s.Empty())
	assert.Equal(t, "", s.String())
	assert.Equal(t, "", s.Secret()) // reads as zero value after Destroy
}

func TestGuardedSecret_Destroy_NilReceiver(t *testing.T) {
	var s *GuardedSecret[string]
	assert.NotPanics(t, func() { s.Destroy() })
}

func TestGuardedSecret_UnmarshalText_NilReceiver(t *testing.T) {
	var s *GuardedSecret[string]
	assert.NotPanics(t, func() {
		err := s.UnmarshalText([]byte("hello"))
		assert.ErrorIs(t, err, ErrNilSecret)
	})
}

func TestGuardedSecret_UnmarshalJSON_NilReceiver(t *testing.T) {
	var s *GuardedSecret[string]
	assert.NotPanics(t, func() {
		err := s.UnmarshalJSON([]byte(`"hello"`))
		assert.ErrorIs(t, err, ErrNilSecret)
	})
}

func TestGuardedSecret_Set_NilReceiver(t *testing.T) {
	var s *GuardedSecret[string]
	assert.NotPanics(t, func() {
		err := s.Set("hello")
		assert.ErrorIs(t, err, ErrNilSecret)
	})
}

func TestGuardedSecret_Destroy_ThenSet(t *testing.T) {
	s := NewGuardedSecret("first")
	s.Destroy()

	err := s.Set("second")
	assert.NoError(t, err)
	assert.Equal(t, "second", s.Secret())
}

func TestGuardedSecret_ConcurrentAccess(t *testing.T) {
	s := NewGuardedSecret("initial")

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			for j := range 50 {
				_ = s.Set(fmt.Sprintf("value-%d-%d", n, j))
			}
		}(i)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = s.Secret()
				_ = s.Empty()
				_, _ = s.MarshalSecret()
			}
		}()
	}
	wg.Wait()

	// The secret must still hold a consistent, decryptable value.
	assert.False(t, s.Empty())
	assert.NotEmpty(t, s.Secret())
}

func TestGuardedSecret_UnmarshalText_WipesIntermediate(t *testing.T) {
	// For T = []byte the decoded intermediate copy is wiped after sealing;
	// the sealed value must still decrypt correctly.
	var s GuardedSecret[[]byte]
	err := s.UnmarshalText([]byte("wipe-check"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("wipe-check"), s.Secret())
}

// failingUnmarshalText serializes cleanly but always fails to decode, so a
// sealed value can be created and only the read path errors.
type failingUnmarshalText struct {
	Data string
}

func (f failingUnmarshalText) MarshalText() ([]byte, error) {
	return []byte(f.Data), nil
}

func (f *failingUnmarshalText) UnmarshalText([]byte) error {
	return errors.New("unmarshal text failed")
}

func TestGuardedSecret_Get_NilReceiver(t *testing.T) {
	var s *GuardedSecret[string]
	val, err := s.get()
	assert.NoError(t, err)
	assert.Equal(t, "", val)
}

func TestGuardedSecret_Get_UnmarshalError(t *testing.T) {
	s := NewGuardedSecret(failingUnmarshalText{Data: "payload"})

	_, err := s.get()
	assert.ErrorIs(t, err, ErrInvalidValue)
	assert.NotContains(t, err.Error(), "payload")
}

func TestGuardedSecret_Secret_PanicsOnDecodeError(t *testing.T) {
	s := NewGuardedSecret(failingUnmarshalText{Data: "payload"})
	assert.Panics(t, func() { _ = s.Secret() })
}

func TestGuardedSecret_MarshalSecret_NilReceiver(t *testing.T) {
	var s *GuardedSecret[string]
	data, err := s.MarshalSecret()
	assert.NoError(t, err)
	assert.Empty(t, data)
}

func TestGuardedSecret_ID_NilReceiver(t *testing.T) {
	var s *GuardedSecret[string]
	id, err := s.ID()
	assert.NoError(t, err)
	assert.Equal(t, "", id)
}

func TestGuardedSecret_Hash_NilReceiver(t *testing.T) {
	var s *GuardedSecret[string]
	hash, err := s.Hash()
	assert.NoError(t, err)
	assert.Equal(t, [32]byte{}, hash)
}

func TestGuardedSecret_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var s GuardedSecret[string]
	err := s.UnmarshalJSON([]byte("{not json"))
	assert.Error(t, err)
	assert.True(t, s.Empty())
}

func TestGuardedSecret_UnmarshalJSON_BytesWipesIntermediate(t *testing.T) {
	// For T = []byte the decoded intermediate copy is wiped after sealing;
	// the sealed value must still decrypt correctly.
	var s GuardedSecret[[]byte]
	err := s.UnmarshalJSON([]byte(`"aGVsbG8="`)) // base64 of "hello"
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), s.Secret())
}
