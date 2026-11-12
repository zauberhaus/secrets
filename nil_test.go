// Copyright 2026 Zauberhaus
// Licensed to Zauberhaus under one or more agreements.
// Zauberhaus licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package secrets

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// nilSafe is the subset of [Secret] that must not panic on a nil pointer
// receiver. String, MarshalText and MarshalJSON use value receivers on some
// types (so fmt and encoding/json mask plain values); they are covered via
// fmt and json in assertNilFormatting instead.
type nilSafe[T any] interface {
	Secret() T
	Empty() bool
	Hash() ([32]byte, error)
	ID() (string, error)
	MarshalSecret() ([]byte, error)
	Type() string
	Set(string) error
	UnmarshalText([]byte) error
	UnmarshalJSON([]byte) error
	Destroy()
	Equal(Secret[T]) bool
}

func assertNilSafe[T any](t *testing.T, s nilSafe[T], other Secret[T]) {
	t.Helper()

	assert.NotPanics(t, func() {
		assert.Empty(t, s.Secret())
		assert.True(t, s.Empty())

		h, err := s.Hash()
		assert.NoError(t, err)
		assert.Equal(t, [32]byte{}, h)

		id, err := s.ID()
		assert.NoError(t, err)
		assert.Empty(t, id)

		data, err := s.MarshalSecret()
		assert.NoError(t, err)
		assert.Empty(t, data)

		assert.NotEmpty(t, s.Type())

		// Writes to a nil secret must fail loudly rather than drop the value.
		assert.ErrorIs(t, s.Set("value"), ErrNilSecret)
		assert.ErrorIs(t, s.UnmarshalText([]byte("value")), ErrNilSecret)
		assert.ErrorIs(t, s.UnmarshalJSON([]byte(`"value"`)), ErrNilSecret)
		assert.True(t, s.Empty(), "nil receiver must stay empty after unmarshal")

		s.Destroy()

		assert.False(t, s.Equal(other))
		assert.False(t, s.Equal(nil))
	})
}

func assertNilFormatting(t *testing.T, s any) {
	t.Helper()

	assert.NotPanics(t, func() {
		// fmt prints <nil> for value-receiver String methods; pointer-receiver
		// ones handle nil themselves and return "".
		assert.Contains(t, []string{"", "<nil>"}, fmt.Sprint(s))
		assert.Contains(t, []string{"", "<nil>"}, fmt.Sprintf("%v", s))

		data, err := json.Marshal(s)
		assert.NoError(t, err)
		assert.Equal(t, "null", string(data))
	})
}

func TestNilReceiver_PlainSecret(t *testing.T) {
	var s *PlainSecret[string]
	assertNilSafe(t, s, NewSecret("value"))
	assertNilFormatting(t, s)
}

func TestNilReceiver_GuardedSecret(t *testing.T) {
	var s *GuardedSecret[string]
	assertNilSafe(t, s, NewGuardedSecret("value"))
	assertNilFormatting(t, s)
}

func TestNilReceiver_EncryptedSecret(t *testing.T) {
	var s *EncryptedSecret[string]
	assertNilSafe(t, s, newEncrypted("value"))
	assertNilFormatting(t, s)
}

func TestNilReceiver_SecretStringFlag(t *testing.T) {
	var s *StringSecret
	assertNilSafe(t, s, NewStringSecret("value"))
	assertNilFormatting(t, s)
}

// Value-typed secrets must keep masking through fmt and encoding/json, which
// is why String, MarshalText and MarshalJSON stay on value receivers.
func TestValueReceiver_Masking(t *testing.T) {
	plain := PlainSecret[string]{val: "top-secret"}
	enc := *newEncrypted("top-secret")
	flag := *NewStringSecret("top-secret").(*StringSecret)

	for name, v := range map[string]any{"plain": plain, "encrypted": enc, "flag": flag} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, "*****", fmt.Sprint(v))
			assert.Equal(t, "*****", fmt.Sprintf("%v", v))
			assert.Equal(t, "*****", fmt.Sprintf("%+v", v))

			data, err := json.Marshal(struct{ S any }{v})
			assert.NoError(t, err)
			assert.JSONEq(t, `{"S":"*****"}`, string(data))
		})
	}
}
