// Copyright 2026 Zauberhaus
// Licensed to Zauberhaus under one or more agreements.
// Zauberhaus licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awnumar/memguard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const leak = "top-secret"

func TestGoString_Masks(t *testing.T) {
	plain := PlainSecret[string]{val: leak}
	enc := newEncrypted(leak)
	flag := NewStringSecret(leak).(*StringSecret)

	for name, v := range map[string]any{
		"plain value":     plain,
		"plain pointer":   &plain,
		"encrypted value": enc,
		"encrypted ptr":   enc,
		"guarded":         NewGuardedSecret(leak),
		"flag value":      *flag,
		"flag pointer":    flag,
		"nested":          struct{ S *PlainSecret[string] }{&plain},
	} {
		t.Run(name, func(t *testing.T) {
			out := fmt.Sprintf("%#v", v)
			assert.NotContains(t, out, leak)
			assert.Contains(t, out, "*****")
		})
	}
}

func TestPlainSecret_SetEmptyClears(t *testing.T) {
	s := NewSecret("value")
	require.NoError(t, s.Set(""))
	assert.True(t, s.Empty())

	n := NewSecret(42)
	require.NoError(t, n.Set(""))
	assert.True(t, n.Empty())
}

func TestPlainSecret_DestroyWipesBytes(t *testing.T) {
	s := NewSecret([]byte("hunter2"))
	inner := s.Secret()
	s.Destroy()
	assert.Equal(t, make([]byte, len("hunter2")), inner)
	assert.True(t, s.Empty())
}

func TestParseErrors_DoNotLeakInput(t *testing.T) {
	const input = "s3cr3t-value"

	cases := map[string]Secret[int]{
		"plain":     NewSecret(0),
		"guarded":   NewGuardedSecret(0),
		"encrypted": newEncrypted(0),
	}

	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			for _, err := range []error{
				s.Set(input),
				s.UnmarshalText([]byte(input)),
				s.UnmarshalJSON([]byte(input)),
			} {
				require.ErrorIs(t, err, ErrInvalidValue)
				assert.NotContains(t, err.Error(), input)
				assert.NotContains(t, err.Error(), "'s'", "json errors quote the first character")
				assert.Equal(t, "secrets: invalid value for secret of type int", err.Error())
			}
		})
	}

	var f StringSecret
	err := f.UnmarshalJSON([]byte(input))
	require.ErrorIs(t, err, ErrInvalidValue)
	assert.NotContains(t, err.Error(), input)
}

func TestSanitizeFlagError_StripsSecretValue(t *testing.T) {
	fs := pflag.NewFlagSet("x", pflag.ContinueOnError)
	fs.SetOutput(&strings.Builder{})
	fs.VarP(NewGuardedSecret(0), "pin", "p", "")

	err := fs.Parse([]string{"--pin=hunter2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hunter2", "pflag itself quotes the value")

	clean := SanitizeFlagError(err)
	assert.NotContains(t, clean.Error(), "hunter2")
	assert.Contains(t, clean.Error(), `"-p, --pin"`)
	assert.ErrorIs(t, clean, ErrInvalidValue)
}

func TestSanitizeFlagError_LeavesOtherErrors(t *testing.T) {
	fs := pflag.NewFlagSet("x", pflag.ContinueOnError)
	fs.SetOutput(&strings.Builder{})
	fs.Int("count", 0, "")

	err := fs.Parse([]string{"--count=abc"})
	require.Error(t, err)
	assert.Equal(t, err, SanitizeFlagError(err))
	assert.Nil(t, SanitizeFlagError(nil))
}

func TestSanitizeFlagError_Cobra(t *testing.T) {
	var out strings.Builder
	cmd := buildCmd(newEncrypted(0))
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return SanitizeFlagError(err)
	})
	cmd.SetArgs([]string{"--secret", "hunter2"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hunter2")
	assert.NotContains(t, out.String(), "hunter2")
}

func TestCiphertext_BoundToType(t *testing.T) {
	str := newEncrypted("value")

	var b EncryptedSecret[[]byte]
	b.data = append([]byte(nil), str.data...)
	_, err := b.MarshalSecret()
	assert.Error(t, err, "string ciphertext must not decrypt as []byte")

	f := StringSecret(append([]byte(nil), str.data...))
	_, err = f.MarshalSecret()
	assert.Error(t, err, "EncryptedSecret ciphertext must not decrypt as SecretStringFlag")
}

func TestSetKey_WipesKeyOnPanic(t *testing.T) {
	oldEnclave := secKey.enclave
	defer func() { secKey.enclave = oldEnclave }()

	secKey.enclave = nil
	short := []byte("too-short")
	assert.Panics(t, func() { SetKey(short) })
	assert.Equal(t, make([]byte, len(short)), short)

	secKey.enclave = memguard.NewEnclave(make([]byte, 32))
	again := []byte("0123456789abcdef0123456789abcdef")
	assert.Panics(t, func() { SetKey(again) })
	assert.Equal(t, make([]byte, len(again)), again)
}

func TestBase58Decode_RejectsOversizedInput(t *testing.T) {
	_, err := Base58Decode(strings.Repeat("2", MaxBase58DecodeLen+1))
	assert.ErrorContains(t, err, "too long")

	_, err = Base58Decode(strings.Repeat("2", MaxBase58DecodeLen))
	assert.NoError(t, err)

	_, err = Base58Decode("2é")
	assert.ErrorContains(t, err, "invalid base58 character")
}

// newEncrypted builds an *EncryptedSecret without NewEncryptedSecret's
// string guard, so tests can exercise EncryptedSecret[string] and inspect
// internals such as the ciphertext.
func newEncrypted[T any](v T) *EncryptedSecret[T] {
	s := &EncryptedSecret[T]{}
	if err := s.set(v); err != nil {
		panic(err)
	}
	return s
}

func TestNewEncryptedSecret_RejectsStrings(t *testing.T) {
	type named string

	assert.Panics(t, func() { NewEncryptedSecret("x") })
	assert.Panics(t, func() { NewEncryptedSecret(named("x")) })
	assert.NotPanics(t, func() { NewEncryptedSecret([]byte("x")) })
	assert.NotPanics(t, func() { NewEncryptedSecret(42) })
	assert.NotPanics(t, func() { NewEncryptedSecret[any](nil) })
}
