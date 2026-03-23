package secrets

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildCmd registers a Secret[T] as a cobra --secret flag and returns the
// command together with a pointer to the registered value.
func buildCmd[T any](secret Secret[T]) *cobra.Command {
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	cmd.Flags().Var(secret, "secret", "a secret value")
	return cmd
}

// --- PlainSecret as a cobra flag ---

func TestCobraFlag_PlainSecret_ParsesValue(t *testing.T) {
	secret := NewSecret("")

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{"--secret", "hello"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, "hello", secret.Secret())
}

func TestCobraFlag_PlainSecret_StringIsMasked(t *testing.T) {
	secret := NewSecret("initial")

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.NoError(t, err)
	// String() must never expose the actual value.
	assert.Equal(t, "*******", secret.String())
}

func TestCobraFlag_PlainSecret_EmptyStringIsEmpty(t *testing.T) {
	secret := NewSecret("")

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.True(t, secret.Empty())
	assert.Equal(t, "", secret.String())
}

func TestCobraFlag_PlainSecret_TypeName(t *testing.T) {
	secret := NewSecret("")
	assert.Equal(t, "string", secret.Type())
}

func TestCobraFlag_PlainSecret_ByteSlice(t *testing.T) {
	secret := NewSecret([]byte(nil))

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{"--secret", "byteval"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, []byte("byteval"), secret.Secret())
	assert.Equal(t, "*******", secret.String())
}

// --- EncryptedSecret as a cobra flag ---

func TestCobraFlag_EncryptedSecret_ParsesValue(t *testing.T) {
	secret := NewEncryptedSecret("")

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{"--secret", "s3cr3t"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", secret.Secret())
}

func TestCobraFlag_EncryptedSecret_StringIsMasked(t *testing.T) {
	secret := NewEncryptedSecret("stored")

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.NoError(t, err)
	// EncryptedSecret always returns exactly "*****" regardless of value length.
	assert.Equal(t, "*****", secret.String())
}

func TestCobraFlag_EncryptedSecret_EmptyStringIsEmpty(t *testing.T) {
	secret := NewEncryptedSecret("")

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.True(t, secret.Empty())
	assert.Equal(t, "", secret.String())
}

func TestCobraFlag_EncryptedSecret_TypeName(t *testing.T) {
	secret := NewEncryptedSecret("")
	assert.Equal(t, "string", secret.Type())
}

func TestCobraFlag_EncryptedSecret_OverwriteValue(t *testing.T) {
	secret := NewEncryptedSecret("original")

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{"--secret", "replaced"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, "replaced", secret.Secret())
}

func TestCobraFlag_EncryptedSecret_ValueIsEncryptedInMemory(t *testing.T) {
	const plaintext = "mysecretvalue"
	secret := NewEncryptedSecret(plaintext)

	// The raw bytes stored in the struct must not contain the plaintext.
	assert.NotContains(t, string(secret.data), plaintext)
	// But decryption via Secret() must still return the original value.
	assert.Equal(t, plaintext, secret.Secret())
}

// --- Both types: invalid flag value ---

func TestCobraFlag_PlainSecret_InvalidJSON(t *testing.T) {
	// For a struct type, Set() calls UnmarshalText which falls back to
	// json.Unmarshal; invalid JSON should propagate as a flag-parse error.
	secret := NewSecret(plainStruct{})

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{"--secret", "not-json"})

	err := cmd.Execute()
	assert.Error(t, err)
}

func TestCobraFlag_EncryptedSecret_InvalidJSON(t *testing.T) {
	secret := NewEncryptedSecret(0) // int uses json round-trip

	cmd := buildCmd(secret)
	cmd.SetArgs([]string{"--secret", "not-a-number"})

	err := cmd.Execute()
	assert.Error(t, err)
}
