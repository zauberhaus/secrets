package secrets

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEncryptedSecretFromEnv(t *testing.T) {
	const name = "SECRETS_TEST_TOKEN"
	t.Setenv(name, "env-token")

	s := NewEncryptedSecretFromEnv(name)

	assert.Equal(t, []byte("env-token"), s.Secret())
	assert.Equal(t, "*****", s.String())

	_, set := os.LookupEnv(name)
	assert.False(t, set, "variable must be unset after reading")
}

func TestNewEncryptedSecretFromEnv_Missing(t *testing.T) {
	s := NewEncryptedSecretFromEnv("SECRETS_TEST_MISSING_VARIABLE")

	assert.True(t, s.Empty())
	assert.Empty(t, s.Secret())
}

func TestWipe(t *testing.T) {
	data := []byte("sensitive")
	Wipe(data)
	assert.Equal(t, make([]byte, len("sensitive")), data)

	assert.NotPanics(t, func() { Wipe(nil) })
}
