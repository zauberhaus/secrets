package secrets_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zauberhaus/secrets"
)

func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return key
}

func TestPrivateKey_ECKey_RoundTrip(t *testing.T) {
	key := generateECKey(t)

	s := secrets.NewEncryptedSecret(key)
	require.NotNil(t, s)
	require.False(t, s.Empty())

	got := s.Secret()
	assert.True(t, key.Equal(got))
}
