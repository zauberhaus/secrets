package secrets_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return key
}

func generateEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
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

func TestPrivateKey_RSAKey_RoundTrip(t *testing.T) {
	key := generateRSAKey(t)

	s := secrets.NewEncryptedSecret(key)
	require.NotNil(t, s)
	require.False(t, s.Empty())

	got := s.Secret()
	assert.True(t, key.Equal(got))
}

func TestPrivateKey_Ed25519Key_RoundTrip(t *testing.T) {
	key := generateEd25519Key(t)

	s := secrets.NewEncryptedSecret(key)
	require.NotNil(t, s)
	require.False(t, s.Empty())

	got := s.Secret()
	assert.True(t, key.Equal(got))
}

func TestEncryptedSecret_CryptoSignerInterface_NoPanicsOnRead(t *testing.T) {
	signer := generateECKey(t)
	s := secrets.NewEncryptedSecret[crypto.Signer](signer)

	assert.NotPanics(t, func() {
		s.Secret()
	})
}

func TestEncryptedSecret_CryptoSignerInterface_RSA_NoPanicsOnRead(t *testing.T) {
	signer := generateRSAKey(t)
	s := secrets.NewEncryptedSecret[crypto.Signer](signer)

	assert.NotPanics(t, func() {
		s.Secret()
	})
}

func TestEncryptedSecret_CryptoSignerInterface_Ed25519_NoPanicsOnRead(t *testing.T) {
	signer := generateEd25519Key(t)
	s := secrets.NewEncryptedSecret[crypto.Signer](signer)

	assert.NotPanics(t, func() {
		s.Secret()
	})
}
