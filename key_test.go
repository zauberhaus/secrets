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

// privateKeyEqualer and publicKeyEqualer let tests compare crypto keys via
// their own Equal method instead of assert.Equal/reflect.DeepEqual: RSA
// keys cache an internal FIPS-mode shadow copy (rsa.PrivateKey.Precomputed.fips)
// that's computed lazily and isn't guaranteed byte-identical between two
// otherwise-equal keys, which makes DeepEqual comparisons flaky.
type privateKeyEqualer interface {
	Equal(x crypto.PrivateKey) bool
}

type publicKeyEqualer interface {
	Equal(x crypto.PublicKey) bool
}

func TestEncryptedSecret_CryptoSignerInterface_NoPanicsOnRead(t *testing.T) {
	signer := generateECKey(t)
	s := secrets.NewEncryptedSecret[crypto.Signer](signer)

	var got crypto.Signer
	assert.NotPanics(t, func() {
		got = s.Secret()
	})
	assert.True(t, signer.Equal(got))
}

func TestEncryptedSecret_CryptoSignerInterface_RSA_NoPanicsOnRead(t *testing.T) {
	signer := generateRSAKey(t)
	s := secrets.NewEncryptedSecret[crypto.Signer](signer)

	var got crypto.Signer
	assert.NotPanics(t, func() {
		got = s.Secret()
	})
	assert.True(t, signer.Equal(got))
}

func TestEncryptedSecret_CryptoSignerInterface_Ed25519_NoPanicsOnRead(t *testing.T) {
	signer := generateEd25519Key(t)
	s := secrets.NewEncryptedSecret[crypto.Signer](signer)

	var got crypto.Signer
	assert.NotPanics(t, func() {
		got = s.Secret()
	})
	assert.True(t, signer.Equal(got))
}

func TestEncryptedSecret_PrivateKeyInterface_RSA_NoPanicsOnRead(t *testing.T) {
	privKey := generateRSAKey(t)
	s := secrets.NewEncryptedSecret[crypto.PrivateKey](privKey)

	var got crypto.PrivateKey
	assert.NotPanics(t, func() {
		got = s.Secret()
	})
	assert.True(t, privKey.Equal(got))
}

func TestEncryptedSecret_PrivateKeyInterface_EC_NoPanicsOnRead(t *testing.T) {
	privKey := generateECKey(t)
	s := secrets.NewEncryptedSecret[crypto.PrivateKey](privKey)

	var got crypto.PrivateKey
	assert.NotPanics(t, func() {
		got = s.Secret()
	})
	assert.True(t, privKey.Equal(got))
}

func TestEncryptedSecret_PrivateKeyInterface_Ed25519_NoPanicsOnRead(t *testing.T) {
	privKey := generateEd25519Key(t)
	s := secrets.NewEncryptedSecret[crypto.PrivateKey](privKey)

	var got crypto.PrivateKey
	assert.NotPanics(t, func() {
		got = s.Secret()
	})
	assert.True(t, privKey.Equal(got))
}

func TestEncryptedSecret_PublicKeyInterface_RSA_NoPanicsOnRead(t *testing.T) {
	pubKey := generateRSAKey(t).Public()
	s := secrets.NewEncryptedSecret[crypto.PrivateKey](pubKey)

	var got crypto.PrivateKey
	assert.NotPanics(t, func() {
		got = s.Secret()
	})

	eq, ok := pubKey.(publicKeyEqualer)
	require.True(t, ok)
	assert.True(t, eq.Equal(got))
}

func TestPublicKey_RSAKey_RoundTrip(t *testing.T) {
	pub := generateRSAKey(t).Public().(*rsa.PublicKey)

	s := secrets.NewEncryptedSecret(pub)
	require.NotNil(t, s)
	require.False(t, s.Empty())

	got := s.Secret()
	assert.True(t, pub.Equal(got))
}

func TestPublicKey_ECKey_RoundTrip(t *testing.T) {
	pub := generateECKey(t).Public().(*ecdsa.PublicKey)

	s := secrets.NewEncryptedSecret(pub)
	require.NotNil(t, s)
	require.False(t, s.Empty())

	got := s.Secret()
	assert.True(t, pub.Equal(got))
}

func TestPublicKey_Ed25519Key_RoundTrip(t *testing.T) {
	pub := generateEd25519Key(t).Public().(ed25519.PublicKey)

	s := secrets.NewEncryptedSecret(pub)
	require.NotNil(t, s)
	require.False(t, s.Empty())

	got := s.Secret()
	assert.True(t, pub.Equal(got))
}

func TestEncryptedSecret_PublicKeyInterface_EC_NoPanicsOnRead(t *testing.T) {
	pubKey := generateECKey(t).Public()
	s := secrets.NewEncryptedSecret(pubKey)

	var got crypto.PublicKey
	assert.NotPanics(t, func() {
		got = s.Secret()
	})

	eq, ok := pubKey.(publicKeyEqualer)
	require.True(t, ok)
	assert.True(t, eq.Equal(got))
}

func TestEncryptedSecret_PublicKeyInterface_Ed25519_NoPanicsOnRead(t *testing.T) {
	pubKey := generateEd25519Key(t).Public()
	s := secrets.NewEncryptedSecret(pubKey)

	var got crypto.PublicKey
	assert.NotPanics(t, func() {
		got = s.Secret()
	})

	eq, ok := pubKey.(publicKeyEqualer)
	require.True(t, ok)
	assert.True(t, eq.Equal(got))
}
