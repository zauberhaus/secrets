// Copyright 2026 Zauberhaus
// Licensed to Zauberhaus under one or more agreements.
// Zauberhaus licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package secrets_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zauberhaus/secrets"
)

func generateJWTToken(t *testing.T) *jwt.Token {
	t.Helper()

	claims := jwt.MapClaims{"sub": "user123", "role": "admin"}
	unsigned := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signed, err := unsigned.SignedString([]byte("test-signing-key"))
	require.NoError(t, err)

	parsed, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	require.NoError(t, err)

	return parsed
}

func TestJWTToken_RoundTrip(t *testing.T) {
	tok := generateJWTToken(t)

	s := secrets.NewEncryptedSecret(tok)
	require.NotNil(t, s)
	require.False(t, s.Empty())

	got := s.Secret()
	require.NotNil(t, got)
	assert.Equal(t, tok.Raw, got.Raw)

	claims, ok := got.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "user123", claims["sub"])
	assert.Equal(t, "admin", claims["role"])
}

func TestJWTToken_MarshalSecret(t *testing.T) {
	tok := generateJWTToken(t)

	s := secrets.NewSecret(tok)
	data, err := s.MarshalSecret()
	require.NoError(t, err)
	assert.Equal(t, tok.Raw, string(data))
}

func TestJWTToken_UnmarshalText_Invalid(t *testing.T) {
	var s jwt.Token
	secret := secrets.NewSecret(&s)

	err := secret.Set("not-a-valid-jwt")
	assert.Error(t, err)
}
