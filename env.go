package secrets

import (
	"os"

	"github.com/awnumar/memguard"
)

// NewEncryptedSecretFromEnv encrypts the value of the environment variable
// name and unsets it. The original value may still remain in the process
// environment block (e.g. /proc/self/environ on Linux) and in the
// immutable string returned by os.Getenv, neither of which can be wiped.
func NewEncryptedSecretFromEnv(name string) *EncryptedSecret[[]byte] {
	secret := os.Getenv(name)
	defer os.Unsetenv(name)

	plaintext := []byte(secret)
	defer memguard.WipeBytes(plaintext)

	s := EncryptedSecret[[]byte]{}
	if err := s.set(plaintext); err != nil {
		panic(err)
	}
	return &s
}
