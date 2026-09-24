package secrets

import "os"

func NewEncryptedSecretFromEnv(name string) *EncryptedSecret[[]byte] {
	secret := os.Getenv(name)
	defer os.Unsetenv(name)

	s := EncryptedSecret[[]byte]{}
	if err := s.set([]byte(secret)); err != nil {
		panic(err)
	}
	return &s
}
