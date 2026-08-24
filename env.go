package secrets

import "os"

func NewEncryptedSecretFromEnv(name string) *EncryptedSecret[string] {
	secret := os.Getenv(name)
	defer os.Unsetenv(name)

	s := EncryptedSecret[string]{}
	if err := s.set(secret); err != nil {
		panic(err)
	}
	return &s
}
