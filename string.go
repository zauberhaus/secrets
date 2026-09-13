package secrets

import (
	"crypto/sha256"
	"encoding/json"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/spf13/pflag"
)

// SecretStringFlag is a string value encrypted with AES-256-GCM, using the same
// package key (and [SetKey]) as [EncryptedSecret]. Unlike EncryptedSecret it
// needs no wrapper struct: the slice itself is the ciphertext.
//
// See [EncryptedSecret] for the key-management and memory-exposure caveats
// that apply here too.
type SecretStringFlag []byte

var _ Secret[[]byte] = (*SecretStringFlag)(nil)
var _ pflag.Value = (*SecretStringFlag)(nil)

// NewStringSecret encrypts val into a new StringSecret. Panics if the value
// cannot be encrypted.
func NewStringSecret(val *string) SecretStringFlag {
	var s SecretStringFlag
	if err := s.set(val); err != nil {
		panic(err)
	}
	return s
}

func (s *SecretStringFlag) set(val *string) error {
	if val == nil || len(*val) == 0 {
		*s = nil
		return nil
	}

	plaintext := make([]byte, len(*val))
	copy(plaintext, []byte(*val))

	defer memguard.WipeBytes(plaintext)

	data, err := encryptBytes(plaintext)
	if err != nil {
		return err
	}

	*s = data
	return nil
}

// Destroy implements [Secret].
func (s *SecretStringFlag) Destroy() {
	if s == nil {
		return
	}
	memguard.WipeBytes(*s)
	*s = nil
}

// Empty implements [Secret].
func (s SecretStringFlag) Empty() bool {
	return len(s) == 0
}

// Hash implements [Secret].
func (s *SecretStringFlag) Hash() ([32]byte, error) {
	if s == nil {
		return [32]byte{}, nil
	}

	data, err := s.MarshalSecret()
	if err != nil {
		return [32]byte{}, err
	}

	hash := sha256.Sum256(data)
	memguard.WipeBytes(data)

	return hash, nil
}

func (s *SecretStringFlag) ID() (string, error) {
	if s == nil {
		return "", nil
	}

	hash, err := s.Hash()
	if err != nil {
		return "", err
	}

	return Base58Encode(hash[:][:8]), nil
}

func (s SecretStringFlag) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s SecretStringFlag) MarshalSecret() (text []byte, err error) {
	if s.Empty() {
		return []byte{}, nil
	}

	return decryptBytes(s)
}

func (s SecretStringFlag) MarshalText() (text []byte, err error) {
	return []byte(s.String()), nil
}

func (s SecretStringFlag) Secret() []byte {
	plaintext, err := s.MarshalSecret()
	if err != nil {
		panic(err)
	}

	return plaintext
}

func (s *SecretStringFlag) Set(val string) error {
	return s.UnmarshalText([]byte(val))
}

func (s SecretStringFlag) String() string {
	if s.Empty() {
		return ""
	}
	return strings.Repeat("*", 5)
}

func (s SecretStringFlag) Type() string {
	return "string"
}

func (s *SecretStringFlag) UnmarshalJSON(data []byte) error {
	if s == nil {
		return nil
	}

	var val string
	if err := json.Unmarshal(data, &val); err != nil {
		return err
	}

	return s.set(&val)
}

// UnmarshalText implements [Secret].
func (s *SecretStringFlag) UnmarshalText(text []byte) error {
	if s == nil {
		return nil
	}

	val := string(text)
	return s.set(&val)
}
