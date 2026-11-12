package secrets

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/awnumar/memguard"
)

// StringSecret is a string value encrypted with AES-256-GCM, using the same
// package key (and [SetKey]) as [EncryptedSecret]. Unlike EncryptedSecret it
// needs no wrapper struct: the slice itself is the ciphertext.
//
// See [EncryptedSecret] for the key-management, memory-exposure and
// concurrency caveats that apply here too.
type StringSecret []byte

var secretStringFlagAAD = []byte("secrets.SecretStringFlag")

func NewStringSecret(val string) Secret[[]byte] {
	var s StringSecret

	if len(val) == 0 {
		return &s
	}

	if err := s.set(new(val)); err != nil {
		panic(err)
	}
	return &s
}

// NewStringFlag encrypts val into a new SecretStringFlag. Panics if the
// value cannot be encrypted.
func NewStringFlag(val *string) Secret[[]byte] {
	var s StringSecret
	if err := s.set(val); err != nil {
		panic(err)
	}
	return &s
}

func (s *StringSecret) set(val *string) error {
	if s == nil {
		return ErrNilSecret
	}

	if val == nil || len(*val) == 0 {
		*s = nil
		return nil
	}

	plaintext := make([]byte, len(*val))
	copy(plaintext, *val)

	defer memguard.WipeBytes(plaintext)

	data, err := encryptBytes(plaintext, secretStringFlagAAD)
	if err != nil {
		return err
	}

	*s = data
	return nil
}

// Destroy implements [Secret].
func (s *StringSecret) Destroy() {
	if s == nil {
		return
	}
	memguard.WipeBytes(*s)
	*s = nil
}

// Empty implements [Secret].
func (s *StringSecret) Empty() bool {
	return s == nil || len(*s) == 0
}

// Hash returns an unsalted SHA-256 hash of the plaintext. For low-entropy
// secrets (e.g. human-chosen passwords) it allows offline dictionary
// attacks and must not be exposed to untrusted parties.
func (s *StringSecret) Hash() ([32]byte, error) {
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

func (s *StringSecret) ID() (string, error) {
	if s == nil {
		return "", nil
	}

	hash, err := s.Hash()
	if err != nil {
		return "", err
	}

	return Base58Encode(hash[:][:8]), nil
}

func (s StringSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *StringSecret) MarshalSecret() (text []byte, err error) {
	if s.Empty() {
		return []byte{}, nil
	}

	return decryptBytes(*s, secretStringFlagAAD)
}

func (s StringSecret) MarshalText() (text []byte, err error) {
	return []byte(s.String()), nil
}

func (s *StringSecret) Secret() []byte {
	plaintext, err := s.MarshalSecret()
	if err != nil {
		panic(err)
	}

	return plaintext
}

func (s *StringSecret) Set(val string) error {
	return s.UnmarshalText([]byte(val))
}

func (s StringSecret) String() string {
	if s.Empty() {
		return ""
	}
	return strings.Repeat("*", 5)
}

// GoString masks the value for %#v, which would otherwise print the
// ciphertext bytes.
func (s StringSecret) GoString() string {
	return goString(reflect.TypeOf(s), s.String())
}

func (s *StringSecret) Type() string {
	return "string"
}

func (s *StringSecret) UnmarshalJSON(data []byte) error {
	if s == nil {
		return ErrNilSecret
	}

	var val string
	if err := json.Unmarshal(data, &val); err != nil {
		return invalidValue[string]()
	}

	return s.set(&val)
}

// UnmarshalText implements [Secret].
func (s *StringSecret) UnmarshalText(text []byte) error {
	if s == nil {
		return ErrNilSecret
	}

	val := string(text)
	return s.set(&val)
}

func (s *StringSecret) Equal(sec Secret[[]byte]) bool {
	return equalHash(s, sec)
}
