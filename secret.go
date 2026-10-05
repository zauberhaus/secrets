package secrets

import (
	"crypto/subtle"
	"encoding"
	"encoding/json"

	"github.com/awnumar/memguard"
	"github.com/spf13/pflag"
)

type Secret[T any] interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler
	json.Unmarshaler
	json.Marshaler
	pflag.Value

	Secret() T
	Empty() bool
	String() string
	Hash() ([32]byte, error)
	ID() (string, error)

	Equal(s Secret[T]) bool

	MarshalSecret() (text []byte, err error)
	Destroy()

	pflag.Value
}

func Wipe(data []byte) {
	memguard.WipeBytes(data)
}

func Equal[X any, Y any](s1 Secret[X], s2 Secret[Y]) bool {
	return equalHash(s1, s2)
}

type hasher interface {
	Hash() ([32]byte, error)
}

func equalHash(s1 hasher, s2 hasher) bool {
	if s1 == nil || s2 == nil {
		return false
	}

	h1, err := s1.Hash()
	if err != nil {
		return false
	}

	h2, err := s2.Hash()
	if err != nil {
		return false
	}

	var zero [32]byte
	if h1 == zero || h2 == zero {
		return false
	}

	return subtle.ConstantTimeCompare(h1[:], h2[:]) == 1
}
