package secrets

import (
	"bytes"
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

	MarshalSecret() (text []byte, err error)
	Destroy()

	pflag.Value
}

func Wipe(data []byte) {
	memguard.WipeBytes(data)
}

func Equal[X any, Y any](s1 Secret[X], s2 Secret[Y]) bool {
	h1, err := s1.Hash()
	if err != nil {
		return false
	}

	h2, err := s2.Hash()
	if err != nil {
		return false
	}

	return bytes.Equal(h1[:], h2[:])
}
