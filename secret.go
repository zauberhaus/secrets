package secrets

import (
	"encoding"
	"encoding/json"

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
}
