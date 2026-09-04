package secrets

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/golang-jwt/jwt/v5"
	"github.com/zauberhaus/reflect_utils"
)

type Serializable interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

const (
	pkixTag  byte = 0x02
	pkcs8Tag byte = 0x03
)

var headerTag = []byte{0xa1, 0x5f, 0x13}

var (
	pkixHeader  = append(headerTag, pkixTag)
	pkcs8Header = append(headerTag, pkcs8Tag)
)

type PlainSecret[T any] struct {
	val T
}

var _ Secret[string] = (*PlainSecret[string])(nil)

func NewSecret[T any](val T) Secret[T] {
	secret := PlainSecret[T]{val}
	return &secret
}

func (s *PlainSecret[T]) UnmarshalText(text []byte) error {
	if s == nil || len(text) == 0 {
		return nil
	}

	switch any(s.val).(type) {
	case string:
		s.val = any(string(text)).(T)
		return nil
	case []byte:
		// Copy so the caller may wipe the input buffer afterwards.
		s.val = any(append([]byte(nil), text...)).(T)
		return nil
	case *jwt.Token:
		tok, _, err := jwt.NewParser().ParseUnverified(string(text), jwt.MapClaims{})
		if err != nil {
			return err
		}

		s.val = any(tok).(T)
		return nil
	}

	// asn1/x509 parsing may return values that alias the input DER bytes
	// (e.g. ed25519 keys), so parse a copy: the caller wipes text after
	// UnmarshalText returns.
	der := append([]byte(nil), text...)

	// A concrete crypto.Signer type (*ecdsa.PrivateKey, …) — or an
	// interface requiring its methods, such as T = crypto.Signer itself —
	// is detected from T alone, even though s.val is still its zero value
	// here (e.g. a nil interface) and can't be type-switched on.
	if reflect.TypeFor[T]().Implements(reflect.TypeFor[crypto.Signer]()) {
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return err
		}

		v, ok := key.(T)
		if !ok {
			return fmt.Errorf("unexpected key type %T", key)
		}

		s.val = v
		return nil
	}

	// A tagged header (written by MarshalSecret's default branch) resolves
	// the encoding in a single parse.
	if len(der) > len(headerTag) && bytes.HasPrefix(der, headerTag[:]) {
		tag := der[len(headerTag)]
		payload := der[len(headerTag)+1:]

		var key any
		var err error

		switch tag {
		case pkcs8Tag:
			key, err = x509.ParsePKCS8PrivateKey(payload)
		case pkixTag:
			key, err = x509.ParsePKIXPublicKey(payload)
		default:
			err = fmt.Errorf("unknown key tag %#x", tag)
		}

		if err != nil {
			return err
		}

		v, ok := key.(T)
		if !ok {
			return fmt.Errorf("unexpected key type %T", key)
		}

		s.val = v
		return nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if v, ok := key.(T); ok {
			s.val = v
			return nil
		}
	}

	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		if v, ok := key.(T); ok {
			s.val = v
			return nil
		}
	}

	if reflect.TypeFor[T]().Kind() == reflect.Pointer {
		switch o := any(s.val).(type) {
		case json.Unmarshaler:
			if reflect_utils.IsNil(o) {
				v, err := reflect_utils.New[T]()
				if err != nil {
					return err
				}

				o = any(v).(json.Unmarshaler)
			}

			err := o.UnmarshalJSON(text)
			if err != nil {
				return err
			}

			s.val = any(o).(T)
			return nil
		case encoding.TextUnmarshaler:
			if reflect_utils.IsNil(o) {
				v, err := reflect_utils.New[T]()
				if err != nil {
					return err
				}

				o = any(v).(encoding.TextUnmarshaler)
			}

			err := o.UnmarshalText(text)
			if err != nil {
				return err
			}

			s.val = any(o).(T)
			return nil
		}
	} else {
		switch o := any(&s.val).(type) {
		case json.Unmarshaler:
			if reflect_utils.IsNil(o) {
				v, err := reflect_utils.New[T]()
				if err != nil {
					return err
				}

				o = any(&v).(json.Unmarshaler)
			}

			err := o.UnmarshalJSON(text)
			if err != nil {
				return err
			}

			s.val = reflect_utils.FromPointer(o).(T)
			return nil
		case encoding.TextUnmarshaler:
			if reflect_utils.IsNil(s.val) {
				v, err := reflect_utils.New[T]()
				if err != nil {
					return err
				}

				o = any(&v).(encoding.TextUnmarshaler)
			}

			err := o.UnmarshalText(text)
			if err != nil {
				return err
			}

			s.val = reflect_utils.FromPointer(o).(T)
			return nil
		}
	}

	if reflect_utils.IsPointer(s.val) {
		if reflect_utils.IsNil(s.val) {
			v, err := reflect_utils.New[T]()
			if err != nil {
				return err
			}
			s.val = v
		}

		err := json.Unmarshal(text, s.val)
		if err != nil {
			return err
		}
	} else {
		err := json.Unmarshal(text, &s.val)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *PlainSecret[T]) UnmarshalJSON(data []byte) error {
	if s == nil {
		return nil
	}

	var val T

	err := json.Unmarshal(data, &val)
	if err != nil {
		return err
	}

	s.val = val
	return nil
}

// MarshalSecret returns the plaintext bytes. The returned buffer is a
// copy owned by the caller, who may wipe it after use. Intermediate
// string conversions are avoided because immutable string copies can
// never be wiped.
func (s PlainSecret[T]) MarshalSecret() ([]byte, error) {
	var data []byte

	switch o := any(s.val).(type) {
	case string:
		data = []byte(o)
	case []byte:
		data = append([]byte(nil), o...)
	case *jwt.Token:
		data = []byte(o.Raw)
	case encoding.TextMarshaler:
		d, err := o.MarshalText()
		if err != nil {
			return nil, err
		}
		data = d
	case crypto.Signer:
		if d, err := x509.MarshalPKCS8PrivateKey(o); err == nil {
			data = d
		} else {
			return nil, err
		}

	default:
		if d, err := x509.MarshalPKCS8PrivateKey(o); err == nil {
			data = append(pkcs8Header, d...)
			break
		}

		if d, err := x509.MarshalPKIXPublicKey(o); err == nil {
			data = append(pkixHeader, d...)
			break
		}

		d, err := json.Marshal(o)
		if err != nil {
			return nil, err
		}

		data = d
	}

	if len(data) == 0 {
		return nil, nil
	}

	return data, nil
}

func (s PlainSecret[T]) MarshalText() (text []byte, err error) {
	return []byte(s.String()), nil
}

func (s PlainSecret[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s PlainSecret[T]) String() string {
	if s.Empty() {
		return ""
	} else {
		return strings.Repeat("*", 5)
	}
}

func (s *PlainSecret[T]) Secret() T {
	if s == nil {
		return *new(T)
	}

	return s.val
}

func (s *PlainSecret[T]) Empty() bool {
	if s == nil {
		return true
	}

	return reflect_utils.IsEmpty(s.val)
}

func (s *PlainSecret[T]) Set(txt string) error {
	return s.UnmarshalText([]byte(txt))
}

func (s *PlainSecret[T]) Type() string {
	t := reflect.TypeFor[T]()
	return fmt.Sprintf("%v", t)
}

// ID returns a short Base58 identifier derived from an unsalted SHA-256
// hash of the plaintext. For low-entropy secrets (e.g. human-chosen
// passwords) the ID allows offline dictionary attacks and must not be
// exposed to untrusted parties.
func (s *PlainSecret[T]) ID() (string, error) {
	if s == nil {
		return "", nil
	}

	hash, err := s.Hash()
	if err != nil {
		return "", err
	}

	return Base58Encode(hash[:][:8]), nil
}

func (s *PlainSecret[T]) Hash() ([32]byte, error) {
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

func (s *PlainSecret[T]) Destroy() {
	if s == nil {
		return
	}
	s.val = *new(T)
}
