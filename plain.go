package secrets

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/zauberhaus/reflect_utils"
)

type Serializable interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

func BytesSecret(data []byte) Secret[[]byte] {
	return NewSecret(data)
}

func StringSecret(text string) Secret[string] {
	return NewSecret(text)
}

type PlainSecret[T any] struct {
	val T
}

var _ Secret[string] = (*PlainSecret[string])(nil)

func NewSecret[T any](val T) Secret[T] {
	secret := PlainSecret[T]{val}
	return &secret
}

func (s *PlainSecret[T]) UnmarshalText(text []byte) error {
	if s == nil {
		return nil
	}

	switch any(s.val).(type) {
	case string:
		s.val = any(string(text)).(T)
		return nil
	case []byte:
		s.val = any(text).(T)
		return nil
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
	var val T

	err := json.Unmarshal(data, &val)
	if err != nil {
		return err
	}

	s.val = val
	return nil
}

func (s PlainSecret[T]) MarshalSecret() ([]byte, error) {
	var text string

	switch o := any(s.val).(type) {
	case string:
		text = o
	case []byte:
		text = string(o)
	case encoding.TextMarshaler:
		data, err := o.MarshalText()
		if err != nil {
			return nil, err
		}
		text = string(data)

	default:
		data, err := json.Marshal(o)
		if err != nil {
			return nil, err
		}

		text = string(data)
	}

	if len(text) == 0 {
		return nil, nil
	}

	return []byte(text), nil
}

func (s PlainSecret[T]) MarshalText() (text []byte, err error) {
	return []byte(s.String()), nil
}

func (s PlainSecret[T]) MarshalJSON() ([]byte, error) {
	txt, err := s.MarshalText()
	if err != nil {
		return nil, err
	}

	return json.Marshal(string(txt))
}

func (s PlainSecret[T]) String() string {
	if s.Empty() {
		return ""
	}

	switch o := any(s.val).(type) {
	case string:
		return strings.Repeat("*", len(o))
	case []byte:
		return strings.Repeat("*", len(o))
	default:
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
