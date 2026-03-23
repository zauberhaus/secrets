package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/zauberhaus/reflect_utils"
)

var _ Secret[string] = (*EncryptedSecret[string])(nil)

var secKey = NewSingleton(func() []byte {
	key := make([]byte, 256/8)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	return key
})

func SetKey(key []byte) {
	if len(secKey.value) > 0 {
		panic("key is already initalized")
	}

	secKey.init = func() []byte {
		return key
	}
}

type EncryptedSecret[T any] struct {
	data []byte
}

func NewEncryptedSecret[T any](secret T) *EncryptedSecret[T] {
	s := EncryptedSecret[T]{}
	s.set(secret)
	return &s
}

func (s EncryptedSecret[T]) String() string {
	if len(s.data) == 0 {
		return ""
	} else {
		return strings.Repeat("*", 5)
	}
}

func (s EncryptedSecret[T]) MarshalSecret() (text []byte, err error) {
	if s.Empty() {
		return []byte{}, nil
	}

	val := s.Secret()

	switch o := any(val).(type) {
	case string:
		return []byte(o), nil
	case []byte:
		return o, nil
	case json.Marshaler:
		return o.MarshalJSON()
	default:
		return nil, fmt.Errorf("can's serialize %v", reflect.TypeFor[T]())
	}

}

func (s EncryptedSecret[T]) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *EncryptedSecret[T]) UnmarshalText(text []byte) error {
	secret := PlainSecret[T]{}
	err := secret.UnmarshalText(text)
	if err != nil {
		return err
	}

	return s.set(secret.Secret())
}

func (s EncryptedSecret[T]) Secret() T {
	secret, err := s.get()
	if err != nil {
		panic(err)
	}

	return secret
}

func (s EncryptedSecret[T]) Empty() bool {
	return len(s.data) == 0
}

func (s *EncryptedSecret[T]) Set(txt string) error {
	return s.UnmarshalText([]byte(txt))
}

func (s EncryptedSecret[T]) Type() string {
	t := reflect.TypeFor[T]()
	return fmt.Sprintf("%v", t)
}

func (s *EncryptedSecret[T]) set(val T) error {
	secret := PlainSecret[T]{val}
	plaintext, err := secret.MarshalSecret()
	if err != nil {
		return err
	}

	if len(plaintext) == 0 {
		s.data = nil
		return nil
	}

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(secKey.Get())
	if err != nil {
		return err
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	s.data = aesGCM.Seal(nonce, nonce, plaintext, nil)

	return nil
}

func (s *EncryptedSecret[T]) get() (T, error) {

	if s == nil || len(s.data) == 0 {
		return *new(T), nil
	}

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(secKey.Get())
	if err != nil {
		return *new(T), err
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return *new(T), err
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	if len(s.data) < nonceSize {
		return *new(T), fmt.Errorf("ciphertext too short")
	}

	//Extract the nonce from the encrypted data
	nonce := s.data[:nonceSize]
	ciphertext := s.data[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return *new(T), err
	}

	if reflect.TypeFor[T]().Kind() == reflect.Pointer {

	} else {

	}

	secret, err := reflect_utils.New[*PlainSecret[T]]()
	if err != nil {
		return *new(T), nil
	}

	err = secret.UnmarshalText(plaintext)
	if err != nil {
		return *new(T), err
	}

	return secret.Secret(), nil
}

func (s *EncryptedSecret[T]) UnmarshalJSON(data []byte) error {
	var val T

	err := json.Unmarshal(data, &val)
	if err != nil {
		return err
	}

	return s.set(val)
}

func (s EncryptedSecret[T]) MarshalJSON() ([]byte, error) {
	val, err := s.get()
	if err != nil {
		return nil, err
	}

	tmp := NewSecret(val)
	return tmp.MarshalJSON()
}
