// Copyright 2026 Zauberhaus
// Licensed to Zauberhaus under one or more agreements.
// Zauberhaus licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"

	"github.com/awnumar/memguard"
	"github.com/zauberhaus/reflect_utils"
)

// secKey holds the AES-256 key sealed in an mlocked memguard enclave,
// so the key is excluded from swap and core dumps and never sits in
// plain heap memory between uses.
var secKey = &keyEnclave{}

type keyEnclave struct {
	enclave *memguard.Enclave
	lock    sync.Mutex
}

// open returns the key in a locked buffer. The caller must Destroy the
// buffer as soon as the cipher has been created.
func (k *keyEnclave) open() (*memguard.LockedBuffer, error) {
	k.lock.Lock()
	if k.enclave == nil {
		key := make([]byte, 256/8)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			k.lock.Unlock()
			return nil, err
		}
		k.enclave = memguard.NewEnclave(key) // NewEnclave wipes the source slice
	}
	enclave := k.enclave
	k.lock.Unlock()

	return enclave.Open()
}

// SetKey sets the AES-256 key used by all EncryptedSecret values. It must
// be called before any EncryptedSecret is created and panics if the key is
// already initialized or is not exactly 32 bytes. The key is moved into a
// locked enclave and the caller's slice is wiped, also when SetKey panics.
func SetKey(key []byte) {
	secKey.lock.Lock()
	defer secKey.lock.Unlock()

	if secKey.enclave != nil {
		memguard.WipeBytes(key)
		panic("key is already initialized")
	}

	if len(key) != 256/8 {
		size := len(key)
		memguard.WipeBytes(key)
		panic(fmt.Sprintf("invalid key size %d, key must be 32 bytes", size))
	}

	secKey.enclave = memguard.NewEnclave(key)
}

// encryptBytes seals plaintext with AES-256-GCM using the package key,
// prefixing the ciphertext with a freshly generated nonce. aad binds the
// ciphertext to its owning type so it cannot be decrypted as another one.
// It returns (nil, nil) for empty input.
func encryptBytes(plaintext, aad []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}

	keyBuf, err := secKey.open()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keyBuf.Bytes())
	keyBuf.Destroy()
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aesGCM.Seal(nonce, nonce, plaintext, aad), nil
}

// decryptBytes reverses [encryptBytes]; aad must match the value used to
// encrypt. It returns (nil, nil) for empty input.
func decryptBytes(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}

	keyBuf, err := secKey.open()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keyBuf.Bytes())
	keyBuf.Destroy()
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]

	return aesGCM.Open(nil, nonce, data, aad)
}

// EncryptedSecret holds the value AES-256-GCM encrypted with the package
// key (see [SetKey]); it is decrypted on every read.
//
// EncryptedSecret is not safe for concurrent use while it is being mutated
// (Set, UnmarshalText, UnmarshalJSON, Destroy): Destroy wipes the
// ciphertext in place, so a concurrent read fails or panics. Use
// [GuardedSecret] when concurrent mutation is needed.
type EncryptedSecret[T any] struct {
	data []byte
}

func (s *EncryptedSecret[T]) aad() []byte {
	return []byte(reflect.TypeFor[EncryptedSecret[T]]().String())
}

func NewEncryptedSecret[T any](secret T) Secret[T] {
	if reflect.TypeFor[T]().Kind() == reflect.String {
		panic(errors.New("NewEncryptedSecret is unsafe for strings, use NewStringSecret instead"))
	}

	s := EncryptedSecret[T]{}
	if err := s.set(secret); err != nil {
		panic(err)
	}
	return &s
}

func (s EncryptedSecret[T]) String() string {
	if len(s.data) == 0 {
		return ""
	} else {
		return strings.Repeat("*", 5)
	}
}

// GoString masks the value for %#v, which bypasses String.
func (s EncryptedSecret[T]) GoString() string {
	return goString(reflect.TypeOf(s), s.String())
}

// MarshalSecret returns the decrypted plaintext bytes, in the same
// serialization as [PlainSecret.MarshalSecret]. The caller owns the
// returned slice and should wipe it after use.
func (s *EncryptedSecret[T]) MarshalSecret() (text []byte, err error) {
	if s.Empty() {
		return []byte{}, nil
	}

	return decryptBytes(s.data, s.aad())
}

func (s EncryptedSecret[T]) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText parses and encrypts text; empty text clears the secret.
// Parse errors are replaced by an [ErrInvalidValue] error that does not
// quote the input.
func (s *EncryptedSecret[T]) UnmarshalText(text []byte) error {
	if s == nil {
		return ErrNilSecret
	}

	secret := PlainSecret[T]{}
	if err := secret.UnmarshalText(text); err != nil {
		return err
	}
	defer secret.Destroy()

	return s.set(secret.Secret())
}

func (s *EncryptedSecret[T]) Secret() T {
	secret, err := s.get()
	if err != nil {
		panic(err)
	}

	return secret
}

func (s *EncryptedSecret[T]) Empty() bool {
	return s == nil || len(s.data) == 0
}

func (s *EncryptedSecret[T]) Set(txt string) error {
	return s.UnmarshalText([]byte(txt))
}

func (s *EncryptedSecret[T]) Type() string {
	t := reflect.TypeFor[T]()
	return fmt.Sprintf("%v", t)
}

func (s *EncryptedSecret[T]) set(val T) error {
	if s == nil {
		return ErrNilSecret
	}

	secret := PlainSecret[T]{val}
	plaintext, err := secret.MarshalSecret()
	if err != nil {
		return err
	}

	if len(plaintext) == 0 {
		s.data = nil
		return nil
	}
	defer memguard.WipeBytes(plaintext)

	data, err := encryptBytes(plaintext, s.aad())
	if err != nil {
		return err
	}

	s.data = data
	return nil
}

func (s *EncryptedSecret[T]) get() (T, error) {

	if s == nil || len(s.data) == 0 {
		return *new(T), nil
	}

	plaintext, err := decryptBytes(s.data, s.aad())
	if err != nil {
		return *new(T), err
	}
	defer memguard.WipeBytes(plaintext)

	secret, err := reflect_utils.New[*PlainSecret[T]]()
	if err != nil {
		return *new(T), err
	}

	err = secret.UnmarshalText(plaintext)
	if err != nil {
		return *new(T), err
	}

	return secret.Secret(), nil
}

func (s *EncryptedSecret[T]) UnmarshalJSON(data []byte) error {
	if s == nil {
		return ErrNilSecret
	}

	tmp := PlainSecret[T]{}
	if err := json.Unmarshal(data, &tmp.val); err != nil {
		return invalidValue[T]()
	}
	defer tmp.Destroy()

	return s.set(tmp.val)
}

// MarshalJSON returns the masked value; the ciphertext is not decrypted.
func (s EncryptedSecret[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// ID returns a short Base58 identifier derived from [EncryptedSecret.Hash].
// See Hash for the dictionary-attack caveat.
func (s *EncryptedSecret[T]) ID() (string, error) {
	if s == nil {
		return "", nil
	}

	hash, err := s.Hash()
	if err != nil {
		return "", err
	}

	return Base58Encode(hash[:][:8]), nil
}

// Hash returns an unsalted SHA-256 hash of the plaintext. For low-entropy
// secrets (e.g. human-chosen passwords) it allows offline dictionary
// attacks and must not be exposed to untrusted parties.
func (s *EncryptedSecret[T]) Hash() ([32]byte, error) {
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

func (s *EncryptedSecret[T]) Destroy() {
	if s == nil {
		return
	}
	memguard.WipeBytes(s.data)
	s.data = nil
}

func (s *EncryptedSecret[T]) Equal(sec Secret[T]) bool {
	return equalHash(s, sec)
}
