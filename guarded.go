package secrets

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"

	"github.com/awnumar/memguard"
	"github.com/zauberhaus/reflect_utils"
)

var _ Secret[string] = (*GuardedSecret[string])(nil)

// GuardedSecret stores the serialized plaintext in a memguard Enclave:
// mlock'd, guard-paged, excluded from swap and core dumps, and encrypted
// at rest using a per-process in-memory key managed entirely by memguard.
// No user-supplied encryption key is required.
//
// Use GuardedSecret when you want the strongest in-process memory
// protection and do not need to persist or share the encrypted form.
// For a user-supplied key or persistence use EncryptedSecret.
//
// GuardedSecret is safe for concurrent use.
//
// # Caveats
//
//   - Calling memguard.Purge rotates memguard's session key, after which
//     every existing GuardedSecret is permanently undecryptable and
//     Secret() panics.
//   - Every read (Secret, MarshalSecret, ID) briefly mlocks a page;
//     extremely high parallel read fan-out may hit RLIMIT_MEMLOCK, on
//     which memguard panics. Read once and reuse the value in hot paths.
//
// # Custom T types
//
// Any custom T whose UnmarshalText/UnmarshalJSON retains the input slice
// must copy it — the library wipes the decrypted buffer after unmarshaling.
type GuardedSecret[T any] struct {
	enclave atomic.Pointer[memguard.Enclave]
}

// NewGuardedSecret seals val into a GuardedSecret. Panics if the value
// cannot be serialized.
func NewGuardedSecret[T any](val T) *GuardedSecret[T] {
	s := &GuardedSecret[T]{}
	if err := s.set(val); err != nil {
		panic(err)
	}
	return s
}

func (s *GuardedSecret[T]) set(val T) error {
	if s == nil {
		return nil
	}
	plain := PlainSecret[T]{val: val}
	data, err := plain.MarshalSecret()
	if err != nil {
		return err
	}

	if len(data) == 0 {
		s.enclave.Store(nil)
		return nil
	}

	// NewEnclave copies data into protected memory and wipes the source slice.
	s.enclave.Store(memguard.NewEnclave(data))
	return nil
}

func (s *GuardedSecret[T]) get() (T, error) {
	if s == nil {
		return *new(T), nil
	}

	enclave := s.enclave.Load()
	if enclave == nil {
		return *new(T), nil
	}

	buf, err := enclave.Open()
	if err != nil {
		return *new(T), err
	}
	defer buf.Destroy()

	plain, err := reflect_utils.New[*PlainSecret[T]]()
	if err != nil {
		return *new(T), err
	}

	if err := plain.UnmarshalText(buf.Bytes()); err != nil {
		return *new(T), err
	}

	return plain.Secret(), nil
}

// Secret decrypts and returns the protected value. Panics on decryption
// failure (tampered enclave or a purged memguard session).
func (s *GuardedSecret[T]) Secret() T {
	val, err := s.get()
	if err != nil {
		panic(err)
	}
	return val
}

// Destroy drops the sealed value; the secret reads as empty afterwards.
// The plaintext cannot be recovered from the discarded ciphertext.
func (s *GuardedSecret[T]) Destroy() {
	if s != nil {
		s.enclave.Store(nil)
	}
}

func (s *GuardedSecret[T]) Empty() bool {
	return s == nil || s.enclave.Load() == nil
}

// String returns a fixed-width mask so that logs never reveal the value
// or its length.
func (s *GuardedSecret[T]) String() string {
	if s.Empty() {
		return ""
	}
	return strings.Repeat("*", 5)
}

func (s *GuardedSecret[T]) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *GuardedSecret[T]) UnmarshalText(text []byte) error {
	plain := &PlainSecret[T]{}
	if err := plain.UnmarshalText(text); err != nil {
		return err
	}

	val := plain.Secret()
	err := s.set(val)

	// The intermediate decoded copy is no longer needed once the value
	// is sealed; wipe it where the type allows.
	if b, ok := any(val).([]byte); ok {
		memguard.WipeBytes(b)
	}

	return err
}

func (s *GuardedSecret[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *GuardedSecret[T]) UnmarshalJSON(data []byte) error {
	var val T
	if err := json.Unmarshal(data, &val); err != nil {
		return err
	}

	err := s.set(val)

	// The intermediate decoded copy is no longer needed once the value
	// is sealed; wipe it where the type allows.
	if b, ok := any(val).([]byte); ok {
		memguard.WipeBytes(b)
	}

	return err
}

// Set implements pflag.Value.
func (s *GuardedSecret[T]) Set(txt string) error {
	return s.UnmarshalText([]byte(txt))
}

// Type implements pflag.Value.
func (s *GuardedSecret[T]) Type() string {
	t := reflect.TypeFor[T]()
	return fmt.Sprintf("%v", t)
}

// MarshalSecret returns a copy of the plaintext bytes from protected
// memory. The caller should wipe the returned slice after use.
func (s *GuardedSecret[T]) MarshalSecret() ([]byte, error) {
	if s == nil {
		return []byte{}, nil
	}

	enclave := s.enclave.Load()
	if enclave == nil {
		return []byte{}, nil
	}

	buf, err := enclave.Open()
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()

	return append([]byte(nil), buf.Bytes()...), nil
}

// ID returns a short Base58 identifier derived from an unsalted SHA-256
// hash of the plaintext. For low-entropy secrets (e.g. human-chosen
// passwords) the ID allows offline dictionary attacks and must not be
// exposed to untrusted parties.
func (s *GuardedSecret[T]) ID() (string, error) {
	if s == nil {
		return "", nil
	}

	hash, err := s.Hash()
	if err != nil {
		return "", err
	}

	return Base58Encode(hash[:][:8]), nil
}

func (s *GuardedSecret[T]) Hash() ([32]byte, error) {
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
