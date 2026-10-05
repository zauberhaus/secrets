package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func stringFlag(val string) Secret[[]byte] {
	return NewStringFlag(&val)
}

func TestEqual_Methods(t *testing.T) {
	tests := []struct {
		name string
		a, b Secret[string]
		want bool
	}{
		{"plain same", NewSecret("pw"), NewSecret("pw"), true},
		{"plain different", NewSecret("pw"), NewSecret("other"), false},
		{"plain prefix", NewSecret("pw"), NewSecret("pw2"), false},
		{"plain empty", NewSecret(""), NewSecret(""), true},
		{"plain empty vs value", NewSecret(""), NewSecret("pw"), false},
		{"guarded same", NewGuardedSecret("pw"), NewGuardedSecret("pw"), true},
		{"guarded different", NewGuardedSecret("pw"), NewGuardedSecret("other"), false},
		{"encrypted same", NewEncryptedSecret("pw"), NewEncryptedSecret("pw"), true},
		{"encrypted different", NewEncryptedSecret("pw"), NewEncryptedSecret("other"), false},
		{"plain vs guarded", NewSecret("pw"), NewGuardedSecret("pw"), true},
		{"plain vs encrypted", NewSecret("pw"), NewEncryptedSecret("pw"), true},
		{"guarded vs encrypted different", NewGuardedSecret("pw"), NewEncryptedSecret("other"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.Equal(tt.b))
			assert.Equal(t, tt.want, tt.b.Equal(tt.a), "Equal must be symmetric")
		})
	}
}

func TestEqual_SecretStringFlag(t *testing.T) {
	assert.True(t, stringFlag("pw").Equal(stringFlag("pw")))
	assert.False(t, stringFlag("pw").Equal(stringFlag("other")))
	assert.False(t, stringFlag("pw").Equal(stringFlag("pw2")))
	assert.True(t, stringFlag("").Equal(stringFlag("")))
	assert.True(t, stringFlag("pw").Equal(NewSecret([]byte("pw"))))
	assert.False(t, stringFlag("pw").Equal(NewSecret([]byte("other"))))
}

func TestEqual_SameInstance(t *testing.T) {
	for _, s := range []Secret[string]{NewSecret("pw"), NewGuardedSecret("pw"), NewEncryptedSecret("pw")} {
		assert.True(t, s.Equal(s))
	}
}

func TestEqual_NilArgument(t *testing.T) {
	assert.NotPanics(t, func() {
		assert.False(t, NewSecret("pw").Equal(nil))
		assert.False(t, NewGuardedSecret("pw").Equal(nil))
		assert.False(t, NewEncryptedSecret("pw").Equal(nil))
		assert.False(t, stringFlag("pw").Equal(nil))
	})
}

func TestEqual_NilReceiver(t *testing.T) {
	var p *PlainSecret[string]
	var g *GuardedSecret[string]
	var e *EncryptedSecret[string]

	assert.NotPanics(t, func() {
		assert.False(t, p.Equal(NewSecret("pw")))
		assert.False(t, g.Equal(NewSecret("pw")))
		assert.False(t, e.Equal(NewSecret("pw")))
	})
}

func TestEqual_AfterDestroy(t *testing.T) {
	a := NewEncryptedSecret("pw")
	b := NewEncryptedSecret("pw")
	a.Destroy()

	assert.False(t, a.Equal(b))
}

func TestEqual_CorruptedData(t *testing.T) {
	a := NewEncryptedSecret("pw")
	a.data[len(a.data)-1] ^= 0xff

	assert.NotPanics(t, func() {
		assert.False(t, a.Equal(NewEncryptedSecret("pw")))
		assert.False(t, NewEncryptedSecret("pw").Equal(a))
	})
}

func TestEqual_CorruptedStringFlag(t *testing.T) {
	s := stringFlag("pw")
	f := s.(*SecretStringFlag)
	(*f)[len(*f)-1] ^= 0xff

	assert.NotPanics(t, func() {
		assert.False(t, s.Equal(stringFlag("pw")))
	})
}

func TestEqual_Generic(t *testing.T) {
	assert.True(t, Equal(NewSecret("pw"), NewEncryptedSecret("pw")))
	assert.False(t, Equal(NewSecret("pw"), NewEncryptedSecret("other")))
	assert.True(t, Equal(stringFlag("pw"), NewGuardedSecret([]byte("pw"))))
	assert.False(t, Equal[string, []byte](NewSecret("pw"), stringFlag("other")))
}

func TestEqual_GenericNil(t *testing.T) {
	assert.NotPanics(t, func() {
		assert.False(t, Equal[string, string](nil, NewSecret("pw")))
		assert.False(t, Equal[string, string](NewSecret("pw"), nil))
		assert.False(t, Equal[string, string](nil, nil))
	})
}

func TestEqual_TwoNilPointers(t *testing.T) {
	var p1, p2 *PlainSecret[string]
	var g1, g2 *GuardedSecret[string]
	var e1, e2 *EncryptedSecret[string]
	var f1, f2 *SecretStringFlag

	assert.False(t, p1.Equal(p2))
	assert.False(t, g1.Equal(g2))
	assert.False(t, e1.Equal(e2))
	assert.False(t, f1.Equal(f2))
	assert.False(t, p1.Equal(e2))
	assert.False(t, Equal[string, string](p1, e1))
	assert.False(t, Equal[string, []byte](g1, f1))
}
