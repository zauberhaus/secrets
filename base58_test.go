package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBase58Encode_KnownValues(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0x00}, "1"},
		{[]byte{0x00, 0x00}, "11"},
		{[]byte{0x00, 0x01}, "12"},
		{[]byte{0x61}, "2g"}, // "a"
		{[]byte("hello"), "Cn8eVZg"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, Base58Encode(tt.input))
	}
}

func TestBase58Encode_Empty(t *testing.T) {
	assert.Equal(t, "", Base58Encode([]byte{}))
}

func TestBase58Decode_KnownValues(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"1", []byte{0x00}},
		{"11", []byte{0x00, 0x00}},
		{"12", []byte{0x00, 0x01}},
		{"2g", []byte{0x61}},
		{"Cn8eVZg", []byte("hello")},
	}
	for _, tt := range tests {
		got, err := Base58Decode(tt.input)
		assert.NoError(t, err)
		assert.Equal(t, tt.expected, got)
	}
}

func TestBase58Decode_Empty(t *testing.T) {
	got, err := Base58Decode("")
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, got)
}

func TestBase58Decode_InvalidCharacter(t *testing.T) {
	_, err := Base58Decode("invalid0OIl") // '0', 'O', 'I', 'l' are not in the alphabet
	assert.Error(t, err)
}

func TestBase58RoundTrip(t *testing.T) {
	inputs := [][]byte{
		{0x00},
		{0x00, 0x00, 0x01},
		[]byte("hello world"),
		{0xff, 0xfe, 0xfd},
		{0x00, 0x00, 0xff},
	}
	for _, input := range inputs {
		encoded := Base58Encode(input)
		decoded, err := Base58Decode(encoded)
		assert.NoError(t, err)
		assert.Equal(t, input, decoded)
	}
}

func TestBase58Encode_OnlyUsesAlphabet(t *testing.T) {
	encoded := Base58Encode([]byte("test data for alphabet check"))
	for _, c := range encoded {
		assert.Contains(t, base58Alphabet, string(c))
	}
}

func TestBase58Encode_LeadingZeros(t *testing.T) {
	// Each leading zero byte encodes as '1'
	encoded := Base58Encode([]byte{0x00, 0x00, 0x00, 0x01})
	assert.True(t, len(encoded) >= 3)
	assert.Equal(t, "111", encoded[:3])
}

func TestBase58Decode_InvalidCharacters(t *testing.T) {
	// '0', 'O', 'I', 'l' are intentionally excluded from the base58 alphabet
	for _, c := range []string{"0", "O", "I", "l"} {
		_, err := Base58Decode(c)
		assert.Errorf(t, err, "expected error for character %q", c)
	}
}
