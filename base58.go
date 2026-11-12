package secrets

import (
	"fmt"
	"math/big"
)

// cspell:disable-next-line
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func Base58Encode(input []byte) string {
	n := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	// Add '1' for each leading zero byte.
	for _, b := range input {
		if b != 0x00 {
			break
		}
		result = append(result, base58Alphabet[0])
	}

	// Reverse.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// MaxBase58DecodeLen bounds the input accepted by [Base58Decode]. Decoding
// is quadratic in the input length, so unbounded untrusted input could be
// used for denial of service.
const MaxBase58DecodeLen = 1 << 16

var base58Index = func() (idx [256]int8) {
	for i := range idx {
		idx[i] = -1
	}
	for i := range len(base58Alphabet) {
		idx[base58Alphabet[i]] = int8(i)
	}
	return idx
}()

func Base58Decode(input string) ([]byte, error) {
	if len(input) > MaxBase58DecodeLen {
		return nil, fmt.Errorf("base58 input too long: %d > %d", len(input), MaxBase58DecodeLen)
	}

	n := big.NewInt(0)
	base := big.NewInt(58)
	digit := new(big.Int)

	for _, c := range input {
		if c >= 0x80 || base58Index[c] < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", c)
		}
		n.Mul(n, base)
		n.Add(n, digit.SetInt64(int64(base58Index[c])))
	}

	decoded := n.Bytes()

	// Re-add leading zero bytes.
	leadingZeros := 0
	for _, c := range input {
		if c != rune(base58Alphabet[0]) {
			break
		}
		leadingZeros++
	}

	result := make([]byte, leadingZeros+len(decoded))
	copy(result[leadingZeros:], decoded)
	return result, nil
}
