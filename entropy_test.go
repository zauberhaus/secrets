package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateEntropy_Empty(t *testing.T) {
	assert.Equal(t, 0.0, CalculateEntropy(nil))
	assert.Equal(t, 0.0, CalculateEntropy([]byte{}))
}

func TestCalculateEntropy_SingleValueIsZero(t *testing.T) {
	// One distinct byte value carries no information.
	assert.Equal(t, 0.0, CalculateEntropy([]byte{0x41}))
	assert.Equal(t, 0.0, CalculateEntropy([]byte("aaaaaaaa")))
}

func TestCalculateEntropy_TwoEqualValuesIsOneBit(t *testing.T) {
	assert.Equal(t, 1.0, CalculateEntropy([]byte("ab")))
	assert.Equal(t, 1.0, CalculateEntropy([]byte("aabb")))
}

func TestCalculateEntropy_UniformDistributionIsMaximal(t *testing.T) {
	// All 256 byte values once each: log2(256) = 8 bits, the maximum.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	assert.InDelta(t, 8.0, CalculateEntropy(data), 1e-9)
}

func TestCalculateEntropy_SkewedIsBelowUniform(t *testing.T) {
	uniform := CalculateEntropy([]byte("abcd"))
	skewed := CalculateEntropy([]byte("aaab"))

	assert.InDelta(t, 2.0, uniform, 1e-9)
	assert.Less(t, skewed, uniform)
	assert.Greater(t, skewed, 0.0)
}
