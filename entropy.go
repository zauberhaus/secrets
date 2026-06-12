package secrets

import "math"

func CalculateEntropy(data []byte) float64 {
	size := len(data)
	if size == 0 {
		return 0
	}

	// 1. Count occurrences of each byte value (0-255)
	counts := make([]int, 256)
	for _, b := range data {
		counts[b]++
	}

	// 2. Calculate Shannon entropy: H = -sum(P(i) * log2(P(i)))
	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}

		// Probability of this byte occurring
		p := float64(count) / float64(size)

		// Shannon formula
		entropy -= p * math.Log2(p)
	}

	return entropy
}
