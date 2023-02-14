package utils

// XorBytes returns the xor of the two byte slices
// pads with 0s to make the bytes of equal length
func XorBytes(a, b []byte) []byte {
	if len(a) > len(b) {
		a, b = b, a
	}
	res := make([]byte, len(b))
	for i := 0; i < len(a); i++ {
		res[i] = a[i] ^ b[i]
	}
	for i := len(a); i < len(b); i++ {
		res[i] = b[i]
	}
	return res
}

// RepeatingKeyXor Xors b with the key repeatedly at len(key) intervals
func RepeatingKeyXor(b, key []byte) []byte {
	n, m := len(b), len(key)
	res := make([]byte, n)
	for i := 0; i < n; i++ {
		res[i] = b[i] ^ key[i%m]
	}
	return res
}

// returns the Hamming Distance between a and b. a and b are assumed
// to be equal length
func HammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		return -1
	}
	d := 0
	for i := 0; i < len(a); i++ {
		c := a[i] ^ b[i]
		d += CountSetBits(c)
	}
	return d
}
