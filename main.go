package main

import (
	"math/rand"
)

func init() {
	// b := make([]byte, 8)
	// crand.Read(b)
	// rand.Seed(int64(binary.BigEndian.Uint64(b)))
	rand.Seed(35 * 23)
}

func main() {
	Solve5_39()
}
