package main

import (
	"math/rand"
)

func init() {
	// b := make([]byte, 8)
	// crand.Read(b)
	// rand.Seed(int64(binary.BigEndian.Uint64(b)))
	rand.Seed(35)
}

func main() {
	for _, s := range []string{"hi mom", "there", "here", "yellow submarine"} {
		Solve6_42(s)
	}
}
