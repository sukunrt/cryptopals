package main

import (
	"fmt"
	"math/rand"
)

func init() {
	// b := make([]byte, 8)
	// crand.Read(b)
	// rand.Seed(int64(binary.BigEndian.Uint64(b)))
	rand.Seed(35)
}

func main() {
	s := "realistic text generation has happened"
	fmt.Println(Solve6_48(s))
}
