package main

import (
	"fmt"
	"math/rand"

	"github.com/sukunrt/cryptopals/crypto"
)

func init() {
	// b := make([]byte, 8)
	// crand.Read(b)
	// rand.Seed(int64(binary.BigEndian.Uint64(b)))
	rand.Seed(35)
}

func main() {
	testAll()
}

func testAll() {
	for i := 2; i < 100; i++ {
		millerPrime := crypto.MillerRabin(crypto.NBI(i))
		isPrime := true
		for j := 2; j < i-1; j++ {
			if i%j == 0 {
				isPrime = false
				break
			}
		}
		if millerPrime != isPrime {
			fmt.Println(millerPrime, isPrime, i)
		}
	}
}
