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
	rand.Seed(5 * 23)
}

func main() {
	for i := 0; i < 100; i++ {
		r := crypto.NewRSAN(10)
		fmt.Printf("%+v\n", r)
		msg := "hello world"
		enc := crypto.EncryptRSA([]byte(msg), r)
		dec := crypto.DecryptRSA(enc, r)
		fmt.Println(string(dec))
		fmt.Println()
	}
}
