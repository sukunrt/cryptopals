package main

import (
	"fmt"

	"github.com/sukunrt/cryptopals/crypto"
)

func Solve6_41() {
	msgs := []string{"hello", "world", "smallstrings", "with spaces"}
	for _, m := range msgs {
		out := crypto.UnPaddedRSAOracle(m)
		if out != m {
			fmt.Println(m, "FAILED")
			return
		}
	}
	fmt.Println("SUCCESS")
}
