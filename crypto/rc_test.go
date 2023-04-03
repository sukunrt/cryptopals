package crypto

import (
	"bytes"
	"fmt"
	"log"
	"testing"

	"github.com/sukunrt/cryptopals/utils"
)

func TestBreakRC(t *testing.T) {
	msg := "abc"
	res := BreakRC4([]byte(msg))
	if !bytes.Equal([]byte(msg), res) {
		fmt.Println(string(res), msg)
		t.Fatalf("failed to break rc4")
	}
}

func TestBreakRC4Full(t *testing.T) {
	msg := "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F"
	b := utils.FromBase64String(msg)
	res := BreakRC4(b)
	// Allow error of 5 characters. The bias is really low
	if utils.HammingDistance(res, b) > 5*8 {
		t.Fatalf("failed to decode stream")
	}
	log.Printf("%s\n", string(res))
}
