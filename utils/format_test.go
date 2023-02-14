package utils

import (
	"testing"
)

func TestHexToBase64(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if ToBase64(FromHexString(input)) != want {
		t.Fatalf("Failed to convert hex to base64")
	}
}

func TestToHexString(t *testing.T) {
	input := []byte{0, 17}
	want := "0011"
	if ToHexString(input) != want {
		t.Fatalf("Failed to convert bytes to hex")
	}
}
