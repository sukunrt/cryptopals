package utils

import (
	"encoding/base64"
	"encoding/hex"
	"log"
)

func FromHexString(s string) []byte {
	if len(s)%2 == 1 {
		s = "0" + s
	}
	data, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("Failed to decode string as hex bytes\n%s", s)
	}
	return data
}

func ToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func ToHexString(b []byte) string {
	return hex.EncodeToString(b)
}

func FromBase64String(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
