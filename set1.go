package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"math"
	"os"

	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

func Solve1_4() {
	f, _ := os.Open("inputs/1-1.txt")
	scanner := bufio.NewScanner(f)
	msg, key, score := []byte{}, byte(0), math.Inf(1)
	for scanner.Scan() {
		t := scanner.Text()
		m, k, s := crypto.BreakSingleCharacterXor(utils.FromHexString(t))
		if s < score {
			score = s
			key = k
			msg = m
		}
	}
	fmt.Println(string(msg), string([]byte{key}), score)
}

func Solve1_6() {
	f, _ := os.Open("inputs/1-6.txt")
	scanner := bufio.NewScanner(f)
	input := make([]byte, 0)
	for scanner.Scan() {
		t := scanner.Text()
		b, err := base64.StdEncoding.DecodeString(t)
		if err != nil {
			panic(err)
		}
		input = append(input, b...)
	}
	plaintext, key := crypto.BreakRepeatingKeyXor(input)
	fmt.Println(string(plaintext), string(key))
}

func Solve1_7() {
	f, _ := os.Open("inputs/1-7.txt")
	scanner := bufio.NewScanner(f)
	input := make([]byte, 0)
	for scanner.Scan() {
		t := scanner.Text()
		b, err := base64.StdEncoding.DecodeString(t)
		if err != nil {
			panic(err)
		}
		input = append(input, b...)
	}
	plaintext := crypto.NewAESInCBCCipher([]byte("YELLOW SUBMARINE")).Decrypt(input, make([]byte, crypto.AESBlockSize))
	fmt.Println(string(plaintext))
}

func Solve1_8() {
	f, _ := os.Open("inputs/1-8.txt")
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		t := scanner.Text()
		b := utils.FromHexString(t)
		if cnt := crypto.DetectAESinECBMode(b); cnt > 0 {
			fmt.Println(cnt)
		}
	}
}
