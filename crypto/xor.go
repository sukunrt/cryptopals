package crypto

import (
	"fmt"
	"math"
	"strings"

	"github.com/sukunrt/cryptopals/utils"
)

var charFreqMap = map[byte]float64{
	'A': 8.12,
	'B': 1.49,
	'C': 2.71,
	'D': 4.32,
	'E': 12.02,
	'F': 2.3,
	'G': 2.03,
	'H': 5.92,
	'I': 7.31,
	'J': 0.1,
	'K': 0.69,
	'L': 3.98,
	'M': 2.61,
	'N': 6.95,
	'O': 7.68,
	'P': 1.82,
	'Q': 0.11,
	'R': 6.02,
	'S': 6.28,
	'T': 9.1,
	'U': 2.88,
	'V': 1.11,
	'W': 2.09,
	'X': 0.17,
	'Y': 2.11,
	'Z': 0.07,
	' ': 20.0,
}

func scoreMsg(b []byte) float64 {
	s := strings.ToUpper(string(b))
	matches := 0
	freqMap := make(map[byte]int)
	for i := 0; i < len(b); i++ {
		if _, ok := charFreqMap[s[i]]; ok {
			matches++
			freqMap[s[i]] += 1.0
		}
	}
	nf := float64(len(b))
	if float64(matches)/nf < 2.0/3.0 {
		return math.Inf(1)
	}
	score := 0.0
	for k, v := range charFreqMap {
		m := (float64(freqMap[k]) / nf) - v
		score += (m * m)
	}
	return score
}

func BreakSingleCharacterXor(b []byte) ([]byte, byte, float64) {
	score := math.Inf(1)
	key := byte(0)
	var msg []byte
	for i := 0; i < 256; i++ {
		kmsg := utils.RepeatingKeyXor(b, []byte{byte(i)})
		ks := scoreMsg(kmsg)
		if ks < score {
			key = byte(i)
			score = ks
			msg = kmsg
		}
	}
	return msg, key, score
}

func normalisedHammingDistance(a, b, c, d []byte) float64 {
	distance := 0
	distance += utils.HammingDistance(a, b)
	distance += utils.HammingDistance(b, c)
	distance += utils.HammingDistance(c, d)
	distance += utils.HammingDistance(a, c)
	distance += utils.HammingDistance(a, d)
	distance += utils.HammingDistance(b, d)
	return float64(distance) / (6.0 * float64(len(a)))
}

func BreakRepeatingKeyXorWithKeySize(msg []byte, keySize int) ([]byte, []byte) {
	key := make([]byte, keySize)
	for i := 0; i < keySize; i++ {
		subMsg := make([]byte, 0)
		for j := i; j < len(msg); j += keySize {
			subMsg = append(subMsg, msg[j])
		}
		_, k, _ := BreakSingleCharacterXor(subMsg)
		key[i] = k
	}
	return utils.RepeatingKeyXor(msg, key), key
}

func BreakRepeatingKeyXor(msg []byte) ([]byte, []byte) {
	// Determine keylength first.
	// Assume key size <= 100
	keySize := -1
	minDist := math.Inf(1)
	for i := 1; i <= 100; i++ {
		a, b, c, d := msg[0:i], msg[i:2*i], msg[2*i:3*i], msg[3*i:4*i]
		dist := normalisedHammingDistance(a, b, c, d)
		if dist < 3.0 {
			fmt.Println(i, dist)
		}
		if dist < minDist-1e-6 {
			// prefer smaller keys over larger keys
			if i%keySize == 0 && dist > minDist-1e-1 {
				continue
			}
			keySize = i
			minDist = dist
		}
	}

	return BreakRepeatingKeyXorWithKeySize(msg, keySize)
}
