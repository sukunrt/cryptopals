package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

const AESBlkSz = crypto.AESBlockSize

func makeCBCMac(cipher crypto.AESInCBCCipher, iv []byte, msg []byte) []byte {
	c := cipher.Encrypt(msg, iv)
	return c[len(c)-AESBlkSz:]
}

func Solve7_49() {
	fmt.Println("partA:")
	partA_49()
	fmt.Println("partB:")
	partB_49()
}

func partA_49() {
	// This attack is not very sophisticated.
	// We can only change the first block which is not too long. But in this case we'll assume account
	// numbers are 2 digits. Also we cannot change the digits much otherwise the msg will get scrambled
	key := crypto.RandAESKey()
	cipher := crypto.NewAESInCBCCipher(key)
	ogIv := utils.RandBytes(AESBlkSz)
	pt := "from=23&to=45&amount=1000000"
	mac := makeCBCMac(cipher, ogIv, []byte(pt))
	msg := utils.ConcatBytes([]byte(pt), ogIv, mac)

	targetMsg := "from=23&to=21&amount=1000000"
	originalIV := msg[len(msg)-2*AESBlkSz : len(msg)-1*AESBlkSz]
	targetIv := utils.XorBytes(utils.XorBytes([]byte(targetMsg[:AESBlkSz]), originalIV), []byte(pt[:AESBlkSz]))
	mac2 := makeCBCMac(cipher, targetIv, []byte(targetMsg))
	if bytes.Equal(mac, mac2) {
		fmt.Println("success")
	} else {
		fmt.Println("failure")
	}
}

func partB_49() {
	// This is again not a very sophisticated attack. Requires the server to use the same key for every
	// client
	ourAccount := 20
	theirAccount := 30
	thirdAccount := 40
	fourthAccount := 50
	cipher := crypto.NewAESInCBCCipher(crypto.RandAESKey())
	m1 := string(utils.PadBytes([]byte(fmt.Sprintf("from=%d&tx_list=%d:100", theirAccount, thirdAccount)), AESBlkSz))
	m2 := fmt.Sprintf("from=%d&tx_list=%d:0000000000001;%d:1000000", ourAccount, fourthAccount, ourAccount)
	mac1 := makeCBCMac(cipher, make([]byte, AESBlkSz), []byte(m1))
	mac2 := makeCBCMac(cipher, make([]byte, AESBlkSz), []byte(m2))

	b1 := m2[:AESBlkSz]
	newB1 := utils.XorBytes([]byte(b1), mac1)
	newMsg := m1 + string(utils.RepBytes(16, 16)) + string(newB1) + m2[AESBlkSz:]
	mac3 := makeCBCMac(cipher, make([]byte, AESBlkSz), []byte(newMsg))
	if !bytes.Equal(mac3, mac2) {
		fmt.Println("FAILED mac should be same")
		return
	}

	// Parse transactions and see if we are getting any money:
	var from int
	parts := strings.Split(newMsg, "&")
	from, _ = strconv.Atoi(parts[0][strings.Index(parts[0], "from=")+len("from="):])
	if from != theirAccount {
		fmt.Println("FAILED money should be from their account")
		return
	}
	txns := strings.Split(parts[1][len("tx_list="):], ";")
	for _, tx := range txns {
		parts := strings.Split(tx, ":")
		to, _ := strconv.Atoi(parts[0])
		amt, _ := strconv.Atoi(parts[1])
		if to == ourAccount && amt > 100000 {
			fmt.Println("success")
			return
		}
	}
	fmt.Println("failed: received no money")
}

func Solve7_50() {
	b := []byte("alert('MZA who was that?');\n")
	cipher := crypto.NewAESInCBCCipher([]byte("YELLOW SUBMARINE"))
	mac := makeCBCMac(cipher, make([]byte, AESBlkSz), b)
	fmt.Println(utils.ToHexString(mac))

	//         |              |               | ;
	attack := "alert('Ayo, the Wu is back!');//"
	enc := cipher.Encrypt([]byte(attack), make([]byte, AESBlkSz))
	cx := enc[len(enc)-2*AESBlkSz : len(enc)-AESBlkSz]
	cx = append(cx, utils.RepBytes(0, len(b)-len(cx))...)
	pad := utils.XorBytes(b, cx)
	attackB := utils.ConcatBytes([]byte(attack), pad)
	mac2 := makeCBCMac(cipher, make([]byte, AESBlkSz), attackB)
	if bytes.Equal(mac, mac2) {
		fmt.Println("SUCCESS")
		os.WriteFile("t.js", attackB, os.ModePerm)
		return
	}
	fmt.Println("FAILED")
}

func Solve7_51() {
	key := crypto.RandAESKey()
	cipher := crypto.NewAESInCBCCipher(key)

	getInput := func(b []byte) []byte {
		return []byte(fmt.Sprintf(`POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: %d
%s`, len(b), string(b)))
	}
	oracle := func(b []byte) int {
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		w.Write(getInput(b))
		w.Close()
		e := cipher.Encrypt(buf.Bytes(), crypto.RandAESKey())
		return len(e)
	}
	b := []byte("sessionid=")
	b = compressionAttackDepth(oracle, b)
	fmt.Println(string(b))
	fmt.Println(string(utils.FromBase64String(string(b)[len("sessionid="):])))
}

func compressionAttackDepth(oracle func([]byte) int, found []byte) []byte {
	candidates := [][]byte{found}
	for {
		rb := make([]byte, 100)
		for i := 0; i < 100; i++ {
			rb[i] = byte(rand.Intn(1 << 8))
		}
		base := oracle(candidates[0])
		var pad []byte
		best := base
		for i := 0; i < 100; i += 1 {
			x := utils.ConcatBytes(rb[:i], candidates[0])
			best = oracle(x)
			if best > base {
				pad = rb[:i-1]
				break
			}
		}

		newCandidates := make([][]byte, 0)
		for _, cand := range candidates {
			extensions, bb := findNext(oracle, pad, cand)
			if bb < best {
				newCandidates = make([][]byte, 0)
				best = bb
			}
			if bb == best {
				for i := 0; i < len(extensions); i++ {
					nc := make([]byte, len(cand)+1)
					copy(nc, cand)
					nc[len(cand)] = extensions[i]
					newCandidates = append(newCandidates, nc)
				}
			}
		}
		if len(newCandidates) == 1 && newCandidates[0][len(newCandidates[0])-1] == '\n' {
			return newCandidates[0]
		} else if len(newCandidates) == 0 {
			panic("failed")
		}
		candidates = newCandidates
	}
}

func findNext(oracle func([]byte) int, pad, found []byte) ([]byte, int) {
	v := make([]byte, len(found)+1)
	copy(v, found)
	n := len(found)
	candidates := make([]byte, 0)
	valid := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=\n")
	best := 1000000
	for i := 0; i < len(valid); i++ {
		v[n] = valid[i]
		nl := oracle(utils.ConcatBytes(pad, v))
		if nl < best {
			candidates = []byte{valid[i]}
			best = nl
		} else if nl == best {
			candidates = append(candidates, valid[i])
		}
	}
	return candidates, best
}

func Solve7_52() {
	md := crypto.NewMD(16)
	collisionChain := make([][2][]byte, 0)
	cmap := make(map[string][]byte)
	h := make([]byte, 2)
	for len(collisionChain) < 10 {
		x := utils.RandBytes(AESBlkSz)
		nh := md.Hash(x, h)
		_, ok := cmap[string(nh)]
		if ok {
			collisionChain = append(collisionChain, [...][]byte{cmap[string(nh)], x})
			cmap = make(map[string][]byte)
			h = nh
			continue
		}
		cmap[string(nh)] = x
	}
	h = make([]byte, 2)
	for i := 0; i < 1024; i++ {
		var x []byte
		var y []byte
		for j := 0; j < 9; j++ {
			x = append(x, utils.PadBytes(collisionChain[j][rand.Intn(2)], AESBlkSz)...)
			y = append(y, utils.PadBytes(collisionChain[j][rand.Intn(2)], AESBlkSz)...)
		}
		x = append(x, utils.PadBytes(collisionChain[9][rand.Intn(2)], AESBlkSz)...)
		y = append(y, utils.PadBytes(collisionChain[9][rand.Intn(2)], AESBlkSz)...)
		if !bytes.Equal(md.Hash(x, h), md.Hash(y, h)) {
			fmt.Println("Failed")
		}
	}

	md2 := crypto.NewMD(32)
	collisionChain = make([][2][]byte, 0)
	cmap = make(map[string][]byte)
	h = make([]byte, 2)
	iter := 0
	for {
		iter++
		x := utils.RandBytes(AESBlkSz)
		nh := md.Hash(x, h)
		_, ok := cmap[string(nh)]
		if ok {
			collisionChain = append(collisionChain, [...][]byte{cmap[string(nh)], x})
			cmap = make(map[string][]byte)
			h = nh
			if dfs(collisionChain, 0, md2, nil, make(map[string][]byte), md) {
				break
			}
			continue
		}
		cmap[string(nh)] = x
		iter++
	}
	fmt.Println(iter)
}

func dfs(collisionChain [][2][]byte, i int, md *crypto.MD, b []byte, mp map[string][]byte, md1 *crypto.MD) bool {
	var m1, m2 []byte
	m1 = append(m1, b...)
	m2 = append(m2, b...)
	if i < len(collisionChain)-1 {
		m1 = append(m1, utils.PadBytes(collisionChain[i][0], AESBlkSz)...)
		m2 = append(m2, utils.PadBytes(collisionChain[i][1], AESBlkSz)...)
		if !dfs(collisionChain, i+1, md, m1, mp, md1) {
			return dfs(collisionChain, i+1, md, m2, mp, md1)
		}
		return true
	} else {
		m1 = append(m1, collisionChain[i][0]...)
		h1 := md.Hash(m1, make([]byte, (md.Size+7)/8))
		_, ok := mp[string(h1)]
		if ok {
			fmt.Printf("found it\n %x \n %x\n", mp[string(h1)], m1)
			return true
		}
		mp[string(h1)] = m1
		m2 = append(m2, collisionChain[i][1]...)
		h2 := md.Hash(m2, make([]byte, (md.Size+7)/8))
		_, ok = mp[string(h2)]
		if ok {
			fmt.Printf("found it \n %x \n %x\n", mp[string(h2)], m2)
			return true
		}
		mp[string(h2)] = m2
		return false

	}
}
