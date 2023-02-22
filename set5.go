package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"

	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

type BInt = crypto.BInt

var BI = crypto.BI

func Solve5_34() {

	asch := make(chan *big.Int, 10)
	arch := make(chan *big.Int, 10)
	bsch := make(chan *big.Int, 10)
	brch := make(chan *big.Int, 10)
	donech := make(chan string)
	mach := make(chan []byte, 1)
	mbch := make(chan []byte, 1)
	middle := func() {
		p := <-arch
		g := <-arch
		<-arch
		// the private key will now be simply 0
		asch <- p
		aesCipherA := crypto.NewAESInCBCCipher(make([]byte, 0))
		bsch <- p
		bsch <- g
		bsch <- p

		<-brch
		// The private key is again 0
		aesCipherB := crypto.NewAESInCBCCipher(make([]byte, 0))
		msg := <-mach
		decmsg := aesCipherA.Decrypt(msg[crypto.AESBlockSize:], msg[:crypto.AESBlockSize])
		fmt.Println("middle:", string(decmsg))
		iv := utils.RandBytes(crypto.AESBlockSize)
		mbch <- append(iv, aesCipherB.Encrypt(decmsg, iv)...)
	}

	B := func() {
		p := <-bsch
		g := <-bsch
		A := <-bsch

		dh := crypto.NewDHFromPAndG(p, g)
		brch <- dh.A
		key := dh.MakeSessionKey(A).Bytes()
		cipher := crypto.NewAESInCBCCipher(key)

		msg := <-mbch
		fmt.Println("end:", string(cipher.Decrypt(msg[crypto.AESBlockSize:], msg[:crypto.AESBlockSize])))
		donech <- "done"
	}

	A := func() {
		dh := crypto.NewDH()
		arch <- dh.P
		arch <- dh.G
		arch <- dh.A
		B := <-asch
		key := dh.MakeSessionKey(B).Bytes()
		cipher := crypto.NewAESInCBCCipher(key)
		msg := []byte("hello world")
		iv := utils.RandBytes(crypto.AESBlockSize)
		mach <- append(iv, cipher.Encrypt(msg, iv)...)
	}
	go B()
	go A()
	go middle()
	<-donech
	fmt.Println("done")
}

func Solve5_36() {
	password := []byte("hello world")
	p, g, k, serverFunc := crypto.SRPServer(password)
	inputCh := make(chan []byte, 10)
	outputCh := make(chan []byte, 10)
	go serverFunc(outputCh, inputCh)
	dh := crypto.NewDHFromPAndG(p, g)
	outputCh <- dh.PA.Bytes()
	salt := <-inputCh
	B := <-inputCh
	b := big.NewInt(0).SetBytes(B)
	shaHF := sha256.New()
	shaHF.Write(dh.PA.Bytes())
	shaHF.Write(B)
	u := big.NewInt(0).SetBytes(shaHF.Sum(nil))
	shaHF.Reset()
	shaHF.Write(salt)
	shaHF.Write(password)
	x := big.NewInt(0).SetBytes(shaHF.Sum(nil))
	v := big.NewInt(0).Exp(g, x, p)
	kv := big.NewInt(0).Mul(k, v)
	po := big.NewInt(0).Add(dh.A, big.NewInt(0).Mul(u, x))
	kk := big.NewInt(0).Exp(big.NewInt(0).Sub(b, kv), po, p)
	shaHF.Reset()
	shaHF.Write(kk.Bytes())
	key := shaHF.Sum(nil)
	fmt.Println("key in client", key)
	outputCh <- key
	msg := <-inputCh
	fmt.Println(string(msg))
}

func Solve5_37() {
	password := []byte("hello world")
	p, _, _, serverFunc := crypto.SRPServer(password)
	inputCh := make(chan []byte, 10)
	outputCh := make(chan []byte, 10)
	go serverFunc(outputCh, inputCh)
	outputCh <- big.NewInt(0).Mul(big.NewInt(2), p).Bytes()
	<-inputCh
	<-inputCh
	kk := big.NewInt(0)
	shaHF := sha256.New()
	shaHF.Write(kk.Bytes())
	key := shaHF.Sum(nil)
	fmt.Println("key in client", key)
	outputCh <- key
	msg := <-inputCh
	fmt.Println(string(msg))
}

func Solve5_38() {
	dh := crypto.NewDH()
	n := dh.P
	g := big.NewInt(2)
	done := make(chan struct{})
	server := func(readCh, writeCh chan []byte) {
		password := "helloworld"
		salt := "salty"
		sha := sha256.New()
		_, err := sha.Write([]byte(salt + password))
		if err != nil {
			panic(err)
		}
		x := sha.Sum(nil)
		xi := big.NewInt(0).SetBytes(x)

		v := big.NewInt(0).Exp(g, xi, n)

		a := <-readCh
		ai := big.NewInt(0).SetBytes(a)
		dh := crypto.NewDHFromPAndG(n, g)
		u := utils.RandBytes(16)
		ui := big.NewInt(0).SetBytes(u)
		writeCh <- []byte(salt)
		writeCh <- dh.PA.Bytes()

		writeCh <- u

		m := big.NewInt(0).Mul(ai, big.NewInt(0).Exp(v, ui, n))
		s := big.NewInt(0).Exp(m, dh.A, n)

		sha.Reset()
		sha.Write(s.Bytes())
		k := sha.Sum(nil)
		hmc := hmac.New(sha256.New, k)
		hmc.Write([]byte(salt))
		expect := hmc.Sum(nil)
		got := <-readCh
		if bytes.Equal(got, expect) {
			writeCh <- []byte("true")
		} else {
			writeCh <- []byte("false")
		}
	}
	client := func(readCh, writeCh chan []byte, password string) {
		dh := crypto.NewDHFromPAndG(n, g)
		writeCh <- dh.PA.Bytes()
		salt := <-readCh
		b := <-readCh
		u := <-readCh

		bi := big.NewInt(0).SetBytes(b)

		ui := big.NewInt(0).SetBytes(u)

		sha := sha256.New()
		sha.Write([]byte(string(salt) + password))
		x := sha.Sum(nil)
		xi := big.NewInt(0).SetBytes(x)

		s := big.NewInt(0).Exp(bi, big.NewInt(0).Add(dh.A, big.NewInt(0).Mul(xi, ui)), n)
		sha.Reset()
		sha.Write(s.Bytes())
		k := sha.Sum(nil)

		hmc := hmac.New(sha256.New, k)
		hmc.Write([]byte(salt))
		v := hmc.Sum(nil)
		writeCh <- v

		worked := <-readCh
		fmt.Println(string(worked))
		done <- struct{}{}
	}
	c1, c2 := make(chan []byte), make(chan []byte)
	go server(c1, c2)
	go client(c2, c1, "helloworld")
	<-done

	mitm := func(readCh, writeCh chan []byte) {
		salt := "salty"
		sha := sha256.New()
		shaDict := make(map[string]string)
		f, _ := os.Open("passwords.txt")
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			pwd := []byte(scanner.Text())
			sha.Reset()
			sha.Write([]byte(salt + string(pwd)))
			x := sha.Sum(nil)
			shaDict[string(x)] = string(pwd)
		}

		a := <-readCh
		ai := big.NewInt(0).SetBytes(a)
		dh := crypto.NewDHFromPAndG(n, g)
		u := utils.RandBytes(16)
		ui := big.NewInt(0).SetBytes(u)
		writeCh <- []byte(salt)
		writeCh <- dh.PA.Bytes()
		writeCh <- u
		got := <-readCh
		writeCh <- []byte("true")
		for s, pwd := range shaDict {
			xi := big.NewInt(0).SetBytes([]byte(s))
			v := big.NewInt(0).Exp(g, xi, n)
			v.Exp(v, ui, n)
			v.Mul(v, ai)
			v.Exp(v, dh.A, n)
			sha.Reset()
			sha.Write(v.Bytes())
			k := sha.Sum(nil)
			hm := hmac.New(sha256.New, k)
			hm.Write([]byte(salt))
			if bytes.Equal(got, hm.Sum(nil)) {
				fmt.Println(pwd)
				break
			}
		}
		done <- struct{}{}
	}
	go mitm(c1, c2)
	go client(c2, c1, "avatar")

	<-done
	<-done
}

func Solve5_40(s string) string {
	decodeBytes := func(c1, c2, c3 []byte, p1, p2, p3 crypto.RSAKey) []byte {
		cs := []BInt{crypto.FromBytes(c1), crypto.FromBytes(c2), crypto.FromBytes(c3)}
		ns := []BInt{p1.N, p2.N, p3.N}
		m := crypto.CRT(cs, ns)
		st, ed := BI(0), crypto.Clone(m)
	binarySearch:
		for ed.Cmp(BI(0).Add(st, BI(1))) > 0 {
			mid := BI(0).Add(st, ed)
			mid.Div(mid, BI(2))
			x := BI(0).Mul(mid, mid)
			x.Mul(x, mid)
			v := x.Cmp(m)
			switch {
			case v == 0:
				st = mid
				break binarySearch
			case v < 0:
				st = mid
			default:
				ed = mid
			}
		}
		return st.Bytes()
	}
	r1, r2, r3 := crypto.NewRSAN(10), crypto.NewRSAN(10), crypto.NewRSAN(10)
	p1, p2, p3 := r1.PubKey(), r2.PubKey(), r3.PubKey()
	msg := []byte(s)
	c1, c2, c3 := r1.Encrypt(msg), r2.Encrypt(msg), r3.Encrypt(msg)
	return string(decodeBytes(c1, c2, c3, p1, p2, p3))
}
