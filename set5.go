package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"

	bi "github.com/sukunrt/cryptopals/bigint"
	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

func Solve5_34() {
	asch := make(chan bi.BInt, 10)
	arch := make(chan bi.BInt, 10)
	bsch := make(chan bi.BInt, 10)
	brch := make(chan bi.BInt, 10)
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
	b := bi.FromBytes(B)
	shaHF := sha256.New()
	shaHF.Write(dh.PA.Bytes())
	shaHF.Write(B)
	u := bi.FromBytes(shaHF.Sum(nil))
	shaHF.Reset()
	shaHF.Write(salt)
	shaHF.Write(password)
	x := bi.FromBytes(shaHF.Sum(nil))
	v := bi.Exp(g, x, p)
	kv := k.Mul(v)
	po := dh.A.Add(u.Mul(x))
	kk := bi.Exp(b.Sub(kv), po, p)
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
	outputCh <- bi.Two.Mul(p).Bytes()
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
	g := bi.FromInt(2)
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
		xi := bi.FromBytes(x)
		v := bi.Exp(g, xi, n)

		a := <-readCh
		ai := bi.FromBytes(a)
		dh := crypto.NewDHFromPAndG(n, g)
		u := utils.RandBytes(16)
		ui := bi.FromBytes(u)
		writeCh <- []byte(salt)
		writeCh <- dh.PA.Bytes()

		writeCh <- u

		m := ai.Mul(bi.Exp(v, ui, n))
		s := bi.Exp(m, dh.A, n)

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

		bb := bi.FromBytes(b)
		ui := bi.FromBytes(u)

		sha := sha256.New()
		sha.Write([]byte(string(salt) + password))
		x := sha.Sum(nil)
		xi := bi.FromBytes(x)
		s := bi.Exp(bb, dh.A.Add(xi.Mul(ui)), n)
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
		ai := bi.FromBytes(a)
		dh := crypto.NewDHFromPAndG(n, g)
		u := utils.RandBytes(16)
		ui := bi.FromBytes(u)
		writeCh <- []byte(salt)
		writeCh <- dh.PA.Bytes()
		writeCh <- u
		got := <-readCh
		writeCh <- []byte("true")
		for s, pwd := range shaDict {
			xi := bi.FromBytes([]byte(s))
			v := bi.Exp(g, xi, n)
			v = bi.Exp(v, ui, n).Mul(ai)
			v = bi.Exp(v, dh.A, n)
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
		cs := []bi.BInt{bi.FromBytes(c1), bi.FromBytes(c2), bi.FromBytes(c3)}
		ns := []bi.BInt{p1.N, p2.N, p3.N}
		m := crypto.CRT(cs, ns)
		st, ed := bi.Zero, bi.Copy(m)
	binarySearch:
		for ed.Cmp(st.Add(bi.One)) > 0 {
			mid := st.Add(ed).Div(bi.Two)
			x := mid.Mul(mid).Mul(mid)
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
