package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

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
