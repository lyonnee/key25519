package main

import (
	"fmt"

	"github.com/lyonnee/key25519"
)

func main() {
	// build random keypair
	kp := key25519.NewKeypair()

	oriMsg := []byte("i am lyon")

	signedMsg := key25519.SignMsg(kp.PrivateKey(), oriMsg)
	res := key25519.VerifyMsg(kp.PublicKey(), oriMsg, signedMsg)

	fmt.Println(res)
}
