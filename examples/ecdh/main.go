package main

import (
	"fmt"
	"log"

	"github.com/lyonnee/key25519"
	"github.com/lyonnee/key25519/format"
)

func main() {
	kp1 := key25519.NewKeyPair()
	kp2 := key25519.NewKeyPair()

	x25519kp1, err := kp1.ExportEcdhKeyPair()
	if err != nil {
		log.Fatalln(err)
	}

	x25519kp2, err := kp2.ExportEcdhKeyPair()
	if err != nil {
		log.Fatalln(err)
	}

	sk1, _ := kp1.ECDH(x25519kp2.PublicKey)
	sk2, _ := kp2.ECDH(x25519kp1.PublicKey)

	fmt.Println(format.EncodeBase58(sk1))
	fmt.Println(format.EncodeBase58(sk2))
}
