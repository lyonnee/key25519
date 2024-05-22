package main

import (
	"fmt"
	"log"

	"github.com/lyonnee/key25519"
	"github.com/lyonnee/key25519/format"
)

func main() {
	kp1 := key25519.NewKeypair()
	kp2 := key25519.NewKeypair()

	kp1EcdhPubKey, err := kp1.ExportEcdhPubKey()
	if err != nil {
		log.Fatalln(err)
	}

	kp2EcdhPubKey, err := kp2.ExportEcdhPubKey()
	if err != nil {
		log.Fatalln(err)
	}

	sk1, _ := kp1.Ecdh(kp2EcdhPubKey)
	sk2, _ := kp2.Ecdh(kp1EcdhPubKey)

	fmt.Println(format.EncodeBase58(sk1))
	fmt.Println(format.EncodeBase58(sk2))
}
