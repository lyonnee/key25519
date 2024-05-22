package main

import (
	"crypto/ed25519"
	"fmt"
	"log"

	"github.com/lyonnee/key25519"
	"github.com/lyonnee/key25519/bip32"
	"github.com/lyonnee/key25519/bip39"
	"github.com/lyonnee/key25519/bip44"
	"github.com/lyonnee/key25519/format"
)

func main() {
	// 1. 生成助记词和种子
	mnemonic, _ := bip39.GenerateMnemonic(bip39.LEN_12, bip39.ENGLISH)
	seed := bip39.ToSeed(mnemonic, "")

	// 2. 生成主账户密钥
	masterKey := bip32.GenerateMasterKey(seed)

	// 3. 定义派生路径(Solana)
	path := "m/44'/501'/0'/0'"
	indexs, err := bip44.ParsePath(path)
	if err != nil {
		log.Fatalln(err)
	}

	// 4. 派生新的密钥
	var newKey = masterKey
	for _, v := range indexs {
		newKey = bip32.CKDPriv(newKey, v)
	}

	// 5. 生成ed25519密钥对
	edPrivKey := ed25519.NewKeyFromSeed(newKey.PrivKey)
	pubk, err := key25519.NewPubKeyFromEd25119PubKey(edPrivKey.Public().(ed25519.PublicKey))
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(format.EncodeBase58(edPrivKey))
	fmt.Println(format.EncodeBase58(pubk.Bytes()))
}
