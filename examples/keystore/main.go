package main

import (
	"fmt"
	"log"

	"github.com/lyonnee/key25519"
	"github.com/lyonnee/key25519/format"
)

func main() {
	// 生成keypair1
	kp := key25519.NewKeypair()

	originMsg := []byte("i am lyon")
	signedMsg := kp.PrivateKey().SignMsg(originMsg)

	// 导出keypair1的keystore
	filename := "./" + format.EncodeBase58(kp.PublicKey().Bytes()) + ".keystore"
	password := "kaixin"

	err := kp.ExportKeystore(filename, password)
	if err != nil {
		log.Fatalln(err)
	}

	// 导入keypair1的keystore 生成keypair2
	key, err := key25519.LoadPrivKeyFromKeystore(filename, password)
	if err != nil {
		log.Fatalln(err)
	}

	kp2, err := key25519.NewKeypairFromPrivKeyBytes(key)
	if err != nil {
		log.Fatalln(err)
	}

	// 用keypair2 验证交易签名
	res := key25519.VerifyMsg(kp2.PublicKey(), originMsg, signedMsg)
	fmt.Println(res)
}
