package key25519

import (
	"crypto/ed25519"
)

// 用私钥签名消息
func SignMsg(privKey PrivateKey, msg []byte) []byte {
	return ed25519.Sign(privKey.ToEd25519PrivKey(), msg)
}

// 用公钥校验签名消息
func VerifyMsg(pubKey PublicKey, originMsg, signMsg []byte) bool {
	return ed25519.Verify(pubKey[:], originMsg, signMsg)
}
