package key25519

import "github.com/lyonnee/key25519/keystore"

type KeyPair struct {
	privKey PrivateKey
	pubKey  PublicKey
}

func NewKeyPair() *KeyPair {
	privKey := NewPrivateKey(nil)

	return &KeyPair{
		privKey: privKey,
		pubKey:  privKey.GetPubKey(),
	}
}

func NewKeyPairWithSeed(seed []byte) *KeyPair {
	privKey := NewPrivateKey(seed)

	return &KeyPair{
		privKey: privKey,
		pubKey:  privKey.GetPubKey(),
	}
}

func NewKeyPairFromPrivKeyBytes(key []byte) (*KeyPair, error) {
	privKey, err := bytesToPrivKey(key)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		privKey: privKey,
		pubKey:  privKey.GetPubKey(),
	}, nil
}

// 加载keystore文件还原KeyPair
func NewKeyPairFromKeystore(filepath, password string) (*KeyPair, error) {
	privKey, err := keystore.LoadPrivKeyFromKeystore(filepath, password)
	if err != nil {
		return nil, err
	}

	return NewKeyPairFromPrivKeyBytes(privKey)
}

func (kp *KeyPair) PrivateKey() PrivateKey {
	return kp.privKey
}

func (kp *KeyPair) PublicKey() PublicKey {
	return kp.pubKey
}

func (kp *KeyPair) LoadFromPrivKey(privKey PrivateKey) {
	kp.privKey = privKey
	kp.pubKey = privKey.GetPubKey()
}

// 导出keystore文件
func (kp *KeyPair) ExportKeystore(filepath, password string) error {
	return keystore.SaveAsKeystore(kp.PrivateKey().Bytes(), filepath, password, false)
}
