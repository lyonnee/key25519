package key25519

type Keypair struct {
	privKey PrivateKey
	pubKey  PublicKey
}

func NewKeypairFromPrivKeyBytes(key []byte) (*Keypair, error) {
	privKey, err := bytesToPrivKey(key)
	if err != nil {
		return nil, err
	}

	return &Keypair{
		privKey: privKey,
		pubKey:  privKey.GetPubKey(),
	}, nil
}

func NewKeypair() *Keypair {
	privKey := NewPrivateKey(nil)

	return &Keypair{
		privKey: privKey,
		pubKey:  privKey.GetPubKey(),
	}
}

func NewKeypairWithSeed(seed []byte) *Keypair {
	privKey := NewPrivateKey(seed)

	return &Keypair{
		privKey: privKey,
		pubKey:  privKey.GetPubKey(),
	}
}

func (kp *Keypair) PrivateKey() PrivateKey {
	return kp.privKey
}

func (kp *Keypair) PublicKey() PublicKey {
	return kp.pubKey
}

func (kp *Keypair) LoadFromPrivKey(privKey PrivateKey) {
	kp.privKey = privKey
	kp.pubKey = privKey.GetPubKey()
}

// 导出keystore文件
func (kp *Keypair) ExportKeystore(filepath, password string) error {
	return SaveAsKeystore(kp.PrivateKey().Bytes(), filepath, password, false)
}

func (kp *Keypair) ExportEcdhPubKey() ([]byte, error) {
	ecdhKp, err := ExportEcdhKeypair(kp.privKey)
	if err != nil {
		return nil, err
	}

	return ecdhKp.PublicKey, nil
}

func (kp *Keypair) Ecdh(peerPubKey []byte) ([]byte, error) {
	return Ecdh(kp.privKey, peerPubKey)
}
