package key25519

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
)

var (
	ErrDecrypt   = errors.New("could not decrypt key with given password")
	ErrNotUnlock = errors.New("the key store not unlock")
)

type Keystore struct {
	Crypto cryptoJson `json:"crtpto"`
}

// 持久化keystore文件
func SaveAsKeystore(key []byte, filepath, password string, useLightweightKDF bool) error {
	scryptN := StandardScryptN
	scryptP := StandardScryptP

	if useLightweightKDF {
		scryptN = LightScryptN
		scryptP = LightScryptP
	}

	var ks = new(Keystore)

	cryptoJson, err := encryptData(key, []byte(password), scryptN, scryptP)
	if err != nil {
		return err
	}

	ks.Crypto = cryptoJson

	var js []byte
	if js, err = json.Marshal(ks); err != nil {
		return err
	}

	if err = os.WriteFile(filepath, js, fs.ModeAppend); err != nil {
		return err
	}

	return nil
}

// 从keystore文件加载私钥
func LoadPrivKeyFromKeystore(filepath, password string) ([]byte, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var ks = new(Keystore)
	if err := json.Unmarshal(data, ks); err != nil {
		return nil, err
	}

	k, err := decryptData(ks.Crypto, password)
	if err != nil {
		return nil, err
	}

	return k, nil
}
