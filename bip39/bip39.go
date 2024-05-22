package bip39

import (
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
)

type Language uint8

const (
	ENGLISH             Language = iota
	CHINESE_SIMPLIFIED  Language = iota
	CHINESE_TRADITIONAL Language = iota
)

type Length uint8

const (
	LEN_12 Length = 12
	LEN_15 Length = 15
	LEN_18 Length = 18
	LEN_21 Length = 21
	LEN_24 Length = 24
)

const (
	EntropyBits128 int = 128
	EntropyBits160 int = 160
	EntropyBits192 int = 192
	EntropyBits224 int = 224
	EntropyBits256 int = 256
)

// GenerateMnemonic 生成助记词
// len 助记词长度
// lang 助记词语言
func GenerateMnemonic(len Length, lang Language) (string, error) {
	var entropyBits int
	switch len {
	case 12:
		entropyBits = EntropyBits128
	case 15:
		entropyBits = EntropyBits160
	case 18:
		entropyBits = EntropyBits192
	case 21:
		entropyBits = EntropyBits224
	case 24:
		entropyBits = EntropyBits256
	}

	switch lang {
	case ENGLISH:
		bip39.SetWordList(wordlists.English)
	case CHINESE_SIMPLIFIED:
		bip39.SetWordList(wordlists.ChineseSimplified)
	case CHINESE_TRADITIONAL:
		bip39.SetWordList(wordlists.ChineseTraditional)
	}

	entropy, _ := bip39.NewEntropy(entropyBits)
	return bip39.NewMnemonic(entropy)
}

func ToSeed(mnemonic, password string) []byte {
	return bip39.NewSeed(mnemonic, password)
}
