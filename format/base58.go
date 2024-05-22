package format

import (
	"fmt"
	"math/big"
)

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var (
	bigRadix    = big.NewInt(58)
	bigZero     = big.NewInt(0)
	zeroByte    = byte(alphabet[0])
	alphabetMap [256]int
)

func init() {
	for i := range alphabetMap {
		alphabetMap[i] = -1
	}
	for i, c := range alphabet {
		alphabetMap[c] = i
	}
}

// EncodeBase58 encodes a byte slice into a Base58 string.
func EncodeBase58(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	// Convert byte slice to big.Int
	intData := new(big.Int).SetBytes(input)

	// Convert big.Int to Base58
	var encoded []byte
	for intData.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		intData.DivMod(intData, bigRadix, mod)
		encoded = append(encoded, alphabet[mod.Int64()])
	}

	// Add '1' for each leading 0 byte in the input
	for _, b := range input {
		if b == 0x00 {
			encoded = append(encoded, zeroByte)
		} else {
			break
		}
	}

	// Since the above loop produces the characters in reverse order, we reverse it.
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}

	return string(encoded)
}

// DecodeBase58 decodes a Base58 string into a byte slice.
func DecodeBase58(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	intData := big.NewInt(0)
	for _, char := range input {
		index := alphabetMap[char]
		if index == -1 {
			return nil, fmt.Errorf("invalid character: %v", char)
		}
		intData.Mul(intData, bigRadix)
		intData.Add(intData, big.NewInt(int64(index)))
	}

	decoded := intData.Bytes()

	// Add leading zero bytes for each leading '1' character
	nLeadingZeros := 0
	for _, char := range input {
		if char == '1' {
			nLeadingZeros++
		} else {
			break
		}
	}
	return append(make([]byte, nLeadingZeros), decoded...), nil
}
