package bip44

import (
	"fmt"
	"strings"

	"github.com/lyonnee/key25519/bip32"
)

func ParsePath(path string) ([]uint32, error) {
	if path == "" || path[0] != 'm' {
		return nil, fmt.Errorf("invalid path format")
	}
	segments := strings.Split(path[2:], "/")
	parsed := make([]uint32, len(segments))
	for i, segment := range segments {
		if segment[len(segment)-1] == '\'' {
			parsed[i] = uint32(0x80000000) + uint32(parseUint(segment[:len(segment)-1]))
		} else {
			parsed[i] = parseUint(segment)
		}
	}
	return parsed, nil
}

func parseUint(s string) uint32 {
	var n uint32
	fmt.Sscanf(s, "%d", &n)
	return n
}

func Derived(path string, seed []byte) (bip32.Key, error) {
	var key = bip32.Key{}

	parsedPath, err := ParsePath(path)
	if err != nil {
		return key, err
	}

	key = bip32.GenerateMasterKey(seed)

	for _, index := range parsedPath {
		key = bip32.CKDPriv(key, uint32(index)+1<<31)
	}

	return key, nil
}
