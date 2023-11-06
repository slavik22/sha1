package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"
	"time"
)

func main() {
	randomString, err := generateRandomString(1024) // Change the string length as needed
	if err != nil {
		fmt.Println("Error generating random string:", err)
		return
	}

	startCustom := time.Now()
	customHash := customSHA1(randomString)
	elapsedCustom := time.Since(startCustom)

	startCrypto := time.Now()
	cryptoHash := sha1.Sum([]byte(randomString))
	elapsedCrypto := time.Since(startCrypto)

	hashMatch := compareHashes(customHash, cryptoHash)

	fmt.Printf("Custom SHA-1 Hash: %x\n", customHash)
	fmt.Printf("Crypto/SHA-1 Hash: %x\n", cryptoHash)
	fmt.Printf("Hashes Match: %v\n", hashMatch)

	fmt.Printf("Custom SHA-1 Execution Time: %s\n", elapsedCustom)
	fmt.Printf("Crypto SHA-1 Execution Time: %s\n", elapsedCrypto)
}

func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randString := make([]byte, length)

	for i := range randString {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		randString[i] = charset[num.Int64()]
	}

	return string(randString), nil
}

func compareHashes(hash1, hash2 [20]byte) bool {
	for i := 0; i < 20; i++ {
		if hash1[i] != hash2[i] {
			return false
		}
	}
	return true
}

func customSHA1(input string) [20]byte {
	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)

	data := []byte(input)
	dataLen := uint64(len(data) * 8)

	data = append(data, 0x80)
	for (len(data)+8)%64 != 0 {
		data = append(data, 0x00)
	}

	dataLenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(dataLenBytes, dataLen)
	data = append(data, dataLenBytes...)

	for i := 0; i < len(data); i += 64 {
		block := data[i : i+64]
		words := make([]uint32, 80)

		for t := 0; t < 16; t++ {
			words[t] = binary.BigEndian.Uint32(block[t*4 : (t+1)*4])
		}
		for t := 16; t < 80; t++ {
			words[t] = bits.RotateLeft32(words[t-3]^words[t-8]^words[t-14]^words[t-16], 1)
		}

		a, b, c, d, e := h0, h1, h2, h3, h4

		for t := 0; t < 80; t++ {
			var f, k uint32

			switch {
			case t < 20:
				f = (b & c) | ((^b) & d)
				k = 0x5A827999
			case t < 40:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			case t < 60:
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			default:
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			temp := bits.RotateLeft32(a, 5) + f + e + k + words[t]
			e, d, c, b, a = d, c, bits.RotateLeft32(b, 30), a, temp
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
	}

	hash := [20]byte{}
	binary.BigEndian.PutUint32(hash[0:4], h0)
	binary.BigEndian.PutUint32(hash[4:8], h1)
	binary.BigEndian.PutUint32(hash[8:12], h2)
	binary.BigEndian.PutUint32(hash[12:16], h3)
	binary.BigEndian.PutUint32(hash[16:20], h4)

	return hash
}
