// Package crypto provides ...
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// AESCBCEncrypt AES-128。key长度：16, 24, 32 bytes 对应 AES-128, AES-192, AES-256
func AESCBCEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plaintext = PKCS5Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])

	crypted := make([]byte, len(plaintext))
	blockMode.CryptBlocks(crypted, plaintext)
	return crypted, nil
}

// AESCBCDecrypt decrypt cipher
func AESCBCDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])

	plaintext := make([]byte, len(crypted))
	blockMode.CryptBlocks(plaintext, crypted)
	plaintext = PKCS5Unpadding(plaintext)
	return plaintext, nil
}
