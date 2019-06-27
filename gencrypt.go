package gencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AES struct {
	Secret []byte
	gcm    cipher.AEAD
}

// Create a new AES encryption using a secret key.
// Secret key length has to be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// See golang crypto/aes for more information.
func New(secret []byte) (*AES, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AES{
		Secret: secret,
		gcm:    gcm,
	}, nil
}

// Encrypts data and returns the encrypted bytes.
func (aes *AES) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, aes.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encrypted := aes.gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// Decrypts encrypted data and return the decrypted bytes.
func (aes *AES) Decrypt(data []byte) ([]byte, error) {
	nonceSize := aes.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrInvalidData
	}

	nonce, encrypted := data[:nonceSize], data[nonceSize:]
	decrypted, err := aes.gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
