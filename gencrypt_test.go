package gencrypt

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAESEncryptAndDecrypt(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	aes, err := New(secret)
	assert.Nil(t, err)
	assert.NotNil(t, aes)

	original := []byte("testing some secret message")
	enc, err := aes.Encrypt(original)
	assert.Nil(t, err)
	assert.NotEqual(t, enc, original)

	dec, err := aes.Decrypt(enc)
	assert.Nil(t, err)
	assert.Equal(t, original, dec)
}
