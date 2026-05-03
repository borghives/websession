package websession

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
)

// constantReader is an io.Reader that returns the same bytes every time.
type constantReader struct {
	seed []byte
}

func (r constantReader) Read(p []byte) (n int, err error) {
	copy(p, r.seed)
	return len(r.seed), nil
}

// Function to sign a message
func SignMessage(privKey *ecdsa.PrivateKey, message []byte) ([]byte, []byte, error) {
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, nil, err
	}
	return r.Bytes(), s.Bytes(), nil
}

// Function to verify a signature
func VerifySignature(pubKey *ecdsa.PublicKey, message []byte, rBytes, sBytes []byte) bool {
	hash := sha256.Sum256(message)
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	return ecdsa.Verify(pubKey, hash[:], r, s)
}

// Encrypts a message using AES-GCM with the given key
func EncryptMessage(secret string, message []byte) (string, error) {
	key := sha256.Sum256([]byte(secret))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	// Create a new GCM instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce of appropriate size
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt and concatenate nonce
	cipherText := gcm.Seal(nonce, nonce, message, nil)
	// Use RawURLEncoding to avoid special chars (+, /, =) in cookies
	return base64.RawURLEncoding.EncodeToString(cipherText), nil
}

// Decrypts a message using AES-GCM with the given key
func DecryptMessage(secret string, encryptedMessage string) ([]byte, error) {
	key := sha256.Sum256([]byte(secret))

	// Decode using RawURLEncoding (or fallback to StdEncoding for backwards compatibility)
	cipherText, err := base64.RawURLEncoding.DecodeString(encryptedMessage)
	if err != nil {
		// Fallback for older sessions
		cipherText, err = base64.StdEncoding.DecodeString(encryptedMessage)
		if err != nil {
			return nil, errors.New("failed to decode base64")
		}
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	// Create a new GCM instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

	// Decrypt message
	return gcm.Open(nil, nonce, cipherText, nil)
}

// function to get 12 random bytes in hex string
// returned empty string if error
func GetRandomHexString() string {
	b := make([]byte, 12) // 12 bytes = 24 hex chars
	if _, err := rand.Read(b); err != nil {
		return ""
	}

	return hex.EncodeToString(b)
}
