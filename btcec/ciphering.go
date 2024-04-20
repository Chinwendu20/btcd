// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// GenerateSharedSecret generates a shared secret based on a private key and a
// public key using Diffie-Hellman key exchange (ECDH) (RFC 4753).
// RFC5903 Section 9 states we should only return x.
func GenerateSharedSecret(privkey *PrivateKey, pubkey *PublicKey) []byte {
	return secp.GenerateSharedSecret(privkey, pubkey)
}

// Encrypt encrypts a message using a public key, returning the encrypted message or an error.
// It generates an ephemeral key, derives a shared secret and an encryption key, then encrypts the message using AES-GCM.
// The ephemeral public key, nonce, tag and encrypted message are then combined and returned as a single byte slice.
func Encrypt(pubKey *PublicKey, msg []byte) ([]byte, error) {
	ephemeral, err := NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	ephemeralPubKey := ephemeral.PubKey().SerializeUncompressed()

	ecdhKey := GenerateSharedSecret(ephemeral, pubKey)
	hashedSecret := sha256.Sum256(ecdhKey)
	encryptionKey := hashedSecret[:16]

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	ciphertext := make([]byte, 4+len(ephemeralPubKey))
	binary.LittleEndian.PutUint32(ciphertext, uint32(len(ephemeralPubKey)))
	copy(ciphertext[4:], ephemeralPubKey)
	ciphertext = gcm.Seal(ciphertext, nonce, msg, ephemeralPubKey)

	return ciphertext, nil
}

// Decrypt decrypts data that was encrypted using the Encrypt function.
// The decrypted message is returned if the decryption is successful, or an error is returned if there are any issues.
func Decrypt(privkey *PrivateKey, msg []byte) ([]byte, error) {
	// Message cannot be less than length of public key (65) + nonce (16) + tag (16)
	if len(msg) <= (1 + 32 + 32 + 16 + 16) {
		return nil, fmt.Errorf("invalid length of message")
	}

	pubKeyLen := binary.LittleEndian.Uint32(msg[:4])
	senderPubKeyBytes := msg[4 : 4+pubKeyLen]
	senderPubKey, err := ParsePubKey(senderPubKeyBytes)
	if err != nil {
		return nil, err
	}

	ecdhKey := GenerateSharedSecret(privkey, senderPubKey)
	hashedSecret := sha256.Sum256(ecdhKey)
	encryptionKey := hashedSecret[:16]

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	recoveredPlaintext, err := gcm.Open(
		nil, nonce, msg[4+pubKeyLen:], senderPubKeyBytes,
	)
	if err != nil {
		return nil, err
	}

	return recoveredPlaintext, nil
}
