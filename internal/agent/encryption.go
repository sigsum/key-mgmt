package agent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"sigsum.org/key-mgmt/internal/bcrypt_pbkdf"
)

const (
	blockSizePlain = 8
	aesKeyLen      = 32 // aes256
	kdfSaltLen     = 16
	kdfRounds      = 24
)

type encryptFunc func([]byte) ([]byte, string, string, *kdfOptions, error)
type decryptFunc func([]byte) ([]byte, error)

func plainEncrypter(privBlobUnpadded []byte) ([]byte, string, string, *kdfOptions, error) {
	privBlob := bytes.Join([][]byte{
		privBlobUnpadded,
		genPadding(len(privBlobUnpadded), blockSizePlain),
	}, nil)
	return privBlob, "none", "none", nil, nil
}

func passphraseEncrypter(passphrase string) (encryptFunc, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("refusing empty passphrase")
	}
	return func(privBlobUnpadded []byte) ([]byte, string, string, *kdfOptions, error) {
		kdfOpts := &kdfOptions{rounds: kdfRounds}
		if _, err := rand.Read(kdfOpts.salt[:]); err != nil {
			return nil, "", "", nil, err
		}
		privBlob := bytes.Join([][]byte{
			privBlobUnpadded,
			genPadding(len(privBlobUnpadded), aes.BlockSize),
		}, nil)
		stream, err := newCipherStream(passphrase, kdfOpts)
		if err != nil {
			return nil, "", "", nil, err
		}
		privBlobEncrypted := make([]byte, len(privBlob))
		stream.XORKeyStream(privBlobEncrypted, privBlob)

		return privBlobEncrypted, "aes256-ctr", "bcrypt", kdfOpts, nil
	}, nil
}

func plainDecrypter() (decryptFunc, int) {
	return func(privBlob []byte) ([]byte, error) {
		return privBlob, nil
	}, blockSizePlain
}

func passphraseDecrypter(passphrase string, cipherName string, kdfName string, kdfOpts *kdfOptions) (decryptFunc, int, error) {
	if cipherName != "aes256-ctr" {
		return nil, 0, fmt.Errorf("unsupported cipher: %s", cipherName)
	}
	if kdfName != "bcrypt" {
		return nil, 0, fmt.Errorf("unsupported kdf: %s", kdfName)
	}
	return func(privBlobEncrypted []byte) ([]byte, error) {
		stream, err := newCipherStream(passphrase, kdfOpts)
		if err != nil {
			return nil, err
		}
		privBlob := make([]byte, len(privBlobEncrypted))
		stream.XORKeyStream(privBlob, privBlobEncrypted)
		return privBlob, nil
	}, aes.BlockSize, nil
}

func newCipherStream(passphrase string, kdfOpts *kdfOptions) (cipher.Stream, error) {
	// For openssh private key encryption both key and IV must be
	// derived from the KDF
	material, err := bcrypt_pbkdf.Key([]byte(passphrase), kdfOpts.salt[:], int(kdfOpts.rounds), aesKeyLen+aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed key derivation: %w", err)
	}
	key := material[:aesKeyLen]
	iv := material[aesKeyLen:]
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	return cipher.NewCTR(cipherBlock, iv), nil
}

type kdfOptions struct {
	salt   [kdfSaltLen]byte
	rounds uint32
}

func serializeKDFOptions(opts *kdfOptions) []byte {
	if opts == nil {
		// Empty string means no options, used with kdf none
		return serializeString("")
	}
	return serializeString(bytes.Join([][]byte{
		serializeString(opts.salt[:]),
		serializeUint32(opts.rounds),
	}, nil))
}

func readKDFOptions(r io.Reader) (*kdfOptions, error) {
	opts, err := readString(r, 40)
	if err != nil {
		return nil, err
	}
	r = bytes.NewReader(opts)
	salt, err := readString(r, kdfSaltLen)
	if err != nil {
		return nil, err
	}
	rounds, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	return &kdfOptions{
		salt:   [kdfSaltLen]byte(salt),
		rounds: rounds,
	}, nil
}
