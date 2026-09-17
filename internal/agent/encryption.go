package agent

import (
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
	// 100 rounds takes ≈0.8 seconds on a rather fast laptop. Current
	// default in ssh-keygen is 24, but it is also configurable.
	kdfRounds = 100
)

// encryptFunc takes a plain privBlob with no padding and returns
// encrypted and padded data, plus encryption parameters.
type encryptFunc func(plain []byte) (encrypted []byte, cipherName string, kdfName string, kdfOpts *kdfOptions, err error)

// decryptFunc takes an encrypted and padded privBlob and returns the
// decrypted but still padded data.
type decryptFunc func(encrypted []byte) (plain []byte, err error)

func padBlob(blob []byte, blockSize int) []byte {
	if blockSize < 2 {
		return nil
	}
	padLen := blockSize - 1 - ((len(blob) + blockSize - 1) % blockSize)
	return append(blob, opensshPrivateKeyPadding[:padLen]...)
}

func noneEncryptor(privBlobUnpadded []byte) ([]byte, string, string, *kdfOptions, error) {
	return padBlob(privBlobUnpadded, blockSizePlain), "none", "none", nil, nil
}

func noneDecryptor(privBlob []byte) ([]byte, error) {
	if l := len(privBlob); (l % blockSizePlain) != 0 {
		return nil, fmt.Errorf("invalid private key length: %d", l)
	}
	return privBlob, nil
}

func NewPassphraseEncryptor(passphrase string) encryptFunc {
	if passphrase == "" {
		return noneEncryptor
	}
	return newAes256ctrEncryptor(passphrase)
}

func newAes256ctrEncryptor(passphrase string) encryptFunc {
	return func(privBlobUnpadded []byte) ([]byte, string, string, *kdfOptions, error) {
		kdfOpts := &kdfOptions{rounds: kdfRounds}
		if _, err := rand.Read(kdfOpts.salt[:]); err != nil {
			return nil, "", "", nil, err
		}
		encrypted, err := aes256CtrPassphraseCrypt(passphrase, kdfOpts, padBlob(privBlobUnpadded, aes.BlockSize))
		if err != nil {
			return nil, "", "", nil, err
		}
		return encrypted, "aes256-ctr", "bcrypt", kdfOpts, nil
	}
}

func newAes256ctrDecryptor(passphrase string, kdfOpts *kdfOptions) decryptFunc {
	return func(privBlobEncrypted []byte) ([]byte, error) {
		if l := len(privBlobEncrypted); (l % aes.BlockSize) != 0 {
			return nil, fmt.Errorf("invalid encrypted private key length: %d", l)
		}
		decrypted, err := aes256CtrPassphraseCrypt(passphrase, kdfOpts, privBlobEncrypted)
		if err != nil {
			return nil, err
		}
		return decrypted, nil
	}
}

func aes256CtrPassphraseCrypt(passphrase string, kdfOpts *kdfOptions, input []byte) ([]byte, error) {
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
	stream := cipher.NewCTR(cipherBlock, iv)
	output := make([]byte, len(input))
	stream.XORKeyStream(output, input)
	return output, nil
}

type kdfOptions struct {
	salt   [kdfSaltLen]byte
	rounds uint32
}

func readKDFOptionsInner(r io.Reader) (*kdfOptions, error) {
	// For now we expect salt to be exactly kdfSaltLen
	salt, err := readStringLen(r, kdfSaltLen)
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
