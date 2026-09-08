package agent

// Based on sigsum-go/internal/ssh/private.go

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// This implementation supports Ed25519 and ML-DSA-44 keys. Encryption
// with cipher "aes256-ctr" and KDF "bcrypt" is supported. That is the
// default cipher used by ssh-keygen.
//
// For documentation of the openssh private key format, see
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
// https://coolaj86.com/articles/the-openssh-private-key-format
//
// ML-DSA-44 protocol details, such as key algorithm name and public
// key format were taken from:
// https://datatracker.ietf.org/doc/html/draft-sfluhrer-ssh-mldsa-08
//
// Serialization of ML-DSA-44 private key is not yet specified, so it
// was modelled after Ed25519.

const (
	AlgoEd25519             = "ssh-ed25519"
	AlgoMLDSA44             = "ssh-mldsa-44"
	pemPrivateKeyTag        = "OPENSSH PRIVATE KEY"
	opensshPrivKeyKeysCount = 1
)

var (
	ErrNotPEM               = errors.New("not a PEM file")
	opensshPrivKeyAuthMagic = []byte("openssh-key-v1\x00")
)

// Both keys and signatures are serialized in the same way.
func SerializeItem(algoName string, blob []byte) []byte {
	return bytes.Join([][]byte{
		serializeString(algoName),
		serializeString(blob[:]),
	}, nil)
}

func getKeySizes(algoName string) (int, int, error) {
	var pubSize, privSize int
	switch algoName {
	case AlgoEd25519:
		pubSize = ed25519.PublicKeySize
		privSize = ed25519.SeedSize
	case AlgoMLDSA44:
		pubSize = mldsa.MLDSA44PublicKeySize
		privSize = mldsa.PrivateKeySize
	default:
		return -1, -1, fmt.Errorf("unsupported key algo: %s", algoName)
	}
	return pubSize, privSize, nil
}

func genPadding(size int, blockSize int) []byte {
	if blockSize < 2 {
		return nil
	}
	var padding []byte
	for padCount := 0; (size+padCount)%blockSize != 0; padCount++ {
		padding = append(padding, byte(padCount+1))
	}
	return padding
}

func writePrivateKeyFile(w io.Writer, algoName string, pub []byte, priv []byte, nonce [4]byte) error {
	pubSize, privSize, err := getKeySizes(algoName)
	if err != nil {
		return err
	}
	if l := len(pub); l != pubSize {
		return fmt.Errorf("got %s public key with size %d but expected %d", algoName, l, pubSize)
	}
	if l := len(priv); l != privSize {
		return fmt.Errorf("got %s private key with size %d but expected %d", algoName, l, privSize)
	}

	pubBlob := SerializeItem(algoName, pub)

	privBlobUnpadded := bytes.Join([][]byte{
		// Add nonce twice, to check for correct decryption
		nonce[:],
		nonce[:],
		// Private key is public key + additional private parameters.
		pubBlob,
		// Finally, the ssh secret key, which includes the raw public
		// key once more.
		serializeString(bytes.Join([][]byte{priv, pub}, nil)),
		// Empty comment.
		serializeUint32(0),
	}, nil)
	privBlob := bytes.Join([][]byte{
		privBlobUnpadded,
		genPadding(len(privBlobUnpadded), 8),
	}, nil)

	blob := bytes.Join([][]byte{
		opensshPrivKeyAuthMagic,
		serializeString("none"), // ciphername
		serializeString("none"), // kdfname
		serializeString(""),     // no kdfoptions
		// One single key
		serializeUint32(1),
		// First copy of public key
		serializeString(pubBlob),
		// Followed by the data, only plain supported
		serializeString(privBlob),
	}, nil)

	return pem.Encode(w, &pem.Block{Type: pemPrivateKeyTag, Bytes: blob})
}

func WritePrivateKeyFile(w io.Writer, algoName string, pub []byte, priv []byte) error {
	var nonce [4]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return err
	}
	return writePrivateKeyFile(w, algoName, pub, priv, nonce)
}

// Reads the inner private key data.
func readPrivateKeyInner(r io.Reader, algoName string, pubBlob []byte) (crypto.Signer, error) {
	pubSize, privSize, err := getKeySizes(algoName)
	if err != nil {
		return nil, err
	}

	pub, err := parseBytes(pubBlob, 0,
		func(r io.Reader) ([]byte, error) {
			if err := readSkip(r, bytes.Join([][]byte{
				serializeString(algoName),
				serializeUint32(uint32(pubSize)),
			}, nil)); err != nil {
				return nil, fmt.Errorf("invalid public key blob prefix: %w", err)
			}
			return readBytes(r, pubSize)
		})
	if err != nil {
		return nil, fmt.Errorf("pubkey invalid: %w", err)
	}

	n1, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	n2, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	if n1 != n2 {
		return nil, fmt.Errorf("invalid key")
	}

	if err := readSkip(r, pubBlob); err != nil {
		return nil, fmt.Errorf("inconsistent public key: %w", err)
	}
	keys, err := readString(r, privSize+pubSize)
	if err != nil {
		return nil, fmt.Errorf("private key missing: %w", err)
	}
	// The keys blob consists of the private key + public key.
	if len(keys) != (privSize + pubSize) {
		return nil, fmt.Errorf("unexpected private key size: %d", len(keys))
	}
	if !bytes.Equal(pub[:], keys[privSize:]) {
		return nil, fmt.Errorf("inconsistent public key")
	}
	_, err = readString(r, 100)
	if err != nil {
		return nil, fmt.Errorf("comment string missing")
	}

	switch algoName {
	case AlgoEd25519:
		return ed25519.PrivateKey(keys), nil
	case AlgoMLDSA44:
		priv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), keys[:privSize])
		if err != nil {
			return nil, fmt.Errorf("failed to create private key: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported key algo: %s", algoName)
	}
}

// Reads a binary private key file, i.e., after PEM decapsulation.
func readPrivateKey(r io.Reader, fileName string) (crypto.Signer, error) {
	if err := readSkip(r, opensshPrivKeyAuthMagic); err != nil {
		return nil, err
	}

	cipherName, err := readString(r, 40)
	if err != nil {
		return nil, fmt.Errorf("reading ciphername: %w", err)
	}
	if string(cipherName) != "none" {
		return nil, fmt.Errorf("unsupported private key cipher: %s", cipherName)
	}
	if err := readSkip(r, bytes.Join([][]byte{
		serializeString("none"),
		serializeString(""),
		serializeUint32(opensshPrivKeyKeysCount),
	}, nil)); err != nil {
		return nil, fmt.Errorf("cipher is %s: %w", cipherName, err)
	}

	// Large enough for Ed25519 and ML-DSA-44
	pubBlob, err := readString(r, 1332)
	if err != nil {
		return nil, fmt.Errorf("reading pubkey: %w", err)
	}
	// Large enough for supported algo names
	algoName, err := readString(bytes.NewReader(pubBlob), 12)
	if err != nil {
		return nil, fmt.Errorf("reading algoname: %w", err)
	}
	// Large enough for the plain blob of supported algos
	privBlob, err := readString(r, 2696)
	if err != nil {
		return nil, fmt.Errorf("reading privblob: %w", err)
	}
	if length := len(privBlob); (length % 8) != 0 {
		return nil, fmt.Errorf("length %d not divisable by %d", length, 8)
	}

	return parseBytes(privBlob, 8,
		func(r io.Reader) (crypto.Signer, error) {
			signer, err := readPrivateKeyInner(r, string(algoName), pubBlob)
			if err != nil {
				return nil, err
			}
			return signer, nil
		})
}

// Reads an ASCII format private key a supported type (Ed25519 or
// ML-DSA-44). Supports only the case of a single key per file. The
// format is plain, unencrypted OpenSSH PEM only.
func ReadPrivateKeyFile(fileName string) (crypto.Signer, error) {
	ascii, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(ascii)
	if block == nil {
		return nil, ErrNotPEM
	}
	if block.Type != pemPrivateKeyTag {
		return nil, fmt.Errorf("unexpected PEM tag: %q", block.Type)
	}
	signer, err := parseBytes(block.Bytes, 0,
		func(r io.Reader) (crypto.Signer, error) {
			return readPrivateKey(r, fileName)
		})
	if err != nil {
		return nil, fmt.Errorf("parsing private key file %q failed: %w", fileName, err)
	}

	return signer, nil
}
