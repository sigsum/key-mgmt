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

// This implementation supports Ed25519 and ML-DSA-44 keys. Only
// plain, unencrypted private key (cipher "none") is supported.
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
	AlgEd25519       = "ssh-ed25519"
	AlgMLDSA44       = "ssh-mldsa-44"
	pemPrivateKeyTag = "OPENSSH PRIVATE KEY"
)

var (
	ErrNotPEM                = errors.New("not a PEM file")
	opensshPrivateKeyMagic   = []byte("openssh-key-v1\x00")
	opensshPrivateKeyPadding = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
)

type GetPassphraseFunc func() (string, error)

// Both keys and signatures are serialized in the same way.
func SerializeItem(algName string, blob []byte) []byte {
	return bytes.Join([][]byte{
		serializeString(algName),
		serializeString(blob[:]),
	}, nil)
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

func getKeySizes(algName string) (int, int, error) {
	var pubSize, privSize int
	switch algName {
	case AlgEd25519:
		pubSize = ed25519.PublicKeySize
		privSize = ed25519.SeedSize
	case AlgMLDSA44:
		pubSize = mldsa.MLDSA44PublicKeySize
		privSize = mldsa.PrivateKeySize
	default:
		return -1, -1, fmt.Errorf("unsupported key algorithm: %s", algName)
	}
	return pubSize, privSize, nil
}

func writePrivateKeyFile(w io.Writer, algName string, pub []byte, priv []byte, nonce [4]byte, encryptor encryptFunc) error {
	pubSize, privSize, err := getKeySizes(algName)
	if err != nil {
		return err
	}
	if l := len(pub); l != pubSize {
		return fmt.Errorf("got %s public key with size %d but expected %d", algName, l, pubSize)
	}
	if l := len(priv); l != privSize {
		return fmt.Errorf("got %s private key with size %d but expected %d", algName, l, privSize)
	}

	pubBlob := SerializeItem(algName, pub)

	privBlob := bytes.Join([][]byte{
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

	encrypted, cipherName, kdfName, kdfOpts, err := encryptor(privBlob)
	if err != nil {
		return fmt.Errorf("failed encrypt: %w", err)
	}

	blob := bytes.Join([][]byte{
		opensshPrivateKeyMagic,
		serializeString(cipherName),
		serializeString(kdfName),
		serializeKDFOptions(kdfOpts),
		serializeUint32(1), // 1 single key
		// First copy of public key
		serializeString(pubBlob),
		// Followed by the data, plain or encrypted
		serializeString(encrypted),
	}, nil)

	return pem.Encode(w, &pem.Block{Type: pemPrivateKeyTag, Bytes: blob})
}

func WritePrivateKeyFile(w io.Writer, encryptor encryptFunc, algName string, pub []byte, priv []byte) error {
	var nonce [4]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return err
	}
	return writePrivateKeyFile(w, algName, pub, priv, nonce, encryptor)
}

type pubData struct {
	pubKey   []byte
	algName  string
	pubSize  int
	privSize int
}

func readPubBlob(r io.Reader) (*pubData, error) {
	var p pubData
	// Large enough for supported algorithm names
	algName, err := readString(r, 12)
	if err != nil {
		return nil, fmt.Errorf("reading algname: %w", err)
	}
	p.algName = string(algName)
	p.pubSize, p.privSize, err = getKeySizes(string(p.algName))
	if err != nil {
		return nil, err
	}
	p.pubKey, err = readString(r, p.pubSize)
	if err != nil {
		return nil, fmt.Errorf("reading pubkey: %w", err)
	}
	if l := len(p.pubKey); l != p.pubSize {
		return nil, fmt.Errorf("unexpected pubkey size: %d", l)
	}
	return &p, nil
}

// Reads the inner private key data, i.e., the section that is
// potentially encrypted (although we handle only unencrypted key
// files).
func readPrivateKeyInner(r io.Reader, publicKeyBlob []byte) (crypto.Signer, error) {
	pubData, err := parseBytes(publicKeyBlob, nil, readPubBlob)
	if err != nil {
		return nil, fmt.Errorf("invalid private key, pubkey invalid: %w", err)
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
		return nil, fmt.Errorf("wrong passphrase or invalid private key")
	}

	if err := readSkip(r, publicKeyBlob); err != nil {
		return nil, fmt.Errorf("invalid private key, inconsistent public key: %v", err)
	}
	keys, err := readString(r, pubData.privSize+pubData.pubSize)
	if err != nil {
		return nil, fmt.Errorf("invalid private key, private key missing: %v", err)
	}
	// The keys blob consists of the private key + public key.
	if len(keys) != (pubData.privSize + pubData.pubSize) {
		return nil, fmt.Errorf("unexpected private key size: %d", len(keys))
	}
	if !bytes.Equal(pubData.pubKey, keys[pubData.privSize:]) {
		return nil, fmt.Errorf("inconsistent public key")
	}
	_, err = readString(r, 100)
	if err != nil {
		return nil, fmt.Errorf("comment string missing")
	}

	switch pubData.algName {
	case AlgEd25519:
		return ed25519.PrivateKey(keys), nil
	case AlgMLDSA44:
		priv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), keys[:pubData.privSize])
		if err != nil {
			return nil, fmt.Errorf("failed to create private key: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", pubData.algName)
	}
}

// Reads a binary private key file, i.e., after PEM decapsulation.
func readPrivateKey(r io.Reader, getPassphrase GetPassphraseFunc) (crypto.Signer, error) {
	if err := readSkip(r, opensshPrivateKeyMagic); err != nil {
		return nil, err
	}

	var decryptor decryptFunc

	cipherName, err := readString(r, 40)
	if err != nil {
		return nil, fmt.Errorf("reading ciphername: %w", err)
	}
	kdfName, err := readString(r, 40)
	if err != nil {
		return nil, fmt.Errorf("reading kdfname: %w", err)
	}

	switch string(cipherName) {
	case "none":
		if string(kdfName) != "none" {
			return nil, fmt.Errorf("cipher is %s but kdf not none: %s", cipherName, kdfName)
		}
		if err := readSkip(r, bytes.Join([][]byte{
			serializeKDFOptions(nil),
			serializeUint32(1), // 1 single key
		}, nil)); err != nil {
			return nil, fmt.Errorf("cipher is %s: %w", cipherName, err)
		}
		decryptor = newNoneDecryptor()
	case "aes256-ctr":
		if string(kdfName) != "bcrypt" {
			return nil, fmt.Errorf("cipher is %s, unsupported kdf: %s", cipherName, kdfName)
		}
		kdfOpts, err := readKDFOptions(r)
		if err != nil {
			return nil, fmt.Errorf("reading kdfoptions: %w", err)
		}
		if err := readSkip(r, serializeUint32(1)); err != nil {
			return nil, fmt.Errorf("cipher is %s, kdf is %s: %w", cipherName, kdfName, err)
		}
		if getPassphrase == nil {
			return nil, fmt.Errorf("encrypted private key but missing passphrase getter")
		}
		passphrase, err := getPassphrase()
		if err != nil {
			return nil, fmt.Errorf("failed to get passphrase: %w", err)
		}
		if passphrase == "" {
			return nil, fmt.Errorf("got empty passphrase")
		}
		decryptor = newAes256ctrDecryptor(passphrase, kdfOpts)
	default:
		return nil, fmt.Errorf("unsupported cipher: %s", cipherName)
	}

	// Large enough for Ed25519 and ML-DSA-44
	publicKeyBlob, err := readString(r, 1332)
	if err != nil {
		return nil, fmt.Errorf("reading pubkey: %w", err)
	}

	// Large enough for plain/encrypted blob of supported algorithms
	privBlob, err := readString(r, 2704)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}

	decrypted, err := decryptor(privBlob)
	if err != nil {
		return nil, fmt.Errorf("failed decrypt: %w", err)
	}

	return parseBytes(decrypted, opensshPrivateKeyPadding,
		func(r io.Reader) (crypto.Signer, error) {
			return readPrivateKeyInner(r, publicKeyBlob)
		})
}

// Reads an ASCII format private key of the supported types (Ed25519
// or ML-DSA-44). Supports only the case of a single key per file. The
// format is OpenSSH PEM, and the contained private key may be plain
// or encrypted.
func ReadPrivateKeyFile(fileName string, getPassphrase GetPassphraseFunc) (crypto.Signer, error) {
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
	signer, err := parseBytes(block.Bytes, nil,
		func(r io.Reader) (crypto.Signer, error) {
			return readPrivateKey(r, getPassphrase)
		})
	if err != nil {
		return nil, fmt.Errorf("parsing private key file %q failed: %v",
			fileName, err)
	}

	return signer, nil
}
