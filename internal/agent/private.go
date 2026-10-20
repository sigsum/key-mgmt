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
)

// This implementation supports Ed25519 and ML-DSA-44 keys. It
// supports plain private key (cipher "none"), and also encryption
// with aes256-ctr and bcrypt-based KDF (the default cipher used by
// ssh-keygen).
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
	// Arbitrary maximum read size when parsing ssh private key
	privateKeyReadMaxSize = 20000
)

var (
	ErrNotPEM                = errors.New("not a PEM file")
	opensshPrivateKeyMagic   = []byte("openssh-key-v1\x00")
	opensshPrivateKeyPadding = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
)

type GetPassphraseFunc func() (string, error)

// ParsePrivateKeyFile reads an ASCII format private key of the
// supported types (Ed25519 or ML-DSA-44). Supports only the case of a
// single key per file. The format is OpenSSH PEM, and the contained
// private key may be plain or encrypted.
func ParsePrivateKeyFile(ascii []byte, getPassphrase GetPassphraseFunc) (crypto.Signer, error) {
	data, err := parsePrivateKeyFile(ascii)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	signer, err := readPrivateKey(data, getPassphrase)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	return signer, nil
}

// ParsePublicFromPrivateKeyFile reads an ASCII format private key in
// a manner similar to ParsePrivateKeyFile. It returns the public key
// without needing to decrypt the private blob.
func ParsePublicFromPrivateKeyFile(ascii []byte) (crypto.PublicKey, error) {
	data, err := parsePrivateKeyFile(ascii)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	pubData, err := parseBytes(data.publicKeyBlob, nil, readPubBlob)
	if err != nil {
		return nil, fmt.Errorf("invalid private key, pubkey invalid: %w", err)
	}
	return publicKeyFromBytes(pubData.algName, pubData.pubKey)
}

// WritePrivateKeyFile writes a private key in OpenSSH PEM format. If
// encryptor is nil the output will not be encrypted.
func WritePrivateKeyFile(w io.Writer, encryptor encryptFunc, algName string, pub []byte, priv []byte) error {
	var nonce [4]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return err
	}
	return writePrivateKeyFile(w, algName, pub, priv, nonce, encryptor)
}

// SerializeItem serializes a key or a signature according to the SSH
// protocol. Both items are serialized in the same way.
func SerializeItem(algName string, blob []byte) []byte {
	return bytes.Join([][]byte{
		serializeString(algName),
		serializeString(blob[:]),
	}, nil)
}

type privateKeyData struct {
	cipherName    string
	kdfName       string
	kdfOptsBlob   []byte
	publicKeyBlob []byte
	privBlob      []byte
}

func parsePrivateKeyFile(ascii []byte) (*privateKeyData, error) {
	block, _ := pem.Decode(ascii)
	if block == nil {
		return nil, ErrNotPEM
	}
	if block.Type != pemPrivateKeyTag {
		return nil, fmt.Errorf("unexpected PEM tag: %q", block.Type)
	}
	return parseBytes(block.Bytes, nil, func(r io.Reader) (*privateKeyData, error) {
		if err := readSkip(r, opensshPrivateKeyMagic); err != nil {
			return nil, err
		}
		cipherName, err := readString(r, privateKeyReadMaxSize)
		if err != nil {
			return nil, fmt.Errorf("reading ciphername: %w", err)
		}
		kdfName, err := readString(r, privateKeyReadMaxSize)
		if err != nil {
			return nil, fmt.Errorf("reading kdfname: %w", err)
		}
		kdfOptsBlob, err := readString(r, privateKeyReadMaxSize)
		if err != nil {
			return nil, fmt.Errorf("reading kdfoptions: %w", err)
		}
		if err = readSkip(r, serializeUint32(1)); err != nil {
			return nil, fmt.Errorf("only 1 single key is supported: %w", err)
		}
		publicKeyBlob, err := readString(r, privateKeyReadMaxSize)
		if err != nil {
			return nil, fmt.Errorf("reading pubkey: %w", err)
		}
		privBlob, err := readString(r, privateKeyReadMaxSize)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %v", err)
		}
		return &privateKeyData{
			cipherName:    string(cipherName),
			kdfName:       string(kdfName),
			kdfOptsBlob:   kdfOptsBlob,
			publicKeyBlob: publicKeyBlob,
			privBlob:      privBlob,
		}, nil
	})
}

func readPrivateKey(data *privateKeyData, getPassphrase GetPassphraseFunc) (crypto.Signer, error) {
	var decryptor decryptFunc
	switch data.cipherName {
	case "none":
		if data.kdfName != "none" {
			return nil, fmt.Errorf("cipher is %s but kdf not none: %s", data.cipherName, data.kdfName)
		}
		if len(data.kdfOptsBlob) > 0 {
			return nil, fmt.Errorf("cipher is %s but kdfoptions is not empty", data.cipherName)
		}
		decryptor = noneDecryptor
	case "aes256-ctr":
		if data.kdfName != "bcrypt" {
			return nil, fmt.Errorf("cipher is %s, unsupported kdf: %s", data.cipherName, data.kdfName)
		}
		kdfOpts, err := parseBytes(data.kdfOptsBlob, nil, readKDFOptions)
		if err != nil {
			return nil, fmt.Errorf("parsing kdfoptions: %w", err)
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
		return nil, fmt.Errorf("unsupported cipher: %s", data.cipherName)
	}

	decrypted, err := decryptor(data.privBlob)
	if err != nil {
		return nil, fmt.Errorf("failed decrypt: %w", err)
	}

	return parseBytes(decrypted, opensshPrivateKeyPadding,
		func(r io.Reader) (crypto.Signer, error) {
			return readPrivateKeyInner(r, data.publicKeyBlob)
		})
}

// readPrivateKeyInner reads the inner private key data, i.e. the
// section that is potentially encrypted.
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
	keys, err := readStringLen(r, pubData.privSize+pubData.pubSize)
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
	_, err = readString(r, privateKeyReadMaxSize)
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

type pubData struct {
	pubKey   []byte
	algName  string
	pubSize  int
	privSize int
}

func readPubBlob(r io.Reader) (*pubData, error) {
	var p pubData
	algName, err := readString(r, privateKeyReadMaxSize)
	if err != nil {
		return nil, fmt.Errorf("reading algname: %w", err)
	}
	p.algName = string(algName)
	p.pubSize, p.privSize, err = getKeySizes(p.algName)
	if err != nil {
		return nil, err
	}
	p.pubKey, err = readStringLen(r, p.pubSize)
	if err != nil {
		return nil, fmt.Errorf("reading pubkey: %w", err)
	}
	if l := len(p.pubKey); l != p.pubSize {
		return nil, fmt.Errorf("unexpected pubkey size: %d", l)
	}
	return &p, nil
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
		serializeString(kdfOpts.serialize()),
		serializeUint32(1), // 1 single key
		// First copy of public key
		serializeString(pubBlob),
		// Followed by the data, plain or encrypted
		serializeString(encrypted),
	}, nil)

	return pem.Encode(w, &pem.Block{Type: pemPrivateKeyTag, Bytes: blob})
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
