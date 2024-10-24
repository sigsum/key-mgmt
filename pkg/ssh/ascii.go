package ssh

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// Ascii key formats

const pemPrivateKeyTag = "OPENSSH PRIVATE KEY"

var NoPEMError = errors.New("not a PEM file")

// Parses an openssh PEM-formatted private key.
func ParseAsciiEd25519PrivateKey(ascii []byte) ([]byte, error) {
	block, _ := pem.Decode(ascii)
	if block == nil {
		return nil, NoPEMError
	}
	if block.Type != pemPrivateKeyTag {
		return nil, fmt.Errorf("unexpected PEM tag: %q", block.Type)
	}
	return ParseBytes(block.Bytes, readEd25519PrivateKey)
}

// Split line into type, blob (base64), comment (optional),
// recognizing exclusively ascii space and TAB as separators. Input
// must be a single line (with optional terminating newline character)
func splitPublicKeyLine(ascii []byte) (string, []byte, string, error) {
	if eol := bytes.IndexRune(ascii, '\n'); eol >= 0 {
		if eol != len(ascii)-1 {
			return "", nil, "", fmt.Errorf("invalid multi-line public key file")
		}
		ascii = ascii[:eol]
	}
	spaceOrTab := func(r rune) bool {
		return r == ' ' || r == '\t'
	}

	s1 := bytes.IndexFunc(ascii, spaceOrTab)
	if s1 < 0 {
		return "", nil, "", fmt.Errorf("invalid public key line")
	}
	t := string(ascii[:s1])
	ascii = bytes.TrimLeftFunc(ascii[s1+1:], spaceOrTab)

	s2 := bytes.IndexFunc(ascii, spaceOrTab)
	if s2 < 0 {
		// No comment field.
		return t, ascii, "", nil
	}
	return t, ascii[:s2], string(bytes.TrimFunc(ascii[s2+1:], spaceOrTab)), nil
}

// Parses an openssh single-line format public key.
func ParseAsciiEd25519PublicKey(ascii []byte) ([]byte, string, error) {
	t, keyBase64, comment, err := splitPublicKeyLine(ascii)
	if err != nil {
		return nil, "", err
	}

	if t != "ssh-ed25519" {
		return nil, "", fmt.Errorf("unsupported public key type: %v", t)
	}
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewBuffer(keyBase64))
	key, err := ReadEd25519PublicKey(decoder)
	if err != nil {
		return nil, "", err
	}
	// Check that that's no trailing garbage.
	buf := make([]byte, 1)
	if n, err := decoder.Read(buf); n > 0 || err != io.EOF {
		return nil, "", fmt.Errorf("trailing garbage in base64 encoded public key")
	}

	return key, comment, nil
}

func WriteAsciiEd25519PublicKey(w io.Writer, pub []byte, comment string) error {
	keyBlob := SerializeEd25519PublicKey(pub)
	if len(comment) > 0 {
		comment = " " + comment
	}
	_, err := fmt.Fprintf(w, "ssh-ed25519 %s%s", base64.StdEncoding.EncodeToString(keyBlob), comment)
	return err
}

func WriteAsciiEd25519PrivateKey(w io.Writer, priv, pub []byte) error {
	var nonce [4]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return err
	}
	keyBlob := serializeEd25519PrivateKey(priv, pub, nonce)
	return pem.Encode(w, &pem.Block{Type: pemPrivateKeyTag, Bytes: keyBlob})
}
