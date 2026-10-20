package agent

import (
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// Based on sigsum-go/internal/ssh/public.go

// ParsePublicKeyFile parses a SSH public key file. It handles only
// one key (one single line).
func ParsePublicKeyFile(ascii []byte) (crypto.PublicKey, error) {
	line := strings.TrimLeft(string(ascii), " \t")
	pub, fieldsCount, err := parsePublicKey(line)
	if err != nil && fieldsCount > 2 {
		// First field might be options, try skipping it
		pub, _, err = parsePublicKey(skipOptions(line))
	}
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// skipOptions skips past an SSH public key's options field, which
// ends at the first unquoted space or tab
func skipOptions(line string) string {
	inQuote := false
	var prev byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if (c == ' ' || c == '\t') && !inQuote {
			return line[i:]
		}
		if c == '"' && prev != '\\' {
			inQuote = !inQuote
		}
		prev = c
	}
	return line
}

// parsePublicKey parses a line in a SSH public key file. The first
// field is expected to be the keytype.
func parsePublicKey(line string) (crypto.PublicKey, int, error) {
	// Split into fields, recognizing exclusively ascii space and TAB
	fields := strings.FieldsFunc(line, func(c rune) bool {
		return c == ' ' || c == '\t'
	})
	if len(fields) < 2 {
		return nil, len(fields), fmt.Errorf("invalid public key, splitting line %q failed", line)
	}
	algName := fields[0]
	pubSize, _, err := getKeySizes(algName)
	if err != nil {
		return nil, len(fields), err
	}
	pubBlob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, len(fields), err
	}
	pub, err := parseBytes(pubBlob, nil,
		func(r io.Reader) (crypto.PublicKey, error) {
			if err := readSkip(r, serializeString(algName)); err != nil {
				return nil, fmt.Errorf("unexpected public key algo: %w", err)
			}
			pubKey, err := readStringLen(r, pubSize)
			if err != nil {
				return nil, fmt.Errorf("unexpected public key length: %w", err)
			}
			return publicKeyFromBytes(algName, pubKey)
		})
	return pub, len(fields), err
}

func publicKeyFromBytes(algName string, pub []byte) (crypto.PublicKey, error) {
	switch algName {
	case AlgEd25519:
		if l := len(pub); l != ed25519.PublicKeySize {
			return nil, fmt.Errorf("unexpected Ed25519 pubkey size: %d", l)
		}
		return ed25519.PublicKey(pub), nil
	case AlgMLDSA44:
		pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pub)
		if err != nil {
			return nil, fmt.Errorf("failed to create public key: %w", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algName)
	}
}
