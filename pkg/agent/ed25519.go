package agent

import (
	"crypto"
	"crypto/ed25519"
	"fmt"

	"sigsum.org/key-mgmt/pkg/ssh"
)

type Ed25519Signer struct {
	signer crypto.Signer
}

func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) {
	sig, err := s.signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("not an Ed25519 signature, bad length %d", len(sig))
	}
	return ssh.SerializeEd25519Signature(sig), nil
}

func NewEd25519Signer(signer crypto.Signer) (string, *Ed25519Signer, error) {
	publicKey := signer.Public()
	pub, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return "", nil, fmt.Errorf("not an Ed25519 key, type %T", publicKey)
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("not an Ed25519 key, unexpected length %d", len(pub))
	}
	return string(ssh.SerializeEd25519PublicKey(pub)), &Ed25519Signer{signer: signer}, nil
}
