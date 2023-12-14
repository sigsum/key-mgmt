package agent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"fmt"
)

// Both keys and signatures are serialized in the same way.
func serializeEd25519(blob []byte) []byte {
	return bytes.Join([][]byte{
		serializeString("ssh-ed25519"),
		serializeString(blob)},
		nil)
}

func ed25519Sign(signer crypto.Signer, msg []byte) ([]byte, error) {
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("not an Ed25519 signature, bad length %d", len(sig))
	}
	return serializeEd25519(sig), nil
}

func AgentKeyFromEd25519(signer crypto.Signer) (AgentKey, error) {
	publicKey := signer.Public()
	pub, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return AgentKey{}, fmt.Errorf("not an Ed25519 key, type %T", publicKey)
	}
	if len(pub) != ed25519.PublicKeySize {
		return AgentKey{}, fmt.Errorf("not an Ed25519 key, unexpected length %d", len(pub))
	}
	return AgentKey{
		KeyBlob: serializeEd25519(pub),
		Sign: func(msg []byte) ([]byte, error) {
			return ed25519Sign(signer, msg)
		},
	}, nil
}
