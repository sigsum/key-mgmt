package agent

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"encoding/hex"
	"fmt"
)

// This from https://datatracker.ietf.org/doc/html/draft-sfluhrer-ssh-mldsa-08
const AlgoMLDSA44 = "ssh-mldsa-44"

// Both keys and signatures are serialized in the same way.
func serializeMLDSA44(blob []byte) []byte {
	return bytes.Join([][]byte{
		serializeString(AlgoMLDSA44),
		serializeString(blob)},
		nil)
}

func mldsa44Sign(signer crypto.Signer, msg []byte) ([]byte, error) {
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if len(sig) != mldsa.MLDSA44SignatureSize {
		return nil, fmt.Errorf("not an ML-DSA-44 signature, bad length %d", len(sig))
	}
	return serializeMLDSA44(sig), nil
}

func SSHFromMLDSA44(signer crypto.Signer) (string, SSHSign, error) {
	publicKey := signer.Public()
	pub, ok := publicKey.(*mldsa.PublicKey)
	if !ok {
		return "", nil, fmt.Errorf("not an ML-DSA-44 key, type %T", publicKey)
	}
	if l := pub.Parameters().PublicKeySize(); l != mldsa.MLDSA44PublicKeySize {
		return "", nil, fmt.Errorf("not an ML-DSA-44 key, unexpected length %d", l)
	}
	return string(serializeMLDSA44(pub.Bytes())),
		func(msg []byte) ([]byte, error) {
			return mldsa44Sign(signer, msg)
		}, nil
}

func NewMLDSA44PrivateKeyFromHex(hexFormat string) (*mldsa.PrivateKey, error) {
	privBytes, err := hex.DecodeString(hexFormat)
	if err != nil {
		return nil, err
	}
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), privBytes)
	if err != nil {
		return nil, fmt.Errorf("not an ML-DSA-44 private key: %w", err)
	}
	return priv, nil
}
