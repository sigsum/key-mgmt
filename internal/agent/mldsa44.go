package agent

import (
	"crypto"
	"crypto/mldsa"
	"fmt"
)

func mldsa44Sign(signer crypto.Signer, msg []byte) ([]byte, error) {
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if len(sig) != mldsa.MLDSA44SignatureSize {
		return nil, fmt.Errorf("not an ML-DSA-44 signature, bad length %d", len(sig))
	}
	return SerializeItem(AlgMLDSA44, sig), nil
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
	return string(SerializeItem(AlgMLDSA44, pub.Bytes())),
		func(msg []byte) ([]byte, error) {
			return mldsa44Sign(signer, msg)
		}, nil
}
