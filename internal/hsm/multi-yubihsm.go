package hsm

import (
	"crypto"
	"io"
	"math/rand"
)

type MultiYubiHSMSigner struct {
   signers []*YubiHSMSigner
}

func NewMultiYubiHSMSigner(signers []*YubiHSMSigner) (*MultiYubiHSMSigner, error) {
	return &MultiYubiHSMSigner{signers}, nil
}

func (multiHSMSigner *MultiYubiHSMSigner) Sign(r io.Reader, msg []byte, o crypto.SignerOpts) ([]byte, error) {
     nSigners := len(multiHSMSigner.signers)
     index := rand.Intn(nSigners)
     return multiHSMSigner.signers[index].Sign(r, msg, o)
}

func (multiHSMSigner *MultiYubiHSMSigner) Public() crypto.PublicKey {
	return multiHSMSigner.signers[0].publicKey
}
