package hsm

import (
	"crypto"
	"fmt"
	"io"
	"math/rand"
)

type MultiYubiHSMSigner struct {
	signers []*YubiHSMSigner
}

func NewMultiYubiHSMSigner(signers []*YubiHSMSigner) (*MultiYubiHSMSigner, error) {
	// Verify that all signers have the same pubkey
	pub0 := signers[0].PublicEd25519()
	for i, s := range signers {
		pub := s.PublicEd25519()
		if !pub.Equal(pub0) {
			return nil, fmt.Errorf("Error in NewMultiYubiHSMSigner: different pubkeys found for HSMs %v and %v", 0, i)
		}
	}
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
