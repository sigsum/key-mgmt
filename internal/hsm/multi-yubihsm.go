package hsm

import (
	"crypto"
	"fmt"
	"io"
	"sync"
)

type MultiYubiHSMSigner struct {
	signers     []*YubiHSMSigner
	jobCounters []int
	mutex       sync.Mutex
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
	var multiYubiHSMSigner MultiYubiHSMSigner
	multiYubiHSMSigner.signers = signers
	n := len(signers)
	multiYubiHSMSigner.jobCounters = make([]int, n, n)
	return &multiYubiHSMSigner, nil
}

func (multiHSMSigner *MultiYubiHSMSigner) Sign(r io.Reader, msg []byte, o crypto.SignerOpts) ([]byte, error) {
	// Choose the HSM with smallest number of ongoing jobs
	nSigners := len(multiHSMSigner.signers)
	multiHSMSigner.mutex.Lock()
	chosenIndex := 0
	for i := 0; i < nSigners; i++ {
		if multiHSMSigner.jobCounters[i] < multiHSMSigner.jobCounters[chosenIndex] {
			chosenIndex = i
		}
	}
	multiHSMSigner.jobCounters[chosenIndex]++
	multiHSMSigner.mutex.Unlock()
	result, err := multiHSMSigner.signers[chosenIndex].Sign(r, msg, o)
	multiHSMSigner.mutex.Lock()
	multiHSMSigner.jobCounters[chosenIndex]--
	multiHSMSigner.mutex.Unlock()
	// TODO: consider fallback to another HSM in case of error
	return result, err
}

func (multiHSMSigner *MultiYubiHSMSigner) Public() crypto.PublicKey {
	return multiHSMSigner.signers[0].publicKey
}
