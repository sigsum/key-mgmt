package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"sigsum.org/sigsum-go/pkg/checkpoint"
)

// Based on sigsum-go's corresponding code for Ed25519 keys

// See https://c2sp.org/signed-note@v1.1.0
const sigTypeCosignatureMLDSA44 = 0x06

type publicKeyMLDSA44 [mldsa.MLDSA44PublicKeySize]byte

type noteVerifierMLDSA44 struct {
	Name      string
	KeyId     checkpoint.KeyId
	Type      checkpoint.SignatureType
	PublicKey publicKeyMLDSA44
}

func newNoteVerifierMLDSA44(keyName string, keyType checkpoint.SignatureType, publicKey *publicKeyMLDSA44) noteVerifierMLDSA44 {
	return noteVerifierMLDSA44{
		Name:      keyName,
		Type:      keyType,
		KeyId:     newKeyIdMLDSA44(keyName, keyType, publicKey),
		PublicKey: *publicKey,
	}
}

func (nv *noteVerifierMLDSA44) String() string {
	return fmt.Sprintf("%s+%x+%s", nv.Name, nv.KeyId,
		base64.StdEncoding.EncodeToString(bytes.Join([][]byte{[]byte{byte(nv.Type)}, nv.PublicKey[:]}, nil)))
}

func newKeyIdMLDSA44(keyName string, sigType checkpoint.SignatureType, publicKey *publicKeyMLDSA44) (res checkpoint.KeyId) {
	hash := sha256.Sum256(bytes.Join([][]byte{[]byte(keyName), []byte{0xA, byte(sigType)}, publicKey[:]}, nil))
	copy(res[:], hash[:4])
	return
}
