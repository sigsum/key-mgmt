package ssh

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestSerializeEd25519PrivateKey(t *testing.T) {
	expBlob := mustDecodeHex(t, "6f70656e7373682d6b65792d763100000000046e6f6e65000000046e6f6e6500"+
		"00000000000001000000330000000b7373682d6564323535313900000020c63d"+
		"96223f7a1961aa44b18d73478350171f7d141fcd36490063ed5d5a4babd60000"+
		"008830313233303132330000000b7373682d6564323535313900000020c63d96"+
		"223f7a1961aa44b18d73478350171f7d141fcd36490063ed5d5a4babd6000000"+
		"40deadbeef000000000000000000000000000000000000000000000000000000"+
		"00c63d96223f7a1961aa44b18d73478350171f7d141fcd36490063ed5d5a4bab"+
		"d6000000000102030405")
	nonce := [4]byte{'0', '1', '2', '3'}
	priv := [32]byte{0xde, 0xad, 0xbe, 0xef}
	signer := ed25519.NewKeyFromSeed(priv[:])
	pub := signer.Public().(ed25519.PublicKey)
	keyBlob := serializeEd25519PrivateKey(priv[:], pub, nonce)

	if !bytes.Equal(keyBlob, expBlob) {
		t.Errorf("unexpected key blob:\n%x", keyBlob)
	}
	got, err := ReadEd25519PrivateKey(bytes.NewBuffer(keyBlob))
	if err != nil {
		t.Fatalf("failed to parse private key file: %v", err)
	}
	if !bytes.Equal(got[:32], priv[:]) {
		t.Errorf("unexpected private key %x, wanted %x", got[:32], priv)
	}
	if !bytes.Equal(got[32:], pub) {
		t.Errorf("unexpected public key %x, wanted %x", got[32:], pub)
	}
}
