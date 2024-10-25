package agent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"testing"
)

func TestEd25519Signer(t *testing.T) {
	key := [32]byte{1}
	var s crypto.Signer = ed25519.NewKeyFromSeed(key[:])
	pub, signer, err := NewEd25519Signer(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix([]byte(pub), []byte{0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32}) {
		t.Errorf("bad pubkey prefix, got %x", pub)
	}
	if got, want := len(pub), 11+8+32; got != want {
		t.Errorf("unexpected pubkey blob length, got %d, want %d: %x", got, want, pub)
	}

	sig, err := signer.Sign([]byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(sig, []byte{0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 64}) {
		t.Errorf("bad signature prefix, got %x", sig)
	}
	if got, want := len(sig), 11+8+64; got != want {
		t.Errorf("unexpected signature blob length, got %d, want %d: %x", got, want, sig)
	}
}
