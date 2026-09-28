package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPrivateKeyED25519Read(t *testing.T) {
	// Generated with ssh-keygen -q -N '' -t ed25519 -f test.key
	testPriv := []byte(
		`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCA7NJS5FcoZ5MTq9ad2sujyYF+KwjHjZRV6Q8maqHQeAAAAJjnOhbl5zoW
5QAAAAtzc2gtZWQyNTUxOQAAACCA7NJS5FcoZ5MTq9ad2sujyYF+KwjHjZRV6Q8maqHQeA
AAAEAwD0Vne2KfZCN+zKUSrRai+/6Vz5ivCQrvT1wU47e1SoDs0lLkVyhnkxOr1p3ay6PJ
gX4rCMeNlFXpDyZqodB4AAAADm5pc3NlQGJseWdsYW5zAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
`)
	testPubFingerprint := "SHA256:IoGP6CxJLUuRDevmxKzBXy0XbzYJee6aAwEQsZJL2DA"
	testSeed := mustDecodeHex(t, "300f45677b629f64237ecca512ad16a2fbfe95cf98af090aef4f5c14e3b7b54a")

	signer, err := ReadPrivateKeyFile(testPriv, nil)
	if err != nil {
		t.Fatalf("failed ReadPrivateKeyFile: %v", err)
	}
	priv, ok := signer.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("unsupported signer type: %T", signer)
	}

	if !bytes.Equal(priv.Seed(), testSeed[:]) {
		t.Errorf("unexpected privatekey %x, wanted %x", priv.Seed(), testSeed)
	}

	if fingerprint(AlgEd25519, priv.Public().(ed25519.PublicKey)) != testPubFingerprint {
		t.Errorf("inconsistent publickey, doesn't match fingerprint")
	}
}

func TestPrivateKeyED25519ReadEncrypted(t *testing.T) {
	knownPub, knownPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed GenerateKey: %v", err)
	}
	knownPass := genPass()

	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(knownPriv, "foo", []byte(knownPass))
	if err != nil {
		t.Fatalf("failed MarshalPrivateKeyWithPassphrase: %v", err)
	}
	data := pem.EncodeToMemory(pemBlock)

	signer, err := ReadPrivateKeyFile(data, func() (string, error) { return knownPass, nil })
	if err != nil {
		t.Fatalf("failed ReadPrivateKeyFile: %v", err)
	}
	priv, ok := signer.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("unsupported signer type: %T", signer)
	}

	if !priv.Equal(knownPriv) {
		t.Errorf("unexpected privatekey %x, wanted %x", priv, knownPriv)
	}

	pub := priv.Public().(ed25519.PublicKey)
	if !pub.Equal(knownPub) {
		t.Errorf("unexpected publickey %x, wanted %x", pub, knownPub)
	}
}

func TestPrivateKeyED25519Write(t *testing.T) {
	fixedNonce := [4]byte{'0', '1', '2', '3'}
	fixedSeed := [ed25519.SeedSize]byte{0xde, 0xad, 0xbe, 0xef} // rest zeroes
	fixedPriv := ed25519.NewKeyFromSeed(fixedSeed[:])
	fixedPub := fixedPriv.Public().(ed25519.PublicKey)
	expFile := []byte(
		`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACDGPZYiP3oZYapEsY1zR4NQFx99FB/NNkkAY+1dWkur1gAA
AIgwMTIzMDEyMwAAAAtzc2gtZWQyNTUxOQAAACDGPZYiP3oZYapEsY1zR4NQFx99
FB/NNkkAY+1dWkur1gAAAEDerb7vAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AMY9liI/ehlhqkSxjXNHg1AXH30UH802SQBj7V1aS6vWAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`)

	var buf bytes.Buffer
	err := writePrivateKeyFile(&buf, AlgEd25519, fixedPub, fixedSeed[:], fixedNonce, noneEncryptor)
	if err != nil {
		t.Fatalf("failed writePrivateKeyFile: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), expFile) {
		t.Errorf("unexpected file:\n%s", buf.Bytes())
	}

	signer, err := ReadPrivateKeyFile(buf.Bytes(), nil)
	if err != nil {
		t.Fatalf("failed ReadPrivateKeyFile: %v", err)
	}
	priv, ok := signer.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("unsupported signer type: %T", signer)
	}

	if !priv.Equal(fixedPriv) {
		t.Errorf("unexpected privatekey %x, wanted %x", priv, fixedPriv)
	}
}

func TestPrivateKeyED25519WriteEncrypted(t *testing.T) {
	knownPub, knownPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed GenerateKey: %v", err)
	}
	knownPass := genPass()

	var buf bytes.Buffer
	err = WritePrivateKeyFile(&buf, NewPassphraseEncryptor(knownPass), AlgEd25519, []byte(knownPub), knownPriv.Seed())
	if err != nil {
		t.Fatalf("failed writePrivateKeyFile: %v", err)
	}

	cryptoPriv, err := ssh.ParseRawPrivateKeyWithPassphrase(buf.Bytes(), []byte(knownPass))
	if err != nil {
		t.Errorf("failed ParseRawPrivateKeyWithPassphrase: %v", err)
	}

	priv, ok := cryptoPriv.(*ed25519.PrivateKey)
	if !ok {
		t.Fatalf("unsupported raw type: %T", cryptoPriv)
	}

	if !priv.Equal(knownPriv) {
		t.Errorf("unexpected privatekey %x, wanted %x", priv, knownPriv)
	}

	pub := priv.Public().(ed25519.PublicKey)
	if !pub.Equal(knownPub) {
		t.Errorf("unexpected publickey %x, wanted %x", pub, knownPub)
	}
}

func TestPrivateKeyMLDSA44Read(t *testing.T) {
	testPriv := []byte(
		`-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

`)
	testPubFingerprint := "SHA256:iJTp2T6c+ej5HZ8c8kpgjwXNpMF13Z/wgH1iJ488uqQ"
	testPrivBytes := mustDecodeHex(t, "028e717425305b3654aea992f38aa3f34a3284ca954d6b00e044b10cd69c02b1")

	signer, err := ReadPrivateKeyFile(testPriv, nil)
	if err != nil {
		t.Fatalf("failed ReadPrivateKeyFile: %v", err)
	}
	priv, ok := signer.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("unsupported signer type: %T", signer)
	}

	if !bytes.Equal(priv.Bytes(), testPrivBytes[:]) {
		t.Errorf("unexpected privatekey %x, wanted %x", priv.Bytes(), testPrivBytes)
	}

	if fingerprint(AlgMLDSA44, priv.PublicKey().Bytes()) != testPubFingerprint {
		t.Errorf("inconsistent publickey, doesn't match fingerprint")
	}
}

func TestPrivateKeyMLDSA44ReadWriteEncrypted(t *testing.T) {
	fixedNonce := [4]byte{'0', '1', '2', '3'}
	fixedSeed := [mldsa.PrivateKeySize]byte{0xde, 0xad, 0xbe, 0xef} // rest zeroes
	fixedPriv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), fixedSeed[:])
	if err != nil {
		t.Fatalf("failed NewPrivateKey: %v", err)
	}
	fixedPub := fixedPriv.PublicKey().Bytes()
	fixedPass := "hunter2"
	encryptor := newAes256ctrEncryptor(fixedPass, func() ([kdfSaltLen]byte, error) {
		fixedSalt := [kdfSaltLen]byte{0, 1, 2, 3} // rest zeroes
		return fixedSalt, nil
	})
	expFile := []byte(
		`-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`)

	var buf bytes.Buffer
	err = writePrivateKeyFile(&buf, AlgMLDSA44, fixedPub, fixedSeed[:], fixedNonce, encryptor)
	if err != nil {
		t.Fatalf("failed writePrivateKeyFile: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), expFile) {
		t.Errorf("unexpected file:\n%s", buf.Bytes())
	}

	signer, err := ReadPrivateKeyFile(buf.Bytes(), func() (string, error) { return fixedPass, nil })
	if err != nil {
		t.Fatalf("failed ReadPrivateKeyFile: %v", err)
	}

	priv, ok := signer.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("unsupported signer type: %T", signer)
	}

	if !priv.Equal(fixedPriv) {
		t.Errorf("unexpected privatekey %x, wanted %x", priv, fixedPriv)
	}

	pub := priv.PublicKey().Bytes()
	if !bytes.Equal(pub, fixedPub) {
		t.Errorf("unexpected publickey %x, wanted %x", pub, fixedPub)
	}
}

func TestPrivateKeyMLDSA44Write(t *testing.T) {
	fixedNonce := [4]byte{'0', '1', '2', '3'}
	fixedSeed := [mldsa.PrivateKeySize]byte{0xde, 0xad, 0xbe, 0xef} // rest zeroes
	fixedPriv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), fixedSeed[:])
	if err != nil {
		t.Fatalf("failed NewPrivateKey: %v", err)
	}
	fixedPub := fixedPriv.PublicKey().Bytes()
	expFile := []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`)

	var buf bytes.Buffer
	err = writePrivateKeyFile(&buf, AlgMLDSA44, fixedPub, fixedSeed[:], fixedNonce, noneEncryptor)
	if err != nil {
		t.Fatalf("failed writePrivateKeyFile: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), expFile) {
		t.Errorf("unexpected file:\n%s", buf.Bytes())
	}

	signer, err := ReadPrivateKeyFile(buf.Bytes(), nil)
	if err != nil {
		t.Fatalf("failed ReadPrivateKeyFile: %v", err)
	}
	priv, ok := signer.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("unsupported signer type: %T", signer)
	}

	if !priv.Equal(fixedPriv) {
		t.Errorf("unexpected privatekey %x, wanted %x", priv, fixedPriv)
	}
}

func genPass() string {
	b := make([]byte, 20)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func fingerprint(algName string, pub []byte) string {
	wirePubkey := SerializeItem(algName, pub)
	sha256sum := sha256.Sum256(wirePubkey)
	hash := base64.RawStdEncoding.EncodeToString(sha256sum[:])
	return fmt.Sprintf("SHA256:%s", hash)
}

func mustDecodeHex(t *testing.T, s string) (out [32]byte) {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != len(out) {
		t.Fatalf("unexpected length of hex data, expected %d, got %d", len(out), len(b))
	}
	copy(out[:], b)
	return
}
