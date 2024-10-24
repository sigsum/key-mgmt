package ssh

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestParsePrivateKeyFile(t *testing.T) {
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
	privateKey, err := ParseAsciiEd25519PrivateKey(testPriv)
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if got, want := privateKey[:32],
		mustDecodeHex(t,
			"300f45677b629f64237ecca512ad16a2fbfe95cf98af090aef4f5c14e3b7b54a"); !bytes.Equal(got, want) {
		t.Errorf("unexpected private key: %x, expected %x", got, want)
	}
	// This hex string corresponds to public key file
	// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIDs0lLkVyhnkxOr1p3ay6PJgX4rCMeNlFXpDyZqodB4
	if got, want := privateKey[32:], mustDecodeHex(t, "80ecd252e45728679313abd69ddacba3c9817e2b08c78d9455e90f266aa1d078"); !bytes.Equal(got, want) {
		t.Errorf("unexpected publicKey: %x, expected %x", got, want)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
