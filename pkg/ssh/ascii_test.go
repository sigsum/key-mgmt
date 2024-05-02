package ssh

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestParsePublicEd25519(t *testing.T) {
	expKey := mustDecodeHex(t, "314cb82ac8b5fe90cf18bf190afa4759b80779709f991f736f044d5e13bcbca6")
	for _, table := range []struct {
		desc       string
		ascii      string
		expSuccess bool
	}{
		{"basic", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym", true},
		{"with newline", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym\n", true},
		{"with comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", true},
		{"truncated b64", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLy comment", false},
		{"truncated bin", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4T comment", false},
	} {
		key, _, err := ParseAsciiEd25519PublicKey([]byte(table.ascii))
		if err != nil {
			if table.expSuccess {
				t.Errorf("%q: parsing failed: %v", table.desc, err)
			}
		} else {
			if !table.expSuccess {
				t.Errorf("%q: unexpected success, should have failed", table.desc)
			} else if !bytes.Equal(key, expKey) {
				t.Errorf("%q: parsing gave wrong key: %x", table.desc, key)
			}
		}
	}
}

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
	testPub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIDs0lLkVyhnkxOr1p3ay6PJgX4rCMeNlFXpDyZqodB4"
	privateKey, err := ParseAsciiEd25519PrivateKey(testPriv)
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if got, want := privateKey[:32],
		mustDecodeHex(t,
			"300f45677b629f64237ecca512ad16a2fbfe95cf98af090aef4f5c14e3b7b54a"); !bytes.Equal(got, want) {
		t.Errorf("unexpected private key: %x, expected %x", got, want)
	}
	publicKey, _, err := ParseAsciiEd25519PublicKey([]byte(testPub))
	if err != nil {
		t.Fatalf("failed to parse pubkey file")
	}
	if got, want := privateKey[32:], publicKey; !bytes.Equal(got, want) {
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
