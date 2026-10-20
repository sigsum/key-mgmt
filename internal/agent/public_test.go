package agent

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"testing"
)

func TestParsePublicKeyFileEd25519(t *testing.T) {
	t.Parallel()
	// Generated with ssh-keygen -q -N '' -t ed25519 -f test.key
	testPubFile := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIDs0lLkVyhnkxOr1p3ay6PJgX4rCMeNlFXpDyZqodB4 nisse@blyglans")
	testSeed := mustDecodeHex(t, "300f45677b629f64237ecca512ad16a2fbfe95cf98af090aef4f5c14e3b7b54a")
	testPriv := ed25519.NewKeyFromSeed(testSeed[:])
	testPub := testPriv.Public().(ed25519.PublicKey)

	pub, err := ParsePublicKeyFile(testPubFile)
	if err != nil {
		t.Errorf("failed ParsePublicKeyFile: %v", err)
	}
	if !testPub.Equal(pub) {
		t.Errorf("unexpected publickey %x, wanted %x", pub, testPub)
	}
}

func TestParsePublicKeyFileMLDSA44(t *testing.T) {
	t.Parallel()
	// Generated with genkey-mldsa -N "" -o test.key
	testPubFile := []byte("ssh-mldsa-44 AAAADHNzaC1tbGRzYS00NAAABSCRyyL+jcvEC+1ckJJN/fNif77e5ApMQ7xNvcNSKEnBI5AE+nX1M6bT8zjHbHlwaftxmIFkg4ocKWj5BUmYF7ilVcSjDfNvSmFI+jZvDQoZoDTdj/hqaFfUIM4JMl4glDXz67G8K3G0LuV0MOJZY1LeoBd5TuGFo3wO3mcdQeOoes2G6dr2dP2dK+BuclxnCJofdLPQ9EkVxfDsDwWGXsdYgw2YSoSaL8wK5LwU8s6JzIN2QRabG2a086e6SdPxPUz6uw2dfROEiPqfPhjX7bYdS2pTNTIUvWNWBO67cUcsXg0ReLNGxUoAcC3NlAGTAcZYmVq0KiHbb3CKlZ17iMZZBRBul3p/7i2M+KThna9sictPsZflbE83jjhrCCBwm3wsFIY6mXTjNcttqIYZhuYJ5Z0b8rS4NMS0iEd1S73pxUXX8iWjm0yOKw1wpg4/SPql2qWjFFYwpthmQUG266gLeY0s9HT9nQV8ZzIwfSdgVg14jgmnxDCanJD0wJcn78hv9natOXkuxFd7Qrcj50AEoMCMoRQuTi8aQ1cSMLqDpWNR6GUWlsao0rJm58iXFtFl65jpt7eZciRih740vSr2WvRdktOK3K1qczrRjxplZtyafJFI+StD6NdftWL7ZBy2FScBOHPMtMEv9clG8YopWiQWZ0aPfpT1RXRHxiB2UyfbJcymRSsnZvqCNAyKJa2WfgG5I+m494PYLxd8Vuf0zub2dWGbZsYK0r6NLsHDaTwJ9nrbCYrkUscxTGwLQR4gV0crKkau9eCyaUZp13iPafrvIT4LSMbR05v2we9HQgaLesAF5qFAOXdLSGGo6GorFXDINga11F/YieLq3dQM98Y+g2WUW6OxOZUb8D3hzrHoiYw5TQI9gQdHr+171kMp5YjoafjueD4f7jDwDoyRxRq4JIwBQSGf9Y3lm5BzONucT89U/L6wllh+Nvm2CYFV96p16ed6yGs3ehXc9Gb0DjW6gRbmhK9CsRxo7ttnMg4LFpNFxFiljFFz15BhmRHv2H4S3Ajt8eWk5fQMbjpN+QzQY4af2YnK0e7bvtunxzDcc4x26OWEJkuxO6aYa+8pzbncggnLl2JaGVxCNfsKfUuBV4VILMJn4ZBVCf9qkMjlDOCKiDyDR8+Y8tSvLY+my9i6l8YZjo0WYG+Xy2Q2Ne7YIhSq2mcsSuzs7NwwYWEmGbH1FpRMYjmWX6T7ZRsgJKaeBjWZox3FEI0OQhZU8y/XC8Je8k5qA7o3t2F4HIclVo3lwqZdUGhUeKxsFFlgoWlWS9Slj1rN5siNzLaMRDlfpzuKMXDqjhmyLM4386kYzThgtF7fWH4/DeQih9zALuhCwEab1fCvAjr54hoCqo+lKcsuOcSbCPLKuob70e30l/O26vc11W0lrxKLAfrEHtYmtBSLhmOY51xEyb/GkhaU8lv+4bL/D+3QylLcYc45dqinXSdyTrpVCob4rst/hQe3OOZ5i03D52mgzUKSfcCJbUg09+He+5DHl8ebo2eSgVjSUJ2y6Le/J3qa27Cs54pB4mW1a+FqB3i6wnpAanytd4bkXbypLIXAwu/ygMhXBXZuo2N8hTCW2KlOmhZ9PVRpotR0SsXxoVSWPPvoBoXu81HeG5HRH6ISwrIc+3djFyDYyY2S4Qo5qzZ/CKnP1BMJ2igEnFHPYSUnlYXXlx67WSOgWvWI+/ZNdYeWCFhRrH2ckHC7z6b6xKqUzM2h1uMiw9dxMoNcR28xXZ0f")
	testSeed := mustDecodeHex(t, "4ad78f2f96d4c9dc25525ca1b6d2980f5fe389a6ef15f21413151b518a71a11f")
	testPriv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), testSeed[:])
	if err != nil {
		t.Fatalf("failed NewPrivateKey: %v", err)
	}
	testPub := testPriv.PublicKey()

	pub, err := ParsePublicKeyFile(testPubFile)
	if err != nil {
		t.Errorf("failed ParsePublicKeyFile: %v", err)
	}
	if !testPub.Equal(pub) {
		t.Errorf("unexpected publickey %x, wanted %x", pub, testPub)
	}
}

func TestParsePublicKeyFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		testName string
		input    string
		expErr   string
	}{
		{
			testName: "No options, no comment",
			input:    ` ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKCyNcIGkCFwhhxFgvzgxajr6S7/Ved7to+zO+YvHc18`,
		},
		{
			testName: "Has options",
			input:    `opt=" ",opt2=\",opt3=" "  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKCyNcIGkCFwhhxFgvzgxajr6S7/Ved7to+zO+YvHc18`,
		},
		{
			testName: "Has options and comment",
			input:    ` opts ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKCyNcIGkCFwhhxFgvzgxajr6S7/Ved7to+zO+YvHc18 long comment`,
		},
		{
			testName: "Bad algo; no options, no comment",
			input:    `ssh-curve1337 AAAAC3NzaC1lZDI1NTE5AAAAIKCyNcIGkCFwhhxFgvzgxajr6S7/Ved7to+zO+YvHc18`,
			expErr:   "unsupported key algorithm: ssh-curve1337",
		},
		{
			testName: "Bad algo; has options",
			input:    `opts ssh-curve1337 AAAAC3NzaC1lZDI1NTE5AAAAIKCyNcIGkCFwhhxFgvzgxajr6S7/Ved7to+zO+YvHc18`,
			expErr:   "unsupported key algorithm: ssh-curve1337",
		},
		{
			testName: "Bad algo; has options and comment",
			input:    `opts ssh-curve1337 AAAAC3NzaC1lZDI1NTE5AAAAIKCyNcIGkCFwhhxFgvzgxajr6S7/Ved7to+zO+YvHc18 long comment`,
			expErr:   "unsupported key algorithm: ssh-curve1337",
		},
		{
			testName: "Bad algo; has comment",
			input:    `ssh-curve1337 AAAAC3NzaC1lZDI1NTE5AAAAIKCyNcIGkCFwhhxFgvzgxajr6S7/Ved7to+zO+YvHc18 long comment`,
			expErr:   "unsupported key algorithm: AAAAC3NzaC1lZDI1NTE5AAAAIKCyNcIGkCFwhhxFgvzgxajr6S7/Ved7to+zO+YvHc18",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePublicKeyFile([]byte(test.input))
			if err != nil {
				if test.expErr == "" {
					t.Errorf("got parse err %q, wanted no err", err)
				} else if err.Error() != test.expErr {
					t.Errorf("got parse err %q, wanted %q", err, test.expErr)
				}
				return
			}
			if test.expErr != "" {
				t.Errorf("parse with no err, wanted err %q", test.expErr)
				return
			}
		})
	}
}
