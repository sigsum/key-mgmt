package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/pborman/getopt/v2"
	"golang.org/x/term"
	"sigsum.org/key-mgmt/internal/agent"
	"sigsum.org/key-mgmt/internal/ui"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	sigsumcrypto "sigsum.org/sigsum-go/pkg/crypto"
)

// The Ed25519 support is used for testing openssh PEM privkey
// encryption interop with ssh-keygen (which does not support
// ML-DSA-44).

func main() {
	const (
		groupOLE = "NOTE1"
		usage    = `
Generate ML-DSA-44 private key

The generated ML-DSA-44 private key is by default printed to stdout in
OpenSSH PEM format, followed by the SSH public key (1 line).

The program asks for a passphrase for encrypting the private key
before writing it. If an empty passphrase is entered the private key
will not be encrypted.

The -S (--seed) option expects the file to contains raw bytes. If your
random number source has hex-encoded bytes, you need to convert them,
like:

    hexrng | basenc -d --base16 | genkey-mldsa44 --seed=- -o thekey

The file will be read until EOF and must contain the exact amount
needed for the seed (which is 32 bytes for both ML-DSA-44 and
Ed25519). If your source has more bytes than that, you may pipe it
through: dd bs=1 count=32

NOTE: The security of the private key relies entirely on the quality
and secrecy of the seed that you provide. Ensure it comes from an
unpredictable source of randomness.

The options -l and -e can read both the SSH private key (PEM), and SSH
public key formats. Reading as private key is attempted first. Since
this always contains the public key in plain, non-enrypted, format, no
passphrase will be needed. If the file is not PEM-encoded, it is read
as an SSH public key, with support for one single public key (one
line).

` + groupOLE + `: options -o, -l, and -e are mutually exclusive
`
	)
	showHelp := false
	outFile := ""
	showFPFile := ""
	showVkeyFile := ""
	vkeyName := ""
	keyType := "mldsa44"
	passphrase := ""
	seedFile := ""

	set := getopt.New()
	set.FlagLong(&showHelp, "help", 'h', "Show this help")
	set.FlagLong(&outFile, "output", 'o', "Output generated private key to filename, its SSH public key to filename.pub, and the fingerprint to stdout", "filename").
		SetGroup(groupOLE)
	set.FlagLong(&passphrase, "passphrase", 'N', "Set passphrase for encryption, empty string for no encryption", "string")
	set.Flag(&keyType, 't', "Set type of key to generate, mldsa44 or ed25519", "keytype")
	set.FlagLong(&seedFile, "seed", 'S', "Read the random seed bytes for the private key from file. \"-\" can be used for stdin.", "filename")
	set.FlagLong(&showFPFile, "show", 'l', "Show SSH fingerprint of a public key from an SSH public or private key file", "filename").
		SetGroup(groupOLE)
	set.Flag(&showVkeyFile, 'e', "Show cosignature vkey (signature type 0x04 or 0x06) of a public key from an SSH public or private key file", "filename").
		SetGroup(groupOLE)
	set.Flag(&vkeyName, 'n', "Set key name for vkey. Required for -e.", "keyname")
	set.SetParameters("")
	err := set.Getopt(os.Args, nil)
	// Check early if user wants help
	if showHelp {
		fmt.Print(usage[1:] + "\n")
		set.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		set.PrintUsage(os.Stderr)
		os.Exit(2)
	}
	if (set.IsSet('t') || set.IsSet('N') || set.IsSet('S')) && (set.IsSet('l') || set.IsSet('e')) {
		fmt.Fprintf(os.Stderr, "Option -t, -N, and -S can only be used when generating a key\n")
		os.Exit(2)
	}
	if set.IsSet('e') && !set.IsSet('n') {
		fmt.Fprintf(os.Stderr, "Option -e requires a key name set using -n\n")
		os.Exit(2)
	}
	if !set.IsSet('e') && set.IsSet('n') {
		fmt.Fprintf(os.Stderr, "Option -n can only be used with -e\n")
		os.Exit(2)
	}
	if set.NArgs() > 0 {
		fmt.Fprintf(os.Stderr, "Unexpected positional args: %q\n", set.Args())
		os.Exit(2)
	}

	if set.IsSet('l') {
		err = showFP(showFPFile)
	} else if set.IsSet('e') {
		err = showVkey(showVkeyFile, vkeyName)
	} else {
		if set.IsSet('S') && seedFile == "" {
			fmt.Fprintf(os.Stderr, "Option -S (--seed) has empty filename\n")
			os.Exit(2)
		}
		if seedFile == "-" {
			seedFile = "/dev/stdin"
		}
		if seedFile != "/dev/stdin" && !term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintf(os.Stderr, "Warning: stdin is piped or redirected to, but option -S (--seed) is not set to /dev/stdin (or \"-\")\n")
		}
		err = genkey(outFile, keyType, seedFile, set.Lookup('N'))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func showFP(fileName string) error {
	pub, err := pubkeyFromFile(fileName)
	if err != nil {
		return err
	}
	var fp string
	switch p := pub.(type) {
	case ed25519.PublicKey:
		fp = fingerprint(agent.AlgEd25519, p)
	case *mldsa.PublicKey:
		fp = fingerprint(agent.AlgMLDSA44, p.Bytes())
	default:
		return fmt.Errorf("unsupported signer type from file %q: %T", fileName, p)
	}
	fmt.Printf("%s\n", fp)
	return nil
}

func showVkey(fileName string, keyName string) error {
	pub, err := pubkeyFromFile(fileName)
	if err != nil {
		return err
	}
	var vkey string
	switch p := pub.(type) {
	case ed25519.PublicKey:
		sigsumPub := sigsumcrypto.PublicKey(p)
		nv := checkpoint.NewNoteVerifier(keyName, checkpoint.SigTypeCosignature, &sigsumPub)
		vkey = nv.String()
	case *mldsa.PublicKey:
		nv := newNoteVerifierMLDSA44(keyName, sigTypeCosignatureMLDSA44, (*publicKeyMLDSA44)(p.Bytes()))
		vkey = nv.String()
	default:
		return fmt.Errorf("unsupported signer type from file %q: %T", fileName, p)
	}
	fmt.Printf("%s\n", vkey)
	return nil
}

func pubkeyFromFile(fileName string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	pub, err := agent.ParsePublicFromPrivateKeyFile(data)
	if err != nil {
		if !errors.Is(err, agent.ErrNotPEM) {
			return nil, fmt.Errorf("reading private key file %q failed: %w", fileName, err)
		}
		pub, err = agent.ParsePublicKeyFile(data)
		if err != nil {
			return nil, fmt.Errorf("reading public key file %q failed: %w", fileName, err)
		}
	}
	return pub, nil
}

func genkey(outFile string, keyType string, seedFile string, passphraseOpt getopt.Option) error {
	var algName string
	var privBytes, pubBytes []byte
	switch keyType {
	case "ed25519":
		algName = agent.AlgEd25519
		var priv ed25519.PrivateKey
		if seedFile != "" {
			seed, err := withInputFile(seedFile, func(r io.Reader) ([]byte, error) {
				return readBytes(r, ed25519.SeedSize)
			})
			if err != nil {
				return fmt.Errorf("failed to read seed from file: %w", err)
			}
			priv = ed25519.NewKeyFromSeed(seed)
		} else {
			var err error
			_, priv, err = ed25519.GenerateKey(nil)
			if err != nil {
				return fmt.Errorf("failed to generate: %w", err)
			}
		}
		privBytes = priv.Seed()
		pubBytes = []byte(priv.Public().(ed25519.PublicKey))
	case "mldsa44":
		algName = agent.AlgMLDSA44
		var priv *mldsa.PrivateKey
		if seedFile != "" {
			seed, err := withInputFile(seedFile, func(r io.Reader) ([]byte, error) {
				return readBytes(r, mldsa.PrivateKeySize)
			})
			if err != nil {
				return fmt.Errorf("failed to read seed from file: %w", err)
			}
			priv, err = mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
			if err != nil {
				return fmt.Errorf("failed NewPrivateKey: %w", err)
			}
		} else {
			var err error
			priv, err = mldsa.GenerateKey(mldsa.MLDSA44())
			if err != nil {
				return fmt.Errorf("failed to generate: %w", err)
			}
		}
		privBytes = priv.Bytes()
		pubBytes = priv.PublicKey().Bytes()
	default:
		return fmt.Errorf("unsupported keytype: %s", keyType)
	}

	var passphrase string
	if passphraseOpt.Seen() {
		passphrase = passphraseOpt.Value().String()
	} else {
		pass, err := ui.ReadSecret("Enter new passphrase (empty for no encryption):")
		if err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
		if again, err := ui.ReadSecret("Confirm passphrase:"); err != nil {
			return fmt.Errorf("failed to read passphrase: %w", err)
		} else if !bytes.Equal(pass, again) {
			return fmt.Errorf("passphrases did not match")
		}
		passphrase = string(pass)
	}

	var f *os.File
	if outFile == "" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
	}

	if err := agent.WritePrivateKeyFile(f, agent.NewPassphraseEncryptor(passphrase), algName, pubBytes, privBytes); err != nil {
		return err
	}

	pubLine := formatPub(algName, pubBytes)
	fp := fingerprint(algName, pubBytes)
	if outFile == "" {
		fmt.Printf("%s\n", pubLine)
		log.Printf("SSH public key fingerprint: %s", fp)
	} else {
		pubOutFile := outFile + ".pub"
		if err := os.WriteFile(pubOutFile, []byte(pubLine+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Printf("%s\n", fp)
	}
	return nil
}

func withInputFile(filename string, f func(r io.Reader) ([]byte, error)) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return f(file)
}

func readBytes(r io.Reader, byteCount int) ([]byte, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if l := len(b); l != byteCount {
		return nil, fmt.Errorf("got %d bytes, expected %d", l, byteCount)
	}
	return b, err
}

// fingerprint creates an SSH-fingerprint from raw pubkey bytes. An
// SSH-fingerprint is the (unpadded) base64-encoded SHA256 over the
// pubkey encoded in the ssh-agent wire format. For ML-DSA-44 this
// follows: https://datatracker.ietf.org/doc/html/draft-sfluhrer-ssh-mldsa-08
func fingerprint(algName string, pub []byte) string {
	wirePubkey := agent.SerializeItem(algName, pub)
	sha256sum := sha256.Sum256(wirePubkey)
	hash := base64.RawStdEncoding.EncodeToString(sha256sum[:])
	return fmt.Sprintf("SHA256:%s", hash)
}

func formatPub(algName string, pub []byte) string {
	return fmt.Sprintf("%s %s", algName, base64.RawStdEncoding.EncodeToString(agent.SerializeItem(algName, pub)))
}
