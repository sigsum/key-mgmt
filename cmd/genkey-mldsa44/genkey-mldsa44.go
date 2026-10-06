package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/pborman/getopt/v2"
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

	set := getopt.New()
	set.FlagLong(&showHelp, "help", 'h', "Show this help")
	set.FlagLong(&outFile, "output", 'o', "Output generated private key to filename, its SSH public key to filename.pub, and the fingerprint to stdout", "filename").
		SetGroup(groupOLE)
	set.FlagLong(&passphrase, "passphrase", 'N', "Set passphrase for encryption, empty string for no encryption", "string")
	set.Flag(&keyType, 't', "Set type of key to generate, mldsa44 or ed25519", "keytype")
	set.FlagLong(&showFPFile, "show", 'l', "Show SSH public key fingerprint from private key in file", "filename").
		SetGroup(groupOLE)
	set.Flag(&showVkeyFile, 'e', "Show cosignature vkey (signature type 0x04 or 0x06) of public key from private key in file. Requires -n.", "filename").
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
	if (set.IsSet('t') || set.IsSet('N')) && (set.IsSet('l') || set.IsSet('e')) {
		fmt.Fprintf(os.Stderr, "Option -t and -N can only be used when generating a key\n")
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
		err = genkey(outFile, keyType, set.Lookup('N'))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func showFP(privFile string) error {
	signer, err := signerFromPrivFile(privFile)
	if err != nil {
		return err
	}
	var fp string
	switch priv := signer.(type) {
	case ed25519.PrivateKey:
		fp = fingerprint(agent.AlgEd25519, priv.Public().(ed25519.PublicKey))
	case *mldsa.PrivateKey:
		fp = fingerprint(agent.AlgMLDSA44, priv.PublicKey().Bytes())
	default:
		return fmt.Errorf("unsupported signer type from file %q: %T", privFile, priv)
	}
	fmt.Printf("%s\n", fp)
	return nil
}

func showVkey(privFile string, keyName string) error {
	signer, err := signerFromPrivFile(privFile)
	if err != nil {
		return err
	}
	var vkey string
	switch priv := signer.(type) {
	case ed25519.PrivateKey:
		pub := sigsumcrypto.PublicKey(priv.Public().(ed25519.PublicKey))
		nv := checkpoint.NewNoteVerifier(keyName, checkpoint.SigTypeCosignature, &pub)
		vkey = nv.String()
	case *mldsa.PrivateKey:
		var pub publicKeyMLDSA44
		copy(pub[:], priv.PublicKey().Bytes())
		nv := newNoteVerifierMLDSA44(keyName, sigTypeCosignatureMLDSA44, &pub)
		vkey = nv.String()
	default:
		return fmt.Errorf("unsupported signer type from file %q: %T", privFile, priv)
	}
	fmt.Printf("%s\n", vkey)
	return nil
}

func signerFromPrivFile(privFile string) (crypto.Signer, error) {
	data, err := os.ReadFile(privFile)
	if err != nil {
		return nil, err
	}
	signer, err := agent.ParsePrivateKeyFile(data, ui.NewTerminalGetPassphrase(privFile))
	if err != nil {
		return nil, fmt.Errorf("reading private key file %q failed: %w", privFile, err)
	}
	return signer, nil
}

func genkey(outFile string, keyType string, passphraseOpt getopt.Option) error {
	var algName string
	var privBytes, pubBytes []byte
	switch keyType {
	case "ed25519":
		algName = agent.AlgEd25519
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return fmt.Errorf("failed to generate: %w", err)
		}
		privBytes = priv.Seed()
		pubBytes = []byte(pub)
	case "mldsa44":
		algName = agent.AlgMLDSA44
		priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			return fmt.Errorf("failed to generate: %w", err)
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
