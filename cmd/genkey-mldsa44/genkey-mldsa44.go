package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
		usage = `
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

Use the --mix option to mix local system entropy together with the
bytes provided by the seed file (-S), into the final seed. This done
using HKDF with SHA256 over both entropy sources.

NOTE: The security of the private key relies entirely on the quality
and secrecy of the seed that you provide. Ensure it comes from an
unpredictable source of randomness.

The options -l and -e can read both the SSH private key (PEM), and SSH
public key formats. Reading as private key is attempted first. Since
this always contains the public key in plain, non-enrypted, format, no
passphrase will be needed. If the file is not PEM-encoded, it is read
as an SSH public key, with support for one single public key (one
line).
`
	)
	showHelp := false
	outFile := ""
	doShowFP := false
	doShowVkey := ""
	doReencrypt := false
	keyPassFile := ""
	keyType := "mldsa44"
	passphrase := ""
	seedFile := ""
	mixSeed := false

	set := set{getopt.New()}
	set.FlagLong(&showHelp, "help", 'h', "Show this help")
	set.FlagLong(&outFile, "output", 'o', "Output generated private key to filename, its SSH public key to filename.pub, and the fingerprint to stdout", "filename")
	set.FlagLong(&passphrase, "passphrase", 'N', "Set passphrase for encrypting the private key, empty string for no encryption", "string")
	set.Flag(&keyType, 't', "Set type of key to generate, mldsa44 or ed25519", "keytype")
	set.FlagLong(&seedFile, "seed", 'S', "Read the random seed bytes for the private key from file. \"-\" can be used for stdin. See also --mix", "filename")
	set.FlagLong(&mixSeed, "mix", 0, "Use HKDF/SHA256 to mix entropy from seed file (-S) together with local system entropy")
	set.FlagLong(&doShowFP, "show", 'l', "Show SSH fingerprint of a public key from an SSH public or private key file")
	set.Flag(&doShowVkey, 'e', "Show cosignature vkey (signature type 0x04 or 0x06) of a public key from an SSH public or private key file", "keyname")
	set.FlagLong(&doReencrypt, "reencrypt", 'r', "Re-encrypt a private key file, usable options: -o, -N, -p")
	set.FlagLong(&keyPassFile, "key-passphrase-file", 'p', "For providing old passphrase for -r, file with lines of: key-file:passphrase", "filename")
	set.SetParameters("[input-file]")
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

	if set.seenMultiple('o', 'l', 'e') {
		fmt.Fprintf(os.Stderr, "Only one of options -o, -l, and -e can be used at once\n")
		os.Exit(2)
	}
	if set.seenMultiple('r', 'l', 'e') {
		fmt.Fprintf(os.Stderr, "Only one of options -r, -l, and -e can be used at once\n")
		os.Exit(2)
	}

	inputFile := ""
	if set.seenAny('r', 'l', 'e') {
		switch set.NArgs() {
		case 0:
			inputFile = "-"
		case 1:
			inputFile = set.Args()[0]
		default:
			fmt.Fprintf(os.Stderr, "Too many positional args\n")
			os.Exit(2)
		}
		if set.seenAny('t', 'S') {
			fmt.Fprintf(os.Stderr, "Options -t and -S can only be used when generating a new key\n")
			os.Exit(2)
		}
	} else if set.NArgs() > 0 {
		fmt.Fprintf(os.Stderr, "Unexpected positional args: %q\n", set.Args())
		os.Exit(2)
	}

	if set.seen('N') && set.seenAny('l', 'e') {
		fmt.Fprintf(os.Stderr, "Option -N can only be used when generating a new key, or re-encrypting an existing\n")
		os.Exit(2)
	}
	if !set.seen('r') && set.seen('p') {
		fmt.Fprintf(os.Stderr, "Option -p can only be used with -r\n")
		os.Exit(2)
	}
	if !set.seen('S') && set.seen("mix") {
		fmt.Fprintf(os.Stderr, "Option --mix can only be used with -S\n")
		os.Exit(2)
	}

	if set.seen('l') {
		err = showFP(inputFile)
	} else if set.seen('e') {
		err = showVkey(inputFile, doShowVkey)
	} else if set.seen('r') {
		err = reencrypt(outFile, inputFile, keyPassFile, set.Lookup('N'))
	} else {
		if set.seen('S') && seedFile == "" {
			fmt.Fprintf(os.Stderr, "Option -S (--seed) has empty filename\n")
			os.Exit(2)
		}
		err = genkey(outFile, keyType, seedFile, mixSeed, set.Lookup('N'))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

type set struct {
	*getopt.Set
}

func (s set) seen(shortOrLong any) bool {
	return s.IsSet(shortOrLong)
}

func (s set) seenAny(shortOrLongs ...any) bool {
	return s.countSeen(shortOrLongs) > 0
}

func (s set) seenMultiple(shortOrLongs ...any) bool {
	return s.countSeen(shortOrLongs) > 1
}

func (s set) countSeen(shortOrLongs []any) int {
	count := 0
	for i := range shortOrLongs {
		if s.seen(shortOrLongs[i]) {
			count++
		}
	}
	return count
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
	data, err := withInputFile(fileName, io.ReadAll)
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

func genkey(outFile string, keyType string, seedFile string, mixSeed bool, passphraseOpt getopt.Option) error {
	var algName string
	var privBytes, pubBytes []byte
	switch keyType {
	case "ed25519":
		algName = agent.AlgEd25519
		var priv ed25519.PrivateKey
		if seedFile != "" {
			seed, err := readSeed(seedFile, mixSeed, ed25519.SeedSize)
			if err != nil {
				return err
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
			seed, err := readSeed(seedFile, mixSeed, mldsa.PrivateKeySize)
			if err != nil {
				return err
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

	if err := writePrivateKeyFile(outFile, algName, privBytes, pubBytes, passphraseOpt); err != nil {
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

// readSeed reads seed bytes of the required size from a file.
// Optionally mix those bytes with same amount of local system
// entropy, using HKDF with SHA256.
func readSeed(extSeedFile string, mixSeed bool, size int) ([]byte, error) {
	extSeed, err := withInputFile(extSeedFile, func(r io.Reader) ([]byte, error) {
		return readBytes(r, size)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read seed from file: %w", err)
	}

	if !mixSeed {
		return extSeed, nil
	}

	loc := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, loc); err != nil {
		return nil, err
	}

	seed, err := hkdf.Key(sha256.New, append(extSeed, loc...), nil, "key-mgmt/genkey/mixed", size)
	if err != nil {
		return nil, err
	}

	return seed, nil
}

func withInputFile(filename string, f func(r io.Reader) ([]byte, error)) ([]byte, error) {
	var file *os.File
	if filename == "-" {
		file = os.Stdin
	} else {
		var err error
		file, err = os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer file.Close()
	}
	return f(file)
}

func readBytes(r io.Reader, byteCount int) ([]byte, error) {
	buf := make([]byte, byteCount+1)
	n, err := io.ReadFull(r, buf)
	if n != byteCount || !errors.Is(err, io.ErrUnexpectedEOF) {
		msg := fmt.Sprintf("got %d bytes, expected %d", n, byteCount)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", msg, err)
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return buf[:byteCount], nil
}

func reencrypt(newKeyFile string, keyFile string, keyPassFile string, passphraseNewOpt getopt.Option) error {
	data, err := withInputFile(keyFile, io.ReadAll)
	if err != nil {
		return err
	}

	newGetPassphraseFunc := ui.NewTerminalGetPassphrase
	if keyPassFile != "" {
		r, err := os.Open(keyPassFile)
		if err != nil {
			return fmt.Errorf("failed to open %q: %w", keyPassFile, err)
		}
		newGetPassphraseFunc, err = ui.ParseKeyPassFile(r)
		_ = r.Close()
		if err != nil {
			return fmt.Errorf("%s:%w", keyPassFile, err)
		}
	}

	algName, privBytes, pubBytes, err := agent.ParseSeedFromPrivateKeyFile(data, newGetPassphraseFunc(keyFile))
	if err != nil {
		return fmt.Errorf("read private key from file %q failed: %w", keyFile, err)
	}

	return writePrivateKeyFile(newKeyFile, algName, privBytes, pubBytes, passphraseNewOpt)
}

func writePrivateKeyFile(outFile string, algName string, privBytes []byte, pubBytes []byte, passphraseOpt getopt.Option) error {
	var passphrase string
	if passphraseOpt.Seen() {
		passphrase = passphraseOpt.Value().String()
	} else {
		var err error
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
	if passphrase == "" {
		log.Printf("No passphrase set, private key file will NOT be encrypted")
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
