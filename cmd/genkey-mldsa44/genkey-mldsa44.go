package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/pborman/getopt/v2"
	"golang.org/x/crypto/ssh"
	"sigsum.org/key-mgmt/internal/agent"
)

var showHelp bool
var outFile, showFile string

func main() {
	const usage = `
Generate ML-DSA-44 private key

The generated ML-DSA-44 private key (32 bytes) is by default printed
to stdout in hex format.
`
	set := getopt.New()
	set.FlagLong(&showHelp, "help", 'h', "Show this help")
	set.FlagLong(&outFile, "output", 'o', "Output generated private key to file, and its SSH public key fingerprint to stdout", "filename")
	set.FlagLong(&showFile, "show", 'l', "Show SSH public key fingerprint from private key in file", "filename")
	set.SetParameters("")
	err := set.Getopt(os.Args, nil)
	if showHelp {
		fmt.Print(usage[1:] + "\n")
		set.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if outFile != "" && showFile != "" {
		err = fmt.Errorf("only one of the -o and -l options can be used at once")
	}
	if err == nil && set.NArgs() > 0 {
		err = fmt.Errorf("unexpected positional args")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		set.PrintUsage(os.Stderr)
		os.Exit(2)
	}

	if showFile != "" {
		err = showkey(showFile)
	} else {
		err = genkey(outFile)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func showkey(privFile string) error {
	privHex, err := os.ReadFile(privFile)
	if err != nil {
		return err
	}

	priv, err := agent.NewMLDSA44PrivateKeyFromHex(string(bytes.TrimSpace(privHex)))
	if err != nil {
		return fmt.Errorf("failed to parse: %w", err)
	}

	fmt.Printf("%s\n", fingerprint(priv.PublicKey().Bytes()))
	return nil
}

func genkey(outFile string) error {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return fmt.Errorf("failed to generate: %w", err)
	}

	var f *os.File
	if outFile == "" {
		f = os.Stdout
		log.Printf("Printing private key to stdout")
	} else {
		f, err = os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		defer f.Close()
		log.Printf("Writing private key to non-encrypted file: %s", outFile)
	}

	if _, err = fmt.Fprintf(f, "%s\n", hex.EncodeToString(priv.Bytes())); err != nil {
		return err
	}

	fp := fingerprint(priv.PublicKey().Bytes())
	if outFile == "" {
		log.Printf("SSH public key fingerprint: %s", fp)
	} else {
		log.Printf("Printing SSH public key fingerprint to stdout")
		fmt.Printf("%s\n", fp)
	}
	return nil
}

// fingerprint creates an SSH-fingerprint from raw pubkey bytes. An
// SSH-fingerprint is the (unpadded) base64-encoded SHA256 over the
// pubkey encoded in the ssh-agent wire format. This is following:
// https://datatracker.ietf.org/doc/html/draft-sfluhrer-ssh-mldsa-08
func fingerprint(b []byte) string {
	wirePubkey := ssh.Marshal(struct {
		algo string
		pub  []byte
	}{
		algo: agent.AlgoMLDSA44,
		pub:  b,
	})
	sha256sum := sha256.Sum256(wirePubkey)
	hash := base64.RawStdEncoding.EncodeToString(sha256sum[:])
	return fmt.Sprintf("SHA256:%s", hash)
}
