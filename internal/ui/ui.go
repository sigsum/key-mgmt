package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
	"sigsum.org/key-mgmt/internal/agent"
)

func NewTerminalGetPassphrase(fileName string) agent.GetPassphraseFunc {
	return func() (string, error) {
		pass, err := ReadSecret(fmt.Sprintf("Enter passphrase to decrypt key file %q:", fileName))
		if err != nil {
			return "", fmt.Errorf("failed to read passphrase: %w", err)
		}
		return string(pass), nil
	}
}

// ReadSecret prompts the user to enter a passphrase without echoing
// the characters to the terminal. It requires an attached terminal.
func ReadSecret(prompt string) ([]byte, error) {
	var inFd int
	var out *os.File
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		inFd = int(tty.Fd())
		out = tty
	} else if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		inFd = fd
		out = os.Stderr
	} else {
		return nil, fmt.Errorf("no terminal for reading passphrase")
	}
	if _, err := fmt.Fprintf(out, "%s ", prompt); err != nil {
		return nil, fmt.Errorf("failed print prompt: %w", err)
	}
	pass, err := term.ReadPassword(inFd)
	_, _ = fmt.Fprintf(out, "\n")
	if err != nil {
		return nil, fmt.Errorf("failed read passphrase: %w", err)
	}
	return pass, nil
}

// ParseKeyPassFile parses a passphrase-file containing lines of
// colon-separated key-file and passphrase. It returns a function that
// takes a key-file and returns an agent.GetPassphraseFunc, which in
// turn returns the passphrase, if provided by the passphrase-file.
func ParseKeyPassFile(r io.Reader) (func(string) agent.GetPassphraseFunc, error) {
	passphrases, err := parseKeyPassFile(r)
	if err != nil {
		return nil, err
	}
	if len(passphrases) == 0 {
		return nil, fmt.Errorf("contains no passphrases")
	}

	return func(keyFile string) agent.GetPassphraseFunc {
		return func() (string, error) {
			pass, ok := passphrases[keyFile]
			if !ok {
				return "", fmt.Errorf("key-passphrase-file has no passphrase for key file %q", keyFile)
			}
			return pass, nil
		}
	}, nil
}

func parseKeyPassFile(r io.Reader) (map[string]string, error) {
	passphrases := make(map[string]string)
	lineno := 0
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lineno++
		line := scanner.Text()
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%d: not in format 'key-file:passphrase'", lineno)
		}
		keyFile, pass := parts[0], parts[1]
		if len(keyFile) == 0 || len(pass) == 0 {
			return nil, fmt.Errorf("%d: key-file or passphrase is empty", lineno)
		}
		if _, ok := passphrases[keyFile]; ok {
			return nil, fmt.Errorf("%d: duplicate key-file %q", lineno, keyFile)
		}
		passphrases[keyFile] = pass
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return passphrases, nil
}
