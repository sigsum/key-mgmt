package ui

import (
	"fmt"
	"os"

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
