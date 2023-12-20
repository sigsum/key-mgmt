package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/pborman/getopt/v2"

	"sigsum.org/yubihsm/internal/agent"
	"sigsum.org/yubihsm/internal/hsm"
)

func main() {
	const usage = `
Start an ssh-agent that acts as an ed25519 signing oracle.

It can use either an unencrypted private key, in openssh format, or a
private key managed by a yubihsm2 device. To use an unencrypted
private key, pass the -k option with the name of the private key file.
To use a yubihsm key, you need to specify both an authorization file
(-a option) and key id (-i option). The contents of the authorization
file is a single line with the the authorization id (decimal number),
and the corresponding passphrase, separated by a single ':' character.

When using a yubihsm key, the agent needs a separate yubihsm-connector
process to be run running. By default, the connector is expected to
listen on TCP port 12345 on localhost, but this can be changed with
the -c option.

The agent listens for connections on a unix socket. By default, a
random name is selected under /tmp, but it can also be set explicitly
using the -s option (it is an error if the name is already used in the
file system).

The next command line argument is the command that the agent should
spawn. The remaining command line arguments are the arguments to pass
to the command. The environment variable SSH_AUTH_SOCK is set to the
name of the unix socket that the agent listens on. The agent keeps
running and accepting connections until the command process exits.

TODO: Add a mode to run without a command. Add a way to take socket to
use on stdin, initd/systemd style.
`
	// Default connector url
	connector := "localhost:12345"
	keyId := -1
	authFile := ""
	keyFile := ""
	socketFile := ""
	help := false

	set := getopt.New()
	set.SetParameters("cmd ...")
	set.SetUsage(func() { fmt.Print(usage) })
	set.FlagLong(&connector, "connector", 'c', "host:port")
	set.FlagLong(&keyId, "key-id", 'i', "yubihsm key id")
	set.FlagLong(&authFile, "auth-file", 'a', "file with yubihsm auth-id:passphrase")
	set.FlagLong(&keyFile, "key-file", 'k', "private key file")
	set.FlagLong(&socketFile, "socket-file", 's', "name of unix socket")
	set.FlagLong(&help, "help", 'h', "Display help")

	err := set.Getopt(os.Args, nil)

	// Check help first; if seen, ignore errors about missing mandatory arguments.
	if help || set.NArgs() < 1 {
		set.PrintUsage(os.Stdout)
		fmt.Print(usage)
		os.Exit(0)
	}

	if err != nil {
		log.Printf("err: %v\n", err)
		set.PrintUsage(log.Writer())
		os.Exit(1)
	}

	if (keyId < 0 && len(keyFile) == 0) || (keyId >= 0 && len(keyFile) > 0) {
		log.Fatal("Exactly one of the --key-id and --key-file options must be provided.")
	}
	if keyId >= 0 && len(authFile) == 0 {
		log.Fatal("The --auth-file option is required with --key-id.")
	}

	if len(socketFile) == 0 {
		r := make([]byte, 8)
		if _, err := rand.Read(r); err != nil {
			log.Fatalf("rand.Read failed: %v", err)
		}
		socketFile = filepath.Join(os.TempDir(), fmt.Sprintf("agent-sock-%x", r))
	} else if err := os.Remove(socketFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("removing file %q failed: %v", socketFile, err)
	}

	var signer crypto.Signer
	if len(keyFile) > 0 {
		var err error
		signer, err = agent.ReadPrivateKeyFile(keyFile)
		if err != nil {
			log.Fatalf("Reading private key file %q failed: %v", keyFile, err)
		}
	} else {
		if keyId >= 0x10000 {
			log.Fatalf("Key id %d out of range.", keyId)
		}
		buf, err := os.ReadFile(authFile)
		if err != nil {
			log.Fatalf("Reading auth file %q failed: %v", authFile, err)
		}
		buf = bytes.TrimSpace(buf)
		colon := bytes.Index(buf, []byte{':'})
		if colon < 0 {
			log.Fatalf("Invalid auth file %q, missing ':'", authFile)
		}
		authId, err := strconv.ParseUint(string(buf[:colon]), 10, 16)
		if err != nil {
			log.Fatalf("Invalid auth id in file %q: %v", authFile, err)
		}
		authPassword := string(buf[colon+1:])
		signer, err = hsm.NewYubiHSMSigner(connector, uint16(authId), authPassword, uint16(keyId))
		if err != nil {
			log.Fatalf("Connecting to hsm failed: %v", err)
		}
	}

	status, err := runAgent(socketFile, signer, set.Args())
	if err != nil {
		log.Fatalf("Terminating: %v", err)
	}
	os.Exit(status)
}

func runAgent(socketFile string, signer crypto.Signer, cmdLine []string) (int, error) {
	key, sign, err := agent.SSHFromEd25519(signer)
	if err != nil {
		return 0, fmt.Errorf("Internal error: %v", err)
	}
	keys := map[string]agent.SSHSign{key: sign}

	oldMask := syscall.Umask(0077)
	l, err := net.Listen("unix", socketFile)
	if err != nil {
		return 0, fmt.Errorf("Failed to listen on UNIX socket %q: %v", socketFile, err)
	}
	defer l.Close()
	defer os.Remove(socketFile)
	syscall.Umask(oldMask)

	cmd := exec.Command(cmdLine[0], cmdLine[1:]...)
	cmd.Env = append(cmd.Environ(), fmt.Sprintf("SSH_AUTH_SOCK=%s", socketFile))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("Failed to start process: %v", err)
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				// Should ideally log the error if
				// it's not poll.errNetClosing, but
				// there's no good way to check for
				// that.
				return
			}
			go agent.ServeAgent(c, c, keys)
		}
	}()

	// Exit after the command has completed, propagate exit code.
	if err := cmd.Wait(); err != nil {
		return 0, fmt.Errorf("Wait failed: %v", err)
	}
	if cmd.ProcessState.Exited() {
		return cmd.ProcessState.ExitCode(), nil
	}

	return 0, fmt.Errorf("Unexpected process exit: %v", cmd.ProcessState)
}
