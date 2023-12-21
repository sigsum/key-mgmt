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
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/pborman/getopt/v2"

	"sigsum.org/yubihsm/internal/agent"
	"sigsum.org/yubihsm/internal/hsm"
)

const sshAgentEnv = "SSH_AUTH_SOCK"

// Since we need to call os.Exit to pass an exit code, we need a
// simple main function without any defer.
func main() {
	status, err := mainWithStatus()
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(status)
}

func mainWithStatus() (int, error) {
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

The first non-option argument, if any, is a command that the agent
should spawn. The remaining command line arguments are the arguments
to pass to the command. The environment variable SSH_AUTH_SOCK is set
to the name of the unix socket that the agent listens on. The agent
keeps running and accepting connections until the command process
exits, and its exit code is propagated.

If no command is provided, the agent prints the name of its socket to
stdout, and then accepts sockets indefinitely. The HUP signal makes
the agent cleanup and exit.

TODO: Add a way to take socket to use on stdin, initd/systemd style.
`
	// Default connector url
	connector := "localhost:12345"
	keyId := -1
	authFile := ""
	keyFile := ""
	socketName := ""
	pidFile := ""
	help := false

	set := getopt.New()
	set.SetParameters("[cmd ...]")
	set.SetUsage(func() { fmt.Print(usage) })
	set.FlagLong(&connector, "connector", 'c', "host:port")
	set.FlagLong(&keyId, "key-id", 'i', "yubihsm key id")
	set.FlagLong(&authFile, "auth-file", 'a', "file with yubihsm auth-id:passphrase")
	set.FlagLong(&keyFile, "key-file", 'k', "private key file")
	set.FlagLong(&socketName, "socket-name", 's', "name of unix socket")
	set.FlagLong(&pidFile, "pid-file", 0, "for for storing agent's pid")
	set.FlagLong(&help, "help", 'h', "Display help")

	err := set.Getopt(os.Args, nil)
	if err != nil {
		log.Printf("err: %v\n", err)
		set.PrintUsage(log.Writer())
		return 1, nil
	}

	if help {
		set.PrintUsage(os.Stdout)
		fmt.Print(usage)
		return 0, nil
	}

	if (keyId < 0 && len(keyFile) == 0) || (keyId >= 0 && len(keyFile) > 0) {
		return 0, fmt.Errorf("Exactly one of the --key-id and --key-file options must be provided.")
	}
	if keyId >= 0 && len(authFile) == 0 {
		return 0, fmt.Errorf("The --auth-file option is required with --key-id.")
	}

	if len(socketName) == 0 {
		r := make([]byte, 8)
		if _, err := rand.Read(r); err != nil {
			return 0, fmt.Errorf("rand.Read failed: %v", err)
		}
		socketName = filepath.Join(os.TempDir(), fmt.Sprintf("agent-sock-%x", r))
	} else if err := os.Remove(socketName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("removing file %q failed: %v", socketName, err)
	}

	var signer crypto.Signer
	if len(keyFile) > 0 {
		var err error
		signer, err = agent.ReadPrivateKeyFile(keyFile)
		if err != nil {
			return 0, fmt.Errorf("Reading private key file %q failed: %v", keyFile, err)
		}
	} else {
		if keyId >= 0x10000 {
			return 0, fmt.Errorf("Key id %d out of range.", keyId)
		}
		buf, err := os.ReadFile(authFile)
		if err != nil {
			return 0, fmt.Errorf("Reading auth file %q failed: %v", authFile, err)
		}
		buf = bytes.TrimSpace(buf)
		colon := bytes.Index(buf, []byte{':'})
		if colon < 0 {
			return 0, fmt.Errorf("Invalid auth file %q, missing ':'", authFile)
		}
		authId, err := strconv.ParseUint(string(buf[:colon]), 10, 16)
		if err != nil {
			return 0, fmt.Errorf("Invalid auth id in file %q: %v", authFile, err)
		}
		authPassword := string(buf[colon+1:])
		hsmSigner, err := hsm.NewYubiHSMSigner(connector, uint16(authId), authPassword, uint16(keyId))
		if err != nil {
			return 0, fmt.Errorf("Connecting to hsm failed: %v", err)
		}
		defer hsmSigner.Close()
		signer = hsmSigner
	}

	sshKey, sshSign, err := agent.SSHFromEd25519(signer)
	if err != nil {
		return 0, fmt.Errorf("Internal error: %v", err)
	}
	keys := map[string]agent.SSHSign{sshKey: sshSign}

	socket, err := openSocket(socketName)
	if err != nil {
		return 0, fmt.Errorf("Failed to listen on UNIX socket %q: %v", socketName, err)
	}
	defer socket.Close()
	defer os.Remove(socketName)

	if len(pidFile) > 0 {
		pid := fmt.Sprintf("%d\n", os.Getpid())
		if err := os.WriteFile(pidFile, []byte(pid), 0660); err != nil {
			return 0, fmt.Errorf("failed creating pid file: %v", err)
		}
		defer os.Remove(pidFile)
	}

	if len(set.Args()) > 0 {
		go runAgent(socket, keys)

		err = runCommand(socketName, set.Args())
		if exit, ok := err.(*exec.ExitError); ok && exit.Exited() {
			return exit.ExitCode(), nil
		}
		return 0, err
	}
	fmt.Printf("%s\n", socketName)
	// We're not going to write anything more to stdout, and
	// closing signals EOF to anyone reading stdout. EOF also
	// means we're listening on the socket.
	os.Stdout.Close()

	// On SIGHUP signal, close the socket, forcing runAgent to
	// return, and hence we cleanup and exit.
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		<-ch
		socket.Close()
	}()
	runAgent(socket, keys)
	return 0, nil
}

func openSocket(socketName string) (net.Listener, error) {
	oldMask := syscall.Umask(0077)
	defer syscall.Umask(oldMask)

	return net.Listen("unix", socketName)
}

// Accepts connections, and spawns a serving goroutine for each. Will
// return when the listening socket is closed under its feet.
func runAgent(socket net.Listener, keys map[string]agent.SSHSign) {
	for {
		c, err := socket.Accept()
		if err != nil {
			// Should ideally log or return the error if
			// it's not poll.errNetClosing, but there's no
			// good way to check for that.
			return
		}
		go agent.ServeAgent(c, c, keys)
	}
}

// Runs command, with appropriate environment variable, and waits for completion.
func runCommand(socketName string, cmdLine []string) error {
	cmd := exec.Command(cmdLine[0], cmdLine[1:]...)
	cmd.Env = append(cmd.Environ(), fmt.Sprintf("SSH_AUTH_SOCK=%s", socketName))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
