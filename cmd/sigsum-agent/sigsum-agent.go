package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
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
	"time"

	"github.com/pborman/getopt/v2"

	"sigsum.org/key-mgmt/internal/agent"
	"sigsum.org/key-mgmt/internal/hsm"
)

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
Start an ssh-agent that acts as a signing oracle. Ed25519 and
ML-DSA-44 private keys are supported.

One or more of the following formats can be used: file with Ed25519
private key in unencrypted OpenSSH PEM format, file with ML-DSA-44 raw
private key in a hex format, Ed25519 private key managed by a yubihsm2
device.

To use a private key file, pass the -k option with the name of the
private key file; the -k option can be used several times.

To use a yubihsm key, you need to specify both an authorization file
(-a option) and key id (-i option). The contents of the authorization
file is a single line with the the authorization id (decimal number),
and the corresponding passphrase, separated by a single ':' character.

When using a yubihsm key, the agent needs a separate yubihsm-connector
process to be running. By default, the connector is expected to
listen on TCP port 12345 on localhost, but this can be changed with
the -c option.

The agent listens for connections on a unix socket. By default, a
random name is selected under /tmp (or ${TMPDIR}, if set), but it can
also be set explicitly using the -s option (any existing file or
socket with that name is deleted). The permissions are set so that the
socket can be accessed only by processes of the user that is running
the agent.

Alternatively, the parent process can provide the socket. If fd 0
(stdin) is a socket in the listen state, the agent will accept
connections on this socket. This convention is supported by systemd
(referred to as "socket activation") as well as by inetd (where it is
called a stream "wait" service). In this mode, it is not possible to
provide a command to execute, or specify a socket name with -s.

The first non-option argument, if any, is a command that the agent
should spawn. The remaining command line arguments are the arguments
to pass to the command. The environment variable SSH_AUTH_SOCK is set
to the name of the unix socket that the agent listens on. The agent
keeps running and accepting connections until the command process
exits, and its exit code is propagated.

If no command is provided, the agent accepts connections indefinitely.
The HUP signal makes the agent cleanup and exit. If the agent uses a
random temporary socket name, the name is written to stdout.
Regardless, the agent closes stdout once the socket has been bound and
it's ready to accept connections.

The --pid-file option can be used to get the process id of the command
the agent started, or, if no command was provided, of the agent
itself. This option takes a filename as argument. The pid is written
to this file, as a decimal number, and the file is automatically
deleted when the agent exits. The special name "-" means stdout, with
the following behavior: If "-" is used together with a command, stdout
is closed after the pid file is written, and the command's stdout is
redirected to /dev/null. If both pid and socket name are written to
stdout, they are written as one line each, pid first.
`
	// Default connector url
	connector := "localhost:12345"
	keyId := -1
	authFile := ""
	keyFiles := []string{}
	socketName := ""
	pidFile := ""
	retry := false
	help := false

	set := getopt.New()
	set.SetParameters("[cmd ...]")
	set.SetUsage(func() { fmt.Print(usage) })
	set.FlagLong(&connector, "connector", 'c', "host:port")
	set.FlagLong(&keyId, "key-id", 'i', "yubihsm key id")
	set.FlagLong(&authFile, "auth-file", 'a', "file with yubihsm auth-id:passphrase")
	set.FlagLong(&keyFiles, "key-file", 'k', "Private key file, either Ed25519 (in OpenSSH PEM Format), or ML-DSA-44 (raw bytes in hex format). Can be used several times.")
	set.FlagLong(&socketName, "socket-name", 's', "name of unix socket")
	set.FlagLong(&pidFile, "pid-file", 0, "for writing pid of agent or command, '-' means stdout")
	set.FlagLong(&retry, "retry", 0, "retry a few times if connecting to the HSM fails at startup")
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

	if keyId < 0 && len(keyFiles) == 0 {
		return 0, fmt.Errorf("must provide at least one of the --key-id and --key-file options")
	}

	if keyId >= 0 && len(authFile) == 0 {
		return 0, fmt.Errorf("The --auth-file option is required with --key-id.")
	}

	printSocket := false

	// Did we get a listening socket from inetd/systemd ?
	socket, err := inetdSocket(os.Stdin)
	if err != nil {
		return 0, err
	}
	if socket != nil {
		defer socket.Close()
		if len(socketName) > 0 {
			return 0, fmt.Errorf("started from inetd / systemd, using --socket-name is invalid")
		}
		if len(set.Args()) > 0 {
			return 0, fmt.Errorf("started from inetd / systemd, specifying command to run is invalid")
		}
		// The net.FileListener function dups the socket, we
		// want only a single fd so that socket.Close() really
		// closes the underlying socket.
		os.Stdin.Close()

	} else {
		if len(socketName) == 0 {
			r := make([]byte, 8)
			if _, err := rand.Read(r); err != nil {
				return 0, fmt.Errorf("rand.Read failed: %v", err)
			}
			socketName = filepath.Join(os.TempDir(), fmt.Sprintf("agent-sock-%x", r))
			printSocket = true
		} else if err := os.Remove(socketName); err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("removing file %q failed: %v", socketName, err)
		}
		socket, err = openSocket(socketName)
		if err != nil {
			return 0, fmt.Errorf("Failed to listen on UNIX socket %q: %v", socketName, err)
		}
		defer socket.Close()
		defer os.Remove(socketName)
	}

	keys := make(map[string]agent.SSHSign)
	if len(keyFiles) > 0 {
		for _, keyFile := range keyFiles {
			sshKey, sshSign, err := sshFromFile(keyFile)
			if err != nil {
				return 0, err
			}
			keys[sshKey] = sshSign
		}
	}
	if keyId > 0 {
		sshKey, sshSign, err := sshFromEd25519HSM(keyId, connector, authFile, retry)
		if err != nil {
			return 0, err
		}
		keys[sshKey] = sshSign
	}

	if len(set.Args()) > 0 {
		go runAgent(socket, keys)

		cmd := createCommand(socketName, pidFile != "-", set.Args())
		if err := cmd.Start(); err != nil {
			return 0, err
		}
		if len(pidFile) > 0 {
			useStdout, err := writePidFile(pidFile, cmd.Process.Pid)
			if err != nil {
				return 0, err
			}
			if useStdout {
				// Close, to signal EOF to the process reading the pid.
				os.Stdout.Close()
			} else {
				defer os.Remove(pidFile)
			}
		}

		err = cmd.Wait()
		if exit, ok := err.(*exec.ExitError); ok && exit.Exited() {
			return exit.ExitCode(), nil
		}
		return 0, err
	}

	if len(pidFile) > 0 {
		useStdout, err := writePidFile(pidFile, os.Getpid())
		if err != nil {
			return 0, err
		}
		if !useStdout {
			defer os.Remove(pidFile)
		}
	}

	if printSocket {
		fmt.Printf("%s\n", socketName)
	}

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

// If the file isn't a listening socket, returns nil listener, no error.
func inetdSocket(f *os.File) (net.Listener, error) {
	acceptConn, err := syscall.GetsockoptInt(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	if err != nil || acceptConn == 0 {
		return nil, nil
	}
	return net.FileListener(f)
}

func openSocket(socketName string) (net.Listener, error) {
	oldMask := syscall.Umask(0077)
	defer syscall.Umask(oldMask)

	return net.Listen("unix", socketName)
}

func sshFromFile(keyFile string) (string, agent.SSHSign, error) {
	signer, err := agent.ReadPrivateKeyFile(keyFile)
	if err != nil {
		return "", nil, fmt.Errorf("read private key in PEM/hex format from file %q failed: %w", keyFile, err)
	}
	switch t := signer.(type) {
	case ed25519.PrivateKey:
		return agent.SSHFromEd25519(signer)
	case *mldsa.PrivateKey:
		return agent.SSHFromMLDSA44(signer)
	default:
		return "", nil, fmt.Errorf("unsupported signer type from file %q: %T", keyFile, t)
	}
}

func sshFromEd25519HSM(keyId int, authFile string, connector string, retry bool) (string, agent.SSHSign, error) {
	if keyId < 0 || keyId >= 0x10000 {
		return "", nil, fmt.Errorf("Key id %d out of range.", keyId)
	}
	buf, err := os.ReadFile(authFile)
	if err != nil {
		return "", nil, fmt.Errorf("Reading auth file %q failed: %v", authFile, err)
	}
	buf = bytes.TrimSpace(buf)
	colon := bytes.Index(buf, []byte{':'})
	if colon < 0 {
		return "", nil, fmt.Errorf("Invalid auth file %q, missing ':'", authFile)
	}
	authId, err := strconv.ParseUint(string(buf[:colon]), 10, 16)
	if err != nil {
		return "", nil, fmt.Errorf("Invalid auth id in file %q: %v", authFile, err)
	}
	authPassword := string(buf[colon+1:])
	hsmSigner, err := openHSM(connector, uint16(authId), authPassword, uint16(keyId), retry)
	if err != nil {
		return "", nil, fmt.Errorf("Connecting to hsm failed: %v", err)
	}
	defer hsmSigner.Close()
	sshKey, sshSign, err := agent.SSHFromEd25519(hsmSigner)
	if err != nil {
		return "", nil, fmt.Errorf("Internal error: %v", err)
	}
	return sshKey, sshSign, nil
}

// We need the connector to be up and running, to initialize and
// retrieve the public key. Optionally retry a few times, in case the
// connector is just being started.
func openHSM(connector string, authId uint16, authPassword string, keyId uint16, retry bool) (*hsm.YubiHSMSigner, error) {
	hsmSigner, err := hsm.NewYubiHSMSigner(connector, authId, authPassword, keyId)
	if err == nil {
		return hsmSigner, nil
	}
	if !retry {
		return nil, err
	}
	for _, delay := range []int{1, 2, 4, 8} {
		log.Printf("Connecting to HSM failed: %v, retrying in %d seconds", err, delay)
		time.Sleep(time.Duration(delay) * time.Second)
		hsmSigner, err = hsm.NewYubiHSMSigner(connector, authId, authPassword, keyId)
		if err == nil {
			log.Printf("Connected to HSM")
			return hsmSigner, nil
		}
	}
	return nil, fmt.Errorf("Connecting to HSM failed: %v", err)
}

func serveAndClose(c net.Conn, keys map[string]agent.SSHSign) {
	defer c.Close()
	agent.ServeAgent(c, c, keys)
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
		go serveAndClose(c, keys)
	}
}

// Sets up the command to run, with appropriate environment variable and redirects.
func createCommand(socketName string, useStdout bool, cmdLine []string) *exec.Cmd {
	cmd := exec.Command(cmdLine[0], cmdLine[1:]...)
	cmd.Env = append(cmd.Environ(), fmt.Sprintf("SSH_AUTH_SOCK=%s", socketName))
	cmd.Stdin = os.Stdin
	if useStdout {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = os.Stderr

	return cmd
}

func writePidFile(file string, pid int) (bool, error) {
	var err error
	if file == "-" {
		_, err = fmt.Printf("%d\n", pid)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	if err := os.WriteFile(file, []byte(fmt.Sprintf("%d\n", pid)), 0660); err != nil {
		return false, fmt.Errorf("failed creating pid file: %v", err)
	}
	return false, nil
}
