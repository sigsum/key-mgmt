// Minimal program to start a process in an inetd-like environment
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/pborman/getopt/v2"
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
	var socketName string
	set := getopt.New()
	set.SetParameters("[cmd ...]")
	set.FlagLong(&socketName, "socket-name", 's', "name of unix socket").Mandatory()

	if err := set.Getopt(os.Args, nil); err != nil {
		return 0, err
	}
	if len(set.Args()) == 0 {
		return 0, fmt.Errorf("No command given")
	}
	socket, err := openSocket(socketName)
	if err != nil {
		return 0, err
	}

	f, err := socket.File()
	if err != nil {
		return 0, err
	}
	socket.SetUnlinkOnClose(false)
	defer os.Remove(socketName)

	cmd := exec.Command(set.Args()[0], set.Args()[1:]...)
	cmd.Stdin = f
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	socket.Close()
	f.Close()
	err = cmd.Wait()

	if exit, ok := err.(*exec.ExitError); ok && exit.Exited() {
		return exit.ExitCode(), nil
	}
	return 0, err
}

func openSocket(socketName string) (*net.UnixListener, error) {
	oldMask := syscall.Umask(0077)
	defer syscall.Umask(oldMask)

	listener, err := net.Listen("unix", socketName)
	if err != nil {
		return nil, err
	}
	return listener.(*net.UnixListener), nil
}
