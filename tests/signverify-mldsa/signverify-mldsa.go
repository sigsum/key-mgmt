package main

import (
	"bytes"
	"crypto/mldsa"
	"encoding/binary"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	wantFP := os.Args[1]
	msg := []byte(os.Args[2])

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Panicf("failed Dial: %s", err)
	}
	defer conn.Close()

	sshAgent := agent.NewClient(conn)

	keys, err := sshAgent.List()
	if err != nil {
		log.Panicf("failed List: %s", err)
	}

	var foundKey *agent.Key
	for _, key := range keys {
		fp := ssh.FingerprintSHA256(key)
		if fp != wantFP {
			continue
		}
		foundKey = key
		break
	}
	if foundKey == nil {
		log.Panicf("agent did not have %s", wantFP)
	}

	sig, err := sshAgent.Sign(foundKey, msg)
	if err != nil {
		log.Panicf("failed Sign: %s", err)
	}

	// The pubkey Blob is in the ssh-agent wire format
	prefix := bytes.Buffer{}
	const (
		algoname          = "ssh-mldsa-44"
		mldsa44pubKeySize = 1312
	)
	binary.Write(&prefix, binary.BigEndian, uint32(len(algoname)))
	prefix.WriteString(algoname)
	binary.Write(&prefix, binary.BigEndian, uint32(mldsa44pubKeySize))
	pubBytes := bytes.TrimPrefix(foundKey.Blob, prefix.Bytes())

	// This works if the expected bytes were trimmed above
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pubBytes)
	if err != nil {
		log.Panicf("failed NewPublicKey: %s", err)
	}

	if err := mldsa.Verify(pub, msg, sig.Blob, nil); err != nil {
		log.Panicf("failed Verify: %s", err)
	}
}
