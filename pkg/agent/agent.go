// Package agent implements a subset of the ssh-agent protocol, see
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent.
package agent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"sigsum.org/key-mgmt/pkg/ssh"
)

const (
	SSH_AGENT_FAILURE             = 5
	SSH_AGENTC_REQUEST_IDENTITIES = 11
	SSH_AGENT_IDENTITIES_ANSWER   = 12
	SSH_AGENTC_SIGN_REQUEST       = 13
	SSH_AGENT_SIGN_RESPONSE       = 14
	// This implementation's arbitrary maximum size for certain
	// message fields.
	// TODO: Review use of agentMaxSize and use more specific limits.
	agentMaxSize = 10000
	sshAgentEnv  = "SSH_AUTH_SOCK"
)

// Reader for the message body. Reads from the underlying reader, but
// only up to the end of message, when it returns EOF.
type bodyReader struct {
	left uint32
	r    io.Reader
}

func (b *bodyReader) Read(buf []byte) (int, error) {
	if b.left == 0 {
		return 0, io.EOF
	}
	if len(buf) == 0 {
		return 0, nil
	}
	if int64(len(buf)) > int64(b.left) {
		buf = buf[:b.left]
	}
	n, err := b.r.Read(buf)
	b.left -= uint32(n)
	return n, err
}

func (b *bodyReader) Len() uint32 {
	return b.left
}

func readMsg(r io.Reader) (byte, *bodyReader, error) {
	size, err := ssh.ReadUint32(r)
	if err != nil {
		return 0, nil, err
	}
	if size == 0 {
		return 0, nil, fmt.Errorf("invalid empty agent message")
	}
	body := bodyReader{left: size, r: r}
	buf := make([]byte, 1)
	if _, err := body.Read(buf); err != nil {
		return 0, nil, err
	}
	return buf[0], &body, nil
}

// Inherits write methods from bytes.Buffer, which are documented to
// always return a nil error. Therefore all related error return
// values can be ignored.
type msgBuf struct {
	bytes.Buffer
}

func newMsgBuf(msgType byte) *msgBuf {
	var m msgBuf
	// Allocate space for length field, and writes the msgType.
	m.Write([]byte{0, 0, 0, 0, msgType})
	return &m
}

func writeMsg(w io.Writer, m *msgBuf) error {
	buf := m.Bytes()
	size := len(buf) - 4
	if size < 0 || size > math.MaxInt32 {
		return fmt.Errorf("invalid agent message size %d", size)
	}
	// Write length field in place.
	binary.BigEndian.PutUint32(buf[:4], uint32(size))
	_, err := w.Write(buf)
	return err
}
