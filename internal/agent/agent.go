package agent

import (
	"bytes"
	"fmt"
	"io"
	"log"
)

const (
	SSH_AGENT_FAILURE             = 5
	SSH_AGENTC_REQUEST_IDENTITIES = 11
	SSH_AGENT_IDENTITIES_ANSWER   = 12
	SSH_AGENTC_SIGN_REQUEST       = 13
	SSH_AGENT_SIGN_RESPONSE       = 14
	// Arbitrary maximum size of received agent messages.
	maxSize = 10000
)

// Returns signature formatted as an SSH signature (without outer
// length field).
type SSHSign func([]byte) ([]byte, error)

type signRequest struct {
	pubKey []byte
	data   []byte
}

func readSignRequest(r io.Reader) (req signRequest, err error) {
	req.pubKey, err = readString(r, maxSize)
	if err != nil {
		return
	}
	req.data, err = readString(r, maxSize)
	if err != nil {
		return
	}
	// Flags, currently ignored.
	_, err = readUint32(r)
	return
}

// The map keys are SSH public key blobs (without outer length field).
func ServeAgent(r io.Reader, w io.Writer, keys map[string]SSHSign) error {
	for {
		data, err := readString(r, maxSize)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return fmt.Errorf("invalid empty agent message")
		}
		t, msg := data[0], data[1:]
		// The write methods on bytes.Buffer are documented to
		// always return a nil error. Therefore all related
		// error return values below are ignored.
		var rsp bytes.Buffer
		switch t {
		case SSH_AGENTC_REQUEST_IDENTITIES:
			if len(msg) > 0 {
				return fmt.Errorf("invalid message, %d left-over bytes in list request", len(msg))
			}

			rsp.WriteByte(SSH_AGENT_IDENTITIES_ANSWER)
			writeUint32(&rsp, uint32(len(keys)))
			for k, _ := range keys {
				writeString(&rsp, k)
				// Arbitrary comment
				writeString(&rsp, "oracle key")
			}
		case SSH_AGENTC_SIGN_REQUEST:
			req, err := parseBytes(msg, nil, readSignRequest)
			if err != nil {
				return err
			}
			signer, ok := keys[string(req.pubKey)]
			if !ok {
				rsp.WriteByte(SSH_AGENT_FAILURE)
				break
			}
			sig, err := signer(req.data)
			if err != nil {
				log.Printf("signing failed: %v", err)
				rsp.WriteByte(SSH_AGENT_FAILURE)
				break
			}
			rsp.WriteByte(SSH_AGENT_SIGN_RESPONSE)
			writeString(&rsp, sig)
		default:
			rsp.WriteByte(SSH_AGENT_FAILURE)
		}
		if err := writeString(w, rsp.Bytes()); err != nil {
			return err
		}
	}
}
