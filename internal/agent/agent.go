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
		var rsp bytes.Buffer
		switch t {
		case SSH_AGENTC_REQUEST_IDENTITIES:
			if len(msg) > 0 {
				return fmt.Errorf("invalid message, %d left-over bytes in list request", len(msg))
			}

			if err := rsp.WriteByte(SSH_AGENT_IDENTITIES_ANSWER); err != nil {
				return err
			}
			if err := writeUint32(&rsp, uint32(len(keys))); err != nil {
				return err
			}
			for k, _ := range keys {
				if err := writeString(&rsp, k); err != nil {
					return err
				}
				// Arbitrary comment
				if err := writeString(&rsp, "oracle key"); err != nil {
					return err
				}
			}
		case SSH_AGENTC_SIGN_REQUEST:
			req, err := parseBytes(msg, nil, readSignRequest)
			if err != nil {
				return err
			}
			signer, ok := keys[string(req.pubKey)]
			if !ok {
				if err := rsp.WriteByte(SSH_AGENT_FAILURE); err != nil {
					return err
				}
				break
			}
			sig, err := signer(req.data)
			if err != nil {
				log.Printf("signing failed: %v", err)
				if err := rsp.WriteByte(SSH_AGENT_FAILURE); err != nil {
					return err
				}
				break
			}
			if err := rsp.WriteByte(SSH_AGENT_SIGN_RESPONSE); err != nil {
				return err
			}
			if err := writeString(&rsp, sig); err != nil {
				return err
			}
		default:
			if err := rsp.WriteByte(SSH_AGENT_FAILURE); err != nil {
				return err
			}
		}
		if err := writeString(w, rsp.Bytes()); err != nil {
			return err
		}
	}
}
