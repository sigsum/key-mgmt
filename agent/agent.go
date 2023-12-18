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
	maxSize = 1000
)

// Returns signature formatted as an SSH signature (without outer
// length field).
type SshSign func([]byte) ([]byte, error)

// The map keys are SSH public key blobs (without outer length field).
func ServeAgent(r io.Reader, w io.Writer, keys map[string]SshSign) error {
	for {
		data, err := readString(r, maxSize)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return fmt.Errorf("invalid empty agent message")
		}
		t, msg := data[0], bytes.NewBuffer(data[1:])
		rsp := &bytes.Buffer{}
		switch t {
		case SSH_AGENTC_REQUEST_IDENTITIES:
			if msg.Len() > 0 {
				return fmt.Errorf("invalid message, %d left-over bytes in list request", msg.Len())
			}

			if err := rsp.WriteByte(SSH_AGENT_IDENTITIES_ANSWER); err != nil {
				return err
			}
			if err := writeUint32(rsp, uint32(len(keys))); err != nil {
				return err
			}
			for k, _ := range keys {
				if err := writeString(rsp, k); err != nil {
					return err
				}
				// Arbitrary comment
				if err := writeString(rsp, "oracle key"); err != nil {
					return err
				}
			}
		case SSH_AGENTC_SIGN_REQUEST:
			key, err := readString(msg, maxSize)
			if err != nil {
				return err
			}
			data, err := readString(msg, maxSize)
			if err != nil {
				return err
			}
			// Flags, currently ignored.
			if _, err := readUint32(msg); err != nil {
				return err
			}
			if msg.Len() > 0 {
				return fmt.Errorf("invalid message, %d left-over bytes in sign request", msg.Len())
			}
			signer, ok := keys[string(key)]
			if !ok {
				if err := rsp.WriteByte(SSH_AGENT_FAILURE); err != nil {
					return err
				}
				break
			}
			sig, err := signer(data)
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
			if err := writeString(rsp, sig); err != nil {
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
