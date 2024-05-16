package agent

import (
	"fmt"
	"io"
	"log"

	"sigsum.org/key-mgmt/pkg/ssh"
)

type signRequest struct {
	pubKey []byte
	data   []byte
}

func readSignRequest(r io.Reader) (req signRequest, err error) {
	req.pubKey, err = ssh.ReadString(r, agentMaxSize)
	if err != nil {
		return
	}
	req.data, err = ssh.ReadString(r, agentMaxSize)
	if err != nil {
		return
	}
	// Flags, currently ignored.
	_, err = ssh.ReadUint32(r)
	return
}

// Signs the given data, and returns a signature formatted as an SSH
// signature (without outer length field).
type Signer interface {
	Sign([]byte) ([]byte, error)
}

// The map keys are SSH public key blobs (without outer length field),
// map values are functions that sign provided data and returns an
// ssh-formatted signature.
func Serve(r io.Reader, w io.Writer, keys map[string]Signer) error {
	for {
		msgType, msg, err := readMsg(r)
		if err != nil {
			return err
		}
		// The write methods on bytes.Buffer are documented to
		// always return a nil error. Therefore all related
		// error return values below are ignored.
		rsp := newMsgBuf(SSH_AGENT_FAILURE) // Default response
		switch msgType {
		case SSH_AGENTC_REQUEST_IDENTITIES:
			if leftOver := msg.Len(); leftOver > 0 {
				return fmt.Errorf("invalid message, %d left-over bytes in list request", leftOver)
			}

			rsp = newMsgBuf(SSH_AGENT_IDENTITIES_ANSWER)
			ssh.WriteUint32(rsp, uint32(len(keys)))
			for k, _ := range keys {
				ssh.WriteString(rsp, k)
				// Arbitrary comment
				ssh.WriteString(rsp, "oracle key")
			}
		case SSH_AGENTC_SIGN_REQUEST:
			req, err := readSignRequest(msg)
			if err != nil {
				return err
			}
			if leftOver := msg.Len(); leftOver > 0 {
				return fmt.Errorf("invalid message, %d left-over bytes in sign request", leftOver)
			}
			signer, ok := keys[string(req.pubKey)]
			if !ok {
				break
			}
			sig, err := signer.Sign(req.data)
			if err != nil {
				log.Printf("signing failed: %v", err)
				break
			}
			rsp = newMsgBuf(SSH_AGENT_SIGN_RESPONSE)
			ssh.WriteString(rsp, sig)
		}
		if err := writeMsg(w, rsp); err != nil {
			return err
		}
	}
}
