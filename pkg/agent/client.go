package agent

import (
	"fmt"
	"io"
	"net"
	"os"

	"sigsum.org/key-mgmt/pkg/ssh"
)

type Client struct {
	c io.ReadWriter
}

func ConnectTo(sockName string) (*Client, error) {
	conn, err := net.Dial("unix", sockName)
	return &Client{c: conn}, err
}

func Connect() (*Client, error) {
	if sockName := os.Getenv(sshAgentEnv); len(sockName) > 0 {
		return ConnectTo(sockName)
	}
	return nil, fmt.Errorf("no ssh-agent available")
}

// Send a request and return the response.
func (c *Client) request(request *msgBuf) (byte, *bodyReader, error) {
	if err := writeMsg(c.c, request); err != nil {
		return 0, nil, err
	}
	rspType, rsp, err := readMsg(c.c)
	if rspType == SSH_AGENT_FAILURE {
		return 0, nil, fmt.Errorf("request refused by agent")
	}
	return rspType, rsp, err
}

type AgentIdentity struct {
	PublicKey string // SSH public key blob (without outer length field).
	Comment   string
}

func (c *Client) RequestIdentities(limit int) ([]AgentIdentity, error) {
	rspType, rsp, err := c.request(newMsgBuf(SSH_AGENTC_REQUEST_IDENTITIES))
	if err != nil {
		return nil, err
	}
	if rspType != SSH_AGENT_IDENTITIES_ANSWER {
		return nil, fmt.Errorf("unexpected agent response type %d", rspType)
	}
	count, err := ssh.ReadUint32(rsp)
	if err != nil {
		return nil, err
	}
	if int64(count) > int64(limit) {
		return nil, fmt.Errorf("too many identities: %d", count)
	}
	list := make([]AgentIdentity, 0, count)

	for i := uint32(0); i < count; i++ {
		publicKey, err := ssh.ReadString(rsp, agentMaxSize)
		if err != nil {
			return nil, err
		}
		comment, err := ssh.ReadString(rsp, agentMaxSize)
		if err != nil {
			return nil, err
		}
		list = append(list, AgentIdentity{PublicKey: string(publicKey), Comment: string(comment)})
	}
	if rsp.Len() > 0 {
		return nil, fmt.Errorf("invalid message, %d left-over bytes in identity response", rsp.Len())
	}

	return list, nil
}

func (c *Client) Sign(publicKey string, msg []byte, flags uint32) ([]byte, error) {
	req := newMsgBuf(SSH_AGENTC_SIGN_REQUEST)
	ssh.WriteString(req, publicKey)
	ssh.WriteString(req, msg)
	ssh.WriteUint32(req, flags)

	rspType, rsp, err := c.request(req)
	if err != nil {
		return nil, err
	}
	if rspType != SSH_AGENT_SIGN_RESPONSE {
		return nil, fmt.Errorf("unexpected agent response type %d", rspType)
	}
	signature, err := ssh.ReadString(rsp, agentMaxSize)
	if err != nil {
		return nil, err
	}
	if rsp.Len() > 0 {
		return nil, fmt.Errorf("invalid message, %d left-over bytes in sign response", rsp.Len())
	}
	return signature, nil
}

type clientSigner struct {
	c         *Client
	publicKey string
	flags     uint32
}

func (c *clientSigner) Sign(msg []byte) ([]byte, error) {
	return c.c.Sign(c.publicKey, msg, c.flags)
}

func (c *Client) NewSigner(publicKey string, flags uint32) Signer {
	return &clientSigner{c, publicKey, flags}
}
