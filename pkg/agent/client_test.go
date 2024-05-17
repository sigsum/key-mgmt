package agent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"sigsum.org/key-mgmt/pkg/ssh"
)

type mockConnection struct {
	readBuf  []byte
	writeBuf []byte
}

func (c *mockConnection) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if c.readBuf == nil {
		return 0, fmt.Errorf("mocked read error")
	}
	if len(c.readBuf) == 0 {
		return 0, io.EOF
	}
	// Return bytes only one at a time.
	buf[0] = c.readBuf[0]
	c.readBuf = c.readBuf[1:]
	return 1, nil
}

func (c *mockConnection) Write(buf []byte) (int, error) {
	if c.writeBuf == nil {
		return 0, fmt.Errorf("mocked write failure")
	}
	c.writeBuf = append(c.writeBuf, buf...)
	return len(buf), nil
}

func h(ascii string) []byte {
	s, err := hex.DecodeString(ascii)
	if err != nil {
		panic(fmt.Errorf("invalid hex %q: %v", ascii, err))
	}
	return s
}

func TestRequest(t *testing.T) {
	for _, table := range []struct {
		desc           string
		request        []byte
		expResponse    []byte // nil for expected error
		expWireRequest []byte // nil for write errors
		wireResponse   []byte
	}{
		{"empty body", []byte{1}, []byte{2}, h("0000000101"), h("0000000102")},
		{"non-empty", []byte("abc"), []byte("defg"), h("00000003616263"), h("0000000464656667")},
		{"eof length", []byte("abc"), nil, h("00000003616263"), h("012345")},
		{"eof type", []byte("abc"), nil, h("00000003616263"), h("00000000")},
		{"eof data", []byte("abc"), nil, h("00000003616263"), h("0000004064656667")},
		{"write error", []byte("abc"), nil, nil, h("0000000464656667")},
		{"read error", []byte("abc"), nil, h("00000003616263"), nil},
	} {
		mockConn := mockConnection{}
		mockConn.readBuf = table.wireResponse
		if table.expWireRequest != nil {
			mockConn.writeBuf = []byte{}
		}
		c := Client{&mockConn}
		req := newMsgBuf(table.request[0])
		req.Write(table.request[1:])
		rspType, rsp, err := c.request(req)
		if err != nil {
			if table.expResponse != nil {
				t.Errorf("%q: unexpected failure: %v", table.desc, err)
			}
		} else {
			if !bytes.Equal(mockConn.writeBuf, table.expWireRequest) {
				t.Errorf("%q: unexpected request on the wire, got %x, wanted %x",
					table.desc, mockConn.writeBuf, table.expWireRequest)
			}
			if table.expResponse == nil {
				if _, err := io.ReadAll(rsp); err == nil {
					t.Errorf("%q: unexpected success, response type: %d", table.desc, rspType)
				}
			} else {
				got, err := io.ReadAll(rsp)
				if err != nil {
					t.Fatal(err)
				}
				got = append([]byte{rspType}, got...)
				if !bytes.Equal(got, table.expResponse) {
					t.Errorf("%q: bad response, got %x, wanted %x",
						table.desc, got, table.expResponse)
				}
			}
		}
	}
}

func TestSign(t *testing.T) {
	privateKey := [32]byte{17}
	signer := ed25519.NewKeyFromSeed(privateKey[:])
	publicKey := string(ssh.SerializeEd25519PublicKey(signer.Public().(ed25519.PublicKey)))

	msg := []byte("abc")
	signature, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	expSignature := ssh.SerializeEd25519Signature(signature)
	response := ssh.SerializeString(bytes.Join([][]byte{
		[]byte{SSH_AGENT_SIGN_RESPONSE},
		ssh.SerializeString(bytes.Join([][]byte{
			ssh.SerializeString("ssh-ed25519"),
			ssh.SerializeString(signature),
		}, nil)),
	}, nil))

	mockConn := mockConnection{readBuf: response, writeBuf: []byte{}}
	c := Client{&mockConn}

	resp, err := c.Sign(publicKey, msg, 0)
	if err != nil {
		t.Errorf("Sign failed: %v", err)
	} else if !bytes.Equal(resp, expSignature) {
		t.Errorf("unexpected signature, got %x, wanted %x", resp, expSignature)
	}
	expRequest := h("000000430d000000330000000b7373682d656432353531390000002066e0b858" +
		"e462a609e66fe71370c816d8846ff103d5499a22a7fec37fdbc424a70000000361626300000000")
	if !bytes.Equal(mockConn.writeBuf, expRequest) {
		t.Errorf("unexpected request on the wire, got %x, wanted %x",
			mockConn.writeBuf, expRequest)
	}
}

func TestSignFail(t *testing.T) {
	// Test a couple of failure cases.
	for _, table := range []struct {
		desc         string
		wireResponse []byte
		expError     string
	}{
		{"agent failure message", h("0000000105"), "refused"},
		{"top parse failure", h("00000000"), "invalid"},
		{"unexpected type", h("000000010f"), "unexpected agent response"},
	} {
		mockConn := mockConnection{readBuf: table.wireResponse, writeBuf: []byte{}}
		c := Client{&mockConn}

		signature, err := c.Sign("dummy key", []byte("msg"), 0)
		if err == nil {
			t.Errorf("%q: unexpected success, got signature %x\n", table.desc, signature)
		} else if !strings.Contains(err.Error(), table.expError) {
			t.Errorf("%q: expected error containing %q, got: %v", table.desc, table.expError, err)
		}
	}
}
