package agent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/golang/mock/gomock"

	"sigsum.org/key-mgmt/internal/mocks"
	"sigsum.org/key-mgmt/pkg/ssh"
)

func TestServerSignEd25519(t *testing.T) {
	key := [32]byte{1}
	var s crypto.Signer = ed25519.NewKeyFromSeed(key[:])
	pub, signer, err := NewEd25519Signer(s)
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.NewBuffer(bytes.Join([][]byte{
		[]byte{0, 0, 0, 67, 13, 0, 0, 0, 51},
		[]byte(pub),
		[]byte{0, 0, 0, 3, 'f', 'o', 'o', 0, 0, 0, 0},
	}, nil))

	var output bytes.Buffer
	if err := Serve(input, &output, map[string]Signer{pub: signer}); err != io.EOF {
		t.Fatalf("expected termination on EOF, got: %v", err)
	}
	rsp := output.Bytes()
	if !bytes.HasPrefix(rsp, []byte{0, 0, 0, 88, 14, 0, 0, 0, 83}) {
		t.Errorf("bad response prefix, got %x", rsp)
	}
	if got, want := len(rsp), 92; got != want {
		t.Errorf("unexpected response length, got %d, want %d: %x", got, want, pub)
	}
	if len(rsp) < 28 || !ed25519.Verify(s.Public().(ed25519.PublicKey), []byte("foo"), rsp[28:]) {
		t.Errorf("invalid signature, response: %x", rsp)
	}
}

type bytesMatcher struct {
	want []byte
}

func (m bytesMatcher) Matches(x interface{}) bool {
	if x, ok := x.([]byte); ok {
		return bytes.Equal(x, m.want)
	}
	return false
}
func (m bytesMatcher) String() string {
	return fmt.Sprintf("bytes.Equal to %v", m.want)
}

func TestServerNonEd25519(t *testing.T) {
	pub := "pubA"
	ctrl := gomock.NewController(t)
	signer := mocks.NewMockSSHSigner(ctrl)

	signer.EXPECT().Sign(bytesMatcher{[]byte("msg")}).Return([]byte("signature"), nil)
	input := bytes.NewBuffer([]byte{0, 0, 0, 20, 13, 0, 0, 0, 4, 'p', 'u', 'b', 'A', 0, 0, 0, 3, 'm', 's', 'g', 0, 0, 0, 0})

	var output bytes.Buffer
	if err := Serve(input, &output, map[string]Signer{pub: signer}); err != io.EOF {
		t.Fatalf("expected termination on EOF, got: %v", err)
	}
	if got, want := output.Bytes(), []byte{0, 0, 0, 14, 14, 0, 0, 0, 9, 's', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e'}; !bytes.Equal(got, want) {
		t.Errorf("bad response, got %x, want %x", got, want)
	}
}

func TestServerIdentities(t *testing.T) {
	input := bytes.NewBuffer([]byte{0, 0, 0, 1, 11})
	var output bytes.Buffer
	if err := Serve(input, &output, map[string]Signer{"A": nil, "B": nil}); err != io.EOF {
		t.Fatalf("expected termination on EOF, got: %v", err)
	}
	rsp := output.Bytes()
	rsp = stripLength(t, rsp)
	rsp, ok := bytes.CutPrefix(rsp, []byte{12, 0, 0, 0, 2})
	if !ok {
		t.Fatalf("bad response: %x", rsp)
	}
	l := splitStrings(t, rsp)
	if got, want := len(l), 4; got != want {
		t.Fatalf("unexpected number of strings in response, got %d, wand %d", got, want)
	}
	if l[0] != "A" && l[2] != "A" {
		t.Errorf("pubkey A is missing")
	}
	if l[0] != "B" && l[2] != "B" {
		t.Errorf("pubkey B is missing")
	}
}

func TestServerSignFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	signer := mocks.NewMockSSHSigner(ctrl)
	signer.EXPECT().Sign(bytesMatcher{[]byte("msg")}).Return(nil, fmt.Errorf("mock sign error"))
	input := bytes.NewBuffer([]byte{
		0, 0, 0, 17, 13, 0, 0, 0, 1, 'A', 0, 0, 0, 3, 'm', 's', 'g', 0, 0, 0, 0,
		0, 0, 0, 17, 13, 0, 0, 0, 1, 'B', 0, 0, 0, 3, 'm', 's', 'g', 0, 0, 0, 0,
	})
	var output bytes.Buffer
	if err := Serve(input, &output, map[string]Signer{"A": signer}); err != io.EOF {
		t.Fatalf("expected termination on EOF, got: %v", err)
	}
	if got, want := output.Bytes(), []byte{0, 0, 0, 1, 5, 0, 0, 0, 1, 5}; !bytes.Equal(got, want) {
		t.Errorf("bad response, got %x, want %x", got, want)
	}
}

// Remove SSH length field.
func stripLength(t *testing.T, s []byte) []byte {
	if len(s) < 4 || int64(len(s)) != 4+int64(binary.BigEndian.Uint32(s)) {
		t.Fatalf("not a valid ssh string: %x", s)
	}
	return s[4:]
}

// Parse a list of ssh strings.
func splitStrings(t *testing.T, in []byte) []string {
	buf := bytes.NewBuffer(in)
	res := []string{}
	for buf.Len() > 0 {
		s, err := ssh.ReadString(buf, 100)
		if err != nil {
			t.Fatalf("invalid ssh string at index %d, input %x: %v",
				len(res), in, err)
		}
		res = append(res, string(s))
	}
	return res
}
