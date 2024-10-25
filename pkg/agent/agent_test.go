package agent

import (
	"bytes"
	"io"
	"testing"
)

func TestReadMsg(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0, 0, 0, 3, 1, 2, 3, 0xff, 0xff})
	cmd, body, err := readMsg(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cmd, byte(1); got != want {
		t.Errorf("bad first byte, got %d, want %d", got, want)
	}
	got, err := io.ReadAll(body)
	if want := []byte{2, 3}; !bytes.Equal(got, want) {
		t.Errorf("bad mesg body, got %v, want %v", got, want)
	}
	if got, want := buf.Len(), 2; got != want {
		t.Errorf("readMsg read beyond end of message, got %d bytes left, want %d", got, want)
	}
}

func TestReadMsgFail(t *testing.T) {
	for _, table := range []struct {
		desc  string
		input []byte
	}{
		{"length eof", []byte{}},
		{"trunc. length", []byte{0, 0, 0}},
		{"zero length", []byte{0, 0, 0, 0, 1}},
		// { "data eof", []byte{0,0,0,10, 1,2,3}},
	} {
		_, _, err := readMsg(bytes.NewBuffer(table.input))
		if err == nil {
			t.Errorf("no error on test %q", table.desc)
		}
	}
	cmd, body, err := readMsg(bytes.NewBuffer([]byte{0, 0, 0, 10, 1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cmd, byte(1); got != want {
		t.Errorf("bad first byte, got %d, want %d", got, want)
	}
	data, err := io.ReadAll(body)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("got %v, data %x, wanted ErrUnexpectedEOF", err, data)
	}
}

func TestMsgBuf(t *testing.T) {
	m := newMsgBuf(1)
	_, err := m.WriteString("foo")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	writeMsg(&buf, m)
	if got, want := buf.Bytes(), []byte{0, 0, 0, 4, 1, 'f', 'o', 'o'}; !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
