package ssh

import (
	"bytes"
	"testing"
)

func TestSerializeString(t *testing.T) {
	for _, tbl := range []struct {
		desc string
		in   string
		want []byte
	}{
		{"empty", "", []byte{0, 0, 0, 0}},
		{"valid", "ö foo is a bar",
			bytes.Join([][]byte{{0, 0, 0, 15, 0xc3, 0xb6},
				[]byte(" foo is a bar")}, nil)},
	} {
		if got, want := SerializeString(tbl.in), tbl.want; !bytes.Equal(got, want) {
			t.Errorf("%q: got %x but wanted %x", tbl.desc, got, want)
		}
	}
}
