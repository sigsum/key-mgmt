package agent

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// SSH protocol utilities, copied from sigsum-go/internal/ssh.go

type bytesOrString interface{ []byte | string }

func serializeUint32(x uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}

func serializeString[T bytesOrString](s T) []byte {
	if len(s) > math.MaxInt32 {
		panic(fmt.Sprintf("string too large for ssh, length %d", len(s)))
	}
	buffer := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buffer, uint32(len(s)))
	copy(buffer[4:], s)
	return buffer
}

func writeUint32(w io.Writer, x uint32) error {
	_, err := w.Write(serializeUint32(x))
	return err
}

func writeString[T bytesOrString](w io.Writer, s T) error {
	_, err := w.Write(serializeString(s))
	return err
}

func readUint32(r io.Reader) (uint32, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(lenBuf), nil
}

func readString(r io.Reader, max uint32) ([]byte, error) {
	len, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	if len > max {
		return nil, fmt.Errorf("length %d exceeds max %d", len, max)
	}
	dataBuf := make([]byte, len)
	if _, err = io.ReadFull(r, dataBuf); err != nil {
		return nil, err
	}
	return dataBuf, nil
}
