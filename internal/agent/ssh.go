package agent

import (
	"bytes"
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

func readBytes(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readUint32(r io.Reader) (uint32, error) {
	lenBuf, err := readBytes(r, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(lenBuf), nil
}

func readString(r io.Reader, max int) ([]byte, error) {
	len, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	if int64(len) > int64(max) {
		return nil, fmt.Errorf("length %d exceeds max %d", len, max)
	}
	return readBytes(r, int(len))
}

// Reads and skips raw prefix.
func readSkip(r io.Reader, prefix []byte) error {
	buf, err := readBytes(r, len(prefix))
	if err != nil {
		return err
	}
	if !bytes.Equal(buf, prefix) {
		return fmt.Errorf("unexpected data: %x", buf)
	}
	return nil
}

// Apply a reader function to a byte slice. Requires that the reader
// consumes all bytes, except for optional padding bytes.
func parseBytes[T any](blob []byte, padding []byte, reader func(io.Reader) (T, error)) (T, error) {
	buf := bytes.NewBuffer(blob)
	res, err := reader(buf)
	if err != nil {
		return res, err
	}
	leftOver := buf.Bytes()
	if len(leftOver) > len(padding) {
		return res, fmt.Errorf("trailing %d bytes of garbage", len(leftOver))
	}
	if !bytes.Equal(leftOver, padding[:len(leftOver)]) {
		return res, fmt.Errorf("unexpected padding bytes: %x", leftOver)
	}
	return res, err
}
