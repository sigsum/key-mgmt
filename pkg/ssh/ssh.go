// The ssh package implements utilities for working with SSH formats.
//
// The way values are serialized in SSH is documented in
// https://www.rfc-editor.org/rfc/rfc4251#section-5.
//
// Use of ED25519 keys is specified in https://www.rfc-editor.org/rfc/rfc8709
//
// There are also a few openssh-specific formats (outside of the IETF standards).
//
// The ssh-agent protocol is documented at
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent.
//
// The private key format used by openssh is documented at
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key

package ssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

type bytesOrString interface{ []byte | string }

func SerializeUint32(x uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}

func SerializeString[T bytesOrString](s T) []byte {
	if len(s) > math.MaxInt32 {
		panic(fmt.Sprintf("string too large for ssh, length %d", len(s)))
	}
	buffer := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buffer, uint32(len(s)))
	copy(buffer[4:], s)
	return buffer
}

func WriteUint32(w io.Writer, x uint32) error {
	_, err := w.Write(SerializeUint32(x))
	return err
}

func WriteString[T bytesOrString](w io.Writer, s T) error {
	_, err := w.Write(SerializeString(s))
	return err
}

func readBytes(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func ReadUint32(r io.Reader) (uint32, error) {
	lenBuf, err := readBytes(r, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(lenBuf), nil
}

func ReadString(r io.Reader, max int) ([]byte, error) {
	len, err := ReadUint32(r)
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

// Both keys and signatures are serialized in the same way.
func serializeEd25519(blob []byte) []byte {
	return bytes.Join([][]byte{
		SerializeString("ssh-ed25519"),
		SerializeString(blob)},
		nil)
}

func SerializeEd25519PublicKey(blob []byte) []byte {
	if len(blob) != 32 {
		panic(fmt.Sprintf("Bad size %d for ed25519 public key", len(blob)))
	}
	return serializeEd25519(blob)
}

func SerializeEd25519Signature(blob []byte) []byte {
	if len(blob) != 64 {
		panic(fmt.Sprintf("Bad size %d for ed25519 signature", len(blob)))
	}
	return serializeEd25519(blob)
}

func ReadEd25519PublicKey(r io.Reader) ([]byte, error) {
	if err := readSkip(r, bytes.Join([][]byte{
		SerializeString("ssh-ed25519"),
		SerializeUint32(32)},
		nil)); err != nil {
		return nil, fmt.Errorf("invalid public key blob prefix: %w", err)
	}
	return readBytes(r, 32)
}

// Apply a reader function to a byte slice. Requires that the reader
// consumes all bytes.
func ParseBytes[T any](blob []byte, reader func(io.Reader) (T, error)) (T, error) {
	return parseBytes(blob, nil, reader)
}
