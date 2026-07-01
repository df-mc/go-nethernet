package discovery

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func writeInt32(buf *bytes.Buffer, v int32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	buf.Write(b[:])
}

func readInt32(r io.Reader) (int32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(b[:])), nil
}

func writeBool(buf *bytes.Buffer, v bool) {
	if v {
		buf.WriteByte(1)
		return
	}
	buf.WriteByte(0)
}

func readBool(r io.ByteReader) (bool, error) {
	b, err := r.ReadByte()
	return b != 0, err
}

func writeString(buf *bytes.Buffer, s string) {
	writeVaruint32(buf, uint32(len(s)))
	buf.WriteString(s)
}

func readString(buf *bytes.Buffer) (string, error) {
	length, err := readVaruint32(buf)
	if err != nil {
		return "", err
	}
	if int(length) > buf.Len() {
		return "", fmt.Errorf("string length %d exceeds remaining %d bytes", length, buf.Len())
	}
	b := make([]byte, length)
	if _, err := io.ReadFull(buf, b); err != nil {
		return "", err
	}
	return string(b), nil
}

func writeVarint32(buf *bytes.Buffer, v int32) {
	u := uint32(v) << 1
	if v < 0 {
		u = ^u
	}
	writeVaruint32(buf, u)
}

func readVarint32(r io.ByteReader) (int32, error) {
	u, err := readVaruint32(r)
	if err != nil {
		return 0, err
	}
	v := int32(u >> 1)
	if u&1 != 0 {
		v = ^v
	}
	return v, nil
}

func writeVaruint32(buf *bytes.Buffer, v uint32) {
	for v >= 0x80 {
		buf.WriteByte(byte(v) | 0x80)
		v >>= 7
	}
	buf.WriteByte(byte(v))
}

func readVaruint32(r io.ByteReader) (uint32, error) {
	var v uint32
	for i := uint(0); i < 35; i += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v |= uint32(b&0x7f) << i
		if b&0x80 == 0 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("varuint32 did not terminate after 5 bytes")
}
