package ws

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

/*
RFC 6455
5.1 Data Framming
*/
type SimpleWsFrame struct {
	Fin           bool
	Rsv1          bool
	Rsv2          bool
	Rsv3          bool
	Opcode        byte
	Masked        bool
	PayloadLength uint64
	MaskKey       [4]byte
	Payload       []byte
}

func parseWsFrame(reader *bufio.Reader) (s SimpleWsFrame, e error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return s, err
	}

	b0 := header[0]
	b1 := header[0]

	s.Fin = b0&0x80 != 0
	s.Rsv1 = b0&0x40 != 0
	s.Rsv2 = b0&0x20 != 0
	s.Rsv3 = b0&0x10 != 0
	s.Opcode = b0 & 0x0F
	s.Masked = b1&0x80 != 0
	payloadLen := b1 & 0x7F

	switch payloadLen {
	case 126:
		{
			length := make([]byte, 2)
			if _, err := io.ReadFull(reader, length[:]); err != nil {
				return s, err
			}
			s.PayloadLength = uint64(binary.BigEndian.Uint16(length))
			break
		}
	case 127:
		{
			length := make([]byte, 8)
			if _, err := io.ReadFull(reader, length[:]); err != nil {
				return s, err
			}
			s.PayloadLength = binary.BigEndian.Uint64(length)
			break
		}
	default:
		s.PayloadLength = uint64(payloadLen)
	}

	mask := make([]byte, 4)
	if s.Masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return s, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return s, err
	}

	fmt.Printf("FIN=%v opcode %d  MASK=%v Len : %d\n", s.Fin, s.Opcode, s.Masked, s.PayloadLength)

	return s, nil
}
