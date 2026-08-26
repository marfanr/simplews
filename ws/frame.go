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
	b1 := header[1]

	s.Fin = b0&0x80 != 0
	s.Rsv1 = b0&0x40 != 0
	s.Rsv2 = b0&0x20 != 0
	s.Rsv3 = b0&0x10 != 0
	s.Opcode = b0 & 0x0F
	s.Masked = b1&0x80 != 0
	payloadLen := b1 & 0x7F

	fmt.Printf("payload length : %d\n", payloadLen)

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

	payload := make([]byte, s.PayloadLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return s, err
	}
	s.Payload = payload
	if s.Masked {
		for i := range s.Payload {
			s.Payload[i] ^= mask[i%4]
		}
	}

	fmt.Printf("FIN=%v opcode %d  MASK=%v Len : %d\n", s.Fin, s.Opcode, s.Masked, s.PayloadLength)
	fmt.Printf("data %s\n", string(s.Payload))

	return s, nil
}

func (s SimpleWsFrame) Build() []byte {
	d := make([]byte, 0, 16)
	var first byte
	if s.Fin {
		first |= 1 << 7
	}
	if s.Rsv1 {
		first |= 1 << 6
	}
	if s.Rsv2 {
		first |= 1 << 5
	}
	if s.Rsv3 {
		first |= 1 << 4
	}
	first |= s.Opcode & 0x0F

	d = append(d, first)

	var second byte
	length := s.PayloadLength
	switch {
	case length <= 125:
		second |= byte(length)
		d = append(d, second)

	case length <= 65535:
		second |= 126
		d = append(d, second)

		d = append(d,
			byte(length>>8),
			byte(length),
		)

	default:
		second |= 127
		d = append(d, second)

		d = append(d,
			byte(length>>56),
			byte(length>>48),
			byte(length>>40),
			byte(length>>32),
			byte(length>>24),
			byte(length>>16),
			byte(length>>8),
			byte(length),
		)
	}
	d = append(d, s.Payload...)

	return d
}
