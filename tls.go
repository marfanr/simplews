package simplews

import (
	"encoding/binary"
	"fmt"
	"net"
)

type SimpleTLS struct {
	con *net.Conn
}

func (SimpleTLS) SendServerHello() {
}

func (SimpleTLS) HandleTLSHandshake(hs_type byte, hs_len uint32, body []byte) {
	fmt.Printf("handle TLS HS (type %d) (len %d)\n", hs_type, hs_len)

	var list_supported_chippers []uint16

	switch hs_type {
	case 1:
		{
			protoc_ver := binary.BigEndian.Uint16(body[0:2])
			random := binary.BigEndian.Uint32(body[2:34])
			fmt.Printf("Handshake: CLIENT_HELLO protocol version : 0x%x\n", protoc_ver)
			fmt.Printf("Random : %X\n", random)

			sess_id_len := int(body[34])
			fmt.Printf("Session Id Len : %d\n", sess_id_len)

			sess_id := body[35 : 35+sess_id_len]
			fmt.Printf("Session ID : %x\n", sess_id)

			pos := 35 + sess_id_len
			chiper_len := binary.BigEndian.Uint16(body[pos : pos+2])
			pos += 2

			fmt.Printf("Chiper Length : %d\n", chiper_len)

			for i := 0; i < int(chiper_len); i += 2 {
				chiper := binary.BigEndian.Uint16(body[pos+i : pos+i+2])
				list_supported_chippers = append(list_supported_chippers, chiper)
				fmt.Printf("chipper: %04x\n", chiper)
			}
			pos += int(chiper_len)

			compress_method_len := int(body[pos])
			pos++
			fmt.Printf("Compression Length : %d\n", compress_method_len)

			for i := 0; i < compress_method_len; i++ {
				compression := body[pos+i]
				fmt.Printf("Compression : %x\n", compression)
			}
			pos += compress_method_len

			// extension part
			extension_len := binary.BigEndian.Uint16(body[pos : pos+2])
			fmt.Printf("extension lenth: %d\n", extension_len)
			pos += 2

			// parse all extension
			extensionEnd := pos + int(extension_len)
			for pos < extensionEnd {
				t := binary.BigEndian.Uint16(body[pos : pos+2])
				pos += 2

				extensionDataLen := binary.BigEndian.Uint16(body[pos : pos+2])
				pos += 2

				fmt.Printf(
					"Extension type: 0x%04x, data length: %d\n",
					t,
					extensionDataLen,
				)

				pos += int(extensionDataLen)
			}

			// time to response server hello

			break
		}

	}
}
