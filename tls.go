/*
By Mohammad Arfan Nur Rahman
refer to
RFC 8446 (https://datatracker.ietf.org/doc/html/rfc8446) for TLS,
RFC 7627 (https://datatracker.ietf.org/doc/html/rfc7627) for
Session Hash and Extended Master Secret Extension
*/
package simplews

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

type KeyExchange struct {
	NamedGroup uint16
	Length     uint16
	Key        []byte
}

type SimpleTLS struct {
	Con                    net.Conn
	server_name            string
	extended_master_secret []byte
	session_id_len         int
	session_id             []byte
	chipers                []uint16
	keyExchanges           []KeyExchange
	version                []byte
}

var SERVER_PREFERENCE = []uint16{
	TLS_AES_128_GCM_SHA256,
}

func (s SimpleTLS) SellectChiper() {
	for i := 0; i < len(s.chipers); i++ {

	}
}

func (s *SimpleTLS) SendServerHello() {
	fmt.Println("\nreplying server echo..")
	var buff bytes.Buffer

	// Legacy Version
	buff.Write([]byte{0x03, 0x03})

	// random
	r := make([]byte, 32)
	if _, err := rand.Read(r); err != nil {
		panic(err)
	}
	buff.Write(r)

	// legacy session id
	buff.WriteByte(byte(32))
	buff.Write(s.session_id)

	s.SendHandshakeProtocol(2, buff)
}

func (s *SimpleTLS) SendHandshakeProtocol(t byte, msg bytes.Buffer) {
	var buff bytes.Buffer
	//  Server Hello
	buff.WriteByte(t)
	total_len := msg.Len()
	buff.Write([]byte{byte(total_len >> 16), byte(total_len >> 8), byte(total_len)})
	buff.Write(msg.Bytes())

	s.SendTLSRecord(buff)
}

func (s *SimpleTLS) SendTLSRecord(buff bytes.Buffer) {
	wr := bufio.NewWriter(s.Con)
	// TLS record
	// Content Type Handshake
	wr.WriteByte(22)

	// Legacy Version
	wr.Write([]byte{0x03, 0x03})

	// length
	total_len := buff.Len()
	wr.Write([]byte{byte(total_len >> 8), byte(total_len)})

	wr.Write(buff.Bytes())
	fmt.Printf("sending tls record\n")
	wr.Flush()
}

func (s *SimpleTLS) HandleTLSHandshake(hs_type byte, hs_len uint32, body []byte) {
	fmt.Printf("handle TLS HandShake (type %d) (len %d)\n", hs_type, hs_len)

	switch hs_type {
	case 1:
		{
			protoc_ver := binary.BigEndian.Uint16(body[0:2])
			random := binary.BigEndian.Uint32(body[2:34])
			fmt.Printf("Handshake: CLIENT_HELLO protocol version : 0x%x\n", protoc_ver)
			s.version = body[:2]
			fmt.Printf("Random : %X\n", random)

			sess_id_len := int(body[34])
			s.session_id_len = sess_id_len

			fmt.Printf("Session Id Len : %d\n", sess_id_len)

			sess_id := body[35 : 35+sess_id_len]
			s.session_id = sess_id
			fmt.Printf("Session ID : %x\n", sess_id)

			pos := 35 + sess_id_len
			chiper_len := binary.BigEndian.Uint16(body[pos : pos+2])
			pos += 2

			fmt.Printf("Chiper Length : %d\n", chiper_len)

			fmt.Println("Chiper: ")
			for i := 0; i < int(chiper_len); i += 2 {
				chiper := binary.BigEndian.Uint16(body[pos+i : pos+i+2])
				s.chipers = append(s.chipers, chiper)
				fmt.Printf("0x%04x (%s) \n", chiper, s.ChiperName(chiper))
			}
			fmt.Println()
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
				data := body[pos : pos+int(extensionDataLen)]

				// fmt.Printf(
				// 	"Extension type: %x, data length: %d\n",
				// 	t,
				// 	extensionDataLen,
				// )

				s.parseExtensions(t, data)
				pos += int(extensionDataLen)
			}

			// time to response server hello
			s.SendServerHello()
			break
		}

	}
}

func (s *SimpleTLS) parseExtensions(t uint16, data []byte) {
	switch t {
	case 0x0:
		{ // server name
			fmt.Printf("	server name : %s\n", data)
			s.server_name = string(data)
			break
		}
	case 0x17:
		{ // extended_master_secret
			if len(data) == 0 {
				data = []byte{0x0, 0x17, 0x0, 0x0}
			}
			s.extended_master_secret = data
			fmt.Printf("	Extended Master Secret : %x\n", data)
			break
		}
	case 0x33: // Key Share
		{
			client_share_length := binary.BigEndian.Uint16(data[:2])
			fmt.Printf("	client_share_length: %d\n", client_share_length)
			pos := 2
			// for pos < pos+int(client_share_length) {
			// keyshareEntry
			ng := binary.BigEndian.Uint16(data[pos : pos+2])
			pos += 2
			fmt.Printf("	Named Group : 0x%04x\n", ng)

			key_exc_length := binary.BigEndian.Uint16(data[pos : pos+2])
			pos += 2

			key_exc := data[pos : pos+int(key_exc_length)]

			fmt.Printf("		Key Exchange (Length %d) %x\n", key_exc_length, key_exc)
			pos += int(key_exc_length)

			s.keyExchanges = append(s.keyExchanges, KeyExchange{
				NamedGroup: ng,
				Length:     key_exc_length,
				Key:        key_exc,
			})
			break
		}
	}
}

func (SimpleTLS) ChiperName(chiper uint16) string {
	switch chiper {
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case TLS_AES_128_CCM_SHA256:
		return "TLS_AES_128_CCM_SHA256"
	case TLS_AES_128_CCM_8_SHA256:
		return "TLS_AES_128_CCM_8_SHA256"
	case 0xc02f:
		return "ECDHE-RSA-AES128-GCM-SHA256"
	case 0xc02b:
		return "ECDHE-ECDSA-AES128-GCM-SHA256"
	case 0xc030:
		return "ECDHE-RSA-AES256-GCM-SHA384"
	case 0xc02c:
		return "ECDHE-ECDSA-AES256-GCM-SHA384"
	case 0xc027:
		return "ECDHE-RSA-AES128-SHA256"
	case 0xcca9:
		return "ECDHE-ECDSA-CHACHA20-POLY1305"
	case 0xcca8:
		return "ECDHE-RSA-CHACHA20-POLY1305"
	case 0xc009:
		return "ECDHE-ECDSA-AES128-SHA"
	case 0xc013:
		return "ECDHE-RSA-AES128-SHA"
	case 0xc014:
		return "ECDHE-RSA-AES256-SHA"
	default:
		return "-"
	}
}
