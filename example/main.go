/*
By Mohammad Arfan Nur Rahman
referred RFC 6445 (https://datatracker.ietf.org/doc/html/rfc6455) for Websocket
and RFC 8446 (https://datatracker.ietf.org/doc/html/rfc8446) for TLS
*/
package main

import (
	"bufio"
	"crypto/sha1"
	b64 "encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/marfanr/simplews"
	"github.com/marfanr/simplews/parser"
)

const GLOBAL_WS_UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func handleConnection(con net.Conn) {
	rd := bufio.NewReader(con)
	h := parser.HttpParser{}
	println("new connection...")

	// first is record protocol
	header := make([]byte, 5)
	if _, err := io.ReadFull(con, header[:]); err != nil {
		fmt.Println(err.Error())
		return
	}
	content_type := header[0]
	version := binary.BigEndian.Uint16(header[1:3])
	record_length := binary.BigEndian.Uint16(header[3:5])

	fmt.Printf("Content Type : %d\n", content_type)
	fmt.Printf("Version: %d, length: %d\n", version, record_length)

	tls := simplews.SimpleTLS{}

	switch content_type {
	case 22:
		// Handshake Protocol
		{
			fragment := make([]byte, record_length)
			if _, err := io.ReadFull(con, fragment[:]); err != nil {
				fmt.Println(err.Error())
				break
			}
			hs_type := fragment[0]
			// manually, because golang didnt support 24 byte
			length := uint32(fragment[1])<<16 | uint32(fragment[2])<<8 | uint32(fragment[3])
			if int(length+4) > len(fragment) {
				fmt.Println("INFO: Must be another record")
			}
			tls.HandleTLSHandshake(hs_type, length, fragment[4:4+length])
			break
		}
	}

	// for {
	// line, err := rd.ReadString('\n')
	// if err != nil {
	// 	break
	// }

	// fmt.Print(line)
	// h.Parse(line)

	// if line == "\r\n" {
	// 	break
	// }
	// }

	if h.WsVersion > 0 && len(h.WsKey) > 0 && len(h.HTTPVersion) > 0 {
		// valid websocket detected, ready for handhsake
		fmt.Println("httpversion:", h.HTTPVersion)

		// concat
		concated := strings.Join([]string{h.WsKey, GLOBAL_WS_UUID}, "")

		// SHA-1
		sh := sha1.New()
		sh.Write([]byte(concated))
		bsum := sh.Sum(nil)

		b64_out := b64.StdEncoding.EncodeToString(bsum)

		fmt.Printf("base64 out : %s\n", b64_out)

		// build handshake
		wr := bufio.NewWriter(con)

		fmt.Fprintf(wr, "HTTP/1.1 101 Switching Protocols\r\n")
		wr.WriteString("Upgrade: websocket\r\n")
		wr.WriteString("Connection: Upgrade\r\n")
		fmt.Fprintf(wr, "Sec-WebSocket-Accept: %s\r\n", b64_out)
		wr.WriteString("\r\n")

		wr.Flush()

		fmt.Println("waiting for message")
		// established

		header := make([]byte, 2)
		for {
			if _, err := io.ReadFull(rd, header); err != nil {
				fmt.Println(err.Error())
				break
			}

			b0 := header[0]
			b1 := header[1]

			fin := b0&0x80 != 0
			opcode := b0 & 0x0F
			masked := b1&0x80 != 0
			payloadLen := b1 & 0x7F

			switch payloadLen {
			case 127:
				// available extend payload

			}

			mask := make([]byte, 4)
			if masked {
				if _, err := io.ReadFull(rd, mask[:]); err != nil {
					fmt.Println(err.Error())
					break
				}
			}

			payload := make([]byte, payloadLen)
			if _, err := io.ReadFull(rd, payload); err != nil {
				fmt.Println(err.Error())
				break
			}

			if masked {
				for i := range payload {
					payload[i] ^= mask[i%4]
				}
			}

			fmt.Printf(
				"FIN=%v OPCODE=%d MASK=%v LEN=%d\n",
				fin,
				opcode,
				masked,
				payloadLen,
			)

			fmt.Printf("payload %q\n", payload)

		}
	}
}

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println("running on :8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			println("error : ", err.Error())
		}

		go handleConnection(conn)
	}
}
