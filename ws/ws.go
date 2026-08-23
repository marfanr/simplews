package ws

import (
	"bufio"
	"crypto/sha1"
	b64 "encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/marfanr/simplews/tls"
)

const GLOBAL_WS_UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type SimpleWebsocket struct {
	http HttpParser
	done bool
}

func (s *SimpleWebsocket) Handler(ctx *tls.SimpleTlsContext) {
	reader := bufio.NewReader(ctx)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		fmt.Print(line)
		s.http.Parse(line)

		if line == "\r\n" {
			break
		}
	}

	if s.http.WsVersion > 0 && len(s.http.WsKey) > 0 && len(s.http.HTTPVersion) > 0 {
		// valid websocket detected, ready for handhsake
		fmt.Println("httpversion:", s.http.HTTPVersion)

		// concat
		concated := strings.Join([]string{s.http.WsKey, GLOBAL_WS_UUID}, "")

		// SHA-1
		sh := sha1.New()
		sh.Write([]byte(concated))
		bsum := sh.Sum(nil)

		b64_out := b64.StdEncoding.EncodeToString(bsum)

		fmt.Printf("base64 out : %s\n", b64_out)

		// build handshake
		wr := bufio.NewWriter(ctx)

		fmt.Fprintf(wr, "HTTP/1.1 101 Switching Protocols\r\n")
		wr.WriteString("Upgrade: websocket\r\n")
		wr.WriteString("Connection: Upgrade\r\n")
		fmt.Fprintf(wr, "Sec-WebSocket-Accept: %s\r\n", b64_out)
		wr.WriteString("\r\n")
		wr.Flush()
		s.done = true

		fmt.Println("waiting for message")
		// established

		header := make([]byte, 2)
		for {
			if _, err := io.ReadFull(reader, header); err != nil {
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
				if _, err := io.ReadFull(reader, mask[:]); err != nil {
					fmt.Println(err.Error())
					break
				}
			}

			payload := make([]byte, payloadLen)
			if _, err := io.ReadFull(reader, payload); err != nil {
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
