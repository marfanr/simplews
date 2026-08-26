package ws

import (
	"bufio"
	"crypto/sha1"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/marfanr/simplews/tls"
)

type SimpleWebSocketEvent struct {
	event  string
	handle func(ctx *SimpleWebSocketContext)
}

type SimpleWebsocket struct {
	http   HttpParser
	done   bool
	events []SimpleWebSocketEvent
	ctx    *SimpleWebSocketContext
}

var suppported_events = []string{"open", "message", "error", "close"}

func (s *SimpleWebsocket) Handler(ctx *tls.SimpleTlsContext) {
	if s.ctx == nil {
		s.ctx = &SimpleWebSocketContext{
			tlsCtx: ctx,
		}
	}
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
		s.invoke("open")

		for {
			_, err := parseWsFrame(reader)
			if err != nil {
			}
			// TODO: break if receive end
		}
	}
}

func (s *SimpleWebsocket) On(event string, h func(*SimpleWebSocketContext)) error {
	if !slices.Contains(suppported_events, event) {
		return errors.New("not supported event")
	}
	s.events = append(s.events, SimpleWebSocketEvent{
		event:  event,
		handle: h,
	})
	return nil
}

func (s *SimpleWebsocket) invoke(event string) {
	for _, v := range s.events {
		if v.event == event {
			v.handle(s.ctx)
		}
	}
}
