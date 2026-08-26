package ws

import (
	"fmt"
	"io"

	"github.com/marfanr/simplews/tls"
)

type SimpleWebSocketContext struct {
	io.ReadWriter
	tlsCtx *tls.SimpleTlsContext
}

func (ctx SimpleWebSocketContext) Write(p []byte) (n int, err error) {
	return ctx.tlsCtx.Write(p)
}

/*
RFC 6455 5.5.2
PING
*/
func (ctx SimpleWebSocketContext) Ping() {
	fmt.Println("PING sended")
	p := []byte("PING")
	frame := SimpleWsFrame{
		Fin:           true,
		Masked:        false,
		Payload:       p,
		PayloadLength: uint64(len(p)),
		Opcode:        SIMPLE_WS_TEXT_FRAME,
	}
	b := frame.Build()
	ctx.Write(b)
}
