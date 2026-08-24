package ws

import "io"

type SimpleWebSocketContext struct {
	io.ReadWriter
}

func (ctx SimpleWebSocketContext) ping() {

}
