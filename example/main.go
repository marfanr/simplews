/*
By Mohammad Arfan Nur Rahman
*/
package main

import (
	"fmt"
	"net"

	"github.com/marfanr/simplews/tls"
	"github.com/marfanr/simplews/ws"
)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	_ = ws.GLOBAL_WS_UUID

	server := tls.NewServer(listener, tls.SimpleTlsConfig{
		CertPath:    "/etc/letsencrypt/live/git.voxiaos.web.id/fullchain.pem",
		PrivKeyPath: "/etc/letsencrypt/live/git.voxiaos.web.id/privkey.pem",
	})

	sws := ws.SimpleWebsocket{}

	sws.On("open", func(ctx *ws.SimpleWebSocketContext) {
		fmt.Println("client connected")
		ctx.Ping()
	})

	server.AddHandler(sws.Handler)
	server.Serve()
}
