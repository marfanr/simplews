package parser

import (
	"fmt"
	"strconv"
	"strings"
)

type HttpParser struct {
	HTTPVersion string
	Path        string
	WsVersion   int
	WsKey       string
}

func (p *HttpParser) Parse(line string) {
	v := strings.Split(line, " ")
	p.parse_http_version(v)
	p.parse_ws_version(v)
	p.parse_ws_key(v)

}

// get http version and path
func (p *HttpParser) parse_http_version(v []string) {
	if len(v) > 2 && strings.Contains(v[2], "HTTP/") {
		p.Path = v[1]

		http_version := strings.Split(v[2], "/")
		p.HTTPVersion = http_version[1]

		fmt.Println("path: " + p.Path)
	}
}

func (p *HttpParser) parse_ws_version(v []string) {
	if len(v) == 2 && strings.EqualFold(v[0], "Sec-WebSocket-Version:") {
		ver, err := strconv.Atoi(strings.TrimSpace(v[1]))
		fmt.Println("WS Version : ", ver)
		if err != nil {
			fmt.Println(err.Error())
		}
		p.WsVersion = ver
	}
}

func (p *HttpParser) parse_ws_key(v []string) {
	if len(v) == 2 && strings.EqualFold(v[0], "Sec-WebSocket-Key:") {
		p.WsKey = strings.TrimSpace(v[1])
		fmt.Println("WS Key : ", p.WsKey)
	}
}
