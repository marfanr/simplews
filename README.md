# SimpleWs

<p align="center">
  <img src="https://github.com/marfanr/simplews/blob/master/screenshot/ss.png?raw=true" width="48%" />
  <img src="https://github.com/marfanr/simplews/blob/master/screenshot/ss2.png?raw=true" width="48%" />
</p>

Simple WebSocket and TLS implementation from scratch in Go.

SimpleWs is a learning-focused networking project that implements WebSocket ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)) and TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) starting directly from a TCP connection.

The project was built to understand how modern network communication works by implementing the protocols step by step rather than relying entirely on existing high-level libraries.

# How To Run
first edit the main.go file in the example and replace the certificate and private key path with the paths to your own certificate and private key

```
cd example
go build
./example
```

## Goals

* Understand networking from the TCP layer upward
* Explore the TLS 1.3 protocol
* Improve understanding of network protocols and their implementation in Go
* Learn how WebSocket communication works
* Build a simple foundation for secure WebSocket communication (WSS)

## Current Scope

* TCP connection handling
* WebSocket protocol
* TLS 1.3 protocol
* Secure WebSocket (WSS) communication
* Basic client/server communication

The project is primarily intended for learning, experimentation, and understanding protocol design. It is not intended to replace production-grade implementations.

## References

* [RFC 6455 — The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455)
* [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
