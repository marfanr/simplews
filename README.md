# SimpleWs

<p align="center">
  <img src="https://github.com/marfanr/simplews/blob/master/screenshot/ss.png?raw=true" width="48%" />
  <img src="https://github.com/marfanr/simplews/blob/master/screenshot/ss2.png?raw=true" width="48%" />
</p>

Simple WebSocket and TLS implementation from scratch in Go.

SimpleWs is a learning-focused networking project that implements WebSocket ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)) and TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) starting directly from a TCP connection. The project was built to understand how modern network communication works by implementing the protocols step by step rather than relying entirely on existing high-level libraries.

# How This Works
<p align="center">
<img src="https://github.com/marfanr/simplews/blob/master/screenshot/diagram.png?raw=true" width="48%"/>
</p>

when client intiates connection using the TLS protocol, first step is sending `Client Hello . this message allow the client to communicate its supported parameters to the server and begin the negotiation process.

In the `ClientHello`, the client offers the supported cipher suites, protocol versions, and various extensions. Some commonly used extensions include the Server Name Indication (SNI), which identifies the target hostname, and Key Share, which contains the client's key exchange parameters. The cipher suites indicate the algorithms used to encrypt the messages during the communication, while the Key Share is used to establish shared keys later through the key scheduling process.

After receiving the `ClientHello`, the server will respond with multiple messages, starting with the `ServerHello`. In the `ServerHello`, the server will choose which TLS version to use, which cipher suite to use, which compression method to use, and send the key share. However, in this project, for now, it only supports `TLS_AES_128_GCM_SHA256` for the cipher suite and `X25519` for the key exchange algorithm.


# How To Run
first edit the main.go file in the example and replace the certificate and private key path with the paths to your own certificate and private key

```
cd example
go build
./example
```

## Goals

- [x] Understand networking from the TCP layer upward
- [x] Explore the TLS 1.3 protocol
- [x] Improve understanding of network protocols and their implementation in Go
- [x] Learn how WebSocket communication works
- [x] Build a simple foundation for secure WebSocket communication (WSS)

## References

* [RFC 6455 — The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455)
* [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
