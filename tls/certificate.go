package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func LoadPEMFile(path string) [][]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	var certs [][]byte
	for {
		p, r := pem.Decode(data)
		if p == nil {
			break
		}
		if p.Type == "CERTIFICATE" {
			certs = append(certs, p.Bytes)
		}
		data = r
	}

	return certs
}

func LoadPrivCertficateFile(path string) any {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	p, _ := pem.Decode(data)
	if p == nil {
		panic("failed to decode PEM")
	}
	fmt.Printf("Block Type: %s\n", p.Type)

	// TODO: for now hardcoded only for pkcs8
	k, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}

	return k
}

/*
RFC 8446 4.4.2
Certificate
*/
type CertificateEntry struct {
	Data      []byte
	Extension []byte
}

type Certificate struct {
	Entries []CertificateEntry
	Context []byte
}

func (c Certificate) build() []byte {
	// asuumed need 512 byte
	entries := make([]byte, 0, 512)
	for _, entry := range c.Entries {
		certLen := len(entry.Data)
		entryData := make([]byte, 0, 5+certLen)
		entryData = append(entryData, byte(certLen>>16),
			byte(certLen>>8),
			byte(certLen))
		entryData = append(entryData, entry.Data...)

		// for now, no certificate extension
		entryData = append(entryData, 0, 0)
		entries = append(entries, entryData...)
	}

	data := make([]byte, 0, len(entries)+4)
	// for now, no request context
	data = append(data, 0)
	entryLen := len(entries)
	data = append(data,
		byte(entryLen>>16),
		byte(entryLen>>8),
		byte(entryLen),
	)
	data = append(data, entries...)
	return data
}

/*
RFC 8446 4.4.3
Certificate Verify

PrivData must be either *ecdsa.PrivateKey or *rsa.PrivateKey
*/
type CertificateVerify struct {
	Alg      uint16
	PrivData any
}

func (c CertificateVerify) build(transcript []byte) ([]byte, error) {
	content := make([]byte, 0, 64)
	content = append(content, bytes.Repeat([]byte{0x20}, 64)...)
	content = append(content, []byte(TLS_CERT_VERIFY_CONTEXT_STR)...)

	var digest []byte
	var hashFunc crypto.Hash
	switch c.Alg {
	case TLS_SIG_ECDSA_SECP256R1_SHA256:
		{
			hashed := sha256.Sum256(transcript)
			content = append(content, 0)
			content = append(content, hashed[:]...)
			d := sha256.Sum256(content)
			digest = d[:]
			hashFunc = crypto.SHA256
			break
		}
	}

	var signedContent []byte
	var err error
	switch key := c.PrivData.(type) {
	case *ecdsa.PrivateKey:
		signedContent, err = ecdsa.SignASN1(
			rand.Reader,
			key,
			digest,
		)

	case *rsa.PrivateKey:
		// TODO: handle pkcs and pss based on 4.2.3
		signedContent, err = rsa.SignPKCS1v15(
			rand.Reader,
			key,
			hashFunc,
			digest,
		)

	default:
		return nil, errors.New("unsupported private key")
	}
	signedContentLength := len(signedContent)

	out := make([]byte, 0, 4+len(signedContent))
	out = append(out, byte(c.Alg>>8), byte(c.Alg))
	out = append(out, byte(signedContentLength>>8), byte(signedContentLength))
	out = append(out, signedContent...)
	return out, err
}
