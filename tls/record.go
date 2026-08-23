package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

/*
Record Protocol
RFC 8446 5.1
*/
type SimpleTLSRecordProtocol struct {
	ContentType         byte
	LegacyRecordVersion uint16
	recordLength        uint16
	data                []byte
}

func ParseRecordProtocol(data []byte) SimpleTLSRecordProtocol {
	content_type := data[0]
	version := binary.BigEndian.Uint16(data[1:3])
	recordLength := binary.BigEndian.Uint16(data[3:5])

	return SimpleTLSRecordProtocol{
		ContentType:         content_type,
		LegacyRecordVersion: version,
		recordLength:        recordLength,
		data:                data[5:],
	}
}

func (s SimpleTLSRecordProtocol) Build() []byte {
	out := make([]byte, 5+len(s.data))
	out[0] = s.ContentType
	binary.BigEndian.PutUint16(out[1:3], s.LegacyRecordVersion)
	binary.BigEndian.PutUint16(out[3:5], s.recordLength)
	copy(out[5:], s.data)
	return out
}

func openTLSRecord(record []byte, key, iv []byte, seq uint64) (SimpleTLSRecordProtocol, error) {
	// TODO: depend on chiper
	out := SimpleTLSRecordProtocol{}
	block, err := aes.NewCipher(key)
	if err != nil {
		return out, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return out, err
	}

	add := []byte{
		TLS_RECORD_APPLICATION_DATA,
		0x03,
		0x03,
		byte(len(record) >> 8),
		byte(len(record)),
	}
	nonce := gcmNonce(iv, seq)
	plaint, err := gcm.Open(nil, nonce, record, add)
	if err != nil {
		return out, err
	}

	if len(plaint) == 0 {
		return out, errors.New("empty TLSInnerPlaintext")
	}

	l := len(plaint) - 1
	for l > 0 && plaint[l] == 0 {
		l--
	}

	if l < 0 {
		return out, errors.New("invalid TLSInnerPlaintext")
	}

	out.ContentType = plaint[l]
	out.recordLength = uint16(l)
	out.LegacyRecordVersion = 0x0303
	out.data = plaint[:l]

	return out, nil
}
