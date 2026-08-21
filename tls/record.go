package tls

import "encoding/binary"

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
	out = append(out, s.ContentType)
	binary.BigEndian.PutUint16(out[1:3], s.LegacyRecordVersion)
	binary.BigEndian.PutUint16(out[3:5], s.recordLength)
	copy(out[5:], s.data)
	return out
}
