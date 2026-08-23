package tls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

/*
Handshake Protocol
RFC 8446 4
*/
type simpleTLSHandshake struct {
	handshakeType byte
	length        uint32
	data          []byte

	// internal
	serverConn *SimpleTLSServerConnection
	logger     *SimpleTLSLogger
}

func (hs simpleTLSHandshake) Build() []byte {
	out := make([]byte, 4+hs.length)
	out[0] = hs.handshakeType
	out[1] = byte(hs.length >> 16)
	out[2] = byte(hs.length >> 8)
	out[3] = byte(hs.length)
	copy(out[4:], hs.data)
	return out
}

func (hs simpleTLSHandshake) BuildEncrypted() []byte {
	plaintData := hs.Build()
	hs.serverConn.transcript = append(hs.serverConn.transcript, plaintData...)
	inner := append(append([]byte{}, plaintData...), 22)
	sealed := seal(inner,
		hs.serverConn.secrets.serverHSWriteKey,
		hs.serverConn.secrets.serverHSWriteIV,
		hs.serverConn.serverHSSeq)
	hs.serverConn.serverHSSeq += 1
	return sealed
}

func (s *SimpleTLSServerConnection) HandleTLSHandShake(fragment []byte) {
	hs := simpleTLSHandshake{
		handshakeType: fragment[0],
		length:        uint32(fragment[1])<<16 | uint32(fragment[2])<<8 | uint32(fragment[3]),
		data:          fragment[4:],
		serverConn:    s,
		logger:        s.logger,
	}

	body := hs.data

	switch hs.handshakeType {
	case TLS_HS_CLIENT_HELLO:
		{
			// concate into transcript
			s.transcript = append(s.transcript, fragment...)
			hs.handleClientHello()
			break
		}
	case TLS_HS_FINISHED:
		{

			finishedKey := s.expandLabel(sha256.New, s.secrets.clientHandShakeTraffic, "finished", []byte{}, sha256.Size)
			th := sha256.Sum256(s.transcript)
			mac := hmac.New(sha256.New, finishedKey)
			mac.Write(th[:])
			expected := mac.Sum(nil)

			got := body
			if !hmac.Equal(expected, got) {
				fmt.Println("client Finished verify_data tidak cocok")
			}

			fmt.Println("Finished ")
		}
	}
}

/*
Handshake Client Protocol
RFC 8446 4.1.2
*/
func (hs *simpleTLSHandshake) handleClientHello() {
	protoc_ver := binary.BigEndian.Uint16(hs.data[0:2])
	hs.logger.Infof("CLIENT_HELLO (Legacy version : 0x%x)\n", protoc_ver)

	// start after random (34)
	// not used, only for make data unpredictable
	pos := 34
	sessionIdLength := int(hs.data[pos])
	pos++

	hs.serverConn.sessionId = hs.data[pos : pos+sessionIdLength]
	hs.logger.Infof("Session ID : %x\n", hs.serverConn.sessionId)
	pos += sessionIdLength

	chiper_len := binary.BigEndian.Uint16(hs.data[pos : pos+2])
	pos += 2
	for i := 0; i < int(chiper_len); i += 2 {
		chiper := binary.BigEndian.Uint16(hs.data[pos+i : pos+i+2])
		hs.serverConn.chiperSuites = append(hs.serverConn.chiperSuites, chiper)
	}
	pos += int(chiper_len)

	// TODO: implemen compression if client requested
	compress_method_len := int(hs.data[pos])
	pos++
	for i := 0; i < compress_method_len; i++ {
		compression := hs.data[pos+i]
		if compression > 0 {
			hs.logger.Infof("Compression : %x\n", compression)
		}
	}
	pos += compress_method_len

	// parse extension
	extensionLen := binary.BigEndian.Uint16(hs.data[pos : pos+2])
	pos += 2
	hs.parseExtensions(hs.data[pos : pos+int(extensionLen)])
	pos += int(extensionLen)

	// response server hello
	hs.SendServerHello()

	// key shcedule
	hs.serverConn.keyScheduleHandshake()
	hs.serverConn.handshakeFinished = false

	// continue sending certificate
	hs.SendEncryptedExtensions()
	hs.SendCertificate()
	hs.SendCertificateVerify()
	hs.SendFinished()

	hs.serverConn.keyScheduleApplication()
}

/*
RFC 8446 4.1.3
Server Hello
*/
func (hs *simpleTLSHandshake) SendServerHello() {
	hs.logger.Infof("\nreplying server echo..\n")

	serverHello := make([]byte, 0, 256)
	serverHello = append(serverHello, 0x03, 0x03)
	r := make([]byte, TLS_RAND_LENGTH)
	if _, err := rand.Read(r); err != nil {
		panic(err)
	}
	serverHello = append(serverHello, r...)
	serverHello = append(serverHello, TLS_RAND_LENGTH)
	serverHello = append(serverHello, hs.serverConn.sessionId...)

	ch, err := hs.serverConn.SelectChiper()
	if err != nil {
		hs.logger.Errorf("No chipper supported, end connection\n")
		hs.serverConn.con.Close()
		return
	}
	hs.logger.Infof("Selected cipher: 0x%04x (%s)\n",
		ch,
		hs.serverConn.ChiperName(ch),
	)
	serverHello = append(serverHello, byte(ch>>8), byte(ch))

	// compression (for now no compression)
	serverHello = append(serverHello, 0)

	// for now only select first, 1.3
	ver := hs.serverConn.supportedVersion[0]

	chosen := hs.serverConn.keyExchanges[0]
	pub, priv := hs.serverConn.generateKeyShare(chosen.NamedGroup)
	hs.serverConn.priv = priv
	hs.serverConn.pub = pub

	ext := hs.buildExtension([]SimpleTLSExtension{
		BuildSupportedVersion(ver),
		BuildKeyShare(chosen.NamedGroup, hs.serverConn.pub),
	})

	serverHello = append(serverHello, ext...)
	hsData := simpleTLSHandshake{
		handshakeType: TLS_HS_SERVER_HELLO,
		length:        uint32(len(serverHello)),
		data:          serverHello,
		serverConn:    hs.serverConn,
		logger:        hs.logger,
	}.Build()

	hs.serverConn.transcript = append(hs.serverConn.transcript, hsData...)

	recordData := SimpleTLSRecordProtocol{
		ContentType:         TLS_RECORD_HANDSHAKE,
		LegacyRecordVersion: 0x0303,
		recordLength:        uint16(len(hsData)),
		data:                hsData,
	}.Build()
	if b, err := hs.serverConn.con.Write(recordData); err != nil {
		hs.logger.Errorf("error on sending server hello: %s\n", err.Error())
	} else {
		hs.logger.Infof("Success sending server hello (%d)\n", b)
	}
}

/*
RFC 8446  4.3.1
Encrypted Extensions
*/
func (hs *simpleTLSHandshake) SendEncryptedExtensions() {
	data := []byte{0, 0}
	encryptedData := simpleTLSHandshake{
		handshakeType: TLS_HS_ENCRYPTED_EXTENSIONS,
		length:        uint32(len(data)),
		data:          data,
		serverConn:    hs.serverConn,
		logger:        hs.logger,
	}.BuildEncrypted()

	recordData := SimpleTLSRecordProtocol{
		ContentType:         TLS_RECORD_APPLICATION_DATA,
		LegacyRecordVersion: 0x0303,
		recordLength:        uint16(len(encryptedData)),
		data:                encryptedData,
	}.Build()
	if b, err := hs.serverConn.con.Write(recordData); err != nil {
		hs.logger.Errorf("error on sending encrypted extension : %s\n", err.Error())
	} else {
		hs.logger.Infof("Success sending encrypted extension (%d)\n", b)
	}
}

/*
RFC 8446 4.4.2
Certificate
*/
func (hs *simpleTLSHandshake) SendCertificate() {
	cert := LoadPEMFile(hs.serverConn.server.config.CertPath)

	cerData := (Certificate{
		Entries: []CertificateEntry{
			{
				Data:      cert,
				Extension: nil,
			},
		},
		Context: nil,
	}).build()

	encryptedData := simpleTLSHandshake{
		handshakeType: TLS_HS_CERTIFICATE,
		length:        uint32(len(cerData)),
		data:          cerData,
		serverConn:    hs.serverConn,
		logger:        hs.logger,
	}.BuildEncrypted()

	recordData := SimpleTLSRecordProtocol{
		ContentType:         TLS_RECORD_APPLICATION_DATA,
		LegacyRecordVersion: 0x0303,
		recordLength:        uint16(len(encryptedData)),
		data:                encryptedData,
	}.Build()
	if b, err := hs.serverConn.con.Write(recordData); err != nil {
		hs.logger.Errorf("error on sending encrypted extension : %s\n", err.Error())
	} else {
		hs.logger.Infof("Success sending encrypted extension (%d)\n", b)
	}
}

/*
RFC 8446 4.4.3
Certificate Verify
*/
func (hs *simpleTLSHandshake) SendCertificateVerify() {
	privData := LoadPrivCertficateFile(hs.serverConn.server.config.PrivKeyPath)

	// for now hardcoded choose ECDSA ecdsa_secp256r1_sha256 (0x403)
	// TODO: chosen dynamically based on certificate file and clients offered alg
	encryptedContent, err := CertificateVerify{
		Alg:      TLS_SIG_ECDSA_SECP256R1_SHA256,
		PrivData: privData,
	}.build(hs.serverConn.transcript)

	if err != nil {
		hs.logger.Errorf("error certificate verify: %s\n", err.Error())
	}

	encryptedData := simpleTLSHandshake{
		handshakeType: TLS_HS_CERTIFICATE_VERIFY,
		length:        uint32(len(encryptedContent)),
		data:          encryptedContent,
		serverConn:    hs.serverConn,
		logger:        hs.logger,
	}.BuildEncrypted()

	recordData := SimpleTLSRecordProtocol{
		ContentType:         TLS_RECORD_APPLICATION_DATA,
		LegacyRecordVersion: 0x0303,
		recordLength:        uint16(len(encryptedData)),
		data:                encryptedData,
	}.Build()
	if b, err := hs.serverConn.con.Write(recordData); err != nil {
		hs.logger.Errorf("error on sending encrypted extension : %s\n", err.Error())
	} else {
		hs.logger.Infof("Success sending encrypted extension (%d)\n", b)
	}
}

/*
RFC 8446 4.4.4
Finished
*/
func (hs *simpleTLSHandshake) SendFinished() {
	// TODO: deepend on choosen algorithm
	hashedTranscript := sha256.Sum256(hs.serverConn.transcript)
	hmac := hmac.New(sha256.New, hs.serverConn.secrets.finishedKey)
	hmac.Write(hashedTranscript[:])
	hmacOut := hmac.Sum(nil)

	encryptedData := simpleTLSHandshake{
		handshakeType: TLS_HS_FINISHED,
		length:        uint32(len(hmacOut)),
		data:          hmacOut,
		serverConn:    hs.serverConn,
		logger:        hs.logger,
	}.BuildEncrypted()

	recordData := SimpleTLSRecordProtocol{
		ContentType:         TLS_RECORD_APPLICATION_DATA,
		LegacyRecordVersion: 0x0303,
		recordLength:        uint16(len(encryptedData)),
		data:                encryptedData,
	}.Build()
	if b, err := hs.serverConn.con.Write(recordData); err != nil {
		hs.logger.Errorf("error on sending encrypted extension : %s\n", err.Error())
	} else {
		hs.logger.Infof("Success sending encrypted extension (%d)\n", b)
	}
}
