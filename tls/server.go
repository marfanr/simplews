package tls

import (
	"io"
	"log"
	"net"
	"os"
)

type SimpleTlsContext struct {
	io.ReadWriter
	data       []byte
	serverConn *SimpleTLSServerConnection
}

func (ctx *SimpleTlsContext) Read(p []byte) (n int, err error) {
	if len(ctx.data) == 0 {
		return 0, io.EOF
	}

	n = copy(p, ctx.data)
	ctx.data = ctx.data[n:]
	return n, nil
}

func (ctx *SimpleTlsContext) Write(p []byte) (n int, err error) {
	securedData := seal(
		p,
		ctx.serverConn.secrets.clientAppWriteKey,
		ctx.serverConn.secrets.clientAppWriteIV,
		ctx.serverConn.serverAppSeq,
	)
	ctx.serverConn.serverAppSeq++

	recordData := SimpleTLSRecordProtocol{
		ContentType:         TLS_RECORD_APPLICATION_DATA,
		LegacyRecordVersion: 0x0303,
		recordLength:        uint16(len(securedData)),
		data:                securedData,
	}.Build()
	return ctx.serverConn.con.Write(recordData)
}

type simpleTLShandler func(*SimpleTlsContext)

type SimpleTlsConfig struct {
	CertPath    string
	PrivKeyPath string
}

type SimpleTlsServer struct {
	listener net.Listener
	handlers []simpleTLShandler
	logger   *SimpleTLSLogger
	config   SimpleTlsConfig
}

type keyExchange struct {
	NamedGroup uint16
	Length     uint16
	Key        []byte
}

// used for each connection
type SimpleTLSServerConnection struct {
	server *SimpleTlsServer
	con    net.Conn

	hostName             string
	extendedMasterSecret []byte
	sessionId            []byte
	chiperSuites         []uint16
	keyExchanges         []keyExchange
	supportedVersion     []uint16
	signatureAlgorithms  []uint16

	// certificate
	priv []byte
	pub  []byte
	pem  []byte

	// RFC 8446 4.4.1
	transcript []byte

	// chosen named group
	serverHSSeq  uint64
	clientHSSeq  uint64
	clientAppSeq uint64
	serverAppSeq uint64

	secrets SimpleTLSKeys

	handshakeFinished bool

	ctx    *SimpleTlsContext
	logger *SimpleTLSLogger
}

func NewServer(listener net.Listener, config SimpleTlsConfig) SimpleTlsServer {
	return SimpleTlsServer{
		listener: listener,
		logger: &SimpleTLSLogger{
			infoLogger:  log.New(os.Stdout, "[info] ", log.Ltime|log.Lmicroseconds),
			errorLogger: log.New(os.Stdout, "[error] ", log.Ltime|log.Lmicroseconds),
			verbose:     true,
		},
		config: config,
	}
}

// main loop fot tcp server (blocking)
func (s *SimpleTlsServer) Serve() {
	s.logger.infoLogger.Println("TLS Server running...")
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.logger.errorLogger.Println(err.Error())
		}

		go s.handleConnection(conn)
	}
}

func (s *SimpleTlsServer) AddHandler(handler func(w *SimpleTlsContext)) {
	s.handlers = append(s.handlers, handler)
}

// must be running on go routine
func (s *SimpleTlsServer) handleConnection(con net.Conn) {
	tlsCon := SimpleTLSServerConnection{
		server: s,
		con:    con,
		logger: s.logger,
		ctx: &SimpleTlsContext{
			data: make([]byte, 0),
		},
	}
	tlsCon.ctx.serverConn = &tlsCon

	// first is record protocol
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(con, header[:]); err != nil {
			s.logger.Error(err.Error())
			return
		}

		record := ParseRecordProtocol(header)
		s.logger.Infof("new TLS request with type %d (len %d)", record.ContentType, record.recordLength)

		fragment := make([]byte, record.recordLength)
		if _, err := io.ReadFull(con, fragment); err != nil {
			s.logger.errorLogger.Println(err)
			return
		}

		switch record.ContentType {
		case TLS_RECORD_HANDSHAKE:
			tlsCon.HandleTLSHandShake(fragment)
		case TLS_RECORD_CHANGE_CHIPPER:
			{
				// TODO: not handleit
				s.logger.Infof("Change chipper requested ...\n")
				break
			}
		case TLS_RECORD_APPLICATION_DATA:
			tlsCon.HandleApplicationData(fragment)
		default:
			s.logger.Infof("Unknown content type: %d\n", record.ContentType)
		}
	}
}

func (hs *SimpleTLSServerConnection) HandleApplicationData(data []byte) {
	var decoded SimpleTLSRecordProtocol
	var err error
	if !hs.handshakeFinished {
		decoded, err = openTLSRecord(
			data,
			hs.secrets.clientHSWriteKey,
			hs.secrets.clientHSWriteIV,
			hs.clientHSSeq,
		)
		hs.handshakeFinished = true
		hs.clientHSSeq++
	} else {
		decoded, err = openTLSRecord(
			data,
			hs.secrets.clientAppWriteKey,
			hs.secrets.clientAppWriteIV,
			hs.clientAppSeq,
		)
		hs.clientAppSeq++
	}

	if err != nil {
		hs.logger.Errorf("open tls record error %s\n", err.Error())
		return
	}

	switch decoded.ContentType {
	case TLS_RECORD_HANDSHAKE:
		{
			hs.HandleTLSHandShake(decoded.data)
			break
		}
	case TLS_RECORD_APPLICATION_DATA:
		{
			// application data
			hs.ctx.data = append(hs.ctx.data, decoded.data...)
			for _, handle := range hs.server.handlers {
				handle(hs.ctx)
			}
		}
	default:
		{
			hs.logger.Errorf("uknown handshake type %d\n", decoded.ContentType)
		}
	}

}
