package tls

import "log"

type SimpleTLSLogger struct {
	infoLogger  *log.Logger
	errorLogger *log.Logger
	verbose     bool
}

func (l *SimpleTLSLogger) Infof(format string, v ...any) {
	l.infoLogger.Printf(format, v...)
}

func (l *SimpleTLSLogger) Error(format string) {
	l.errorLogger.Println(format)
}

func (l *SimpleTLSLogger) Errorf(format string, v ...any) {
	l.errorLogger.Printf(format, v...)
}

func (SimpleTLSServerConnection) ChiperName(chiper uint16) string {
	switch chiper {
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case TLS_AES_128_CCM_SHA256:
		return "TLS_AES_128_CCM_SHA256"
	case TLS_AES_128_CCM_8_SHA256:
		return "TLS_AES_128_CCM_8_SHA256"
	case 0xc02f:
		return "ECDHE-RSA-AES128-GCM-SHA256"
	case 0xc02b:
		return "ECDHE-ECDSA-AES128-GCM-SHA256"
	case 0xc030:
		return "ECDHE-RSA-AES256-GCM-SHA384"
	case 0xc02c:
		return "ECDHE-ECDSA-AES256-GCM-SHA384"
	case 0xc027:
		return "ECDHE-RSA-AES128-SHA256"
	case 0xcca9:
		return "ECDHE-ECDSA-CHACHA20-POLY1305"
	case 0xcca8:
		return "ECDHE-RSA-CHACHA20-POLY1305"
	case 0xc009:
		return "ECDHE-ECDSA-AES128-SHA"
	case 0xc013:
		return "ECDHE-RSA-AES128-SHA"
	case 0xc014:
		return "ECDHE-RSA-AES256-SHA"
	default:
		return "-"
	}
}
