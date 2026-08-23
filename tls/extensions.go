package tls

import (
	"encoding/binary"
	"fmt"
)

/*
RFC  8446 4.2
Extensions
*/
type SimpleTLSExtension struct {
	extensionType uint16
	length        uint16
	data          []byte

	// internal
	serverConn *SimpleTLSServerConnection
	logger     *SimpleTLSLogger
}

func (hs *simpleTLSHandshake) parseExtensions(data []byte) {
	pos := 0
	for pos < len(data) {
		extensionDataLen := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		dataEnd := pos + 4 + int(extensionDataLen)
		ext := SimpleTLSExtension{
			extensionType: binary.BigEndian.Uint16(data[pos : pos+2]),
			length:        extensionDataLen,
			data:          data[pos+4 : dataEnd],
			serverConn:    hs.serverConn,
			logger:        hs.logger,
		}
		ext.process()
		pos = dataEnd
	}
}

func (ext *SimpleTLSExtension) process() {
	// TODO: handle backward compatible (ex: extended master secret)
	switch ext.extensionType {
	case TLS_EXT_SERVER_NAME:
		ext.parseServerName()
	case TLS_EXT_KEY_SHARE:
		ext.parseKeyShare()
	case TLS_EXT_SUPPORTED_VERSION:
		ext.parseSupportedVersion()
	case TLS_EXT_PSK_KEY_EXCHANGES_MODE:
		ext.parsePSKKeyExchangesMode()
	case TLS_EXT_PRE_SHARED_KEY:
		ext.parsePreSharedKey()
	case TLS_EXT_SIGNATURED_ALG:
		ext.parseSignaturedAlg()
	case TLS_EXT_SIGNATURED_ALG_CERT:
		fmt.Println("found signature algorith cert")
	default:
		ext.logger.Infof("unhandled extension type %d (%d)\n", ext.extensionType, ext.length)
	}
}

func (ext *SimpleTLSExtension) parseServerName() {
	// RFC 6066 3
	// server name list

	listLen := binary.BigEndian.Uint16(ext.data[:2])
	serverName := ext.data[2 : 2+int(listLen)]
	nameType := serverName[0]
	switch nameType {
	// host_name
	case TLS_SN_HOSTNAME:
		{
			hostNameLen := binary.BigEndian.Uint16(serverName[1:3])
			ext.serverConn.hostName = string(serverName[3 : 3+int(hostNameLen)])
			ext.logger.Infof(" host name: %s (%d)\n", ext.serverConn.hostName, hostNameLen)
		}
	}
}

/*
RFC 8446 4.2.8
Key Share
*/
func (ext *SimpleTLSExtension) parseKeyShare() {
	clientShareLength := binary.BigEndian.Uint16(ext.data[:2])
	pos := 2
	end := pos + int(clientShareLength)
	for pos < end {
		ng := binary.BigEndian.Uint16(ext.data[pos : pos+2])
		pos += 2
		fmt.Printf("Named Group : 0x%04x\n", ng)

		key_exc_length := binary.BigEndian.Uint16(ext.data[pos : pos+2])
		pos += 2

		key_exc := ext.data[pos : pos+int(key_exc_length)]
		pos += int(key_exc_length)
		fmt.Printf("	Key Exchange (Length %d) %x\n", key_exc_length, key_exc)

		ext.serverConn.keyExchanges = append(ext.serverConn.keyExchanges, keyExchange{
			NamedGroup: ng,
			Length:     key_exc_length,
			Key:        key_exc,
		})
	}
}

/*
RFC 8446 4.2.1
Supported Versions
*/
func (ext *SimpleTLSExtension) parseSupportedVersion() {
	len := int(ext.data[0])
	pos := 1
	for i := 0; i < len; i += 2 {
		ver := binary.BigEndian.Uint16(ext.data[pos : pos+2])
		pos += 2
		ext.serverConn.supportedVersion = append(ext.serverConn.supportedVersion, ver)
	}
	ext.logger.Infof("Supported Version : %x\n", ext.serverConn.supportedVersion)
}

/*
RFC 8446 4.2.3
Signature Algorithms
*/
func (ext *SimpleTLSExtension) parseSignaturedAlg() {
	sigLen := binary.BigEndian.Uint16(ext.data[:2])
	pos := 2
	for i := 0; i < int(sigLen); i += 2 {
		alg := binary.BigEndian.Uint16(ext.data[pos : pos+2])
		ext.serverConn.signatureAlgorithms = append(ext.serverConn.signatureAlgorithms, alg)
		pos += 2
	}
	ext.logger.Infof("Supported Algorithm : %x\n", ext.serverConn.signatureAlgorithms)
}

// TODO:
func (ext *SimpleTLSExtension) parsePSKKeyExchangesMode() {
	ext.logger.Infof("found PSK Key Exhange\n")
}

func (ext *SimpleTLSExtension) parsePreSharedKey() {
	ext.logger.Infof("found Pre Shared Key\n")
}

/*
Extension Builder
*/
func BuildSupportedVersion(version uint16) SimpleTLSExtension {
	versionData := []byte{byte(version >> 8), byte(version)}
	return SimpleTLSExtension{
		extensionType: TLS_EXT_SUPPORTED_VERSION,
		length:        2,
		data:          versionData,
	}
}

func BuildKeyShare(namedGroup uint16, publicKey []byte) SimpleTLSExtension {
	keyShareData := make([]byte, 0, 4+len(publicKey))
	keyShareData = append(keyShareData, byte(namedGroup>>8), byte(namedGroup))
	publicKeyLen := len(publicKey)
	keyShareData = append(keyShareData, byte(publicKeyLen>>8), byte(publicKeyLen))
	keyShareData = append(keyShareData, publicKey...)

	return SimpleTLSExtension{
		extensionType: TLS_EXT_KEY_SHARE,
		length:        uint16(len(keyShareData)),
		data:          keyShareData,
	}
}

func (hs *simpleTLSHandshake) buildExtension(exts []SimpleTLSExtension) []byte {
	extentionsData := make([]byte, 0, 256)
	for _, ext := range exts {
		extentionsData = append(extentionsData, byte(ext.extensionType>>8), byte(ext.extensionType))
		extentionsData = append(extentionsData, byte(ext.length>>8), byte(ext.length))
		extentionsData = append(extentionsData, ext.data...)
	}

	outData := make([]byte, 0, 512)
	extensionsLen := len(extentionsData)
	outData = append(outData, byte(extensionsLen>>8), byte(extensionsLen))
	outData = append(outData, extentionsData...)
	return outData
}
