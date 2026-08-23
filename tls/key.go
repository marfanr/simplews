package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

type SimpleTLSKeys struct {
	handShakeSecret          []byte
	clientHandShakeTraffic   []byte
	serverHandShakeTraffic   []byte
	clientApplicationTraffic []byte
	serverApplicationTraffic []byte
	serverHSWriteKey         []byte
	serverHSWriteIV          []byte
	clientHSWriteKey         []byte
	clientHSWriteIV          []byte
	clientAppWriteKey        []byte
	clientAppWriteIV         []byte
	finishedKey              []byte
	masterSecret             []byte
}

var SERVER_PREFERENCE = []uint16{
	TLS_AES_128_GCM_SHA256,
}

func (hs SimpleTLSServerConnection) SelectChiper() (uint16, error) {
	for _, pref := range SERVER_PREFERENCE {
		for _, choice := range hs.chiperSuites {
			if pref == choice {
				fmt.Printf("found match chippers: %s\n", hs.ChiperName(choice))
				return choice, nil
			}
		}
	}
	return 0, errors.New("no chipper supported")
}

func gcmNonce(iv []byte, seq uint64) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	seq_byte := make([]byte, len(iv))
	binary.BigEndian.PutUint64(seq_byte[len(seq_byte)-8:], seq)

	for i := range nonce {
		nonce[i] ^= seq_byte[i]
	}
	return nonce
}

func seal(inner []byte, key, iv []byte, seq uint64) []byte {
	// depend on the chosen chipper
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := gcmNonce(iv, seq)
	length := len(inner) + gcm.Overhead()
	add := []byte{23, 0x03, 0x03, byte(length >> 8), byte(length)}
	return gcm.Seal(nil, nonce, inner, add)
}

func (hs *SimpleTLSServerConnection) computeSharedSecret(ng uint16) []byte {
	switch ng {
	case TLS_X25519:
		{
			curve := ecdh.X25519()
			priv, err := curve.NewPrivateKey(hs.priv)
			if err != nil {
				panic(err)
			}
			clientPub, err := priv.Curve().NewPublicKey(hs.keyExchanges[0].Key)
			if err != nil {
				panic(err)
			}

			shared, err := priv.ECDH(clientPub)
			if err != nil {
				panic(err)
			}

			return shared
		}
	}
	return nil
}

func (hs *SimpleTLSServerConnection) generateKeyShare(ng uint16) ([]byte, []byte) {
	switch ng {
	case TLS_X25519:
		curve := ecdh.X25519()
		r := make([]byte, 32)
		if _, err := rand.Read(r); err != nil {
			panic(err)
		}

		priv, err := curve.NewPrivateKey(r)
		if err != nil {
			panic(err)
		}

		pub := priv.PublicKey()

		return pub.Bytes(), priv.Bytes()
	}
	return nil, nil
}

/*
RFC 8446 7.1
HKDF-Expand-Label
*/
func (SimpleTLSServerConnection) expandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel bytes.Buffer
	hkdfLabel.Write([]byte{byte(length >> 8), byte(length)})

	fullLabel := "tls13 " + label
	hkdfLabel.WriteByte(byte(len(fullLabel)))
	hkdfLabel.WriteString(fullLabel)

	hkdfLabel.WriteByte(byte(len(context)))
	hkdfLabel.Write(context)

	res, err := hkdf.Expand(h, secret, hkdfLabel.String(), length)
	if err != nil {
		panic(err)
	}
	return res
}

/*
RFC 8446 7.1
Derive-Secret
*/
func (hs SimpleTLSServerConnection) deriveKey(shared_secret []byte, label string, transcript []byte) []byte {
	// TODO: deepend on the prefered namedgroup from keyexchanges
	sum := sha256.Sum256(transcript)
	return hs.expandLabel(sha256.New, shared_secret, label, sum[:], sha256.Size)

}

/*
RFC 8446 7.1
Key Schedule
*/
func (hs *SimpleTLSServerConnection) keyScheduleHandshake() {
	fmt.Println("\nHandshake Secret")
	shared_secret := hs.computeSharedSecret(hs.keyExchanges[0].NamedGroup)

	var size int = sha256.Size
	h := sha256.New
	zero := make([]byte, size)

	// TODO: handle PSK if available
	earlySecret, err := hkdf.Extract(h, zero, zero)
	if err != nil {
		panic(err)
	}

	// derived
	derived := hs.deriveKey(earlySecret, "derived", []byte{})

	fmt.Printf("	1st Derived : %x\n", derived)
	hs.secrets.handShakeSecret, err = hkdf.Extract(h, shared_secret, derived)
	if err != nil {
		panic(err)
	}
	hs.secrets.clientHandShakeTraffic = hs.deriveKey(hs.secrets.handShakeSecret, "c hs traffic", hs.transcript)
	hs.secrets.serverHandShakeTraffic = hs.deriveKey(hs.secrets.handShakeSecret, "s hs traffic", hs.transcript)

	hs.secrets.serverHSWriteKey = hs.expandLabel(h, hs.secrets.serverHandShakeTraffic, "key", []byte{}, 16)
	hs.secrets.serverHSWriteIV = hs.expandLabel(h, hs.secrets.serverHandShakeTraffic, "iv", []byte{}, 12)
	hs.secrets.clientHSWriteKey = hs.expandLabel(h, hs.secrets.clientHandShakeTraffic, "key", []byte{}, 16)
	hs.secrets.clientHSWriteIV = hs.expandLabel(h, hs.secrets.clientHandShakeTraffic, "iv", []byte{}, 12)
	hs.clientHSSeq = 0
	hs.serverHSSeq = 0

	hs.secrets.finishedKey = hs.expandLabel(h, hs.secrets.serverHandShakeTraffic, "finished", []byte{}, sha256.Size)

	fmt.Printf("Client Write Key (for decryption): %x\n", hs.secrets.clientHSWriteKey)
	fmt.Printf("Client Write IV: %x\n", hs.secrets.clientHSWriteIV)
}

func (hs *SimpleTLSServerConnection) keyScheduleApplication() {
	fmt.Println("Application Secret")
	derivedHs := hs.deriveKey(hs.secrets.handShakeSecret, "derived", []byte{})

	zero := make([]byte, sha256.Size)
	var err error
	hs.secrets.masterSecret, err = hkdf.Extract(sha256.New, zero, derivedHs)
	if err != nil {
		panic(err)
	}

	hs.secrets.clientApplicationTraffic = hs.deriveKey(hs.secrets.masterSecret, "c ap traffic", hs.transcript)
	hs.secrets.serverApplicationTraffic = hs.deriveKey(hs.secrets.masterSecret, "s ap traffic", hs.transcript)
	hs.secrets.clientAppWriteKey = hs.expandLabel(sha256.New, hs.secrets.clientApplicationTraffic, "key", []byte{}, 16)
	hs.secrets.clientAppWriteIV = hs.expandLabel(sha256.New, hs.secrets.clientApplicationTraffic, "iv", []byte{}, 12)

	fmt.Printf("Client App Write Key (for decryption): %x\n", hs.secrets.clientAppWriteKey)
	fmt.Printf("Client App Write IV: %x\n", hs.secrets.clientAppWriteIV)
}
