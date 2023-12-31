package main

import (
	"crypto/tls"
	"fmt"
	"sync"
)

// SafeCert is a struct to hold and manage a tls certificate
type SafeCert struct {
	cert *tls.Certificate
	sync.RWMutex
}

// newSafeCert makes a SafeCert using the supplied tlsCert
func NewSafeCert(tlsCert *tls.Certificate) *SafeCert {
	return &SafeCert{
		cert: tlsCert,
	}
}

// TlsCertFunc returns the function to get the tls.Certificate from SafeCert
func (sc *SafeCert) TlsCertFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		sc.RLock()
		defer sc.RUnlock()

		return sc.cert, nil
	}
}

// Update updates the certificate with the specified key and cert pem
func (sc *SafeCert) Update(keyPem, certPem []byte) error {
	sc.Lock()
	defer sc.Unlock()

	// make tls certificate
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return fmt.Errorf("failed to make x509 key pair for cert update (%s)", err)
	}

	// update certificate
	sc.cert = &tlsCert

	return nil
}
