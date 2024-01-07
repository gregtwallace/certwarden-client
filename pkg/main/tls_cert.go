package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// SafeCert is a struct to hold and manage a tls certificate
type SafeCert struct {
	keyPem  []byte
	certPem []byte

	cert *tls.Certificate

	sync.RWMutex
}

// newSafeCert makes a SafeCert using the supplied tlsCert
func NewSafeCert() *SafeCert {
	return &SafeCert{}
}

// TlsCertFunc returns the function to get the tls.Certificate from SafeCert
func (sc *SafeCert) TlsCertFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		sc.RLock()
		defer sc.RUnlock()

		return sc.cert, nil
	}
}

// HasValieTLSCertificate returns true if the SafeCert has a tls.Certificate, and that
// certificate is not expired. Otherwise it returns false
func (sc *SafeCert) HasValidTLSCertificate() bool {
	sc.RLock()
	defer sc.RUnlock()

	// invalid if no cert
	if sc.cert == nil {
		return false
	}

	// initialize if nil
	if sc.cert.Leaf == nil {
		var err error
		sc.cert.Leaf, err = x509.ParseCertificate(sc.cert.Certificate[0])
		if err != nil {
			return false
		}
	}

	// invalid if expired
	if time.Now().After(sc.cert.Leaf.NotAfter) {
		return false
	}

	return true
}

// Read returns the pem currenlty in use
func (sc *SafeCert) Read() (keyPem, certPem []byte) {
	sc.RLock()
	defer sc.RUnlock()

	return sc.keyPem, sc.certPem
}

// Update updates the certificate with the specified key and cert pem
func (sc *SafeCert) Update(keyPem, certPem []byte) (updated bool, err error) {
	sc.Lock()
	defer sc.Unlock()

	// check if pem is new
	keyUpdated := !bytes.Equal(sc.keyPem, keyPem)
	certUpdated := !bytes.Equal(sc.certPem, certPem)

	// if no update to do, don't do anything
	if !keyUpdated && !certUpdated {
		return false, nil
	}

	// update pem in cert struct
	sc.keyPem = keyPem
	sc.certPem = certPem

	// make tls certificate
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return false, fmt.Errorf("failed to make x509 key pair for tls cert update (%s)", err)
	}

	// update certificate
	sc.cert = &tlsCert

	return true, nil
}
