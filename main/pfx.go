package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"software.sslmate.com/src/go-pkcs12"
)

// keyPemToKey returns the private key from pemBytes
func keyPemToKey(keyPem []byte) (key any, err error) {
	// decode private key
	keyPemBlock, _ := pem.Decode(keyPem)
	if keyPemBlock == nil {
		return nil, errors.New("key pem block did not decode")
	}

	// parsing depends on block type
	switch keyPemBlock.Type {
	case "RSA PRIVATE KEY": // PKCS1
		var rsaKey *rsa.PrivateKey
		rsaKey, err = x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return rsaKey, nil

	case "EC PRIVATE KEY": // SEC1, ASN.1
		var ecdKey *ecdsa.PrivateKey
		ecdKey, err = x509.ParseECPrivateKey(keyPemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return ecdKey, nil

	case "PRIVATE KEY": // PKCS8
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(keyPemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return pkcs8Key, nil

	default:
		// fallthrough
	}

	return nil, errors.New("key pem block type unsupported")
}

// certPemToCerts returns the certificate from cert pem bytes. if the pem
// bytes contain more than one certificate, the first is returned as the
// certificate and the rest are returned as an array for what is presumably
// the rest of a chain
func certPemToCerts(certPem []byte) (cert *x509.Certificate, certChain []*x509.Certificate, err error) {
	// decode 1st cert
	certPemBlock, rest := pem.Decode(certPem)
	if certPemBlock == nil {
		return nil, nil, errors.New("cert pem block did not decode")
	}

	// parse 1st cert
	cert, err = x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// decode cert chain
	certChainPemBlocks := []*pem.Block{}
	for {
		// try to decode next block
		var nextCertBlock *pem.Block
		nextCertBlock, rest = pem.Decode(rest)

		// no next block, done
		if nextCertBlock == nil {
			break
		}

		// success, append
		certChainPemBlocks = append(certChainPemBlocks, nextCertBlock)
	}

	// parse each cert in chain
	certChain = []*x509.Certificate{}
	for i := range certChainPemBlocks {
		certChainMember, err := x509.ParseCertificate(certChainPemBlocks[i].Bytes)
		if err != nil {
			return nil, nil, err
		}

		certChain = append(certChain, certChainMember)
	}

	return cert, certChain, nil
}

// makeModernPfx returns the pkcs12 pfx data for the given key and cert pem
func makeModernPfx(keyPem, certPem []byte, password string) (pfxData []byte, err error) {
	// get private key
	key, err := keyPemToKey(keyPem)
	if err != nil {
		return nil, err
	}

	// get cert and chain (if there is a chain)
	cert, certChain, err := certPemToCerts(certPem)
	if err != nil {
		return nil, err
	}

	// encode using modern pkcs12 standard
	pfxData, err = pkcs12.Modern.Encode(key, cert, certChain, password)
	if err != nil {
		return nil, err
	}

	return pfxData, nil
}

// makeLegacyPfx returns the pkcs12 pfx data for the given key and cert pem but in a
// legacy format that should be avoided unless the application only supports the legacy
// format
func makeLegacyPfx(keyPem, certPem []byte, password string) (pfxData []byte, err error) {
	// get private key
	key, err := keyPemToKey(keyPem)
	if err != nil {
		return nil, err
	}

	// get cert and chain (if there is a chain)
	cert, certChain, err := certPemToCerts(certPem)
	if err != nil {
		return nil, err
	}

	// encode using modern pkcs12 standard
	pfxData, err = pkcs12.Legacy.Encode(key, cert, certChain, password)
	if err != nil {
		return nil, err
	}

	return pfxData, nil
}
