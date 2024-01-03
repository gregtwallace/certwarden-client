package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
)

const (
	authHeader = "Authorization"
	postRoute  = "/legocerthubclient/api/v1/install"
)

// postKeyAndCertPayload is the data the LeGo server sends to the client
type postKeyAndCertPayload struct {
	KeyPem  string `json:"key_pem"`
	CertPem string `json:"cert_pem"`
}

func (app *app) postKeyAndCert(w http.ResponseWriter, r *http.Request) {
	// verify route is correct, else 404
	if (r.URL.Path != postRoute && r.URL.Path != postRoute+"/") || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// resp vary header
	w.Header().Add("Vary", authHeader)

	// read, decode, and try to decrypt request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		app.logger.Debugf("failed to read body")
		return
	}

	bodyDecoded, err := base64.RawURLEncoding.DecodeString(string(bodyBytes))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		app.logger.Debugf("failed to decode body")
		return
	}

	// decrypt
	nonceSize := app.cipherAEAD.NonceSize()
	nonce, ciphertext := bodyDecoded[:nonceSize], bodyDecoded[nonceSize:]

	bodyDecrypted, err := app.cipherAEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		app.logger.Debugf("failed to decrypt body")
		return
	}

	// right route & authorized, try to do work

	// decode payload
	var payload postKeyAndCertPayload

	// unmarshal decrypted data into payload
	err = json.Unmarshal(bodyDecrypted, &payload)
	if err != nil {
		app.logger.Errorf("failed to decode payload from lego post (%s)", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// process and install new key/cert
	err = app.processPem([]byte(payload.KeyPem), []byte(payload.CertPem))
	if err != nil {
		app.logger.Errorf("failed to process key and/or cert file(s) from lego post (%s)", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}
