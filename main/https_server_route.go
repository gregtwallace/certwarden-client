package main

import (
	"encoding/json"
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

	// confirm authorization else 401
	if app.apiKey != r.Header.Get(authHeader) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// right route & authorized, try to do work
	app.logger.Info("received authorized post to install new key and certificate")

	// decode payload
	var payload postKeyAndCertPayload

	// decode body into payload
	err := json.NewDecoder(r.Body).Decode(&payload)
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
