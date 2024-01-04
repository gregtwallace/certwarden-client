package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
)

const (
	postRoute = "/legocerthubclient/api/v1/install"
)

// innerPayload is the struct for the unencrypted data that is inside the payload sent from
// LeGo to the client
type innerPayload struct {
	KeyPem  string `json:"key_pem"`
	CertPem string `json:"cert_pem"`
}

// postPayload is the actual payload sent from LeGo to the client
type postPayload struct {
	// Payload is the base64 encoded string of the cipherData produced from encrypting innerPayload
	Payload string `json:"payload"`
}

func (app *app) postKeyAndCert(w http.ResponseWriter, r *http.Request) {
	// verify route is correct, else 404
	if (r.URL.Path != postRoute && r.URL.Path != postRoute+"/") || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// decode body into payload
	payload := postPayload{}
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		app.logger.Debugf("failed to umarshal body (%s)", err)
		return
	}

	bodyDecoded, err := base64.RawURLEncoding.DecodeString(payload.Payload)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		app.logger.Debugf("failed to decode inner payload (%s)", err)
		return
	}

	// decrypt
	nonceSize := app.cipherAEAD.NonceSize()
	nonce, ciphertext := bodyDecoded[:nonceSize], bodyDecoded[nonceSize:]

	bodyDecrypted, err := app.cipherAEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		app.logger.Debugf("failed to decrypt inner payload (%s)", err)
		return
	}

	// right route & authorized, try to do work

	// decode payload
	innerPayload := innerPayload{}

	// unmarshal decrypted data into payload
	err = json.Unmarshal(bodyDecrypted, &innerPayload)
	if err != nil {
		app.logger.Errorf("failed to umarshal decrypted inner payload (%s)", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// process and install new key/cert
	err = app.update([]byte(innerPayload.KeyPem), []byte(innerPayload.CertPem))
	if err != nil {
		app.logger.Errorf("failed to process key and/or cert file(s) from lego post (%s)", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}
