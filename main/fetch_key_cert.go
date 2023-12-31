package main

import (
	"fmt"
)

// LeGo Server Endpoints
const (
	serverEndpointDownloadKeys  = "/legocerthub/api/v1/download/privatekeys"
	serverEndpointDownloadCerts = "/legocerthub/api/v1/download/certificates"
)

// fetchKeyAndCertchain queries the LeGo server and retrieves the specified key
// and certificate PEM from the server
func (app *app) fetchKeyAndCertchain() (keyPem, certPem []byte, err error) {
	// get key
	keyPem, err = app.httpClient.getPemWithApiKey(app.cfg.ServerAddress+serverEndpointDownloadKeys+"/"+app.cfg.KeyName, app.cfg.KeyApiKey)
	if err != nil {
		return nil, nil, fmt.Errorf("get key pem failed (%s)", err)
	}

	// get cert
	certPem, err = app.httpClient.getPemWithApiKey(app.cfg.ServerAddress+serverEndpointDownloadCerts+"/"+app.cfg.CertName, app.cfg.CertApiKey)
	if err != nil {
		return nil, nil, fmt.Errorf("get cert pem failed (%s)", err)
	}

	return keyPem, certPem, nil
}
