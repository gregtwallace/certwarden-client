package main

import "fmt"

// LeGo Server Endpoints
const (
	serverEndpointDownloadKeys  = "/legocerthub/api/v1/download/privatekeys"
	serverEndpointDownloadCerts = "/legocerthub/api/v1/download/certificates"
)

// updateClientKeyAndCertchain queries the LeGo server and retrieves the specified key
// and certificate PEM from the server. it then updates the app with the new pem
func (app *app) updateClientKeyAndCertchain() error {
	// get key
	keyPem, err := app.httpClient.getPemWithApiKey(app.cfg.ServerAddress+serverEndpointDownloadKeys+"/"+app.cfg.KeyName, app.cfg.KeyApiKey)
	if err != nil {
		return fmt.Errorf("failed to get key pem from lego server (%s)", err)
	}

	// get cert
	certPem, err := app.httpClient.getPemWithApiKey(app.cfg.ServerAddress+serverEndpointDownloadCerts+"/"+app.cfg.CertName, app.cfg.CertApiKey)
	if err != nil {
		return fmt.Errorf("failed to get cert pem from lego server (%s)", err)
	}

	// do update of local tls cert
	err = app.updateClientCert(keyPem, certPem)
	if err != nil {
		return err
	}

	return nil
}
