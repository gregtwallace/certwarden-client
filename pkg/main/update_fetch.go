package main

import "fmt"

// Server Endpoints
const (
	serverEndpointDownloadKeys  = "/certwarden/api/v1/download/privatekeys"
	serverEndpointDownloadCerts = "/certwarden/api/v1/download/certificates"
)

// updateClientKeyAndCertchain queries the server and retrieves the specified key
// and certificate PEM from the server. it then updates the app with the new pem
func (app *app) updateClientKeyAndCertchain() error {
	// get key
	keyPem, err := app.getPemWithApiKey(app.cfg.ServerAddress+serverEndpointDownloadKeys+"/"+app.cfg.KeyName, app.cfg.KeyApiKey)
	if err != nil {
		return fmt.Errorf("failed to get key pem from server (%s)", err)
	}

	// get cert
	certPem, err := app.getPemWithApiKey(app.cfg.ServerAddress+serverEndpointDownloadCerts+"/"+app.cfg.CertName, app.cfg.CertApiKey)
	if err != nil {
		return fmt.Errorf("failed to get cert pem from server (%s)", err)
	}

	// do update of local tls cert
	err = app.updateClientCert(keyPem, certPem)
	if err != nil {
		return err
	}

	return nil
}
