package main

import (
	"fmt"
	"os"
)

// processPem validates the specified key and cert pem are valid and then saves them. it also
// generates any additional file formats specified in config
func (app *app) processPem(keyPem, certPem []byte) error {
	// update app's key/cert (validates the pair as well, tls won't work if bad)
	err := app.tlsCert.Update(keyPem, certPem)
	if err != nil {
		return fmt.Errorf("failed to key and/or cert in lego client tls cert (%s)", err)
	}
	app.logger.Infof("new tls cert and key installed in https server")

	// save pem files to disk
	err = os.WriteFile(app.cfg.CertStoragePath+"/key.pem", keyPem, app.cfg.KeyPermissions)
	if err != nil {
		return fmt.Errorf("failed to write key.pem (%s)", err)
	}

	err = os.WriteFile(app.cfg.CertStoragePath+"/certchain.pem", certPem, app.cfg.CertPermissions)
	if err != nil {
		return fmt.Errorf("failed to write certchain.pem (%s)", err)
	}

	// if enabled - make modern pfx and save to disk
	if app.cfg.PfxCreate {
		pfx, err := makeModernPfx(keyPem, certPem, app.cfg.PfxPassword)
		if err != nil {
			return fmt.Errorf("failed to make modern pfx (%s)", err)
		} else {
			err = os.WriteFile(app.cfg.CertStoragePath+"/"+app.cfg.PfxFilename, pfx, app.cfg.KeyPermissions)
			if err != nil {
				return fmt.Errorf("failed to write %s (%s)", app.cfg.PfxFilename, err)
			}
		}
	}

	// if enabled - make legacy pfx and save to disk
	if app.cfg.PfxLegacyCreate {
		pfx, err := makeLegacyPfx(keyPem, certPem, app.cfg.PfxLegacyPassword)
		if err != nil {
			return fmt.Errorf("failed to make legacy pfx (%s)", err)
		} else {
			err = os.WriteFile(app.cfg.CertStoragePath+"/"+app.cfg.PfxLegacyFilename, pfx, app.cfg.KeyPermissions)
			if err != nil {
				return fmt.Errorf("failed to write %s (%s)", app.cfg.PfxLegacyFilename, err)
			}
		}
	}

	app.logger.Infof("successfully updated on disk cert and key files")

	return nil
}
