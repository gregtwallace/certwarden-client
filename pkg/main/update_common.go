package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// updateCertFilesAndRestartContainers writes updated pem and any other requested files to the
// storage location. It takes a bool arg `onlyIfMissing` that will only allow writing and
// restarting if any of the needed files are missing or unreadable (vs. just stale).
func (app *app) updateCertFilesAndRestartContainers(onlyIfMissing bool) (diskNeedsUpdate bool) {
	// get current pem data from client
	keyPemApp, certPemApp := app.tlsCert.Read()

	// read key.pem
	keyFileExists := true
	keyFileUpdated := false
	// check if file exists
	if _, err := os.Stat(app.cfg.CertStoragePath + "/key.pem"); errors.Is(err, os.ErrNotExist) {
		keyFileExists = false
	}
	// if exists, read it and compare
	if keyFileExists {
		pemFile, err := os.ReadFile(app.cfg.CertStoragePath + "/key.pem")
		if err != nil {
			// if cant read file, treat as if doesn't exist
			keyFileExists = false
			app.logger.Errorf("could not read key.pem from disk (%s), will treat as non-existing", err)
		} else if !bytes.Equal(pemFile, keyPemApp) {
			// if file and app pem are different, its an update
			keyFileUpdated = true
		}
	}

	// read certchain.pem
	certFileExists := true
	certFileUpdated := false
	// check if file exists
	certFileExists = true
	if _, err := os.Stat(app.cfg.CertStoragePath + "/certchain.pem"); errors.Is(err, os.ErrNotExist) {
		certFileExists = false
	}

	// if exists, read it and compare
	if certFileExists {
		pemFile, err := os.ReadFile(app.cfg.CertStoragePath + "/certchain.pem")
		if err != nil {
			// if cant read file, treat as if doesn't exist
			certFileExists = false
			app.logger.Errorf("could not read certchain.pem from disk (%s), will treat as non-existing", err)
		} else if !bytes.Equal(pemFile, certPemApp) {
			// if file and app pem are different, its an update
			certFileUpdated = true

			// if its an update, check expiration of on disk cert
			cert, _ := pem.Decode(pemFile)

			// parse DER bytes
			derCert, err := x509.ParseCertificate(cert.Bytes)
			if err != nil {
				// disk cert not validly parsed, treat as not exist
				certFileExists = false
			} else if time.Now().After(derCert.NotAfter) {
				// disk cert expired, treat as not exist
				certFileExists = false
			}
		}
	}

	// check for modern pfx
	modernPfxFileExists := true
	if _, err := os.Stat(app.cfg.CertStoragePath + "/" + app.cfg.PfxFilename); errors.Is(err, os.ErrNotExist) {
		modernPfxFileExists = false
	}

	// check for legacy pfx
	legacyPfxFileExists := true
	if _, err := os.Stat(app.cfg.CertStoragePath + "/" + app.cfg.PfxLegacyFilename); errors.Is(err, os.ErrNotExist) {
		legacyPfxFileExists = false
	}

	// calculate if any desired files are missing
	anyFileMissing := !keyFileExists || !certFileExists || (app.cfg.PfxCreate && !modernPfxFileExists) || (app.cfg.PfxLegacyCreate && !legacyPfxFileExists)
	// track if any new files are written; at end, if yes, restart containers
	wroteAnyFiles := false
	failedAnyWrite := false

	// write key pem (always if not exist, if exists but updated: only write if NOT only missing files OR any file is missing)
	// AKA write file anyway even if !onlyIfMissing if something else is missing, because something will be written and trigger restart anyway
	if !keyFileExists || (keyFileUpdated && (!onlyIfMissing || anyFileMissing)) {
		err := os.WriteFile(app.cfg.CertStoragePath+"/key.pem", keyPemApp, app.cfg.KeyPermissions)
		if err != nil {
			app.logger.Errorf("failed to write key.pem (%s)", err)
			failedAnyWrite = true
			// failed, but keep trying
		} else {
			wroteAnyFiles = true
			app.logger.Info("wrote new key.pem file")
		}
	}

	// write cert pem
	if !certFileExists || (certFileUpdated && (!onlyIfMissing || anyFileMissing)) {
		err := os.WriteFile(app.cfg.CertStoragePath+"/certchain.pem", certPemApp, app.cfg.CertPermissions)
		if err != nil {
			app.logger.Errorf("failed to write certchain.pem (%s)", err)
			failedAnyWrite = true
			// failed, but keep trying
		} else {
			wroteAnyFiles = true
			app.logger.Info("wrote new certchain.pem file")
		}
	}

	// use key/cert updated as proxy for other files updated check
	keyOrCertFileUpdated := keyFileUpdated || certFileUpdated

	// write modern pfx (if enabled)
	if app.cfg.PfxCreate && (!modernPfxFileExists || (keyOrCertFileUpdated && (!onlyIfMissing || anyFileMissing))) {
		pfx, err := makeModernPfx(keyPemApp, certPemApp, app.cfg.PfxPassword)
		if err != nil {
			app.logger.Errorf("failed to make modern pfx (%s)", err)
			// failed, but keep trying
			failedAnyWrite = true
		} else {
			err = os.WriteFile(app.cfg.CertStoragePath+"/"+app.cfg.PfxFilename, pfx, app.cfg.KeyPermissions)
			if err != nil {
				app.logger.Errorf("failed to write %s (%s)", app.cfg.PfxFilename, err)
				// failed, but keep trying
				failedAnyWrite = true
			} else {
				app.logger.Infof("wrote new modern pfx %s file", app.cfg.PfxFilename)
				wroteAnyFiles = true
			}
		}
	}

	// write legacy pfx (if enabled)
	if app.cfg.PfxLegacyCreate && (!legacyPfxFileExists || (keyOrCertFileUpdated && (!onlyIfMissing || anyFileMissing))) {
		pfx, err := makeLegacyPfx(keyPemApp, certPemApp, app.cfg.PfxLegacyPassword)
		if err != nil {
			app.logger.Errorf("failed to make legacy pfx (%s)", err)
			// failed, but keep trying
			failedAnyWrite = true
		} else {
			err = os.WriteFile(app.cfg.CertStoragePath+"/"+app.cfg.PfxLegacyFilename, pfx, app.cfg.KeyPermissions)
			if err != nil {
				app.logger.Errorf("failed to write legacy pfx %s (%s)", app.cfg.PfxLegacyFilename, err)
				// failed, but keep trying
				failedAnyWrite = true
			} else {
				app.logger.Infof("wrote new legacy pfx %s file", app.cfg.PfxLegacyFilename)
				wroteAnyFiles = true
			}
		}
	}

	// done updating files, restart docker containers (if any files written)
	if len(app.cfg.DockerContainersToRestart) > 0 {
		if wroteAnyFiles {
			app.logger.Info("at least one file changed, updating docker containers")
			app.restartOrStopDockerContainers()
		} else {
			app.logger.Debug("not updating docker containers, no file changes")
		}
	}

	app.logger.Info("key/cert file update complete")

	// if key or cert in memory was different than disk AND files didn't get written, disk is due for an update
	diskNeedsUpdate = (keyOrCertFileUpdated && !wroteAnyFiles) || failedAnyWrite
	return diskNeedsUpdate
}

// updateClientCert validates the specified key and cert pem are valid and updates the client's cert
// key pair (if not already up to date)
func (app *app) updateClientCert(keyPem, certPem []byte) error {
	app.logger.Info("running key/cert update of lego client's cert")

	// update app's key/cert (validates the pair as well, tls won't work if bad)
	updated, err := app.tlsCert.Update(keyPem, certPem)
	if err != nil {
		return fmt.Errorf("failed to update key and/or cert in lego client tls cert (%s)", err)
	}

	// log
	if updated {
		app.logger.Infof("new tls key/cert installed in https server")
	} else {
		app.logger.Infof("new tls key/cert same as current, no update performed")
	}

	return nil
}
