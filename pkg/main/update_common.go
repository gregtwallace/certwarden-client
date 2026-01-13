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
func (app *app) updateCertFilesAndRestartContainers(certIndex int, onlyIfMissing bool) (diskNeedsUpdate bool) {
	app.logger.Infof("updating cert %d files and restarting containers", certIndex)

	// get current pem data from client
	keyPemApp, certPemApp := app.tlsCerts[certIndex].Read()

	// read key.pem
	keyFileExists := true
	keyFileUpdated := false
	// check if file exists
	if _, err := os.Stat(app.cfg.Certs[certIndex].CertStoragePath + "/" + app.cfg.Certs[certIndex].KeyPemFilename); errors.Is(err, os.ErrNotExist) {
		keyFileExists = false
	}
	// if exists, read it and compare
	if keyFileExists {
		pemFile, err := os.ReadFile(app.cfg.Certs[certIndex].CertStoragePath + "/" + app.cfg.Certs[certIndex].KeyPemFilename)
		if err != nil {
			// if cant read file, treat as if doesn't exist
			keyFileExists = false
			app.logger.Errorf("could not read %s from disk (%s), will treat as non-existing", app.cfg.Certs[certIndex].KeyPemFilename, err)
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
	if _, err := os.Stat(app.cfg.Certs[certIndex].CertStoragePath + "/" + app.cfg.Certs[certIndex].CertPemFilename); errors.Is(err, os.ErrNotExist) {
		certFileExists = false
	}

	// if exists, read it and compare
	if certFileExists {
		pemFile, err := os.ReadFile(app.cfg.Certs[certIndex].CertStoragePath + "/" + app.cfg.Certs[certIndex].CertPemFilename)
		if err != nil {
			// if cant read file, treat as if doesn't exist
			certFileExists = false
			app.logger.Errorf("could not read %s from disk (%s), will treat as non-existing", app.cfg.Certs[certIndex].CertPemFilename, err)
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
	if _, err := os.Stat(app.cfg.Certs[certIndex].CertStoragePath + "/" + app.cfg.Certs[certIndex].PfxFilename); errors.Is(err, os.ErrNotExist) {
		modernPfxFileExists = false
	}

	// check for legacy pfx
	legacyPfxFileExists := true
	if _, err := os.Stat(app.cfg.Certs[certIndex].CertStoragePath + "/" + app.cfg.Certs[certIndex].PfxLegacyFilename); errors.Is(err, os.ErrNotExist) {
		legacyPfxFileExists = false
	}

	// calculate if any desired files are missing
	anyFileMissing := !keyFileExists || !certFileExists || (app.cfg.Certs[certIndex].PfxCreate && !modernPfxFileExists) || (app.cfg.Certs[certIndex].PfxLegacyCreate && !legacyPfxFileExists)
	// track if any new files are written; at end, if yes, restart containers
	wroteAnyFiles := false
	failedAnyWrite := false

	// write key pem (always if not exist, if exists but updated: only write if NOT only missing files OR any file is missing)
	// AKA write file anyway even if !onlyIfMissing if something else is missing, because something will be written and trigger restart anyway
	if !keyFileExists || (keyFileUpdated && (!onlyIfMissing || anyFileMissing)) {
		err := os.WriteFile(app.cfg.Certs[certIndex].CertStoragePath+"/"+app.cfg.Certs[certIndex].KeyPemFilename, keyPemApp, app.cfg.Certs[certIndex].KeyPermissions)
		if err != nil {
			app.logger.Errorf("failed to write key %s file (%s)", app.cfg.Certs[certIndex].KeyPemFilename, err)
			failedAnyWrite = true
			// failed, but keep trying
		} else {
			wroteAnyFiles = true
			app.logger.Infof("wrote new key %s file", app.cfg.Certs[certIndex].KeyPemFilename)
		}
	}

	// write cert pem
	if !certFileExists || (certFileUpdated && (!onlyIfMissing || anyFileMissing)) {
		err := os.WriteFile(app.cfg.Certs[certIndex].CertStoragePath+"/"+app.cfg.Certs[certIndex].CertPemFilename, certPemApp, app.cfg.Certs[certIndex].CertPermissions)
		if err != nil {
			app.logger.Errorf("failed to write cert %s file (%s)", app.cfg.Certs[certIndex].CertPemFilename, err)
			failedAnyWrite = true
			// failed, but keep trying
		} else {
			wroteAnyFiles = true
			app.logger.Infof("wrote new cert %s file", app.cfg.Certs[certIndex].CertPemFilename)
		}
	}

	// use key/cert updated as proxy for other files updated check
	keyOrCertFileUpdated := keyFileUpdated || certFileUpdated

	// write modern pfx (if enabled)
	if app.cfg.Certs[certIndex].PfxCreate && (!modernPfxFileExists || (keyOrCertFileUpdated && (!onlyIfMissing || anyFileMissing))) {
		pfx, err := makeModernPfx(keyPemApp, certPemApp, app.cfg.Certs[certIndex].PfxPassword)
		if err != nil {
			app.logger.Errorf("failed to make modern pfx (%s)", err)
			// failed, but keep trying
			failedAnyWrite = true
		} else {
			err = os.WriteFile(app.cfg.Certs[certIndex].CertStoragePath+"/"+app.cfg.Certs[certIndex].PfxFilename, pfx, app.cfg.Certs[certIndex].KeyPermissions)
			if err != nil {
				app.logger.Errorf("failed to write %s (%s)", app.cfg.Certs[certIndex].PfxFilename, err)
				// failed, but keep trying
				failedAnyWrite = true
			} else {
				app.logger.Infof("wrote new modern pfx %s file", app.cfg.Certs[certIndex].PfxFilename)
				wroteAnyFiles = true
			}
		}
	}

	// write legacy pfx (if enabled)
	if app.cfg.Certs[certIndex].PfxLegacyCreate && (!legacyPfxFileExists || (keyOrCertFileUpdated && (!onlyIfMissing || anyFileMissing))) {
		pfx, err := makeLegacyPfx(keyPemApp, certPemApp, app.cfg.Certs[certIndex].PfxLegacyPassword)
		if err != nil {
			app.logger.Errorf("failed to make legacy pfx (%s)", err)
			// failed, but keep trying
			failedAnyWrite = true
		} else {
			err = os.WriteFile(app.cfg.Certs[certIndex].CertStoragePath+"/"+app.cfg.Certs[certIndex].PfxLegacyFilename, pfx, app.cfg.Certs[certIndex].KeyPermissions)
			if err != nil {
				app.logger.Errorf("failed to write legacy pfx %s (%s)", app.cfg.Certs[certIndex].PfxLegacyFilename, err)
				// failed, but keep trying
				failedAnyWrite = true
			} else {
				app.logger.Infof("wrote new legacy pfx %s file", app.cfg.Certs[certIndex].PfxLegacyFilename)
				wroteAnyFiles = true
			}
		}
	}

	// done updating files, restart docker containers (if any files written)
	if len(app.cfg.Certs[certIndex].DockerContainersToRestart) > 0 {
		if wroteAnyFiles {
			app.logger.Infof("at least one file changed for cert %d, updating docker containers", certIndex)
			app.restartOrStopDockerContainers(certIndex)
		} else {
			app.logger.Debugf("not updating docker containers for cert %d, no changes were written to disk", certIndex)
		}
	}

	// execute commands in docker containers (if any files written)
	if len(app.cfg.Certs[certIndex].DockerContainerCommands) > 0 {
		if wroteAnyFiles {
			app.logger.Infof("at least one file changed for cert %d, executing docker container commands", certIndex)
			app.executeDockerContainerCommands(certIndex)
		} else {
			app.logger.Debugf("not executing docker container commands for cert %d, no changes were written to disk", certIndex)
		}
	}

	// log result
	diskNeedsUpdate = false
	if failedAnyWrite {
		// any write failure
		app.logger.Errorf("key/cert file(s) write at least one write failed for cert %d", certIndex)
		diskNeedsUpdate = true
	} else if wroteAnyFiles {
		// no write failure, and wrote file(s)
		app.logger.Infof("key/cert file(s) write successfully wrote complete disk update for cert %d", certIndex)
		diskNeedsUpdate = false
	} else if keyOrCertFileUpdated && !wroteAnyFiles /* && not needed but just in case above code changes */ {
		// didn't write any files but update needed
		app.logger.Infof("key/cert file(s) write not performed, but a write is needed for cert %d", certIndex)
		diskNeedsUpdate = true
	} else {
		// everything good to go
		app.logger.Infof("key/cert file(s) write not performed, all files are up to date for cert %d", certIndex)
	}

	return diskNeedsUpdate
}

// updateClientCert validates the specified key and cert pem are valid and updates the client's cert
// key pair in memory (if not already up to date)
func (app *app) updateClientCert(keyPem, certPem []byte, certIndex int) error {
	app.logger.Infof("running key/cert update of cert %d in cert warden client memory", certIndex)

	// update app's key/cert (validates the pair as well, tls won't work if bad)
	updated, err := app.tlsCerts[certIndex].Update(keyPem, certPem)
	if err != nil {
		return fmt.Errorf("failed to update key and/or cert %d in cert warden client memory (%s)", certIndex, err)
	}

	// log
	if updated {
		app.logger.Infof("new tls key/cert %d loaded into certwarden client memory", certIndex)
		if certIndex == 0 {
			app.logger.Infof("certwarden client https server certificate updated")
		}
	} else {
		app.logger.Infof("new tls key/cert %d same as current in cert warden client, no update performed", certIndex)
	}

	return nil
}
