package main

import (
	"errors"
	"fmt"
	"os"
)

// update validates the specified key and cert pem are valid and then saves them. it also
// generates any additional file formats specified in config. finally, if docker container
// names are specified, restart commands are issued to them
func (app *app) update(keyPem, certPem []byte) error {
	app.logger.Info("running key/cert file update")

	// track if any new files are written; at end, if yes, restart containers
	anyNewFiles := false

	// update app's key/cert (validates the pair as well, tls won't work if bad)
	keyUpdated, certUpdated, err := app.tlsCert.Update(keyPem, certPem)
	if err != nil {
		return fmt.Errorf("failed to key and/or cert in lego client tls cert (%s)", err)
	}

	// log
	if keyUpdated || certUpdated {
		app.logger.Infof("new tls key/cert installed in https server")
	} else {
		app.logger.Infof("new tls key/cert same as current, no update performed")
	}

	// save key pem file to disk
	// check if file exists
	fileExists := true
	if _, err := os.Stat(app.cfg.CertStoragePath + "/key.pem"); errors.Is(err, os.ErrNotExist) {
		fileExists = false
	}

	if !fileExists || keyUpdated {
		anyNewFiles = true

		err = os.WriteFile(app.cfg.CertStoragePath+"/key.pem", keyPem, app.cfg.KeyPermissions)
		if err != nil {
			return fmt.Errorf("failed to write key.pem (%s)", err)
		}
		app.logger.Info("wrote new key.pem file")
	}

	// save cert pem file to disk
	// check if file exists
	fileExists = true
	if _, err := os.Stat(app.cfg.CertStoragePath + "/certchain.pem"); errors.Is(err, os.ErrNotExist) {
		fileExists = false
	}

	if !fileExists || certUpdated {
		anyNewFiles = true

		err = os.WriteFile(app.cfg.CertStoragePath+"/certchain.pem", certPem, app.cfg.CertPermissions)
		if err != nil {
			return fmt.Errorf("failed to write certchain.pem (%s)", err)
		}
		app.logger.Info("wrote new certchain.pem file")
	}

	// if enabled - make modern pfx and save to disk
	if app.cfg.PfxCreate {
		// check if file exists
		fileExists := true
		if _, err := os.Stat(app.cfg.CertStoragePath + "/" + app.cfg.PfxFilename); errors.Is(err, os.ErrNotExist) {
			fileExists = false
		}

		// if file missing or key/cert change, make new file
		if !fileExists || keyUpdated || certUpdated {
			anyNewFiles = true

			pfx, err := makeModernPfx(keyPem, certPem, app.cfg.PfxPassword)
			if err != nil {
				return fmt.Errorf("failed to make modern pfx (%s)", err)
			} else {
				err = os.WriteFile(app.cfg.CertStoragePath+"/"+app.cfg.PfxFilename, pfx, app.cfg.KeyPermissions)
				if err != nil {
					return fmt.Errorf("failed to write %s (%s)", app.cfg.PfxFilename, err)
				}
				app.logger.Infof("wrote new %s file", app.cfg.PfxFilename)
			}
		}
	}

	// if enabled - make legacy pfx and save to disk
	if app.cfg.PfxLegacyCreate {
		// check if file exists
		fileExists := true
		if _, err := os.Stat(app.cfg.CertStoragePath + "/" + app.cfg.PfxLegacyFilename); errors.Is(err, os.ErrNotExist) {
			fileExists = false
		}

		// if file missing or key/cert change, make new file
		if !fileExists || keyUpdated || certUpdated {
			anyNewFiles = true

			pfx, err := makeLegacyPfx(keyPem, certPem, app.cfg.PfxLegacyPassword)
			if err != nil {
				return fmt.Errorf("failed to make legacy pfx (%s)", err)
			} else {
				err = os.WriteFile(app.cfg.CertStoragePath+"/"+app.cfg.PfxLegacyFilename, pfx, app.cfg.KeyPermissions)
				if err != nil {
					return fmt.Errorf("failed to write %s (%s)", app.cfg.PfxLegacyFilename, err)
				}
				app.logger.Infof("wrote new %s file", app.cfg.PfxLegacyFilename)
			}
		}
	}

	// done updating files, restart docker containers
	if len(app.cfg.DockerContainersToRestart) > 0 {
		if anyNewFiles {
			app.logger.Info("at least one file changed, restarting containers")
			err = app.restartDockerContainers()
			if err != nil {
				app.logger.Error("some container(s) failed to restart, review earlier log entries to see which")
			}
		} else {
			app.logger.Debug("not restarting containers, no file changes")
		}
	}

	app.logger.Info("key/cert file update complete")

	return nil
}
