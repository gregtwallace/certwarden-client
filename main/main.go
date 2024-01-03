package main

import (
	"errors"
	"os"
	"time"
)

// version
const appVersion = "0.1.0"

// main entrypoint
func main() {
	// configure app
	app, err := configureApp()
	if err != nil {
		app.logger.Fatalf("failed to configure app (%s)", err)
		// os.Exit(1)
	}

	// make cert storage path (if not exist)
	_, err = os.Stat(app.cfg.CertStoragePath)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(app.cfg.CertStoragePath, 0755)
		if err != nil {
			app.logger.Fatalf("failed to make cert storage directory (%s)", err)
			// os.Exit(1)
		} else {
			app.logger.Infof("cert storage path created")
		}
	} else if err != nil {
		app.logger.Fatalf("failed to stat cert storage directory (%s)", err)
		// os.Exit(1)
	}

	// TODO: (?) Add loop with exponential backoff as opposed to fatal?

	// do initial cert update on disk
	keyPem, certPem, err := app.fetchKeyAndCertchain()
	if err != nil {
		app.logger.Fatalf("failed to fetch initial key and/or cert from LeGo (%s)", err)
		// os.Exit(1)
	}

	err = app.processPem(keyPem, certPem)
	if err != nil {
		app.logger.Fatalf("failed to process initial key and/or cert file(s) (%s)", err)
		// os.Exit(1)
	}

	// start https server
	_ = app.startHttpsServer()

	// shutdown logic
	// wait for shutdown context to signal
	<-app.shutdownContext.Done()

	// wait for each component/service to shutdown
	// but also implement a maxWait chan to force close (panic)
	maxWait := 2 * time.Minute
	waitChan := make(chan struct{})

	// close wait chan when wg finishes waiting
	go func() {
		defer close(waitChan)
		app.shutdownWaitgroup.Wait()
	}()

	select {
	case <-waitChan:
		// continue, normal
	case <-time.After(maxWait):
		// timed out
		app.logger.Panic("graceful shutdown of component(s) failed due to time out, forcing shutdown")
	}

	app.logger.Info("lego-certhub-client exited")
}
