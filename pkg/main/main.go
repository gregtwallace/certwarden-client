package main

import (
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

	// create or (if needed) update existing key/cert in storage
	keyPem, certPem, err := app.fetchKeyAndCertchain()
	if err != nil {
		app.logger.Fatalf("failed to fetch initial key and/or cert from LeGo (%s)", err)
		// os.Exit(1)
	}

	err = app.update(keyPem, certPem)
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
