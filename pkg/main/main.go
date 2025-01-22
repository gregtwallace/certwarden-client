package main

import (
	"time"
)

// version
const appVersion = "0.4.0"

// main entrypoint
func main() {
	// configure app
	app, err := configureApp()
	if err != nil {
		// only fails if config is bad, so fatal ok
		app.logger.Fatalf("failed to configure app (%s)", err)
		// os.Exit(1)
	}

	// try and get newer key/cert from server on start
	currentCertInMemory := false
	err = app.updateClientKeyAndCertchain()
	if err != nil {
		app.logger.Errorf("failed to fetch key/cert from server (%s)", err)
	} else {
		currentCertInMemory = true
	}

	// Fatal if never got a valid TLS certificate (either local or from fetch)
	if !app.tlsCert.HasValidTLSCertificate() {
		app.logger.Fatal("no certificate was available locally or via remote fetch, exiting")
		// os.Exit(1)
	}

	// run / schedule jobs based on if newest cert is confirmed in memory
	if currentCertInMemory {
		// initial fetch worked, try to write disk
		diskNeedsUpdate := app.updateCertFilesAndRestartContainers(true)

		// schedule write, if needed
		if diskNeedsUpdate {
			// fetch was fine but files not written yet, schedule file write
			app.scheduleJobWriteCertsMemoryToDisk()
		}
	} else {
		// failed to get newest cert, so schedule future fetch and write
		app.scheduleJobFetchCertsAndWriteToDisk()
	}

	// start https server
	err = app.startHttpsServer()
	if err != nil {
		app.logger.Fatal("could not start https server (%s)")
		// os.Exit(1)
	}

	// shutdown logic
	// wait for shutdown context to signal
	<-app.shutdownContext.Done()

	// cancel any pending job
	if app.pendingJobCancel != nil {
		app.pendingJobCancel()
	}

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

	app.logger.Info("cert-warden-client exited")
}
