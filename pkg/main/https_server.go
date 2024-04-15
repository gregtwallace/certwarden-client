package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// http server timeouts
const httpServerReadTimeout = 5 * time.Second
const httpServerWriteTimeout = 10 * time.Second
const httpServerIdleTimeout = 1 * time.Minute

// startHttpsServer starts the client https server
func (app *app) startHttpsServer() error {
	// http server config
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", app.cfg.BindAddress, app.cfg.BindPort),
		Handler:      http.HandlerFunc(app.postKeyAndCert),
		IdleTimeout:  httpServerIdleTimeout,
		ReadTimeout:  httpServerReadTimeout,
		WriteTimeout: httpServerWriteTimeout,
		TLSConfig: &tls.Config{
			GetCertificate: app.tlsCert.TlsCertFunc(),
		},
	}

	// launch https
	app.logger.Infof("starting https server bound to %s", srv.Addr)

	// create listener for web server
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("https server cannot bind to %s (%s), exiting", srv.Addr, err)
	}

	// start server
	app.shutdownWaitgroup.Add(1)
	go func() {
		defer func() { _ = ln.Close }()

		err := srv.ServeTLS(ln, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			app.logger.Errorf("https server returned error (%s)", err)
		}

		app.logger.Info("https server shutdown complete")
		app.shutdownWaitgroup.Done()
	}()

	// shutdown server when shutdown context closes
	go func() {
		<-app.shutdownContext.Done()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err = srv.Shutdown(ctx)
		if err != nil {
			app.logger.Errorf("error shutting down https server")
		}
	}()

	return nil
}
