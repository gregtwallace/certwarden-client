package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Environment Variables (to configure client):
// Mandatory:
//		LEGO_CERTHUB_CLIENT_SERVER_ADDRESS	-	DNS name of the LeGo server. Must start with https and have a valid ssl certificate.
//		LEGO_CERTHUB_CLIENT_KEY_NAME				-	Name of private key in LeGo server
//		LEGO_CERTHUB_CLIENT_KEY_APIKEY			- API Key of private key in LeGo server
//		LEGO_CERTHUB_CLIENT_CERT_NAME				- Name of certificate in LeGo server
//		LEGO_CERTHUB_CLIENT_CERT_APIKEY			- API Key of certificate in LeGo server

// Optional:
//		LEGO_CERTHUB_CLIENT_LOGLEVEL				- zap log level for the app (default: info)

// 		LEGO_CERTHUB_CLIENT_CERT_PATH				- the path to save all keys and certificates to
//    LEGO_CERTHUB_CLIENT_KEY_PERM				- permissions for files containing the key
//    LEGO_CERTHUB_CLIENT_CERT_PERM				- permissions for files only containing the cert

//    LEGO_CERTHUB_CLIENT_PFX_CREATE			- if `true`, an additional pkcs12 encoded key/certchain will be generated with modern algorithms
//    LEGO_CERTHUB_CLIENT_PFX_FILENAME		- if pfx create enabled, the filename for the pfx generated
//    LEGO_CERTHUB_CLIENT_PFX_PASSWORD		- if pfx create enabled, the password for the pfx file generated

//		Note: Do not use `LEGACY` unless your application specifically requires it
//    LEGO_CERTHUB_CLIENT_PFX_LEGACY_CREATE			- if `true`, an additional pkcs12 encoded key/certchain will be generated using legacy algorithms
//    LEGO_CERTHUB_CLIENT_PFX_LEGACY_FILENAME		- if pfx create enabled, the filename for the legacy pfx generated
//    LEGO_CERTHUB_CLIENT_PFX_LEGACY_PASSWORD		- if pfx create enabled, the password for the legacy pfx file generated

// defaults for Optional vars
const (
	defaultLogLevel = zapcore.InfoLevel

	defaultCertStoragePath = "/opt/legoclient/certs"
	defaultKeyPermissions  = fs.FileMode(0640)
	defaultCertPermissions = fs.FileMode(0644)

	defaultPFXCreate   = false
	defaultPFXFilename = "key_certchain.pfx"
	defaultPFXPassword = ""

	defaultPFXLegacyCreate   = false
	defaultPFXLegacyFilename = "key_certchain.legacy.pfx"
	defaultPFXLegacyPassword = ""
)

//
//
//

// app is the struct for the main application
type app struct {
	logger *zap.SugaredLogger
	cfg    *config

	shutdownContext   context.Context
	shutdownWaitgroup *sync.WaitGroup

	httpClient *httpClient
	tlsCert    *SafeCert
}

// config holds all of the lego client configuration
type config struct {
	LogLevel          zapcore.Level
	ServerAddress     string
	KeyName           string
	KeyApiKey         string
	CertName          string
	CertApiKey        string
	CertStoragePath   string
	KeyPermissions    fs.FileMode
	CertPermissions   fs.FileMode
	PfxCreate         bool
	PfxFilename       string
	PfxPassword       string
	PfxLegacyCreate   bool
	PfxLegacyFilename string
	PfxLegacyPassword string
}

// configureApp creates the application from environment variables and/or defaults;
// an error is returned if a mandatory variable is missing or invalid
func configureApp() (*app, error) {
	// LEGO_CERTHUB_CLIENT_LOGLEVEL - optional
	logLevelEnv := os.Getenv("LEGO_CERTHUB_CLIENT_LOGLEVEL")
	logLevel, logLevelErr := zapcore.ParseLevel(logLevelEnv)
	if logLevelErr != nil {
		logLevel = defaultLogLevel
	}
	logger := makeZapLogger(logLevel)
	logger.Infof("starting LeGo CertHub Client v%s", appVersion)
	// deferred log message for if log level was not specified
	if logLevelErr != nil {
		logger.Infof("LEGO_CERTHUB_CLIENT_SERVER_ADDRESS not specified or invalid, using default \"%s\"", defaultLogLevel)
	}

	// make app
	app := &app{
		logger:     logger,
		cfg:        &config{LogLevel: logLevel},
		httpClient: newHttpClient(),
		tlsCert:    NewSafeCert(nil),
	}

	// make rest of config

	// mandatory

	// LEGO_CERTHUB_CLIENT_SERVER_ADDRESS
	app.cfg.ServerAddress = os.Getenv("LEGO_CERTHUB_CLIENT_SERVER_ADDRESS")
	if app.cfg.ServerAddress == "" || !strings.HasPrefix(app.cfg.ServerAddress, "https://") {
		return app, errors.New("LEGO_CERTHUB_CLIENT_SERVER_ADDRESS is required and must start with https://")
	}

	// LEGO_CERTHUB_CLIENT_KEY_NAME
	app.cfg.KeyName = os.Getenv("LEGO_CERTHUB_CLIENT_KEY_NAME")
	if app.cfg.KeyName == "" {
		return app, errors.New("LEGO_CERTHUB_CLIENT_KEY_NAME is required")
	}

	// LEGO_CERTHUB_CLIENT_KEY_APIKEY
	app.cfg.KeyApiKey = os.Getenv("LEGO_CERTHUB_CLIENT_KEY_APIKEY")
	if app.cfg.KeyApiKey == "" {
		return app, errors.New("LEGO_CERTHUB_CLIENT_KEY_APIKEY is required")
	}

	// LEGO_CERTHUB_CLIENT_CERT_NAME
	app.cfg.CertName = os.Getenv("LEGO_CERTHUB_CLIENT_CERT_NAME")
	if app.cfg.CertName == "" {
		return app, errors.New("LEGO_CERTHUB_CLIENT_CERT_NAME is required")
	}

	// LEGO_CERTHUB_CLIENT_CERT_APIKEY
	app.cfg.CertApiKey = os.Getenv("LEGO_CERTHUB_CLIENT_CERT_APIKEY")
	if app.cfg.CertApiKey == "" {
		return app, errors.New("LEGO_CERTHUB_CLIENT_CERT_APIKEY is required")
	}

	// optional

	// LEGO_CERTHUB_CLIENT_CERT_PATH
	app.cfg.CertStoragePath = os.Getenv("LEGO_CERTHUB_CLIENT_CERT_PATH")
	if app.cfg.CertStoragePath == "" {
		app.logger.Debugf("LEGO_CERTHUB_CLIENT_CERT_PATH not specified, using default \"%s\"", defaultCertStoragePath)
		app.cfg.CertStoragePath = defaultCertStoragePath
	}

	// LEGO_CERTHUB_CLIENT_KEY_PERM
	keyPerm := os.Getenv("LEGO_CERTHUB_CLIENT_KEY_PERM")
	keyPermInt, err := strconv.Atoi(keyPerm)
	if keyPerm == "" || err != nil {
		app.logger.Debugf("LEGO_CERTHUB_CLIENT_KEY_PERM not specified or invalid, using default \"%o\"", defaultKeyPermissions)
		app.cfg.KeyPermissions = defaultKeyPermissions
	} else {
		app.cfg.KeyPermissions = fs.FileMode(keyPermInt)
	}

	// LEGO_CERTHUB_CLIENT_CERT_PERM
	certPerm := os.Getenv("LEGO_CERTHUB_CLIENT_CERT_PERM")
	certPermInt, err := strconv.Atoi(certPerm)
	if certPerm == "" || err != nil {
		app.logger.Debugf("LEGO_CERTHUB_CLIENT_CERT_PERM not specified, using default \"%o\"", defaultCertPermissions)
		app.cfg.CertPermissions = defaultCertPermissions
	} else {
		app.cfg.CertPermissions = fs.FileMode(certPermInt)
	}

	// LEGO_CERTHUB_CLIENT_PFX_CREATE
	pfxCreate := os.Getenv("LEGO_CERTHUB_CLIENT_PFX_CREATE")
	if pfxCreate == "true" {
		app.cfg.PfxCreate = true
	} else if pfxCreate == "false" {
		app.cfg.PfxCreate = false
	} else {
		app.logger.Debugf("LEGO_CERTHUB_CLIENT_PFX_CREATE not specified or invalid, using default \"%t\"", defaultPFXCreate)
		app.cfg.PfxCreate = defaultPFXCreate
	}

	if app.cfg.PfxCreate {
		// LEGO_CERTHUB_CLIENT_PFX_FILENAME
		app.cfg.PfxFilename = os.Getenv("LEGO_CERTHUB_CLIENT_PFX_FILENAME")
		if app.cfg.PfxFilename == "" {
			app.logger.Debugf("LEGO_CERTHUB_CLIENT_PFX_FILENAME not specified, using default \"%s\"", defaultPFXFilename)
			app.cfg.PfxFilename = defaultPFXFilename
		}

		// LEGO_CERTHUB_CLIENT_PFX_PASSWORD
		exists := false
		app.cfg.PfxPassword, exists = os.LookupEnv("LEGO_CERTHUB_CLIENT_PFX_PASSWORD")
		if !exists {
			app.logger.Debugf("LEGO_CERTHUB_CLIENT_PFX_PASSWORD not specified, using default \"%s\"", defaultPFXPassword)
			app.cfg.PfxPassword = defaultPFXPassword
		}
	}

	// LEGO_CERTHUB_CLIENT_PFX_LEGACY_CREATE
	pfxLegacyCreate := os.Getenv("LEGO_CERTHUB_CLIENT_PFX_LEGACY_CREATE")
	if pfxLegacyCreate == "true" {
		app.cfg.PfxLegacyCreate = true
	} else if pfxLegacyCreate == "false" {
		app.cfg.PfxLegacyCreate = false
	} else {
		app.logger.Debugf("LEGO_CERTHUB_CLIENT_PFX_LEGACY_CREATE not specified or invalid, using default \"%t\"", defaultPFXLegacyCreate)
		app.cfg.PfxLegacyCreate = defaultPFXLegacyCreate
	}

	if app.cfg.PfxLegacyCreate {
		// LEGO_CERTHUB_CLIENT_PFX_LEGACY_FILENAME
		app.cfg.PfxLegacyFilename = os.Getenv("LEGO_CERTHUB_CLIENT_PFX_LEGACY_FILENAME")
		if app.cfg.PfxLegacyFilename == "" {
			app.logger.Debugf("LEGO_CERTHUB_CLIENT_PFX_LEGACY_FILENAME not specified, using default \"%s\"", defaultPFXLegacyFilename)
			app.cfg.PfxLegacyFilename = defaultPFXLegacyFilename
		}

		// LEGO_CERTHUB_CLIENT_PFX_LEGACY_PASSWORD
		exists := false
		app.cfg.PfxLegacyPassword, exists = os.LookupEnv("LEGO_CERTHUB_CLIENT_PFX_LEGACY_PASSWORD")
		if !exists {
			app.logger.Debugf("LEGO_CERTHUB_CLIENT_PFX_LEGACY_PASSWORD not specified, using default \"%s\"", defaultPFXLegacyPassword)
			app.cfg.PfxLegacyPassword = defaultPFXLegacyPassword
		}
	}

	// graceful shutdown stuff
	shutdownContext, doShutdown := context.WithCancel(context.Background())
	app.shutdownContext = shutdownContext

	// context for shutdown OS signal
	osSignalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// wait for the OS signal and then stop listening and call shutdown
	go func() {
		<-osSignalCtx.Done()

		// disable shutdown context listener (allows for ctrl-c again to force close)
		stop()

		// log os signal call unless shutdown was already triggered somewhere else
		select {
		case <-app.shutdownContext.Done():
			// no-op
		default:
			app.logger.Info("os signal received for shutdown")
		}

		// do shutdown
		doShutdown()
	}()

	// wait group for graceful shutdown
	app.shutdownWaitgroup = new(sync.WaitGroup)

	app.logger.Debugf("app successfully configured")

	return app, nil
}
