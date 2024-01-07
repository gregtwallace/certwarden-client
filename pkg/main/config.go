package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	dockerClient "github.com/docker/docker/client"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Environment Variables (to configure client):
// Mandatory:
//    LEGO_CERTHUB_CLIENT_AES_KEY_BASE64  - base64 raw url encoding of AES key used for communication between LeGo server and client (generate one on LeGo server)
//		LEGO_CERTHUB_CLIENT_SERVER_ADDRESS	-	DNS name of the LeGo server. Must start with https and have a valid ssl certificate.
//		LEGO_CERTHUB_CLIENT_KEY_NAME				-	Name of private key in LeGo server
//		LEGO_CERTHUB_CLIENT_KEY_APIKEY			- API Key of private key in LeGo server
//		LEGO_CERTHUB_CLIENT_CERT_NAME				- Name of certificate in LeGo server
//		LEGO_CERTHUB_CLIENT_CERT_APIKEY			- API Key of certificate in LeGo server

// Optional:
//		LEGO_CERTHUB_CLIENT_FILE_UPDATE_TIME					- 24-hour time when key/cert updates are written to filesystem

//    LEGO_CERTHUB_CLIENT_RESTART_DOCKER_CONTAINER0 - name of a container to restart via docker sock on key/cert file update (useful for containers that need to restart to update certs)
//    LEGO_CERTHUB_CLIENT_RESTART_DOCKER_CONTAINER1 - another container name that should be restarted (keep adding 1 to the number for more)
//		LEGO_CERTHUB_CLIENT_RESTART_DOCKER_CONTAINER2 ... etc.
//		Note: Restart is based on file update, so use the var above to set a file update time

//		LEGO_CERTHUB_CLIENT_LOGLEVEL									- zap log level for the app
//		LEGO_CERTHUB_CLIENT_BIND_ADDRESS							- address to bind the https server to
//		LEGO_CERTHUB_CLIENT_BIND_PORT									- https server port

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
	defaultUpdateTimeHour   = 1
	defaultUpdateTimeMinute = 15

	defaultLogLevel    = zapcore.InfoLevel
	defaultBindAddress = ""
	defaultBindPort    = 5055

	defaultCertStoragePath = "/opt/lego/certs"
	defaultKeyPermissions  = fs.FileMode(0640)
	defaultCertPermissions = fs.FileMode(0644)

	defaultPFXCreate   = false
	defaultPFXFilename = "key_certchain.pfx"
	defaultPFXPassword = ""

	defaultPFXLegacyCreate   = false
	defaultPFXLegacyFilename = "key_certchain.legacy.pfx"
	defaultPFXLegacyPassword = ""
)

var defaultUpdateTimeString = fmt.Sprintf("%d:%d", defaultUpdateTimeHour, defaultUpdateTimeMinute)

//
//
//

// app is the struct for the main application
type app struct {
	logger *zap.SugaredLogger
	cfg    *config

	shutdownContext   context.Context
	shutdownWaitgroup *sync.WaitGroup

	pendingJobCancel context.CancelFunc

	httpClient      *httpClient
	dockerAPIClient *dockerClient.Client
	tlsCert         *SafeCert
	cipherAEAD      cipher.AEAD
}

// config holds all of the lego client configuration
type config struct {
	BindAddress               string
	BindPort                  int
	ServerAddress             string
	FileUpdateTimeString      string
	FileUpdateDayOfWeek       time.Weekday
	DockerContainersToRestart []string
	KeyName                   string
	KeyApiKey                 string
	CertName                  string
	CertApiKey                string
	CertStoragePath           string
	KeyPermissions            fs.FileMode
	CertPermissions           fs.FileMode
	PfxCreate                 bool
	PfxFilename               string
	PfxPassword               string
	PfxLegacyCreate           bool
	PfxLegacyFilename         string
	PfxLegacyPassword         string
}

// parseTime is a helper for time parsing that returns the hour and
// minute ints
func parseTimeString(timeStr string) (hour int, min int, err error) {
	splitTime := strings.Split(timeStr, ":")
	if len(splitTime) == 2 {
		hourInt, hourErr := strconv.Atoi(splitTime[0])
		minInt, minErr := strconv.Atoi(splitTime[1])
		if hourErr == nil && minErr == nil && hourInt >= 0 && hourInt <= 23 && minInt >= 0 && minInt <= 59 {
			return hourInt, minInt, nil
		}
	}

	return -1, -1, errors.New("invalid time specified (use 24 hour format, e.g. 18:05 for 6:05 PM)")
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
		logger.Infof("LEGO_CERTHUB_CLIENT_LOGLEVEL not specified or invalid, using default \"%s\"", defaultLogLevel)
	}

	// make app
	app := &app{
		logger:     logger,
		cfg:        &config{},
		httpClient: newHttpClient(),
		tlsCert:    NewSafeCert(),
	}

	// make rest of config

	// mandatory

	// LEGO_CERTHUB_CLIENT_AES_KEY_BASE64
	secretB64 := os.Getenv("LEGO_CERTHUB_CLIENT_AES_KEY_BASE64")
	aesKey, err := base64.RawURLEncoding.DecodeString(secretB64)
	if err != nil {
		return app, errors.New("LEGO_CERTHUB_CLIENT_AES_KEY_BASE64 is not a valid base64 raw url encoded string")
	}
	if len(aesKey) != 32 {
		return app, errors.New("LEGO_CERTHUB_CLIENT_AES_KEY_BASE64 AES key is not 32 bytes long")
	}
	aes, err := aes.NewCipher(aesKey)
	if err != nil {
		return app, fmt.Errorf("failed to make aes cipher from secret key (%s)", err)
	}
	app.cipherAEAD, err = cipher.NewGCM(aes)
	if err != nil {
		return app, fmt.Errorf("failed to make gcm aead aes cipher (%s)", err)
	}

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

	// LEGO_CERTHUB_CLIENT_FILE_UPDATE_TIME
	app.cfg.FileUpdateTimeString = os.Getenv("LEGO_CERTHUB_CLIENT_FILE_UPDATE_TIME")
	_, _, err = parseTimeString(app.cfg.FileUpdateTimeString)
	if err != nil {
		app.logger.Debug("LEGO_CERTHUB_CLIENT_FILE_UPDATE_TIME not specified or invalid, using time %s", defaultUpdateTimeString)
		app.cfg.FileUpdateTimeString = defaultUpdateTimeString
	}

	// LEGO_CERTHUB_CLIENT_RESTART_DOCKER_CONTAINER (0... etc.)
	app.cfg.DockerContainersToRestart = []string{}
	for i := 0; true; i++ {
		containerName := os.Getenv("LEGO_CERTHUB_CLIENT_RESTART_DOCKER_CONTAINER" + strconv.Itoa(i))
		if containerName == "" {
			// if next number not specified, done
			break
		}
		app.cfg.DockerContainersToRestart = append(app.cfg.DockerContainersToRestart, containerName)
	}
	if len(app.cfg.DockerContainersToRestart) > 0 {
		app.dockerAPIClient, err = dockerClient.NewClientWithOpts(dockerClient.WithAPIVersionNegotiation())
		if err != nil {
			return app, fmt.Errorf("specified LEGO_CERTHUB_CLIENT_RESTART_DOCKER_CONTAINER but couldn't make docker api client (%s)", err)
		}

		testPingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelPing()
		_, err := app.dockerAPIClient.Ping(testPingCtx)
		if err != nil {
			app.logger.Errorf("specified LEGO_CERTHUB_CLIENT_RESTART_DOCKER_CONTAINER but couldn't connect to docker api (%s), verify access to docker or restarts will not occur", err)
		}
	}

	// LEGO_CERTHUB_CLIENT_BIND_ADDRESS
	app.cfg.BindAddress = os.Getenv("LEGO_CERTHUB_CLIENT_BIND_ADDRESS")
	if app.cfg.BindAddress == "" {
		app.logger.Debugf("LEGO_CERTHUB_CLIENT_BIND_ADDRESS not specified, using default \"%s\"", defaultBindAddress)
		app.cfg.BindAddress = defaultBindAddress
	}

	// LEGO_CERTHUB_CLIENT_BIND_PORT
	bindPort := os.Getenv("LEGO_CERTHUB_CLIENT_BIND_PORT")
	app.cfg.BindPort, err = strconv.Atoi(bindPort)
	if bindPort == "" || err != nil || app.cfg.BindPort < 1 || app.cfg.BindPort > 65535 {
		app.logger.Debugf("LEGO_CERTHUB_CLIENT_BIND_PORT not specified or invalid, using default \"%d\"", defaultBindPort)
		app.cfg.BindPort = defaultBindPort
	}

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

	// end config vars

	// make cert storage path (if not exist)
	_, err = os.Stat(app.cfg.CertStoragePath)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(app.cfg.CertStoragePath, 0755)
		if err != nil {
			return app, fmt.Errorf("failed to make cert storage directory (%s)", err)
		} else {
			app.logger.Infof("cert storage path created")
		}
	} else if err != nil {
		return app, fmt.Errorf("failed to stat cert storage directory (%s)", err)
	}

	// read existing key/cert pem from disk
	cert, err := os.ReadFile(app.cfg.CertStoragePath + "/certchain.pem")
	if err != nil {
		app.logger.Infof("could not read cert from disk (%s), will try fetch from remote", err)
	} else {
		key, err := os.ReadFile(app.cfg.CertStoragePath + "/key.pem")
		if err != nil {
			app.logger.Infof("could not read key from disk (%s), will try fetch from remote", err)
		} else {
			// read both key and cert, put them in tlsCert
			_, err := app.tlsCert.Update(key, cert)
			if err != nil {
				app.logger.Errorf("could not use key/cert pair from disk (%s), will try fetch from remote", err)
			}
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
