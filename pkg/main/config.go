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
//    CW_CLIENT_AES_KEY_BASE64  - base64 raw url encoding of AES key used for communication between server and client (generate one on server)
//		CW_CLIENT_SERVER_ADDRESS	-	DNS name of the server. Must start with https and have a valid ssl certificate.
//		CW_CLIENT_KEY_NAME				-	Name of private key in server
//		CW_CLIENT_KEY_APIKEY			- API Key of private key in server
//		CW_CLIENT_CERT_NAME				- Name of certificate in server
//		CW_CLIENT_CERT_APIKEY			- API Key of certificate in server

// Optional:
//		CW_CLIENT_FILE_UPDATE_TIME_START		- 24-hour time when window opens to write key/cert updates to filesystem
//		CW_CLIENT_FILE_UPDATE_TIME_END			- 24-hour time when window closes to write key/cert updates to filesystem
// 		CW_CLIENT_FILE_UPDATE_DAYS_OF_WEEK	- Day(s) of the week to write updated key/cert to filesystem (blank is any) - separate multiple using spaces
//		Note: If midnight falls between start and end time, weekday is applied to the start time (e.g. Weds 10p-2a would we Weds 10p - Thu 2a)

//    CW_CLIENT_RESTART_DOCKER_CONTAINER0 - name of a container to restart via docker sock on key/cert file update (useful for containers that need to restart to update certs)
//    CW_CLIENT_RESTART_DOCKER_CONTAINER1 - another container name that should be restarted (keep adding 1 to the number for more)
//		CW_CLIENT_RESTART_DOCKER_CONTAINER2 ... etc.
//		Note: Restart is based on file update, so use the vars above to set a file update time window and day(s) of week
//		CW_CLIENT_RESTART_DOCKER_STOP_ONLY	- if 'true' docker containers will be stopped instead of restarted (this is useful if another process like systemctl will start them back up)

//		CW_CLIENT_LOGLEVEL									- zap log level for the app
//		CW_CLIENT_BIND_ADDRESS							- address to bind the https server to
//		CW_CLIENT_BIND_PORT									- https server port

// 		CW_CLIENT_CERT_PATH				- the path to save all keys and certificates to
//    CW_CLIENT_KEY_PERM				- permissions for files containing the key
//    CW_CLIENT_CERT_PERM				- permissions for files only containing the cert

//    CW_CLIENT_PFX_CREATE			- if `true`, an additional pkcs12 encoded key/certchain will be generated with modern algorithms
//    CW_CLIENT_PFX_FILENAME		- if pfx create enabled, the filename for the pfx generated
//    CW_CLIENT_PFX_PASSWORD		- if pfx create enabled, the password for the pfx file generated

//		Note: Do not use `LEGACY` unless your application specifically requires it
//    CW_CLIENT_PFX_LEGACY_CREATE			- if `true`, an additional pkcs12 encoded key/certchain will be generated using legacy algorithms
//    CW_CLIENT_PFX_LEGACY_FILENAME		- if pfx create enabled, the filename for the legacy pfx generated
//    CW_CLIENT_PFX_LEGACY_PASSWORD		- if pfx create enabled, the password for the legacy pfx file generated

// defaults for Optional vars
const (
	defaultUpdateTimeStartHour   = 3
	defaultUpdateTimeStartMinute = 0
	defaultUpdateTimeEndHour     = 5
	defaultUpdateTimeEndMinute   = 0
	defaultUpdateDayOfWeek       = ""

	defaultRestartDockerStopOnly = false

	defaultLogLevel    = zapcore.InfoLevel
	defaultBindAddress = ""
	defaultBindPort    = 5055

	defaultCertStoragePath = "/opt/certwarden/certs"
	defaultKeyPermissions  = fs.FileMode(0600)
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

	pendingJobCancel context.CancelFunc

	httpClient      *httpClient
	dockerAPIClient *dockerClient.Client
	tlsCert         *SafeCert
	cipherAEAD      cipher.AEAD
}

// config holds all of the client configuration
type config struct {
	BindAddress                    string
	BindPort                       int
	ServerAddress                  string
	FileUpdateTimeStartHour        int
	FileUpdateTimeStartMinute      int
	FileUpdateTimeEndHour          int
	FileUpdateTimeEndMinute        int
	FileUpdateTimeIncludesMidnight bool
	FileUpdateDaysOfWeek           map[time.Weekday]struct{}
	DockerContainersToRestart      []string
	DockerStopOnly                 bool
	KeyName                        string
	KeyApiKey                      string
	CertName                       string
	CertApiKey                     string
	CertStoragePath                string
	KeyPermissions                 fs.FileMode
	CertPermissions                fs.FileMode
	PfxCreate                      bool
	PfxFilename                    string
	PfxPassword                    string
	PfxLegacyCreate                bool
	PfxLegacyFilename              string
	PfxLegacyPassword              string
}

// configureApp creates the application from environment variables and/or defaults;
// an error is returned if a mandatory variable is missing or invalid
func configureApp() (*app, error) {
	// CW_CLIENT_LOGLEVEL - optional
	logLevelEnv := os.Getenv("CW_CLIENT_LOGLEVEL")
	logLevel, logLevelErr := zapcore.ParseLevel(logLevelEnv)
	if logLevelErr != nil {
		logLevel = defaultLogLevel
	}
	logger := makeZapLogger(logLevel)
	logger.Infof("starting Cert Warden Client v%s", appVersion)
	// deferred log message for if log level was not specified
	if logLevelErr != nil {
		logger.Infof("CW_CLIENT_LOGLEVEL not specified or invalid, using default \"%s\"", defaultLogLevel)
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

	// CW_CLIENT_AES_KEY_BASE64
	secretB64 := os.Getenv("CW_CLIENT_AES_KEY_BASE64")
	aesKey, err := base64.RawURLEncoding.DecodeString(secretB64)
	if err != nil {
		return app, errors.New("CW_CLIENT_AES_KEY_BASE64 is not a valid base64 raw url encoded string")
	}
	if len(aesKey) != 32 {
		return app, errors.New("CW_CLIENT_AES_KEY_BASE64 AES key is not 32 bytes long")
	}
	aes, err := aes.NewCipher(aesKey)
	if err != nil {
		return app, fmt.Errorf("failed to make aes cipher from secret key (%s)", err)
	}
	app.cipherAEAD, err = cipher.NewGCM(aes)
	if err != nil {
		return app, fmt.Errorf("failed to make gcm aead aes cipher (%s)", err)
	}

	// CW_CLIENT_SERVER_ADDRESS
	app.cfg.ServerAddress = os.Getenv("CW_CLIENT_SERVER_ADDRESS")
	if app.cfg.ServerAddress == "" || !strings.HasPrefix(app.cfg.ServerAddress, "https://") {
		return app, errors.New("CW_CLIENT_SERVER_ADDRESS is required and must start with https://")
	}

	// CW_CLIENT_KEY_NAME
	app.cfg.KeyName = os.Getenv("CW_CLIENT_KEY_NAME")
	if app.cfg.KeyName == "" {
		return app, errors.New("CW_CLIENT_KEY_NAME is required")
	}

	// CW_CLIENT_KEY_APIKEY
	app.cfg.KeyApiKey = os.Getenv("CW_CLIENT_KEY_APIKEY")
	if app.cfg.KeyApiKey == "" {
		return app, errors.New("CW_CLIENT_KEY_APIKEY is required")
	}

	// CW_CLIENT_CERT_NAME
	app.cfg.CertName = os.Getenv("CW_CLIENT_CERT_NAME")
	if app.cfg.CertName == "" {
		return app, errors.New("CW_CLIENT_CERT_NAME is required")
	}

	// CW_CLIENT_CERT_APIKEY
	app.cfg.CertApiKey = os.Getenv("CW_CLIENT_CERT_APIKEY")
	if app.cfg.CertApiKey == "" {
		return app, errors.New("CW_CLIENT_CERT_APIKEY is required")
	}

	// optional

	// CW_CLIENT_FILE_UPDATE_TIME_START
	fileUpdateTimeStartString := os.Getenv("CW_CLIENT_FILE_UPDATE_TIME_START")
	app.cfg.FileUpdateTimeStartHour, app.cfg.FileUpdateTimeStartMinute, err = parseTimeString(fileUpdateTimeStartString)
	if err != nil {
		app.logger.Debugf("CW_CLIENT_FILE_UPDATE_TIME_START not specified or invalid, using time %02d:%02d", defaultUpdateTimeStartHour, defaultUpdateTimeStartMinute)
		app.cfg.FileUpdateTimeStartHour = defaultUpdateTimeStartHour
		app.cfg.FileUpdateTimeStartMinute = defaultUpdateTimeStartMinute
	}

	// CW_CLIENT_FILE_UPDATE_TIME_END
	fileUpdateTimeEndString := os.Getenv("CW_CLIENT_FILE_UPDATE_TIME_END")
	app.cfg.FileUpdateTimeEndHour, app.cfg.FileUpdateTimeEndMinute, err = parseTimeString(fileUpdateTimeEndString)
	if err != nil {
		app.logger.Debugf("CW_CLIENT_FILE_UPDATE_TIME_END not specified or invalid, using time %02d:%02d", defaultUpdateTimeEndHour, defaultUpdateTimeEndMinute)
		app.cfg.FileUpdateTimeEndHour = defaultUpdateTimeEndHour
		app.cfg.FileUpdateTimeEndMinute = defaultUpdateTimeEndMinute
	}

	// calculate if time window includes midnight
	app.cfg.FileUpdateTimeIncludesMidnight = false
	if app.cfg.FileUpdateTimeEndHour < app.cfg.FileUpdateTimeStartHour || (app.cfg.FileUpdateTimeEndHour == app.cfg.FileUpdateTimeStartHour && app.cfg.FileUpdateTimeEndMinute < app.cfg.FileUpdateTimeStartMinute) {
		app.cfg.FileUpdateTimeIncludesMidnight = true
	}

	// CW_CLIENT_FILE_UPDATE_DAYS_OF_WEEK
	weekdaysStr := os.Getenv("CW_CLIENT_FILE_UPDATE_DAYS_OF_WEEK")
	app.cfg.FileUpdateDaysOfWeek, err = parseWeekdaysString(weekdaysStr)
	if weekdaysStr == "" || err != nil {
		// invalid weekdays val = all Weekday
		app.cfg.FileUpdateDaysOfWeek = allWeekdays
		app.logger.Debug("CW_CLIENT_FILE_UPDATE_DAYS_OF_WEEK not specified or invalid, key/cert file updates will occur on any day")
	}

	// log file write plan
	dayOfWeekLogText := ""
	for k := range app.cfg.FileUpdateDaysOfWeek {
		if dayOfWeekLogText != "" {
			dayOfWeekLogText = dayOfWeekLogText + " "
		}
		dayOfWeekLogText = dayOfWeekLogText + k.String()
	}

	app.logger.Infof("new key/cert files will be permitted to write on %s between %02d:%02d and %02d:%02d", dayOfWeekLogText, app.cfg.FileUpdateTimeStartHour,
		app.cfg.FileUpdateTimeStartMinute, app.cfg.FileUpdateTimeEndHour, app.cfg.FileUpdateTimeEndMinute)

	// CW_CLIENT_RESTART_DOCKER_CONTAINER (0... etc.)
	app.cfg.DockerContainersToRestart = []string{}
	for i := 0; true; i++ {
		containerName := os.Getenv("CW_CLIENT_RESTART_DOCKER_CONTAINER" + strconv.Itoa(i))
		if containerName == "" {
			// if next number not specified, done
			break
		}
		app.cfg.DockerContainersToRestart = append(app.cfg.DockerContainersToRestart, containerName)
	}
	if len(app.cfg.DockerContainersToRestart) > 0 {
		app.dockerAPIClient, err = dockerClient.NewClientWithOpts(
			dockerClient.FromEnv,
			dockerClient.WithAPIVersionNegotiation(),
		)
		if err != nil {
			return app, fmt.Errorf("specified CW_CLIENT_RESTART_DOCKER_CONTAINER but couldn't make docker api client (%s)", err)
		}

		testPingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelPing()
		_, err := app.dockerAPIClient.Ping(testPingCtx)
		if err != nil {
			app.logger.Errorf("specified CW_CLIENT_RESTART_DOCKER_CONTAINER but couldn't connect to docker api (%s), verify access to docker or restarts will not occur", err)
		}
	}

	// CW_CLIENT_RESTART_DOCKER_STOP_ONLY
	dockerStopOnlyStr := os.Getenv("CW_CLIENT_RESTART_DOCKER_STOP_ONLY")
	if dockerStopOnlyStr == "true" {
		app.cfg.DockerStopOnly = true
	} else if dockerStopOnlyStr == "false" {
		app.cfg.DockerStopOnly = false
	} else {
		app.logger.Debugf("CW_CLIENT_RESTART_DOCKER_STOP_ONLY not specified or invalid, using default \"%s\"", defaultRestartDockerStopOnly)
		app.cfg.DockerStopOnly = defaultRestartDockerStopOnly
	}
	if app.cfg.DockerStopOnly {
		app.logger.Warn("docker containers will only be stopped, not restarted, on cert file updates")
	}

	// CW_CLIENT_BIND_ADDRESS
	app.cfg.BindAddress = os.Getenv("CW_CLIENT_BIND_ADDRESS")
	if app.cfg.BindAddress == "" {
		app.logger.Debugf("CW_CLIENT_BIND_ADDRESS not specified, using default \"%s\"", defaultBindAddress)
		app.cfg.BindAddress = defaultBindAddress
	}

	// CW_CLIENT_BIND_PORT
	bindPort := os.Getenv("CW_CLIENT_BIND_PORT")
	app.cfg.BindPort, err = strconv.Atoi(bindPort)
	if bindPort == "" || err != nil || app.cfg.BindPort < 1 || app.cfg.BindPort > 65535 {
		app.logger.Debugf("CW_CLIENT_BIND_PORT not specified or invalid, using default \"%d\"", defaultBindPort)
		app.cfg.BindPort = defaultBindPort
	}

	// CW_CLIENT_CERT_PATH
	app.cfg.CertStoragePath = os.Getenv("CW_CLIENT_CERT_PATH")
	if app.cfg.CertStoragePath == "" {
		app.logger.Debugf("CW_CLIENT_CERT_PATH not specified, using default \"%s\"", defaultCertStoragePath)
		app.cfg.CertStoragePath = defaultCertStoragePath
	}

	// CW_CLIENT_KEY_PERM
	keyPerm := os.Getenv("CW_CLIENT_KEY_PERM")
	keyPermInt, err := strconv.ParseInt(keyPerm, 0, 0)
	app.logger.Debugf("CW_CLIENT_KEY_PERM \"%o\"", keyPermInt)
	if keyPerm == "" || err != nil {
		app.logger.Debugf("CW_CLIENT_KEY_PERM not specified or invalid, using default \"%o\"", defaultKeyPermissions)
		app.cfg.KeyPermissions = defaultKeyPermissions
	} else {
		app.cfg.KeyPermissions = fs.FileMode(keyPermInt)
	}

	// CW_CLIENT_CERT_PERM
	certPerm := os.Getenv("CW_CLIENT_CERT_PERM")
	certPermInt, err := strconv.ParseInt(certPerm, 0, 0)
	app.logger.Debugf("CW_CLIENT_CERT_PERM \"%o\"", certPermInt)
	if certPerm == "" || err != nil {
		app.logger.Debugf("CW_CLIENT_CERT_PERM not specified, using default \"%o\"", defaultCertPermissions)
		app.cfg.CertPermissions = defaultCertPermissions
	} else {
		app.cfg.CertPermissions = fs.FileMode(certPermInt)
	}

	// CW_CLIENT_PFX_CREATE
	pfxCreate := os.Getenv("CW_CLIENT_PFX_CREATE")
	if pfxCreate == "true" {
		app.cfg.PfxCreate = true
	} else if pfxCreate == "false" {
		app.cfg.PfxCreate = false
	} else {
		app.logger.Debugf("CW_CLIENT_PFX_CREATE not specified or invalid, using default \"%t\"", defaultPFXCreate)
		app.cfg.PfxCreate = defaultPFXCreate
	}

	if app.cfg.PfxCreate {
		// CW_CLIENT_PFX_FILENAME
		app.cfg.PfxFilename = os.Getenv("CW_CLIENT_PFX_FILENAME")
		if app.cfg.PfxFilename == "" {
			app.logger.Debugf("CW_CLIENT_PFX_FILENAME not specified, using default \"%s\"", defaultPFXFilename)
			app.cfg.PfxFilename = defaultPFXFilename
		}

		// CW_CLIENT_PFX_PASSWORD
		exists := false
		app.cfg.PfxPassword, exists = os.LookupEnv("CW_CLIENT_PFX_PASSWORD")
		if !exists {
			app.logger.Debugf("CW_CLIENT_PFX_PASSWORD not specified, using default \"%s\"", defaultPFXPassword)
			app.cfg.PfxPassword = defaultPFXPassword
		}
	}

	// CW_CLIENT_PFX_LEGACY_CREATE
	pfxLegacyCreate := os.Getenv("CW_CLIENT_PFX_LEGACY_CREATE")
	if pfxLegacyCreate == "true" {
		app.cfg.PfxLegacyCreate = true
	} else if pfxLegacyCreate == "false" {
		app.cfg.PfxLegacyCreate = false
	} else {
		app.logger.Debugf("CW_CLIENT_PFX_LEGACY_CREATE not specified or invalid, using default \"%t\"", defaultPFXLegacyCreate)
		app.cfg.PfxLegacyCreate = defaultPFXLegacyCreate
	}

	if app.cfg.PfxLegacyCreate {
		// CW_CLIENT_PFX_LEGACY_FILENAME
		app.cfg.PfxLegacyFilename = os.Getenv("CW_CLIENT_PFX_LEGACY_FILENAME")
		if app.cfg.PfxLegacyFilename == "" {
			app.logger.Debugf("CW_CLIENT_PFX_LEGACY_FILENAME not specified, using default \"%s\"", defaultPFXLegacyFilename)
			app.cfg.PfxLegacyFilename = defaultPFXLegacyFilename
		}

		// CW_CLIENT_PFX_LEGACY_PASSWORD
		exists := false
		app.cfg.PfxLegacyPassword, exists = os.LookupEnv("CW_CLIENT_PFX_LEGACY_PASSWORD")
		if !exists {
			app.logger.Debugf("CW_CLIENT_PFX_LEGACY_PASSWORD not specified, using default \"%s\"", defaultPFXLegacyPassword)
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
