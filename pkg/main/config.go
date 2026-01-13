package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
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
// 		Certificate specific items include an index (e.g., CW_CLIENT_AES_KEY_BASE64 vs. CW_CLIENT_0_AES_KEY_BASE64)
//		If the index is missing, the assumed index will be 0. It is highly recommended you ALWAYS use the index. The
//		non-indexed parsing to an assumed 0 only remains for backward compatibility.

// Mandatory:
//		Client Global:
//			CW_CLIENT_SERVER_ADDRESS	-	DNS name of the server. Must start with https and have a valid ssl certificate.
//
//		Certificate Specific:
//    	CW_CLIENT_0_AES_KEY_BASE64  - base64 raw url encoding of AES key used for communication between server and client (generate one on server)
//			CW_CLIENT_0_KEY_NAME				-	Name of private key in server
//			CW_CLIENT_0_KEY_APIKEY			- API Key of private key in server
//			CW_CLIENT_0_CERT_NAME				- Name of certificate in server
//			CW_CLIENT_0_CERT_APIKEY			- API Key of certificate in server

// Optional:
//		Client Global:
//			CW_CLIENT_LOGLEVEL									- zap log level for the app
//			CW_CLIENT_BIND_ADDRESS							- address to bind the https server to
//			CW_CLIENT_BIND_PORT									- https server port
//			CW_CLIENT_POLLING_INTERVAL					- interval for polling server for new certificates (e.g., 1d, 5h, 30m)
//																								if not specified, polling is disabled (uses server push notifications)

//		Certificate Specific:
//			CW_CLIENT_0_FILE_UPDATE_TIME_START		- 24-hour time when window opens to write key/cert updates to filesystem
//			CW_CLIENT_0_FILE_UPDATE_TIME_END			- 24-hour time when window closes to write key/cert updates to filesystem
// 			CW_CLIENT_0_FILE_UPDATE_DAYS_OF_WEEK	- Day(s) of the week to write updated key/cert to filesystem (blank is any) - separate multiple using spaces
//				Note: If midnight falls between start and end time, weekday is applied to the start time (e.g. Weds 10p-2a would we Weds 10p - Thu 2a)

//    	CW_CLIENT_0_RESTART_DOCKER_CONTAINER0 - name of a container to restart via docker sock on key/cert file update (useful for containers that need to restart to update certs)
//    	CW_CLIENT_0_RESTART_DOCKER_CONTAINER1 - another container name that should be restarted (keep adding 1 to the number for more)
//			CW_CLIENT_0_RESTART_DOCKER_CONTAINER2 ... etc.
//				Note: Restart is based on file update, so use the vars above to set a file update time window and day(s) of week
//			CW_CLIENT_0_RESTART_DOCKER_STOP_ONLY	- if 'true' docker containers will be stopped instead of restarted (this is useful if another process like systemctl will start them back up)

// 			CW_CLIENT_0_CERT_PATH								- the path to save all keys and certificates to
// 			CW_CLIENT_0_KEY_PEM_FILENAME				- filename to save the key pem as (default is key0.pem ; number == index)
// 			CW_CLIENT_0_CERTCHAIN_PEM_FILENAME	- filename to save the certchain as (default is certchain0.pem ; number == index)
//    	CW_CLIENT_0_KEY_PERM								- permissions for files containing the key
//    	CW_CLIENT_0_CERT_PERM								- permissions for files only containing the cert

//    	CW_CLIENT_0_PFX_CREATE			- if `true`, an additional pkcs12 encoded key/certchain will be generated with modern algorithms
//    	CW_CLIENT_0_PFX_FILENAME		- if pfx create enabled, the filename for the pfx generated
//    	CW_CLIENT_0_PFX_PASSWORD		- if pfx create enabled, the password for the pfx file generated

//				Note: Do not use `LEGACY` unless your application specifically requires it
//    	CW_CLIENT_0_PFX_LEGACY_CREATE			- if `true`, an additional pkcs12 encoded key/certchain will be generated using legacy algorithms
//    	CW_CLIENT_0_PFX_LEGACY_FILENAME		- if pfx create enabled, the filename for the legacy pfx generated
//    	CW_CLIENT_0_PFX_LEGACY_PASSWORD		- if pfx create enabled, the password for the legacy pfx file generated

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
	defaultPFXPassword = ""

	defaultPFXLegacyCreate   = false
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

	httpClient      *http.Client
	dockerAPIClient *dockerClient.Client

	// one for each cert (index corresponds to cfg index)
	tlsCerts          []*SafeCert // 0 is always used for the Client's https cert
	pendingJobCancels []context.CancelFunc
	cipherAEAD        []cipher.AEAD
}

// certConfig contains all of the configuration specific to
// a given certificate
type certConfig struct {
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
	KeyPemFilename                 string
	CertPemFilename                string
	KeyPermissions                 fs.FileMode
	CertPermissions                fs.FileMode
	PfxCreate                      bool
	PfxFilename                    string
	PfxPassword                    string
	PfxLegacyCreate                bool
	PfxLegacyFilename              string
	PfxLegacyPassword              string
}

// config holds all of the client configuration
type config struct {
	BindAddress     string
	BindPort        int
	ServerAddress   string
	PollingInterval time.Duration // 0 means polling is disabled
	Certs           []certConfig
}

// configureApp creates the application from environment variables and/or defaults;
// an error is returned if a mandatory variable is missing or invalid
func configureApp() (*app, error) {
	// Logging is Special (Optional)

	// CW_CLIENT_LOGLEVEL
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
		httpClient: makeHttpClient(),
	}

	// Global: Mandatory

	// CW_CLIENT_SERVER_ADDRESS
	app.cfg.ServerAddress = os.Getenv("CW_CLIENT_SERVER_ADDRESS")
	if app.cfg.ServerAddress == "" || !strings.HasPrefix(app.cfg.ServerAddress, "https://") {
		return app, errors.New("CW_CLIENT_SERVER_ADDRESS is required and must start with https://")
	}

	// Global: Optional

	// CW_CLIENT_BIND_ADDRESS
	app.cfg.BindAddress = os.Getenv("CW_CLIENT_BIND_ADDRESS")
	if app.cfg.BindAddress == "" {
		app.logger.Debugf("CW_CLIENT_BIND_ADDRESS not specified, using default \"%s\"", defaultBindAddress)
		app.cfg.BindAddress = defaultBindAddress
	}

	// CW_CLIENT_BIND_PORT
	var err error
	bindPort := os.Getenv("CW_CLIENT_BIND_PORT")
	app.cfg.BindPort, err = strconv.Atoi(bindPort)
	if bindPort == "" || err != nil || app.cfg.BindPort < 1 || app.cfg.BindPort > 65535 {
		app.logger.Debugf("CW_CLIENT_BIND_PORT not specified or invalid, using default \"%d\"", defaultBindPort)
		app.cfg.BindPort = defaultBindPort
	}

	// CW_CLIENT_POLLING_INTERVAL
	pollingIntervalStr := os.Getenv("CW_CLIENT_POLLING_INTERVAL")
	if pollingIntervalStr != "" {
		app.cfg.PollingInterval, err = parseDurationString(pollingIntervalStr)
		if err != nil {
			return app, fmt.Errorf("CW_CLIENT_POLLING_INTERVAL is invalid (%s)", err)
		}
		if app.cfg.PollingInterval < time.Minute {
			return app, errors.New("CW_CLIENT_POLLING_INTERVAL must be at least 1 minute")
		}
		app.logger.Infof("polling interval set to %v", app.cfg.PollingInterval)
	} else {
		app.cfg.PollingInterval = 0
		app.logger.Debug("CW_CLIENT_POLLING_INTERVAL not specified, polling disabled (using server push notifications)")
	}

	// Configure each cert
	certIndex := 0
	for {
		cert := certConfig{}

		// prefix to use for environment vars
		prefix := fmt.Sprintf("CW_CLIENT_%d_", certIndex)

		// Cert: Mandatory

		// CW_CLIENT_AES_KEY_BASE64
		secretB64 := os.Getenv(prefix + "AES_KEY_BASE64")

		// backwards compat prefix if _0_ wasn't found
		if certIndex == 0 && secretB64 == "" {
			prefix = "CW_CLIENT_"
			secretB64 = os.Getenv(prefix + "AES_KEY_BASE64")
		}

		// done loading certs, found an index that doesn't exist (not including 0 which is required)
		if secretB64 == "" && certIndex > 0 {
			break
		}

		aesKey, err := base64.RawURLEncoding.DecodeString(secretB64)
		if err != nil {
			return app, errors.New(prefix + "AES_KEY_BASE64 is not a valid base64 raw url encoded string")
		}
		if len(aesKey) != 32 {
			return app, errors.New(prefix + "AES_KEY_BASE64 AES key is not 32 bytes long")
		}
		aes, err := aes.NewCipher(aesKey)
		if err != nil {
			return app, fmt.Errorf("failed to make aes cipher from secret key %sAES_KEY_BASE64 (%s)", prefix, err)
		}
		cipherAEAD, err := cipher.NewGCM(aes)
		if err != nil {
			return app, fmt.Errorf("failed to make gcm aead aes cipher from secret key %sAES_KEY_BASE64 (%s)", prefix, err)
		}

		// CW_CLIENT_KEY_NAME
		cert.KeyName = os.Getenv(prefix + "KEY_NAME")
		if cert.KeyName == "" {
			return app, errors.New(prefix + "KEY_NAME is required")
		}

		// CW_CLIENT_KEY_APIKEY
		cert.KeyApiKey = os.Getenv(prefix + "KEY_APIKEY")
		if cert.KeyApiKey == "" {
			return app, errors.New(prefix + "KEY_APIKEY is required")
		}

		// CW_CLIENT_CERT_NAME
		cert.CertName = os.Getenv(prefix + "CERT_NAME")
		if cert.CertName == "" {
			return app, errors.New(prefix + "CERT_NAME is required")
		}

		// CW_CLIENT_CERT_APIKEY
		cert.CertApiKey = os.Getenv(prefix + "CERT_APIKEY")
		if cert.CertApiKey == "" {
			return app, errors.New(prefix + "CERT_APIKEY is required")
		}

		// Cert: Optional

		// CW_CLIENT_FILE_UPDATE_TIME_START
		fileUpdateTimeStartString := os.Getenv(prefix + "FILE_UPDATE_TIME_START")
		cert.FileUpdateTimeStartHour, cert.FileUpdateTimeStartMinute, err = parseTimeString(fileUpdateTimeStartString)
		if err != nil {
			app.logger.Debugf("%sFILE_UPDATE_TIME_START not specified or invalid, using time %02d:%02d", prefix, defaultUpdateTimeStartHour, defaultUpdateTimeStartMinute)
			cert.FileUpdateTimeStartHour = defaultUpdateTimeStartHour
			cert.FileUpdateTimeStartMinute = defaultUpdateTimeStartMinute
		}

		// CW_CLIENT_FILE_UPDATE_TIME_END
		fileUpdateTimeEndString := os.Getenv(prefix + "FILE_UPDATE_TIME_END")
		cert.FileUpdateTimeEndHour, cert.FileUpdateTimeEndMinute, err = parseTimeString(fileUpdateTimeEndString)
		if err != nil {
			app.logger.Debugf("%sFILE_UPDATE_TIME_END not specified or invalid, using time %02d:%02d", prefix, defaultUpdateTimeEndHour, defaultUpdateTimeEndMinute)
			cert.FileUpdateTimeEndHour = defaultUpdateTimeEndHour
			cert.FileUpdateTimeEndMinute = defaultUpdateTimeEndMinute
		}

		// calculate if time window includes midnight
		cert.FileUpdateTimeIncludesMidnight = false
		if cert.FileUpdateTimeEndHour < cert.FileUpdateTimeStartHour || (cert.FileUpdateTimeEndHour == cert.FileUpdateTimeStartHour && cert.FileUpdateTimeEndMinute < cert.FileUpdateTimeStartMinute) {
			cert.FileUpdateTimeIncludesMidnight = true
		}

		// CW_CLIENT_FILE_UPDATE_DAYS_OF_WEEK
		weekdaysStr := os.Getenv(prefix + "FILE_UPDATE_DAYS_OF_WEEK")
		cert.FileUpdateDaysOfWeek, err = parseWeekdaysString(weekdaysStr)
		if weekdaysStr == "" || err != nil {
			// invalid weekdays val = all Weekday
			cert.FileUpdateDaysOfWeek = allWeekdays
			app.logger.Debug(prefix + "FILE_UPDATE_DAYS_OF_WEEK not specified or invalid, key/cert file updates will occur on any day")
		}

		// log file write plan
		dayOfWeekLogText := ""
		for k := range cert.FileUpdateDaysOfWeek {
			if dayOfWeekLogText != "" {
				dayOfWeekLogText = dayOfWeekLogText + " "
			}
			dayOfWeekLogText = dayOfWeekLogText + k.String()
		}
		app.logger.Infof("cert %d new key/cert files will be permitted to write on %s between %02d:%02d and %02d:%02d", certIndex, dayOfWeekLogText, cert.FileUpdateTimeStartHour,
			cert.FileUpdateTimeStartMinute, cert.FileUpdateTimeEndHour, cert.FileUpdateTimeEndMinute)

		// CW_CLIENT_RESTART_DOCKER_CONTAINER (0... etc.)
		cert.DockerContainersToRestart = []string{}
		for i := 0; true; i++ {
			containerName := os.Getenv(prefix + "RESTART_DOCKER_CONTAINER" + strconv.Itoa(i))
			if containerName == "" {
				// if next number not specified, done
				break
			}
			cert.DockerContainersToRestart = append(cert.DockerContainersToRestart, containerName)
		}

		// ensure this only happens once -- app has one common api client
		if len(cert.DockerContainersToRestart) > 0 && app.dockerAPIClient == nil {
			app.dockerAPIClient, err = dockerClient.NewClientWithOpts(
				dockerClient.FromEnv,
				dockerClient.WithAPIVersionNegotiation(),
			)
			if err != nil {
				return app, fmt.Errorf("specified %sRESTART_DOCKER_CONTAINER but couldn't make docker api client (%s)", prefix, err)
			}

			testPingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelPing()
			_, err := app.dockerAPIClient.Ping(testPingCtx)
			if err != nil {
				app.logger.Errorf("specified %sRESTART_DOCKER_CONTAINER but couldn't connect to docker api (%s), verify access to docker or restarts will not occur", prefix, err)
			}
		}

		// CW_CLIENT_RESTART_DOCKER_STOP_ONLY
		dockerStopOnlyStr := os.Getenv(prefix + "RESTART_DOCKER_STOP_ONLY")
		if dockerStopOnlyStr == "true" {
			cert.DockerStopOnly = true
		} else if dockerStopOnlyStr == "false" {
			cert.DockerStopOnly = false
		} else {
			app.logger.Debugf("%sRESTART_DOCKER_STOP_ONLY not specified or invalid, using default \"%t\"", prefix, defaultRestartDockerStopOnly)
			cert.DockerStopOnly = defaultRestartDockerStopOnly
		}
		if cert.DockerStopOnly {
			app.logger.Warnf("cert %d docker containers will only be stopped, not restarted, on cert file updates", certIndex)
		}

		// CW_CLIENT_CERT_PATH
		cert.CertStoragePath = os.Getenv(prefix + "CERT_PATH")
		if cert.CertStoragePath == "" {
			app.logger.Debugf("%sCERT_PATH not specified, using default \"%s\"", prefix, defaultCertStoragePath)
			cert.CertStoragePath = defaultCertStoragePath
		}

		// CW_CLIENT_KEY_PEM_FILENAME
		cert.KeyPemFilename = os.Getenv(prefix + "KEY_PEM_FILENAME")
		if cert.KeyPemFilename == "" {
			// not specified, use default
			cert.KeyPemFilename = fmt.Sprintf("key%d.pem", certIndex)
			// backwards compat
			if prefix == "CW_CLIENT_" {
				cert.KeyPemFilename = "key.pem"
			}

			app.logger.Debugf("%sKEY_PEM_FILENAME not specified, using default \"%s\"", prefix, cert.KeyPemFilename)
		}

		// CW_CLIENT_CERTCHAIN_PEM_FILENAME
		cert.CertPemFilename = os.Getenv(prefix + "CERTCHAIN_PEM_FILENAME")
		if cert.CertPemFilename == "" {
			// not specified, use default
			cert.CertPemFilename = fmt.Sprintf("certchain%d.pem", certIndex)
			// backwards compat
			if prefix == "CW_CLIENT_" {
				cert.CertPemFilename = "certchain.pem"
			}

			app.logger.Debugf("%sCERTCHAIN_PEM_FILENAME not specified, using default \"%s\"", prefix, cert.CertPemFilename)
		}

		// CW_CLIENT_KEY_PERM
		keyPerm := os.Getenv(prefix + "KEY_PERM")
		keyPermInt, err := strconv.ParseInt(keyPerm, 0, 0)
		if keyPerm == "" || err != nil {
			app.logger.Debugf("%sKEY_PERM not specified or invalid, using default \"%o\"", prefix, defaultKeyPermissions)
			cert.KeyPermissions = defaultKeyPermissions
		} else {
			cert.KeyPermissions = fs.FileMode(keyPermInt)
		}
		app.logger.Debugf("%sKEY_PERM \"%o\"", prefix, cert.KeyPermissions)

		// CW_CLIENT_CERT_PERM
		certPerm := os.Getenv(prefix + "CERT_PERM")
		certPermInt, err := strconv.ParseInt(certPerm, 0, 0)
		if certPerm == "" || err != nil {
			app.logger.Debugf("%sCERT_PERM not specified, using default \"%o\"", prefix, defaultCertPermissions)
			cert.CertPermissions = defaultCertPermissions
		} else {
			cert.CertPermissions = fs.FileMode(certPermInt)
		}
		app.logger.Debugf("%sCERT_PERM \"%o\"", prefix, cert.CertPermissions)

		// CW_CLIENT_PFX_CREATE
		pfxCreate := os.Getenv(prefix + "PFX_CREATE")
		if pfxCreate == "true" {
			cert.PfxCreate = true
		} else if pfxCreate == "false" {
			cert.PfxCreate = false
		} else {
			app.logger.Debugf("%sPFX_CREATE not specified or invalid, using default \"%t\"", prefix, defaultPFXCreate)
			cert.PfxCreate = defaultPFXCreate
		}

		if cert.PfxCreate {
			// CW_CLIENT_PFX_FILENAME
			cert.PfxFilename = os.Getenv(prefix + "PFX_FILENAME")
			if cert.PfxFilename == "" {
				// not specified, use default
				cert.PfxFilename = fmt.Sprintf("key_certchain%d.pfx", certIndex)
				// backwards compat
				if prefix == "CW_CLIENT_" {
					cert.PfxFilename = "key_certchain.pfx"
				}

				app.logger.Debugf("%sPFX_FILENAME not specified, using default \"%s\"", prefix, cert.PfxFilename)
			}

			// CW_CLIENT_PFX_PASSWORD
			exists := false
			cert.PfxPassword, exists = os.LookupEnv(prefix + "PFX_PASSWORD")
			if !exists {
				app.logger.Debugf("%sPFX_PASSWORD not specified, using default \"%s\"", prefix, defaultPFXPassword)
				cert.PfxPassword = defaultPFXPassword
			}
		}

		// CW_CLIENT_PFX_LEGACY_CREATE
		pfxLegacyCreate := os.Getenv(prefix + "PFX_LEGACY_CREATE")
		if pfxLegacyCreate == "true" {
			cert.PfxLegacyCreate = true
		} else if pfxLegacyCreate == "false" {
			cert.PfxLegacyCreate = false
		} else {
			app.logger.Debugf("%sPFX_LEGACY_CREATE not specified or invalid, using default \"%t\"", prefix, defaultPFXLegacyCreate)
			cert.PfxLegacyCreate = defaultPFXLegacyCreate
		}

		if cert.PfxLegacyCreate {
			// CW_CLIENT_PFX_LEGACY_FILENAME
			cert.PfxLegacyFilename = os.Getenv(prefix + "PFX_LEGACY_FILENAME")
			if cert.PfxLegacyFilename == "" {
				// not specified, use default
				cert.PfxLegacyFilename = fmt.Sprintf("key_certchain%d.legacy.pfx", certIndex)
				// backwards compat
				if prefix == "CW_CLIENT_" {
					cert.PfxLegacyFilename = "key_certchain.legacy.pfx"
				}

				app.logger.Debugf("%sPFX_LEGACY_FILENAME not specified, using default \"%s\"", prefix, cert.PfxLegacyFilename)
			}

			// CW_CLIENT_PFX_LEGACY_PASSWORD
			exists := false
			cert.PfxLegacyPassword, exists = os.LookupEnv(prefix + "PFX_LEGACY_PASSWORD")
			if !exists {
				app.logger.Debugf("%sPFX_LEGACY_PASSWORD not specified, using default \"%s\"", prefix, defaultPFXLegacyPassword)
				cert.PfxLegacyPassword = defaultPFXLegacyPassword
			}
		}

		// append cert
		app.cfg.Certs = append(app.cfg.Certs, cert)
		app.tlsCerts = append(app.tlsCerts, NewSafeCert())
		app.cipherAEAD = append(app.cipherAEAD, cipherAEAD)
		app.pendingJobCancels = append(app.pendingJobCancels, nil)

		// make cert storage path (if not exist)
		_, err = os.Stat(app.cfg.Certs[certIndex].CertStoragePath)
		if errors.Is(err, os.ErrNotExist) {
			err = os.MkdirAll(app.cfg.Certs[certIndex].CertStoragePath, 0755)
			if err != nil {
				return app, fmt.Errorf("failed to make cert storage directory (%s)", err)
			} else {
				app.logger.Infof("cert storage path created")
			}
		} else if err != nil {
			return app, fmt.Errorf("failed to stat cert storage directory (%s)", err)
		}

		// increment and loop around
		certIndex++
	}

	// end config

	// for client use -- read existing key/cert pem from disk
	cert, err := os.ReadFile(app.cfg.Certs[0].CertStoragePath + "/" + app.cfg.Certs[0].CertPemFilename)
	if err != nil {
		app.logger.Infof("could not read cert (%s) from disk (%s), will try fetch from remote", app.cfg.Certs[0].CertPemFilename, err)
	} else {
		key, err := os.ReadFile(app.cfg.Certs[0].CertStoragePath + "/" + app.cfg.Certs[0].KeyPemFilename)
		if err != nil {
			app.logger.Infof("could not read key (%s) from disk (%s), will try fetch from remote", app.cfg.Certs[0].KeyPemFilename, err)
		} else {
			// read both key and cert, put them in tlsCert
			_, err := app.tlsCerts[0].Update(key, cert)
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
