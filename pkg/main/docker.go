package main

import (
	"context"
	"time"

	dockerContainerTypes "github.com/docker/docker/api/types/container"
)

const dockerRestartContextTimeout = 3 * time.Minute
const dockerGracefulExitTimeoutSeconds = 60

// restartDockerContainers restarts each of the container names specified in the
// config file; this func is called after cert files are updated
func (app *app) restartDockerContainers() error {
	var retErr error
	for i := range app.cfg.DockerContainersToRestart {
		restartCtx, cancel := context.WithTimeout(context.Background(), dockerRestartContextTimeout)
		defer cancel()

		timeoutSecs := dockerGracefulExitTimeoutSeconds
		err := app.dockerAPIClient.ContainerRestart(restartCtx, app.cfg.DockerContainersToRestart[i], dockerContainerTypes.StopOptions{Timeout: &timeoutSecs})
		if err != nil {
			retErr = err
			app.logger.Errorf("failed to restart container %s (%s)", app.cfg.DockerContainersToRestart[i], err)
		} else {
			app.logger.Infof("successfully restarted container: %s", app.cfg.DockerContainersToRestart[i])
		}
	}

	// return one of the errs above, if any occurred
	return retErr
}
