package main

import (
	"context"
	"time"

	dockerContainerTypes "github.com/docker/docker/api/types/container"
)

const dockerRestartContextTimeout = 3 * time.Minute
const dockerGracefulExitTimeoutSeconds = 60

// restartDockerContainers restarts each of the container names specified in the
// config file; this func is called after cert files are updated; restarts are done
// async and results are logged
func (app *app) restartDockerContainers() {
	for _, container := range app.cfg.DockerContainersToRestart {
		go func(asyncContainer string) {
			restartCtx, cancel := context.WithTimeout(context.Background(), dockerRestartContextTimeout)
			defer cancel()

			timeoutSecs := dockerGracefulExitTimeoutSeconds
			err := app.dockerAPIClient.ContainerRestart(restartCtx, asyncContainer, dockerContainerTypes.StopOptions{Timeout: &timeoutSecs})
			if err != nil {
				app.logger.Errorf("failed to restart container %s (%s)", asyncContainer, err)
			} else {
				app.logger.Infof("successfully restarted container: %s", asyncContainer)
			}
		}(container)
	}
}
