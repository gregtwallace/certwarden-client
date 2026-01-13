package main

import (
	"context"
	"io"
	"strings"
	"time"

	dockerContainerTypes "github.com/docker/docker/api/types/container"
)

const dockerRestartContextTimeout = 3 * time.Minute
const dockerGracefulExitTimeoutSeconds = 60
const dockerExecContextTimeout = 2 * time.Minute

// restartOrStopDockerContainers stops or restarts each of the container names specified in the
// config file; this func is called after cert files are updated; restarts/stops are done
// async and results are logged
func (app *app) restartOrStopDockerContainers(certIndex int) {
	app.logger.Infof("docker restarting container(s) for cert %d", certIndex)

	// abort if invalid index
	if certIndex > len(app.cfg.Certs) {
		app.logger.Errorf("docker restart failed, invalid cert index %d (how'd that happen??)", certIndex)
		return
	}

	for _, container := range app.cfg.Certs[certIndex].DockerContainersToRestart {
		go func(asyncContainer string) {
			restartCtx, cancel := context.WithTimeout(context.Background(), dockerRestartContextTimeout)
			defer cancel()

			// restart (or stop if configured)
			timeoutSecs := dockerGracefulExitTimeoutSeconds
			if app.cfg.Certs[certIndex].DockerStopOnly {
				err := app.dockerAPIClient.ContainerStop(restartCtx, asyncContainer, dockerContainerTypes.StopOptions{Timeout: &timeoutSecs})
				if err != nil {
					app.logger.Errorf("failed to stop container %s (%s)", asyncContainer, err)
				} else {
					app.logger.Infof("successfully stopped container: %s", asyncContainer)
				}

			} else {
				err := app.dockerAPIClient.ContainerRestart(restartCtx, asyncContainer, dockerContainerTypes.StopOptions{Timeout: &timeoutSecs})
				if err != nil {
					app.logger.Errorf("failed to restart container %s (%s)", asyncContainer, err)
				} else {
					app.logger.Infof("successfully restarted container: %s", asyncContainer)
				}
			}

		}(container)
	}
}

// executeDockerContainerCommands executes commands in specified Docker containers
// after cert files are updated; executions are done async and results are logged
func (app *app) executeDockerContainerCommands(certIndex int) {
	app.logger.Infof("executing docker container command(s) for cert %d", certIndex)

	// abort if invalid index
	if certIndex > len(app.cfg.Certs) {
		app.logger.Errorf("docker command execution failed, invalid cert index %d (how'd that happen??)", certIndex)
		return
	}

	for _, containerCmd := range app.cfg.Certs[certIndex].DockerContainerCommands {
		go func(asyncContainerCmd containerCommand) {
			execCtx, cancel := context.WithTimeout(context.Background(), dockerExecContextTimeout)
			defer cancel()

			// Create exec configuration
			execConfig := dockerContainerTypes.ExecOptions{
				AttachStdout: true,
				AttachStderr: true,
				Cmd:          asyncContainerCmd.Command,
			}

			// Create exec instance
			execID, err := app.dockerAPIClient.ContainerExecCreate(execCtx, asyncContainerCmd.ContainerName, execConfig)
			if err != nil {
				app.logger.Errorf("failed to create exec for container %s command %v (%s)",
					asyncContainerCmd.ContainerName, asyncContainerCmd.Command, err)
				return
			}

			// Start exec
			execStartCheck := dockerContainerTypes.ExecStartOptions{
				Detach: false,
				Tty:    false,
			}

			resp, err := app.dockerAPIClient.ContainerExecAttach(execCtx, execID.ID, execStartCheck)
			if err != nil {
				app.logger.Errorf("failed to attach exec for container %s command %v (%s)",
					asyncContainerCmd.ContainerName, asyncContainerCmd.Command, err)
				return
			}
			defer resp.Close()

			// Read output
			output, err := io.ReadAll(resp.Reader)
			if err != nil {
				app.logger.Errorf("failed to read exec output for container %s command %v (%s)",
					asyncContainerCmd.ContainerName, asyncContainerCmd.Command, err)
			}

			// Check exit code
			inspectResp, err := app.dockerAPIClient.ContainerExecInspect(execCtx, execID.ID)
			if err != nil {
				app.logger.Errorf("failed to inspect exec for container %s command %v (%s)",
					asyncContainerCmd.ContainerName, asyncContainerCmd.Command, err)
				return
			}

			if inspectResp.ExitCode == 0 {
				outputStr := strings.TrimSpace(string(output))
				if outputStr != "" {
					app.logger.Infof("successfully executed command in container %s: %v (output: %s)",
						asyncContainerCmd.ContainerName, asyncContainerCmd.Command, outputStr)
				} else {
					app.logger.Infof("successfully executed command in container %s: %v",
						asyncContainerCmd.ContainerName, asyncContainerCmd.Command)
				}
			} else {
				app.logger.Errorf("command failed in container %s: %v (exit code: %d, output: %s)",
					asyncContainerCmd.ContainerName, asyncContainerCmd.Command, inspectResp.ExitCode, strings.TrimSpace(string(output)))
			}

		}(containerCmd)
	}
}
