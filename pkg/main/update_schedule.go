package main

import (
	"context"
	"math/rand"
	"time"
)

// nextWeeklyDay returns the day of the month that is the first occurence of
// the specified weekday after the specified time
func nextWeeklyDay(t time.Time, weekday time.Weekday) int {
	days := int((7 + (weekday - t.Weekday())) % 7)
	_, _, day := t.AddDate(0, 0, days).Date()
	return day
}

// scheduleJobWriteCertsMemoryToDisk schedules a job to write the new cert files
// using data already loaded into the client cert. This is used when the client
// launched with valid key/cert files but newer ones were found on the lego
// server.
func (app *app) scheduleJobWriteCertsMemoryToDisk() {
	go func() {
		// cancel any old job
		if app.pendingJobCancel != nil {
			app.pendingJobCancel()
		}

		// make new cancel context for this job
		ctx, cancel := context.WithCancel(context.Background())
		// always defer cancel in case something weird happens (e.g. cancelFunc
		// race causes overwritten before being called)
		defer cancel()
		app.pendingJobCancel = cancel

		// determine when this job should run and log it
		now := time.Now().Round(time.Second)
		day := now.Day()

		// if weekday is selected, find next day
		if app.cfg.FileUpdateDayOfWeek >= 0 && app.cfg.FileUpdateDayOfWeek < 7 {
			day = nextWeeklyDay(now, app.cfg.FileUpdateDayOfWeek)
		}

		runHr, runMin, err := parseTimeString(app.cfg.FileUpdateTimeString)
		if err != nil {
			app.logger.Errorf("somehow an invalid time string exists (%s) in config, please report bug", app.cfg.FileUpdateTimeString)
			runHr = defaultUpdateTimeHour
			runMin = defaultUpdateTimeMinute
		}
		runTime := time.Date(now.Year(), now.Month(), day, runHr, runMin, 0, now.Nanosecond(), now.Location())
		// if run time past for today, add a day (or week if only running weekly)
		if now.After(runTime) {
			if app.cfg.FileUpdateDayOfWeek >= 0 && app.cfg.FileUpdateDayOfWeek < 7 {
				runTime = runTime.Add(7 * 24 * time.Hour)
			} else {
				runTime = runTime.Add(24 * time.Hour)
			}
		}
		// add random second
		runTime = runTime.Add(time.Duration(rand.Intn(60)) * time.Second)
		runTimeString := runTime.String()

		app.logger.Infof("scheduling write certs job for %s", runTimeString)

		// wait for user specified run window to occur
		select {
		case <-ctx.Done():
			// job canceled (presumably new job scheduled instead)
			app.logger.Infof("write certs job scheduled for %s canceled (ctx closed - probably another job scheduled in its place)", runTimeString)
			// DONE
			return

		case <-time.After(time.Until(runTime)):
			// sleep until next run
		}

		app.logger.Infof("write certs job scheduled for %s executing", runTimeString)

		// write certs in memory to disk, regardless of existence on disk
		diskNeedsUpdate := app.updateCertFilesAndRestartContainers(false)

		// if something failed and update still needed, schedule next job
		if diskNeedsUpdate {
			app.scheduleJobWriteCertsMemoryToDisk()
		}

		app.logger.Infof("write certs job scheduled for %s complete", runTimeString)
	}()
}

// scheduleJobFetchCertsAndWriteToDisk fetches the latest key/cert from LeGo
// updates the client's key/cert. It repeats this task every 15 minutes until
// it succeeds. Then it schedules a job to write the new files to disk.
func (app *app) scheduleJobFetchCertsAndWriteToDisk() {
	go func() {
		// cancel any old job
		if app.pendingJobCancel != nil {
			app.pendingJobCancel()
		}

		// make new cancel context for this job
		ctx, cancel := context.WithCancel(context.Background())
		// always defer cancel in case something weird happens (e.g. cancelFunc
		// race causes overwritten before being called)
		defer cancel()
		app.pendingJobCancel = cancel

		// fetch job will only wait 15 minutes (since no file write or docker restart will trigger)
		runTime := time.Now().Round(time.Second).Add(15 * time.Minute).Add(time.Duration(rand.Intn(60)) * time.Second)
		runTimeString := runTime.String()

		app.logger.Infof("scheduling fetch certs job for %s", runTimeString)

		// wait for user specified run time to occur
		select {
		case <-ctx.Done():
			// job canceled (presumably new job scheduled instead)
			app.logger.Infof("fetch certs job scheduled for %s canceled (ctx closed - probably another job scheduled in its place)", runTimeString)
			// DONE
			return

		case <-time.After(time.Until(runTime)):
			// sleep until next run
		}

		app.logger.Infof("fetch certs job scheduled for %s executing", runTimeString)

		// try and get newer key/cert from lego server
		err := app.updateClientKeyAndCertchain()
		if err != nil {
			app.logger.Errorf("failed to fetch key/cert from lego server (%s)", err)
			// schedule try again
			app.scheduleJobFetchCertsAndWriteToDisk()
		} else {
			// success & updated - schedule write job (which may or may not actually write depending on if files need update)
			app.scheduleJobWriteCertsMemoryToDisk()
		}

		app.logger.Infof("fetch certs job scheduled for %s complete", runTimeString)
	}()
}
