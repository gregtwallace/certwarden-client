package main

import (
	"context"
	"math/rand"
	"time"
)

// inFileUpdateWindow returns true if the job should run immediately because t is in the
// permitted file update time window
func (app *app) inFileUpdateWindow(certIndex int, t time.Time) bool {
	// check if t is an approved starting weekday or if the day before was approved
	approvedWeekday := false
	prevDayWasApprovedWeekday := false
	for weekday := range app.cfg.Certs[certIndex].FileUpdateDaysOfWeek {
		// check today
		if t.Weekday() == weekday {
			approvedWeekday = true
		}

		// check yesterday
		if (t.Weekday()+7-1)%7 == weekday {
			prevDayWasApprovedWeekday = true
		}
	}

	// compare t to start and end times
	tAfterOrEqualStartTime := timeAIsAfterOrEqualB(t.Hour(), t.Minute(), app.cfg.Certs[certIndex].FileUpdateTimeStartHour, app.cfg.Certs[certIndex].FileUpdateTimeStartMinute)
	tBeforeOrEqualEndTime := timeAIsBeforeOrEqualB(t.Hour(), t.Minute(), app.cfg.Certs[certIndex].FileUpdateTimeEndHour, app.cfg.Certs[certIndex].FileUpdateTimeEndMinute)

	// handling varies depending on if time window includes midnight
	if app.cfg.Certs[certIndex].FileUpdateTimeIncludesMidnight {
		// if prior day approved weekday, check if t is before end of window
		if prevDayWasApprovedWeekday && tBeforeOrEqualEndTime {
			return true
		}

		// if today is approved weekday, check if t is after start of window
		if approvedWeekday && tAfterOrEqualStartTime {
			return true
		}

	} else {
		// window does NOT include midnight

		// if t is after or equal start AND before or equal to end; in window
		if approvedWeekday && tAfterOrEqualStartTime && tBeforeOrEqualEndTime {
			return true
		}
	}

	// anything else, outside of window
	return false
}

// nextFileUpdateWindowStart returns the time the next update window begins
func (app *app) nextFileUpdateWindowStart(certIndex int) time.Time {
	now := time.Now().Round(time.Minute)

	// set time stamp for today with window start time
	nextWindow := time.Date(now.Year(), now.Month(), now.Day(), app.cfg.Certs[certIndex].FileUpdateTimeStartHour, app.cfg.Certs[certIndex].FileUpdateTimeStartMinute, 0, now.Nanosecond(), now.Location())

	// if today is acceptable and start hasn't happened yet, use today's start
	_, todayWeekdayOk := app.cfg.Certs[certIndex].FileUpdateDaysOfWeek[now.Weekday()]
	if todayWeekdayOk && timeAIsBeforeOrEqualB(now.Hour(), now.Minute(), app.cfg.Certs[certIndex].FileUpdateTimeStartHour, app.cfg.Certs[certIndex].FileUpdateTimeStartMinute) {
		return nextWindow
	}

	// if today is not an acceptable weekday or it is acceptable but start has passed, use next acceptable start

	// find next acceptable weekday (cap at +8 days to avoid infinite if some weird anomoly happens)
	addDays := 0
	for addDays++; addDays <= 8; addDays++ {
		_, newWeekdayOk := app.cfg.Certs[certIndex].FileUpdateDaysOfWeek[(now.Weekday()+time.Weekday(addDays))%7]
		if newWeekdayOk {
			break
		}
	}

	if addDays == 8 {
		app.logger.Error("somehow next update window added more than 7 days, this should never happen, report bug")
	}

	// add days to get to next proper weekday and return
	return nextWindow.Add(time.Duration(addDays) * 24 * time.Hour)
}

// scheduleJobWriteCertsMemoryToDisk schedules a job to write the client's
// key/cert pem from memory to disk (and generate any additional files on disk that
// are configured)
func (app *app) scheduleJobWriteCertsMemoryToDisk(certIndex int) {
	go func() {
		// cancel any old job
		if app.pendingJobCancels[certIndex] != nil {
			app.pendingJobCancels[certIndex]()
		}

		// make new cancel context for this job
		ctx, cancel := context.WithCancel(context.Background())
		// always defer cancel in case something weird happens (e.g. cancelFunc
		// race causes overwritten before being called)
		defer cancel()
		app.pendingJobCancels[certIndex] = cancel

		// determine when this job should run and log it
		now := time.Now().Round(time.Minute)

		// if not within the approved update window, add delay until next window
		if !app.inFileUpdateWindow(certIndex, now) {
			// next window start
			runTime := app.nextFileUpdateWindowStart(certIndex)

			// add random second
			runTime = runTime.Add(time.Duration(rand.Intn(60)) * time.Second)
			runTimeString := runTime.String()

			app.logger.Infof("scheduling write cert %d job for %s", certIndex, runTimeString)

			// wait for user specified run window to occur
			select {
			case <-ctx.Done():
				// job canceled (presumably new job scheduled instead)
				app.logger.Infof("write cert %d job scheduled for %s canceled (ctx closed - probably another job scheduled in its place)", certIndex, runTimeString)
				// DONE
				return

			case <-time.After(time.Until(runTime)):
				// sleep until next run
			}

			app.logger.Infof("write cert %d job scheduled for %s executing", certIndex, runTimeString)
		} else {
			app.logger.Infof("write cert %d job executing imemdiately", certIndex)
		}

		// write certs in memory to disk, regardless of existence on disk
		diskNeedsUpdate := app.updateCertFilesAndRestartContainers(certIndex, false)

		// if something failed and update still needed, schedule next job
		if diskNeedsUpdate {
			app.scheduleJobWriteCertsMemoryToDisk(certIndex)
		}

		app.logger.Infof("write cert %d job complete", certIndex)
	}()
}

// scheduleJobFetchCertsAndWriteToDisk fetches the latest key/cert from server
// and updates the client's key/cert. It repeats this task every 15 minutes until
// it succeeds. Then it schedules a job to write client's key/cert pem from
// memory to disk (along with any other files that are configured).
func (app *app) scheduleJobFetchCertsAndWriteToDisk(certIndex int) {
	go func() {
		// cancel any old job
		if app.pendingJobCancels[certIndex] != nil {
			app.pendingJobCancels[certIndex]()
		}

		// make new cancel context for this job
		ctx, cancel := context.WithCancel(context.Background())
		// always defer cancel in case something weird happens (e.g. cancelFunc
		// race causes overwritten before being called)
		defer cancel()
		app.pendingJobCancels[certIndex] = cancel

		// fetch job will only wait 15 minutes (since no file write or docker restart will trigger)
		runTime := time.Now().Round(time.Second).Add(15 * time.Minute).Add(time.Duration(rand.Intn(60)) * time.Second)
		runTimeString := runTime.String()

		app.logger.Infof("scheduling fetch cert %d job for %s", certIndex, runTimeString)

		// wait for user specified run time to occur
		select {
		case <-ctx.Done():
			// job canceled (presumably new job scheduled instead)
			app.logger.Infof("fetch cert %d job scheduled for %s canceled (ctx closed - probably another job scheduled in its place)", certIndex, runTimeString)
			// DONE
			return

		case <-time.After(time.Until(runTime)):
			// sleep until next run
		}

		app.logger.Infof("fetch cert %d job scheduled for %s executing", certIndex, runTimeString)

		// try and get newer key/cert from server
		err := app.updateClientKeyAndCertchain(certIndex)
		if err != nil {
			app.logger.Errorf("failed to fetch key/cert %d from server (%s)", certIndex, err)
			// schedule try again
			app.scheduleJobFetchCertsAndWriteToDisk(certIndex)
		} else {
			// success & updated - schedule write job (which may or may not actually write depending on if files need update)
			app.scheduleJobWriteCertsMemoryToDisk(certIndex)
		}

		app.logger.Infof("fetch cert %d job scheduled for %s complete", certIndex, runTimeString)
	}()
}

// scheduleJobPollingFetch creates a background job that polls the server at regular
// intervals to check for new certificates. This is an alternative to server push
// notifications when the client cannot accept incoming connections.
func (app *app) scheduleJobPollingFetch(certIndex int) {
	go func() {
		// cancel any old job
		if app.pendingJobCancels[certIndex] != nil {
			app.pendingJobCancels[certIndex]()
		}

		// make new cancel context for this job
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		app.pendingJobCancels[certIndex] = cancel

		app.logger.Infof("starting polling for cert %d with interval %v", certIndex, app.cfg.PollingInterval)

		ticker := time.NewTicker(app.cfg.PollingInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				app.logger.Infof("polling job for cert %d canceled", certIndex)
				return

			case <-ticker.C:
				app.logger.Debugf("polling server for cert %d updates", certIndex)

				// try to fetch newer key/cert from server
				err := app.updateClientKeyAndCertchain(certIndex)
				if err != nil {
					app.logger.Errorf("failed to poll and fetch key/cert %d from server (%s)", certIndex, err)
					// continue polling despite error
				} else {
					// success - check if disk needs update
					diskNeedsUpdate := app.updateCertFilesAndRestartContainers(certIndex, false)

					// if disk needs update but we're outside the update window,
					// schedule a write job for the next window
					if diskNeedsUpdate {
						app.scheduleJobWriteCertsMemoryToDisk(certIndex)
					}
				}
			}
		}
	}()
}
