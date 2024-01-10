package main

import (
	"context"
	"math/rand"
	"time"
)

// inFileUpdateWindow returns true if the job should run immediately because t is in the
// permitted file update time window
func (app *app) inFileUpdateWindow(t time.Time) bool {
	// check if t is an approved starting weekday or if the day before was approved
	approvedWeekday := false
	prevDayWasApprovedWeekday := false
	for weekday := range app.cfg.FileUpdateDaysOfWeek {
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
	tAfterOrEqualStartTime := timeAIsAfterOrEqualB(t.Hour(), t.Minute(), app.cfg.FileUpdateTimeStartHour, app.cfg.FileUpdateTimeStartMinute)
	tBeforeOrEqualEndTime := timeAIsBeforeOrEqualB(t.Hour(), t.Minute(), app.cfg.FileUpdateTimeEndHour, app.cfg.FileUpdateTimeEndMinute)

	// handling varies depending on if time window includes midnight
	if app.cfg.FileUpdateTimeIncludesMidnight {
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
func (app *app) nextFileUpdateWindowStart() time.Time {
	now := time.Now().Round(time.Minute)

	// set time stamp for today with window start time
	nextWindow := time.Date(now.Year(), now.Month(), now.Day(), app.cfg.FileUpdateTimeStartHour, app.cfg.FileUpdateTimeStartMinute, 0, now.Nanosecond(), now.Location())

	// if today is acceptable and start hasn't happened yet, use today's start
	_, todayWeekdayOk := app.cfg.FileUpdateDaysOfWeek[now.Weekday()]
	if todayWeekdayOk && timeAIsBeforeOrEqualB(now.Hour(), now.Minute(), app.cfg.FileUpdateTimeStartHour, app.cfg.FileUpdateTimeStartMinute) {
		return nextWindow
	}

	// if today is not an acceptable weekday or it is acceptable but start has passed, use next acceptable start

	// find next acceptable weekday (cap at +8 days to avoid infinite if some weird anomoly happens)
	addDays := 0
	for addDays++; addDays <= 8; addDays++ {
		_, newWeekdayOk := app.cfg.FileUpdateDaysOfWeek[(now.Weekday()+time.Weekday(addDays))%7]
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

// scheduleJobWriteCertsMemoryToDisk schedules a job to write the lego client's
// key/cert pem from memory to disk (and generate any additional files on disk that
// are configured)
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
		now := time.Now().Round(time.Minute)

		// if not within the approved update window, add delay until next window
		if !app.inFileUpdateWindow(now) {
			// next window start
			runTime := app.nextFileUpdateWindowStart()

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
		} else {
			app.logger.Info("write certs job executing imemdiately")
		}

		// write certs in memory to disk, regardless of existence on disk
		diskNeedsUpdate := app.updateCertFilesAndRestartContainers(false)

		// if something failed and update still needed, schedule next job
		if diskNeedsUpdate {
			app.scheduleJobWriteCertsMemoryToDisk()
		}

		app.logger.Info("write certs job complete")
	}()
}

// scheduleJobFetchCertsAndWriteToDisk fetches the latest key/cert from LeGo server
// and updates the client's key/cert. It repeats this task every 15 minutes until
// it succeeds. Then it schedules a job to write lego client's key/cert pem from
// memory to disk (along with any other files that are configured).
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
