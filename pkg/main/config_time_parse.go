package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// daysOfWeek maps weekday strings to Weekday values
var daysOfWeek = map[string]time.Weekday{
	"sunday":    time.Sunday,
	"monday":    time.Monday,
	"tuesday":   time.Tuesday,
	"wednesday": time.Wednesday,
	"thursday":  time.Thursday,
	"friday":    time.Friday,
	"saturday":  time.Saturday,

	"sun": time.Sunday,
	"mon": time.Monday,
	"tue": time.Tuesday,
	"wed": time.Wednesday,
	"thu": time.Thursday,
	"fri": time.Friday,
	"sat": time.Saturday,
}

// parseWeekday returns Weekday for a given weekday string
func parseWeekday(weekdayName string) (time.Weekday, error) {
	weekdayLower := strings.ToLower(weekdayName)

	if wd, ok := daysOfWeek[weekdayLower]; ok {
		return wd, nil
	}

	return -1, fmt.Errorf("invalid weekday '%s'", weekdayName)
}

// allWeekdays is a map that contains all Weekday values
var allWeekdays = map[time.Weekday]struct{}{
	time.Sunday:    {},
	time.Monday:    {},
	time.Tuesday:   {},
	time.Wednesday: {},
	time.Thursday:  {},
	time.Friday:    {},
	time.Saturday:  {},
}

// parseWeekdaysString returns a map of Weekday from the provided space
// separated string
func parseWeekdaysString(weekdaysStr string) (map[time.Weekday]struct{}, error) {
	weekdayMap := make(map[time.Weekday]struct{})

	// split and check each weekday string value
	for _, weekdayStr := range strings.Split(weekdaysStr, " ") {
		weekday, err := parseWeekday(weekdayStr)
		if err != nil {
			return nil, err
		}

		// repeats are irrelevant, will just set value again
		weekdayMap[weekday] = struct{}{}
	}

	return weekdayMap, nil
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

// timeAIsBeforeOrEqualB returns true if the time specified by A is before or equal to B
func timeAIsBeforeOrEqualB(aHr, aMin, bHr, bMin int) bool {
	if aHr < bHr || (aHr == bHr && aMin <= bMin) {
		return true
	}

	return false
}

// timeAIsBeforeOrEqualB returns true if the time specified by A is before or equal to B
func timeAIsAfterOrEqualB(aHr, aMin, bHr, bMin int) bool {
	if aHr > bHr || (aHr == bHr && aMin >= bMin) {
		return true
	}

	return false
}

// parseDurationString parses a duration string like "1d", "5h", "30m" and returns
// a time.Duration. Supported units: d (days), h (hours), m (minutes), s (seconds)
func parseDurationString(durationStr string) (time.Duration, error) {
	if durationStr == "" {
		return 0, errors.New("duration string is empty")
	}

	// check for standard Go duration format first (supports combinations like "1h30m")
	duration, err := time.ParseDuration(durationStr)
	if err == nil {
		return duration, nil
	}

	// if standard parsing fails, try custom day format
	if strings.HasSuffix(durationStr, "d") {
		daysStr := strings.TrimSuffix(durationStr, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil || days <= 0 {
			return 0, errors.New("invalid duration format (use formats like: 1d, 5h, 30m, 1h30m)")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	return 0, errors.New("invalid duration format (use formats like: 1d, 5h, 30m, 1h30m)")
}
