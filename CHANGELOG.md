# LeGo CertHub Client Changelog

NOTE: This application is not yet intended for general use.

## [v0.1.7] - 2024-01-11

- Add a log message for no write and up to date.

## [v0.1.6] - 2024-01-10

- Clarify log message about file write.


## [v0.1.5] - 2024-01-10

- Fix incorrect scheduling of file write job when not needed.


## [v0.1.4] - 2024-01-10

- Add timezone support.
- Change writing files options from specific time to a time window.
- Support multiple weekday selection for write windows.
- Add option to stop docker containers instead of restart.


## [v0.1.3] - 2024-01-06

Add file write update schedule. Files will only be written at 
the specified time and subsequently containers will only restart 
when files are written.

If any files are missing, the client disregards scheduling and 
updates right away (on the assumption the dependent applications 
are, or will, fail without the missing files).


## [v0.1.2] - 2024-01-06

Add docker API version negotiation.


## [v0.1.1] - 2024-01-06

Change default cert storage path.


## [v0.1.0] - 2024-01-06

Initial release.
