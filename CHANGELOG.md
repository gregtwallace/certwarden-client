# Cert Warden Client Changelog

## [v0.4.0] - 2025-01-22

Update Go & Alpine to the latest version, updated the Docker client pkg, 
and allow specifying environment vars related to the Docker client 
connection (e.g., `DOCKER_HOST`).

Also, remove backwards compatibility with LeGo CertHub and changes from
using a custom http Client to a custom http Transport.


## [v0.3.1] - 2024-06-26

Fix incorrect parsing of cert and key file permission environment
variables. Also set default key permissions to `0600`.


## [v0.3.0] - 2024-04-15

Name changed to Cert Warden.

> [!CAUTION]
> The environment variable names were changed. Since the client is still
> in a relatively alpha stage, I did not implement any backward compat
> and you will need to update your environment variable names.

The client route that the client listens for was changed, but backward 
compat actions were taken on this front (the new server version will send 
to both routes and the new client will listen for both). This will be
dropped eventually but for now keeps the breaking change contained to the
environment variable names.

In addition to the name change and compatibility issue, this release
updates some dependencies.


## [v0.2.1] - 2024-03-06

Update to Go 1.22.1, which includes some security fixes.


## [v0.2.0] - 2024-02-12

First 'real' release. Some bug fixes and dependency updates from the
last version.


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
