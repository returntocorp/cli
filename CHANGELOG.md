# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [0.0.18] - 2019-04-17

## Changed

- Client network timeout defaults.
- When pushed, analyzer contain README.md within the analyzer directory.

## Added

- Developing two dependent analyzers in tandem via overriding "path": "../some/path/to/analyzer" in `analyzer.json`.
- Added ability to run parameterized analyzer, i.e. pass arguments `--parameters` flag.

## [0.0.17] - 2019-04-17

## Changed

- Unified unittest and integration test functionality under `r2c test`

## Added

- Ability to drop a shell into docker contiainer with `--interactive` option for `r2c run`
- Caching to enable faster local run times

## [0.0.16] - 2019-04-01

## Changed

- Better handle docker errors
- Major refactor to make cli code more modular
- Simplified `r2c init` template to not rely on UID/GID

## Added

- Ability to create github issues on exception
- Log file for easy of interaction with cli in normal mode and debug info
- Ability (`-v`) to filter by verbosity
- Color and emoji for outputs to `stdout`

## [0.0.15] - 2019-03-21

## Changed

- Added better type hints for library classes
- Error handling to swallow exceptions during normal run
- Client errors are redirected to `stderr`

## Added

- Ability to run parameterized analyzers
- Ability to run analyzers that has output type `fs` and `both`
- Reporting of stale client versions

## [0.0.14] - 2019-03-13

### Fixed

- Fixed analyzer stdout default behavior

## [0.0.13] - 2019-03-13

### Changed

- Fixed analyzer stdout default behavior

## [0.0.12] - 2019-03-12

### Changed

- Fixed ubuntu user level permission issue

## [0.0.11] - 2019-03-12

### Added

- Enabled a way to get output of analyzer written into path
- Better debug functionalities
- Better STDOUT handling for analyzers
- Ability to save extra information in the `analyzer.json` under `extra` field
- Optional fields `author_name`, `author_email` in `analyzer.json`

### Changed

- Fixed ubntu-specific permissions issue
- `r2c login` now prompts for url to visit
- `--code` is now implicit argument to `r2c run` command

## [0.0.10] - 2019-03-11

- Fixed templated analyzer dependency issue
- Added better redirection for docker login

## [0.0.9] - 2019-03-06

### Changed

- Fixed linux-specific permission issue

## [0.0.8] - 2019-03-06

### Changed

- Fixed ubuntu-specific installation issue

## [0.0.7] - 2019-03-06

### Changed

- Created CHANGELOG.md

### Added

- Enabled `r2c` commands from subdirectories
- Added schema validator for integration tests
- Improved credential handling
- Added Windows to supported OS
- Standarized CLI with GNU arg standards
- Improving `r2c push` to handled mismatching organization
- Improved network error handling to include next steps along with meaningful details on what went wrong
- Some language improvements that clarifies analyzer specific language

## [0.0.6] - 2019-02-26

### Changed

- Updated `r2c login` experience (asks for permission)
- Update `r2c push` experience (no stack trace except in no-debug)
- Updated exception handling. Now catches all exceptions at top-level and only shows it to user during `--debug` mode
- Updated wording around `r2c` commands to clarify analyzer terms and set right expectations

### Added

- Added `r2c --version`
- Added logging of users's installed versions when making requests to \*.massive.ret2.co
