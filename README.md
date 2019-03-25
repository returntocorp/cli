# r2c-cli

This is the CLI for interacting with the R2C platform.

## Installation

### Prerequisites

- [Install Docker](https://docs.docker.com/install/) for your platform
- [Python 3.7 and up](https://www.python.org/about/gettingstarted/) for your platform

### Setup

- Install r2c-cli via `pip`:

  ```
  pip3 install r2c-cli
  ```

- Run `r2c` to check that the CLI was installed properly. If installed properly, you should see our help text.

## Documentation

See [getr2c.com](http://getr2c.com) for details on how write analyzer using `r2c-cli`.

## Usage

```bash
r2c <command> [options]
```

You can also run `r2c --help` or just `r2c` to see usage information.

For help with a command in particular, you can run `r2c <command> --help` and see help specifically for that command.

For the commands `run` `test` `push` and `unittest` they will require that you run them in an analyzer directory (i.e. a directory containing an `analyzer.json` and associated files).

## Unit Testing

Instructions to run unittests are defined `src/unittest.sh`. Make sure to add `mocha test` or `npm test` to enable
unittesting for your analyzer.

## Integration Testing

Integration tests should be defined in the `src/examples` directory.
Integration test on a github REPO@COMMIT could be defined as

```json
{
  "target": "{REPO}",
  "target_hash": "{COMMIT}",
  "expected": []
}
```

## Uploading new analyzer

Once you are done developing and testing your analyzer locally, you must update `version` in your
`analyzer.json` and run

```bash
r2c push
```

to upload your analyzer to your repository.

## Troubleshooting

- If you run into issues running `r2c` commands, you can run with `--debug` flag and reach out to `support@ret2.co` with the error log.
