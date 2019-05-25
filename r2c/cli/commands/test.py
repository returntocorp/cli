import os

import click

from r2c.cli.commands.cli import cli
from r2c.cli.logger import abort_on_build_failure, print_error, print_msg, print_success
from r2c.cli.network import get_registry_data
from r2c.cli.util import find_and_open_analyzer_manifest, parse_remaining
from r2c.lib.errors import SymlinkNeedsElevationError
from r2c.lib.run import build_docker, integration_test, run_docker_unittest
from r2c.lib.versioned_analyzer import VersionedAnalyzer


@cli.command()
@click.option(
    "-d",
    "--analyzer-directory",
    default=os.getcwd(),
    help="The directory where the analyzer is located, defaulting to the current directory.",
)
@click.option(
    "--which",
    type=click.Choice(["unit", "integration", "all"]),
    default="all",
    help="Run unit tests, integration tests, or all.",
)
@click.option(
    "--cache", is_flag=True, default=False, help="Use local filesystem cache."
)
@click.argument("env-args-string", nargs=-1, type=click.Path())
@click.pass_context
def test(ctx, analyzer_directory, which, cache, env_args_string):
    """
    Locally run tests for the current analyzer.

    You can add integration test files to the `examples/` directory.
    For more information, refer to the integration test section of the README.

    For unittests, you can define how to run your unit tests in `src/unittest.sh`.

    You may have to login if your analyzer depends on privately
    published analyzers.
    """

    verbose = ctx.obj["VERBOSE"]
    env_args_dict = parse_remaining(env_args_string)
    print_msg(
        f"Running integration tests for analyzer {'with debug mode' if ctx.obj['DEBUG'] else ''}"
    )

    manifest, analyzer_directory = find_and_open_analyzer_manifest(
        analyzer_directory, ctx
    )
    print_msg("🔨 Building docker container")
    abort_on_build_failure(
        build_docker(
            manifest.analyzer_name,
            manifest.version,
            os.path.relpath(analyzer_directory, os.getcwd()),
            env_args_dict=env_args_dict,
            verbose=verbose,
        )
    )
    if which == "unit" or which == "all":
        image_id = VersionedAnalyzer(manifest.analyzer_name, manifest.version).image_id
        status = run_docker_unittest(
            analyzer_directory=analyzer_directory,
            analyzer_name=manifest.analyzer_name,
            docker_image=image_id,
            verbose=verbose,
            env_args_dict=env_args_dict,
        )
        if status == 0:
            print_success(f"Unit tests passed")
        else:
            print_error(f"Unit tests failed with status {status}")
    if which == "integration" or which == "all":
        try:
            integration_test(
                manifest=manifest,
                analyzer_directory=analyzer_directory,
                workdir=None,
                env_args_dict=env_args_dict,
                registry_data=get_registry_data(),
                use_cache=cache,
            )
            print_success(f"Integration tests passed")
        except SymlinkNeedsElevationError as sym:
            print_error(
                f"Error setting up integration tests. {sym}. Try again as an admin"
            )
