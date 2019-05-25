import os
from typing import List

import click

from r2c.cli.commands.cli import cli
from r2c.cli.logger import (
    abort_on_build_failure,
    get_logger,
    print_error_exit,
    print_msg,
    print_success,
    print_warning,
)
from r2c.cli.network import (
    docker_login,
    get_base_url,
    get_docker_creds,
    get_registry_data,
)
from r2c.cli.util import (
    find_and_open_analyzer_manifest,
    load_params,
    parse_remaining,
    set_debug_flag,
    set_verbose_flag,
)
from r2c.lib.errors import SymlinkNeedsElevationError
from r2c.lib.run import build_docker, run_analyzer_on_local_code
from r2c.lib.versioned_analyzer import AnalyzerName

logger = get_logger()

# Hack click to accepting optional options
# https://stackoverflow.com/questions/40753999/python-click-make-option-value-optional
class InteractiveOption(click.Option):
    pass


class InteractiveNameOption(click.Option):
    def get_help_record(self, ctx):
        """ Fix the help text to eliminate  _name suffix """
        cmd_help = super().get_help_record(ctx)
        # replace _name from help menu, rest of the menu stays the same
        update_cmd_help = cmd_help[0].replace("_name", "=").replace(" ", "")
        return (update_cmd_help,) + cmd_help[1:]


class InteractiveCommand(click.Command):
    def parse_args(self, ctx, args):
        interactive_options: List = []
        for option in ctx.command.params:
            if isinstance(option, InteractiveOption):
                interactive_options = option.opts

        # only for InteractiveOption, rewrite the option so that InteractiveNameOption can pick it up
        for i, arg in enumerate(args):
            arg = arg.split("=")
            # if InteractiveOption was specified with arguments
            if arg[0] in interactive_options and len(arg) > 1:
                arg[0] += "_name"
                args[i] = "=".join(arg)

        return super().parse_args(ctx, args)


@cli.command(cls=InteractiveCommand)
@click.argument("analyzer_input")
@click.option(
    "-d",
    "--analyzer-directory",
    default=os.getcwd(),
    help="The directory where the analyzer is located, defaulting to the current directory.",
)
@click.option("-o", "--output-path", help="Output path for analyzer's output json")
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    default=False,
    help="Don't print analyzer output to stdout after it completes",
)
@click.option(
    "--analyzer-quiet",
    is_flag=True,
    default=False,
    help="Don't print analyzer logging to stdout or stderr while it runs",
)
@click.option(
    "--no-login",
    is_flag=True,
    default=False,
    help="Do not run `docker login` command during run.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show extra output, error messages, and exception stack traces with INFO filtering",
    default=False,
)
@click.option(
    "--debug",
    "-d",
    is_flag=True,
    help="Show extra output, error messages, and exception stack traces with DEBUG filtering",
    default=False,
    hidden=True,
)
@click.option(
    "--interactive",
    "-i",
    is_flag=True,
    cls=InteractiveOption,
    default=False,
    help="Shell into last docker container in the execution chain.",
)
@click.option(
    "--interactive_name",
    "-i_name",
    cls=InteractiveNameOption,
    type=str,
    default=None,
    help="Shell into docker container via `docker exec -it` by analyzer name. If multiple analyzer match, shells into the first container in the execution chain.",
)
@click.option(
    "--reset-cache",
    is_flag=True,
    default=False,
    show_default=True,
    help="Resets local cache.",
)
@click.option(
    "--parameters",
    default="{}",
    help="Parameters to pass to the top level analyzer being run.",
    hidden=True,
)
@click.argument("env-args-string", nargs=-1, type=click.Path())
@click.pass_context
def run(
    ctx,
    analyzer_directory,
    analyzer_input,
    output_path,
    quiet,
    analyzer_quiet,
    no_login,
    debug,
    interactive,
    interactive_name,
    reset_cache,
    verbose,
    parameters,
    env_args_string,
):
    """
    Run the analyzer in the current directory over a code directory.

    You may have to log in if your analyzer depends on privately
    published analyzers.
    """

    if verbose == True:  # allow passing --verbose to run as well as globally
        set_verbose_flag(ctx, True)
    if debug == True:
        set_debug_flag(ctx, True)
    docker_verbose_mode = ctx.obj["VERBOSE"] or ctx.obj["DEBUG"]
    print_msg(f"🏃 Starting to run analyzer...")

    interactive_index = -1 if interactive else None
    env_args_dict = parse_remaining(env_args_string)

    parameter_obj = load_params(parameters)

    manifest, analyzer_directory = find_and_open_analyzer_manifest(
        analyzer_directory, ctx
    )

    registry_data = get_registry_data()

    dependencies = manifest.dependencies
    print_msg("Resolving dependencies")
    logger.debug(f"Parsing and resolving dependencies: {dependencies}")
    if dependencies:
        for analyzer_dep in dependencies:
            dep_name = analyzer_dep.name
            dep_semver_version = analyzer_dep.wildcard_version
            dep_version = registry_data._resolve(
                AnalyzerName(analyzer_dep.name), dep_semver_version
            )
            if not dep_version:
                if not analyzer_dep.path:
                    print_error_exit(
                        f"Error resolving dependency {dep_name} at version {dep_semver_version}. Check that you're using the right version of this dependency and try again."
                    )
            logger.debug(f"Resolved dependency {dep_name}:{dep_semver_version}")

        if not no_login:
            # we need at least one dep and its version to get credentials when the user isn't logged in
            dep_name = dependencies[0].name
            dep_semver_version = dependencies[0].wildcard_version
            dep_version = registry_data._resolve(
                AnalyzerName(dep_name), dep_semver_version
            )

            artifact_link = (
                f"{get_base_url()}/api/v1/artifacts/{dep_name}/{dep_version}"
            )
            logger.debug(f"Getting credential from {artifact_link}")

            # TODO (ulzii) use proper auth credential once its done
            creds = get_docker_creds(artifact_link)
            if creds is None:
                print_error_exit(
                    "Error getting dependency credentials. Please contact us with the following information: failed to get Docker credentials."
                )
            # docker login
            successful_login = docker_login(creds)
            if not successful_login:
                print_error_exit(
                    "Error validating dependency credentials. Please contact us with the following information: failed to log in to Docker."
                )
    else:
        print_warning(
            "No dependencies found; are dependencies intentionally omitted in analyzer.json? Most analyzers are expected to have 1 or more dependencies (e.g. for taking source code as input)."
        )
    print_msg("🔨 Building docker container")

    abort_on_build_failure(
        build_docker(
            manifest.analyzer_name,
            manifest.version,
            os.path.relpath(analyzer_directory, os.getcwd()),
            env_args_dict=env_args_dict,
            verbose=docker_verbose_mode,
        )
    )
    try:
        if interactive_index:
            print_msg(
                f"🔎 Inspecting containers interactively by `docker exec` into last analyzer in execution."
            )
        elif interactive_name:
            print_msg(
                f"🔎 Inspecting containers interactively by `docker exec` into analyzer with name containing `{interactive_name}`."
            )
        else:
            print_msg(f"🔎 Running analysis on `{analyzer_input}`")

        logger.info(f"Reset cache: {reset_cache}")
        run_analyzer_on_local_code(
            registry_data=registry_data,
            manifest=manifest,
            workdir=None,
            analyzer_dir=analyzer_directory,
            code_dir=analyzer_input,
            output_path=output_path,
            show_output_on_stdout=not quiet,
            pass_analyzer_output=not analyzer_quiet,
            no_preserve_workdir=True,
            parameters=parameter_obj,
            env_args_dict=env_args_dict,
            interactive_index=interactive_index,
            interactive_name=interactive_name,
            reset_cache=reset_cache,
        )
        if output_path:
            path_msg = f"Analysis results in `{output_path}`."
        else:
            path_msg = f"Analysis results printed to `stdout`."
        print_success(f"Finished analyzing `{analyzer_input}`. {path_msg}")

    except SymlinkNeedsElevationError as sym:
        print_error_exit(
            f"Error setting up local analysis. {sym}. Try again as an admin."
        )
