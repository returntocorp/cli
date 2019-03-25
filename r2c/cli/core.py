#!/usr/bin/env python3
import itertools
import json
import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, Iterator, Optional, Tuple

import click
import requests
from requests.models import HTTPError, Response
from semantic_version import Version

from r2c.cli.create_template import create_template_analyzer
from r2c.cli.errors import ManifestNotFoundError
from r2c.cli.network import (
    MAX_RETRIES,
    auth_get,
    auth_post,
    auth_put,
    do_login,
    get_authentication_url,
    get_base_url,
    get_docker_creds,
    handle_request_with_error_message,
    validate_token,
)
from r2c.cli.util import (
    delete_creds,
    delete_default_org,
    get_default_org,
    get_version,
    is_local_dev,
    log_manifest_not_found_then_die,
    print_error,
    print_error_exit,
    print_msg,
    print_success,
    print_warning,
    save_config_creds,
)
from r2c.lib.manifest import AnalyzerManifest, MalformedManifestException
from r2c.lib.registry import RegistryData
from r2c.lib.run import (
    build_docker,
    integration_test,
    run_analyzer_on_local_code,
    run_docker_unittest,
)
from r2c.lib.util import SymlinkNeedsElevationError
from r2c.lib.versioned_analyzer import AnalyzerName, VersionedAnalyzer

logger = logging.getLogger(__name__)
R2C_LOGIN_TOKEN_ENVVAR_NAME = "R2C_LOGIN_TOKEN"


DEFAULT_MANIFEST_TRAVERSAL_LIMIT = 50  # number of dirs to climb before giving up
DEFAULT_ENV_ARGS_TO_DOCKER = {
    "GID": os.getgid(),
    "UID": os.getuid(),
    "UNAME": "analysis",
}

UPGRADE_WARNING_OUTPUT = f"""\n╭─────────────────────────────────────────────╮
│        You need to upgrade R2C! Run:        │
│                                             │
│       {click.style("pip3 install --upgrade r2c-cli", fg="yellow")}        │
│                                             │
│   or functionality may break unexpectedly   │
╰─────────────────────────────────────────────╯\n"""


def print_version(ctx, param, value):
    """Print the current r2c-cli version based on setuptools runtime"""
    if not value or ctx.resilient_parsing:
        return
    print_msg(f"r2c-cli/{get_version()}")
    ctx.exit()


def fetch_registry_data():
    org = get_default_org()
    url = f"{get_base_url()}/api/v1/analyzers/"
    r = auth_get(url)

    response_json = handle_request_with_error_message(r)
    if response_json["status"] == "success":
        return response_json["analyzers"]
    else:
        raise ValueError("Couldn't parse analyzer registry response")


def fetch_latest_version() -> Optional[str]:
    try:
        org = get_default_org()

        url = f"{get_base_url()}/api/cli/version/latest"
        r = auth_get(url)
        response_json = handle_request_with_error_message(r)
        return response_json.get("latest")
    except Exception as e:
        return None


def is_running_latest() -> bool:
    try:
        latest = fetch_latest_version()
        curent = get_version()
        if latest:
            latest_version = Version(latest, partial=True)
            current_version = Version(curent, partial=True)
            if current_version < latest_version:
                return False
            else:
                return True
        else:
            # fail safe
            logger.info("Unable to get latest cli version from server")
            return True
    except Exception as e:
        # fail safe
        logger.info(f"Unexpected error comparing latest and current version: {e}")
        return True


def abort_on_build_failure(build_status: int) -> None:
    if build_status != 0:
        print_error_exit(
            f"Failed to build analyzer: {build_status}", status_code=build_status
        )


def get_org_from_analyzer_name(analyzer_name: str) -> str:
    """Given a '/' separated name of analyzer, e.g. r2c/typeflow, returns the org name which is 'r2c'
    """
    names = analyzer_name.split("/")
    assert (
        len(names) == 2
    ), f"Make sure you specified org and analyzer_name as `org/analyzer_name` in your analyzer.json"
    return names[0]


def climb_dir_tree(start_path: str) -> Iterator[str]:
    next_path = start_path
    current_path = None
    while next_path != current_path:
        current_path = next_path
        next_path = os.path.dirname(current_path)
        yield current_path


def _find_analyzer_manifest_path(path: str, parent_limit: int) -> Tuple[str, str]:
    """Finds an analyzer manifest file starting at PATH and ascending up the dir tree.

    Arguments:
        path: where to start looking for analyzer.json
        parent_limit: limit on the number of directories to ascend

    Returns:
        (path to analyzer.json, path containing analyzer.json for Docker build)
    """
    for path in itertools.islice(climb_dir_tree(path), parent_limit):
        manifest_path = os.path.join(path, "analyzer.json")
        if os.path.exists(manifest_path):
            return manifest_path, os.path.dirname(manifest_path)

    raise ManifestNotFoundError()


def find_and_open_analyzer_manifest(
    path: str, ctx: Any = None
) -> Tuple[AnalyzerManifest, str]:
    """Returns the parsed AnalyzerManifest object and the parent dir of the manifest for the manifest discovered by starting at `path` and ascending up

    """
    try:
        manifest_path, manifest_parent_dir = _find_analyzer_manifest_path(
            path,
            parent_limit=get_manifest_traversal_limit(ctx)
            if ctx
            else DEFAULT_MANIFEST_TRAVERSAL_LIMIT,
        )
    except ManifestNotFoundError:
        log_manifest_not_found_then_die()

    logger.info(f"Found analyzer.json at {manifest_path}")

    with open(manifest_path, encoding="utf-8") as f:
        try:
            return (AnalyzerManifest.from_json_str(f.read()), manifest_parent_dir)
        except MalformedManifestException as e:
            print_error_exit(
                f"The analyzer.json at {manifest_path} does not conform to the schema: {e}"
            )
            raise e


def upload_analyzer_manifest(manifest: AnalyzerManifest) -> str:
    logger.info(f"Uploading manifest")
    analyzer_json = manifest.to_original_json()
    r = auth_post(f"{get_base_url()}/api/v1/analyzers/", json=analyzer_json)
    data = handle_request_with_error_message(r)
    link = data.get("links", {}).get("artifact_url")
    return link


def docker_login(creds, debug=False):
    docker_login_cmd = [
        "docker",
        "login",
        "-u",
        creds.get("login"),
        "-p",
        creds.get("password"),
        creds.get("endpoint"),
    ]
    if is_local_dev():
        logger.info(f"Using ecr credentials in .aws during development")
        try:
            erc_login = subprocess.check_output(
                [
                    "aws",
                    "ecr",
                    "get-login",
                    "--no-include-email",
                    "--region",
                    "us-west-2",
                ]
            )
            docker_login_cmd = erc_login.decode("utf-8").strip().split(" ")
        except Exception as e:
            logger.info(f"Docker login failed with {e}")
            return True
    with open(os.devnull, "w") as FNULL:
        if debug:
            return_code = subprocess.call(
                docker_login_cmd, stdout=FNULL, stderr=subprocess.STDOUT
            )
        else:
            return_code = subprocess.call(docker_login_cmd, stdout=FNULL, stderr=FNULL)
    return return_code == 0


def docker_push(image_id):
    docker_push_cmd = ["docker", "push", image_id]
    logger.info(f"Running push with {' '.join(docker_push_cmd)}")
    return_code = subprocess.call(docker_push_cmd)
    return return_code == 0


def get_git_author():
    try:
        git_name = (
            subprocess.check_output(["git", "config", "--get", "user.name"])
            .decode("utf-8")
            .strip()
        )
        git_email = (
            subprocess.check_output(["git", "config", "--get", "user.email"])
            .decode("utf-8")
            .strip()
        )
        return (git_name, git_email)
    except Exception as e:
        logger.info(e)
        return (None, None)


def get_manifest_traversal_limit(ctx):
    return 1 if ctx.obj["NO_TRAVERSE_MANIFEST"] else DEFAULT_MANIFEST_TRAVERSAL_LIMIT


@click.group()
@click.option(
    "--debug",
    is_flag=True,
    help="Show extra output, error messages, and exception stack traces",
    default=False,
)
@click.option(
    "--version",
    is_flag=True,
    help="Show current version of r2c cli.",
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
@click.option(
    "--no-traverse-manifest",
    is_flag=True,
    help="Don't attempt to find an analyzer.json if it doesn't exist in the current or specified directory",
    default=False,
)
@click.pass_context
def cli(ctx, debug, no_traverse_manifest):
    ctx.ensure_object(dict)
    if not is_running_latest():
        print_msg(UPGRADE_WARNING_OUTPUT)
    set_debug_flag(ctx, debug)
    ctx.obj["NO_TRAVERSE_MANIFEST"] = no_traverse_manifest
    os.environ["DEBUG"] = str(debug)


def set_debug_flag(ctx, debug):
    if debug:
        logging.basicConfig(level=logging.INFO)
    ctx.obj["DEBUG"] = debug


@cli.command()
@click.option(
    "--org",
    help="org to sign into. Ask R2C if you have questions about this",
    required=False,
)
def login(org=None):
    """
    Log in to the R2C analysis platform. You can set environment variable R2C_LOGIN_TOKEN to automatically use that token.

    Logging in will grant you access to private analyzers published to
    your org. After logging in, you can locally run analyzers that depend
    on these privately published analyzers.
    """
    login_token = os.environ.get(R2C_LOGIN_TOKEN_ENVVAR_NAME)
    do_login(org=org, login_token=login_token)


@cli.command()
@click.option(
    "--org",
    help="The org to sign into. Ask R2C if you have questions about this",
    required=False,
)
def logout(org=None):
    """Log out of the R2C analysis platform.

    Logging out will remove all authentication tokens.
    If --org is specified, you will only log out of that org.
    """
    try:
        success = True
        success = delete_creds(org) and success
        # remove default org
        if org is None or get_default_org() == org:
            success = delete_default_org() and success
        if success:
            if org:
                print_success(f"logged out of {org}")
            else:
                print_success("logged out of all orgs")
        else:
            print_error_exit("Unexpected error. Please contact us")
    except Exception as e:
        logger.exception(e)
        print_error_exit("Unexpected error. Please contact us")


@cli.command()
@click.option("--analyzer-directory", default=os.getcwd())
@click.argument("env-args-string", nargs=-1, type=click.Path())
@click.pass_context
def unittest(ctx, analyzer_directory, env_args_string):
    """
    Locally unit tests for the current analyzer directory.

    You can define how to run your unit tests in `src/unittest.sh`.

    You may have to login if your analyzer depends on privately
    published analyzers.
    """
    debug = ctx.obj["DEBUG"]
    env_args_dict = parse_remaining(env_args_string)

    manifest, analyzer_directory = find_and_open_analyzer_manifest(
        analyzer_directory, ctx
    )

    abort_on_build_failure(
        build_docker(
            manifest.analyzer_name,
            manifest.version,
            os.path.relpath(analyzer_directory, os.getcwd()),
            env_args_dict={**DEFAULT_ENV_ARGS_TO_DOCKER, **env_args_dict},
            verbose=debug,
        )
    )

    image_id = VersionedAnalyzer(manifest.analyzer_name, manifest.version).image_id

    status = run_docker_unittest(
        analyzer_directory=analyzer_directory,
        analyzer_name=manifest.analyzer_name,
        docker_image=image_id,
        verbose=debug,
        env_args_dict={**DEFAULT_ENV_ARGS_TO_DOCKER, **env_args_dict},
    )
    if status == 0:
        print_success(f"Unit tests passed")
        sys.exit(0)
    else:
        print_error_exit(f"Unit tests failed with status {status}", status_code=status)


@cli.command()
@click.option("-d", "--analyzer-directory", default=os.getcwd())
@click.argument("env-args-string", nargs=-1, type=click.Path())
@click.pass_context
def test(ctx, analyzer_directory, env_args_string):
    """
    Locally run integration tests for the current analyzer.

    You can add integration test files to the `examples/` directory.
    For more information, refer to the integration test section of the README.

    You may have to login if your analyzer depends on privately
    published analyzers.
    """

    debug = ctx.obj["DEBUG"]
    env_args_dict = parse_remaining(env_args_string)
    print_msg(
        f"Running integration tests for analyzer {'with debug mode' if ctx.obj['DEBUG'] else ''}"
    )

    manifest, analyzer_directory = find_and_open_analyzer_manifest(
        analyzer_directory, ctx
    )

    abort_on_build_failure(
        build_docker(
            manifest.analyzer_name,
            manifest.version,
            os.path.relpath(analyzer_directory, os.getcwd()),
            env_args_dict={**DEFAULT_ENV_ARGS_TO_DOCKER, **env_args_dict},
            verbose=debug,
        )
    )

    try:
        integration_test(
            manifest=manifest,
            analyzer_directory=analyzer_directory,
            workdir=None,
            env_args_dict={**DEFAULT_ENV_ARGS_TO_DOCKER, **env_args_dict},
            registry_data=RegistryData.from_json(fetch_registry_data()),
        )
    except SymlinkNeedsElevationError as sym:
        print_error_exit(
            f"Error setting up integration tests. {sym}. Try again as an admin"
        )


@cli.command()
@click.option("-d", "--analyzer-directory", default=os.getcwd())
@click.argument("env_args_string", nargs=-1, type=click.Path())
@click.pass_context
def push(ctx, analyzer_directory, env_args_string):
    """
    Push the analyzer in the current directory to the R2C platform.

    You must log in to push analyzers.

    This command will validate your analyzer and privately publish your analyzer
    to your org with the name specified in analyzer.json.

    Your analyzer name must follow {org}/{name}.
    """
    debug = ctx.obj["DEBUG"]
    env_args_dict = parse_remaining(env_args_string)

    manifest, analyzer_directory = find_and_open_analyzer_manifest(
        analyzer_directory, ctx
    )
    analyzer_org = get_org_from_analyzer_name(manifest.analyzer_name)

    # TODO(ulzii): let's decide which source of truth we're using for analyzer_name above and/or check consistency.
    # can't have both dir name and what's in analyzer.json
    print_msg(f"Pushing analyzer in {analyzer_directory}...")

    default_org = get_default_org()
    if default_org != analyzer_org:
        print_error_exit(
            f"Attempting to push to organization: `{default_org}`. However, the org specified as the prefix of the analyzer name in `analyzer.json` does not match it. "
            + f"Replace `{analyzer_org}` with `{default_org}` and try again."
            + "Please ask for help from R2C support"
        )

    try:
        # upload analyzer.json
        artifact_link = upload_analyzer_manifest(manifest)
    except Exception as e:
        message = getattr(e, "message", repr(e))
        print_error_exit(f"There was an error uploading your analyzer: {message}")
    if artifact_link is None:
        print_error_exit(
            "There was an error uploading your analyzer. Please ask for help from R2C support"
        )
    # get docker login creds
    creds = get_docker_creds(artifact_link)
    if creds is None:
        print_error_exit(
            "There was an error getting Docker credentials. Please ask for help from R2C support"
        )
    # docker login
    successful_login = docker_login(creds)
    if not successful_login:
        print_error_exit(
            "There was an error logging into Docker. Please ask for help from R2C support"
        )
    # docker build and tag
    abort_on_build_failure(
        build_docker(
            manifest.analyzer_name,
            manifest.version,
            os.path.relpath(analyzer_directory, os.getcwd()),
            env_args_dict={**DEFAULT_ENV_ARGS_TO_DOCKER, **env_args_dict},
            verbose=debug,
        )
    )
    # docker push
    image_id = VersionedAnalyzer(manifest.analyzer_name, manifest.version).image_id
    successful_push = docker_push(image_id)
    if not successful_push:
        print_error_exit(
            "There was an error pushing the Docker image. Please ask for help from R2C support"
        )
    # mark uploaded with API
    # TODO figure out how to determine org from analyzer.json
    try:
        uploaded_url = f"{get_base_url()}/api/v1/analyzers/{manifest.analyzer_name}/{manifest.version}/uploaded"
        r = auth_put(uploaded_url)
        data = handle_request_with_error_message(r)
        if data.get("status") == "uploaded":
            web_url = data["links"]["web_url"]
            # display status to user and give link to view in web UI
            print_success(f"Successfully uploaded analyzer! Visit: {web_url}")
        else:
            print_error_exit(
                "Error confirming analyzer was successfully uploaded. Please contact us with the following information: failed to confirm analyzer finished uploading."
            )
    except Exception as e:
        message = getattr(e, "message", repr(e))
        print_error_exit(
            f"Error confirming analyzer was successfully uploaded: {message}"
        )


def parse_remaining(pairs):
    """
    Given a string of remaining arguments (after the "--"), that looks like "['x=y', 'a=b'] return a dict of { 'x': 'y' }
    """
    return {pair.split("=")[0]: pair.split("=")[1] for pair in pairs}


@cli.command()
@click.option("-d", "--analyzer-directory", default=os.getcwd())
@click.argument("env-args-string", nargs=-1, type=click.Path())
@click.pass_context
def build(ctx, analyzer_directory, env_args_string):
    """Builds an analyzer without running it.

    """

    manifest, analyzer_directory = find_and_open_analyzer_manifest(
        analyzer_directory, ctx
    )
    debug_mode = ctx.obj["DEBUG"]

    abort_on_build_failure(
        build_docker(
            manifest.analyzer_name,
            manifest.version,
            os.path.relpath(analyzer_directory, os.getcwd()),
            env_args_dict=parse_remaining(env_args_string),
            verbose=debug_mode,
        )
    )


@cli.command()
@click.option("-d", "--analyzer-directory", default=os.getcwd())
@click.option("-o", "--output-path")
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
    "--debug",
    is_flag=True,
    help="Show extra output, error messages, and exception stack traces",
    default=False,
)
@click.option(
    "--wait",
    is_flag=True,
    default=False,
    help="Don't start the container, wait for user.",
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
    wait,
    debug,
    parameters,
    env_args_string,
):
    """
    Run the analyzer in the current directory over a code directory.

    You may have to log in if your analyzer depends on privately
    published analyzers.
    """
    if debug == True:  # allow passing --debug to run as well as globally
        set_debug_flag(ctx, True)

    debug_mode = ctx.obj["DEBUG"]
    print_msg(f"🏃 Running analyzer...{'with debug mode' if debug_mode else ''}")
    env_args_dict = parse_remaining(env_args_string)

    try:
        parameter_obj = json.loads(parameters)
    except ValueError as e:
        print_error_exit(
            f'Failed to parse parameter string:"{parameters}" as json. Parse Error: {e}'
        )

    manifest, analyzer_directory = find_and_open_analyzer_manifest(
        analyzer_directory, ctx
    )

    try:
        registry_data = RegistryData.from_json(fetch_registry_data())
    except Exception as e:
        message = getattr(e, "message", repr(e))
        print_error_exit(
            f"There was an error fetching data from the registry: {message}"
        )
    dependencies = manifest.dependencies
    logger.info(f"Parsing and resolving dependencies: {dependencies}")
    if dependencies:
        for analyzer_dep in dependencies:
            dep_name = analyzer_dep.name
            dep_semver_version = analyzer_dep.wildcard_version
            dep_version = registry_data._resolve(
                AnalyzerName(analyzer_dep.name), dep_semver_version
            )
            if not dep_version:
                print_error_exit(
                    f"Error resolving dependency {dep_name} at version {dep_semver_version}. Check that you're using the right version of this dependency and try again."
                )
            logger.info(f"Resolved dependency {dep_name}:{dep_semver_version}")

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
            logger.info(f"Getting credential from {artifact_link}")

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

    abort_on_build_failure(
        build_docker(
            manifest.analyzer_name,
            manifest.version,
            os.path.relpath(analyzer_directory, os.getcwd()),
            env_args_dict={**DEFAULT_ENV_ARGS_TO_DOCKER, **env_args_dict},
            verbose=debug_mode,
        )
    )

    try:
        run_analyzer_on_local_code(
            registry_data=registry_data,
            manifest=manifest,
            workdir=None,
            code_dir=analyzer_input.strip(
                '"'
            ),  # idk why this is happening for quoted paths
            output_path=output_path,
            wait=wait,
            show_output_on_stdout=not quiet,
            pass_analyzer_output=not analyzer_quiet,
            no_preserve_workdir=True,
            parameters=parameter_obj,
            env_args_dict={**DEFAULT_ENV_ARGS_TO_DOCKER, **env_args_dict},
        )
    except SymlinkNeedsElevationError as sym:
        print_error_exit(
            f"Error setting up local analysis. {sym}. Try again as an admin."
        )


@cli.command()
@click.option("--analyzer-name")
@click.option("--author-name")
@click.option("--author-email")
@click.option("--run-on")
@click.option("--output-type")
@click.pass_context
def init(ctx, analyzer_name, author_name, author_email, run_on, output_type):
    """
    Creates an example analyzer for analyzing JavaScript/TypeScript.

    You may use any language to write your analysis and run it from `src/analyze.sh`.

    Once you create your analyzer, you can navigate to your analyzer directory
    and run 'r2c' commands inside that directory.

    Type `r2c -—help` to see all of the commands available.
    """
    debug = ctx.obj["DEBUG"]
    default_name, default_email = get_git_author()
    if not analyzer_name:
        analyzer_name = click.prompt("Analyzer name", default="example")
    if not author_name:
        author_name = click.prompt("Author name", default=default_name)
    if not author_email:
        author_email = click.prompt("Author email", default=default_email)
    if not run_on:
        run_on = click.prompt(
            "Will your analyzer produce: \n"
            + "- output for a particular `git` repository\n"
            + "- output for a particular git `commit` in a repo\n"
            + "- the same `constant` output regardless of commit or repo?",
            default="commit",
            type=click.Choice(["git", "commit", "constant"]),
        )
    if not output_type:
        output_type = click.prompt(
            "Does your analyzer output \n"
            + "- a single schema-compliant JSON file \n"
            + "- a full filesystem output?",
            default="json",
            type=click.Choice(["json", "filesystem"]),
        )
    create_template_analyzer(
        get_default_org(), analyzer_name, author_name, author_email, run_on, output_type
    )
    print_success(f"Done! Your analyzer can be found in the {analyzer_name} directory")
