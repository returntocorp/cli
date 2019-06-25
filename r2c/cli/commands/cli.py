import sys
from typing import Optional, Tuple

import click
from semantic_version import Version

from r2c.cli.logger import get_logger, print_error, print_error_exit, print_msg
from r2c.cli.network import auth_get, get_base_url, handle_request_with_error_message
from r2c.cli.util import get_version, set_debug_flag, set_verbose_flag

logger = get_logger()

DEFAULT_MANIFEST_TRAVERSAL_LIMIT = 50  # number of dirs to climb before giving up

UPGRADE_WARNING_OUTPUT = f"""\n╭─────────────────────────────────────────────╮
│        You need to upgrade R2C! Run:        │
│                                             │
│       {click.style("pip3 install --upgrade r2c-cli", fg="yellow")}        │
│                                             │
│   or functionality may break unexpectedly   │
│   For non-backwards compatible changes, see |
|   docs.r2c.dev/en/latest/troubleshooting.html │
╰─────────────────────────────────────────────╯\n"""


def _print_version(ctx, param, value):
    """Print the current r2c-cli version based on setuptools runtime"""
    if not value or ctx.resilient_parsing:
        return
    print_msg(f"r2c-cli/{get_version()}")
    ctx.exit()


def fetch_latest_version() -> Tuple[Optional[str], Optional[bool]]:
    try:
        url = f"{get_base_url()}/api/cli/version/latest"
        r = auth_get(url, timeout=2.0)  # sec
        response_json = handle_request_with_error_message(r)
        return response_json.get("latest"), response_json.get("forceUpgrade")
    except Exception:
        return None, None


def is_running_latest() -> bool:
    try:
        latest, force = fetch_latest_version()
        curent = get_version()
        if latest:
            latest_version = Version(latest, partial=True)
            current_version = Version(curent, partial=True)
            if current_version < latest_version:
                if force:
                    print_msg(UPGRADE_WARNING_OUTPUT)
                    print_error_exit(
                        "Something is wrong with your CLI version. You must upgrade to continue"
                    )
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


def is_running_supported_python3() -> bool:
    python_major_v = sys.version_info.major
    python_minor_v = sys.version_info.minor
    return python_major_v >= 3 and python_minor_v >= 6


@click.group()
@click.option(
    "--debug",
    "-d",
    is_flag=True,
    help="Show extra output, error messages, and exception stack traces with DEBUG filtering",
    default=False,
    hidden=True,
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show extra output, error messages, and exception stack traces with INFO filtering",
    default=False,
)
@click.option(
    "--version",
    is_flag=True,
    help="Show current version of r2c cli.",
    callback=_print_version,
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
def cli(ctx, debug, verbose, no_traverse_manifest):
    ctx.ensure_object(dict)
    if not is_running_latest():
        print_msg(UPGRADE_WARNING_OUTPUT)
    if not is_running_supported_python3():
        print_error("Please upgrade to python3.6 to run r2c-cli.")
    set_debug_flag(ctx, debug)
    set_verbose_flag(ctx, verbose)
    ctx.obj["NO_TRAVERSE_MANIFEST"] = no_traverse_manifest
