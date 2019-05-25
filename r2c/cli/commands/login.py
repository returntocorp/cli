import os

import click

from r2c.cli.commands.cli import cli
from r2c.cli.logger import get_logger, print_error_exit, print_success
from r2c.cli.network import do_login
from r2c.cli.util import delete_creds, delete_default_org, get_default_org

R2C_LOGIN_TOKEN_ENVVAR_NAME = "R2C_LOGIN_TOKEN"


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
        get_logger().exception(e)
        print_error_exit("Unexpected error. Please contact us")
