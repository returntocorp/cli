import logging
import webbrowser
from typing import Any, Dict, Iterator, Optional, Tuple

import click
import requests
from requests.models import HTTPError, Response

from r2c.cli.errors import get_cli_error_for_api_error
from r2c.cli.util import (
    get_default_org,
    get_default_token,
    get_version,
    is_local_dev,
    print_error,
    print_error_exit,
    print_msg,
    print_success,
    print_warning,
    save_config_creds,
)

BAD_AUTH_CODES = {401, 422}
MAX_RETRIES = 3

logger = logging.getLogger(__name__)


def handle_request_with_error_message(r: Response) -> dict:
    """Handles the requests.response object. If the response
    code is anything other than success, CliError will be thrown.
    """
    try:
        r.raise_for_status()
    except HTTPError as e:
        json_response = r.json()
        api_error_code = json_response["error_type"]
        api_error_msg = f"{json_response['message']}. {json_response['next_steps']}"

        raise get_cli_error_for_api_error(api_error_code, api_error_msg)
    return r.json()


def get_default_headers() -> Dict[str, str]:
    """Headers for all CLI http/s requests"""
    return {"X-R2C-CLI-VERSION": f"{get_version()}", "Accept": "application/json"}


def get_auth_header(token: Optional[str]) -> Dict[str, str]:
    """Return header object with 'Authorization' for a given token"""
    if token:
        return {"Authorization": f"Bearer {token}"}
    else:
        return {}


def open_browser_login(org: Optional[str]) -> None:
    url = get_authentication_url(org)
    print_msg(f"trying to open {url} in your browser...")
    try:
        webbrowser.open(url, new=0, autoraise=True)
    except Exception as e:
        print_msg(
            f"Unable to open a web browser. Please visit {url} and paste the token in here"
        )


def do_login(
    org: Optional[str] = None, login_token: Optional[str] = None
) -> Optional[str]:
    # ensure org
    if org is None:
        org = get_default_org()
        if org is None:
            org = click.prompt("Please enter your group name")
    if not login_token:
        if click.confirm(
            "Opening web browser to get login token. Do you want to continue?",
            default=True,
        ):
            open_browser_login(org)
        else:
            url = get_authentication_url(org)
            print_msg(f"Visit {url} and enter the token below")
        # prompt for token
        for attempt in range(MAX_RETRIES):
            # validate token
            token = check_valid_token_with_logging(
                org, click.prompt("Please enter the API token")
            )
            if token:
                return token
        print_error_exit("Max attempts exceeded. Please contact R2C support for help")
    else:
        return check_valid_token_with_logging(org, login_token)

    return None


def login_retry(fn):
    def login_retry_wrapper(*args, **kwargs):
        r = fn(*args, **kwargs)
        if r.status_code in BAD_AUTH_CODES:
            print_warning(
                "Something is wrong with your credentials. Let's login and try again..."
            )
            new_token = do_login()
            print_msg("Back to what we were doing...")
            r = fn(*args, **kwargs, token=new_token)
        return r

    return login_retry_wrapper


def get_docker_creds(artifact_link):
    if is_local_dev():
        return {}
    r = auth_get(artifact_link)
    if r.status_code == requests.codes.ok:
        data = r.json()
        return data.get("credentials")
    else:
        return None


def get_base_url(
    org: Optional[str] = get_default_org(), local_dev: bool = is_local_dev()
) -> str:
    """Return the base url for an org or the public instance. Return a localhost url if local_dev is True"""
    if local_dev:
        return "http://localhost:5000"
    elif org:
        return f"https://{org}.massive.ret2.co"
    else:
        logger.info("No org set so going to use 'public' org")
        return f"https://public.massive.ret2.co"


def get_authentication_url(org: Optional[str]) -> str:
    """Return URL for getting login authenticatio token"""
    return f"{get_base_url(org)}/settings/token"


@login_retry
def auth_get(
    url: str,
    params: Dict[str, str] = {},
    headers: Dict[str, str] = {},
    token: Optional[str] = None,
) -> requests.models.Response:
    """Perform a requests.get with Authorization and default headers set"""
    headers = {
        **get_default_headers(),
        **headers,
        **get_auth_header(token or get_default_token()),
    }
    r = requests.get(url, headers=headers, params=params)
    return r


@login_retry
def auth_post(
    url: str,
    json: Any = {},
    params: Dict[str, str] = {},
    headers: Dict[str, str] = {},
    token: Optional[str] = None,
) -> requests.models.Response:
    """Perform a requests.post with Authorization and default headers set"""
    headers = {
        **get_default_headers(),
        **headers,
        **get_auth_header(token or get_default_token()),
    }
    r = requests.post(url, headers=headers, params=params, json=json)
    return r


@login_retry
def auth_put(
    url: str,
    json: Any = {},
    params: Dict[str, str] = {},
    headers: Dict[str, str] = {},
    token: Optional[str] = None,
) -> requests.models.Response:
    """Perform a requests.put with Authorization and default headers set"""
    headers = {
        **get_default_headers(),
        **headers,
        **get_auth_header(token or get_default_token()),
    }
    r = requests.put(url, headers=headers, params=params, json=json)
    return r


@login_retry
def auth_delete(
    url: str,
    json: Any = {},
    params: Dict[str, str] = {},
    headers: Dict[str, str] = {},
    token: Optional[str] = None,
) -> requests.models.Response:
    """Perform a requests.delete with Authorization and default headers set"""
    headers = {
        **get_default_headers(),
        **headers,
        **get_auth_header(token or get_default_token()),
    }
    r = requests.delete(url, headers=headers, params=params, json=json)
    return r


def validate_token(org: str, token: str) -> bool:
    try:
        headers = {**get_default_headers(), **get_auth_header(token)}
        r = requests.get(f"{get_base_url(org)}/api/users", headers=headers)
        return r.status_code == requests.codes.ok
    except Exception as e:
        # TODO log exception
        return False


def check_valid_token_with_logging(org: str, token: str) -> Optional[str]:
    valid_token = validate_token(org, token)
    if valid_token:
        # save to ~/.r2c
        save_config_creds(org, token)
        print_success(f"You are now logged in to: {org} 🎉")
        return token
    else:
        print_error(
            "Couldn't log you in with that token. Please check your input and try again"
        )
        return None
