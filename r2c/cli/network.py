import os
import subprocess
import webbrowser
from typing import Any, Dict, Optional

import click
import docker
import requests
from docker.errors import APIError
from requests.models import HTTPError, Response

from r2c.cli.errors import get_cli_error_for_api_error
from r2c.cli.logger import (
    get_logger,
    print_error,
    print_error_exit,
    print_exception_exit,
    print_msg,
    print_success,
    print_warning,
)
from r2c.cli.util import (
    get_default_org,
    get_default_token,
    get_version,
    save_config_creds,
)
from r2c.lib.constants import PLATFORM_ANALYZER_PREFIX, PLATFORM_BASE_URL
from r2c.lib.registry import RegistryData

BAD_AUTH_CODES = {401, 422}
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 10  # sec
logger = get_logger()


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


def get_registry_data() -> RegistryData:
    try:
        registry_data = RegistryData.from_json(fetch_registry_data())
    except Exception as e:
        print_exception_exit("There was an error fetching data from the registry", e)
    return registry_data


def fetch_registry_data():
    org = get_default_org()
    url = f"{get_base_url()}/api/v1/analyzers/"
    r = auth_get(url)

    response_json = handle_request_with_error_message(r)
    if response_json["status"] == "success":
        return response_json["analyzers"]
    else:
        raise ValueError("Couldn't parse analyzer registry response")


def open_browser_login(org: Optional[str]) -> None:
    url = get_authentication_url(org)
    print_msg(f"trying to open {url} in your browser...")
    try:
        webbrowser.open(url, new=0, autoraise=True)
    except Exception as e:
        print_msg(
            f"Unable to open a web browser. Please visit {url} and paste the token in here"
        )


def check_docker_is_running():
    try:
        client = docker.from_env()
        client.info()
    except APIError as e:
        # when docker server fails
        print_error_exit(
            "`docker info` failed. Please confirm docker daemon is running in user mode."
        )
    except Exception as e:
        # Other stuff this might throw like, permission error
        print_error_exit(
            "`docker info` failed. Please confirm docker is installed and its daemon is running in user mode."
        )


def docker_login(creds, debug=False):
    check_docker_is_running()
    docker_login_cmd = [
        "docker",
        "login",
        "-u",
        creds.get("login"),
        "-p",
        creds.get("password"),
        creds.get("endpoint"),
    ]
    with open(os.devnull, "w") as FNULL:
        if debug:
            return_code = subprocess.call(
                docker_login_cmd, stdout=FNULL, stderr=subprocess.STDOUT
            )
        else:
            return_code = subprocess.call(docker_login_cmd, stdout=FNULL, stderr=FNULL)
    return return_code == 0


def do_login(
    org: Optional[str] = None, login_token: Optional[str] = None
) -> Optional[str]:
    # ensure org
    if org is None:
        org = get_default_org()
        if org is None:
            org = click.prompt(
                "Please enter your org name, or to use the common r2c platform, press enter",
                default=PLATFORM_ANALYZER_PREFIX,
            )
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
    logger.info(f"changed_artifact link to {artifact_link}")
    r = auth_get(artifact_link)
    if r.status_code == requests.codes.ok:
        data = r.json()
        return data.get("credentials")
    else:
        return None


def get_base_url(org: Optional[str] = get_default_org()) -> str:
    """Return the base url for an org or the public instance."""
    if org and org != PLATFORM_ANALYZER_PREFIX:
        return f"https://{org}.massive.ret2.co"
    else:
        logger.info(
            f"Using {PLATFORM_ANALYZER_PREFIX} org with base {PLATFORM_BASE_URL}"
        )
        return PLATFORM_BASE_URL


def get_authentication_url(org: Optional[str]) -> str:
    """Return URL for getting login authenticatio token"""
    return f"{get_base_url(org)}/settings/token"


@login_retry
def auth_get(
    url: str,
    params: Dict[str, str] = {},
    headers: Dict[str, str] = {},
    token: Optional[str] = None,
    timeout: Optional[float] = DEFAULT_TIMEOUT,
) -> requests.models.Response:
    """Perform a requests.get with Authorization and default headers set"""
    headers = {
        **get_default_headers(),
        **headers,
        **get_auth_header(token or get_default_token()),
    }
    r = requests.get(url, headers=headers, params=params, timeout=timeout)
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
    r = requests.post(
        url, headers=headers, params=params, json=json, timeout=DEFAULT_TIMEOUT
    )
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
    r = requests.put(
        url, headers=headers, params=params, json=json, timeout=DEFAULT_TIMEOUT
    )
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
        r = requests.get(
            f"{get_base_url(org)}/api/users", headers=headers, timeout=DEFAULT_TIMEOUT
        )
        return r.status_code == requests.codes.ok
    except Exception as e:
        # TODO log exception
        return False


def check_valid_token_with_logging(org: str, token: str) -> Optional[str]:
    valid_token = validate_token(org, token)
    if valid_token:
        # save to ~/.r2c
        save_config_creds(org, token)
        if org == PLATFORM_ANALYZER_PREFIX:
            print_success(f"You are now logged in to the r2c platform 🎉")
        else:
            print_success(f"You are now logged in to: {org} 🎉")
        return token
    else:
        print_error(
            "Couldn't log you in with that token. Please check your input and try again"
        )
        return None
