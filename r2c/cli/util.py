import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

import click

from r2c.cli import __version__

LOCAL_CONFIG_DIR = os.path.join(Path.home(), ".r2c")
CONFIG_FILENAME = "config.json"
CREDS_FILENAME = "credentials.json"
DEFAULT_ORG_KEY = "defaultOrg"

logger = logging.getLogger(__name__)


def is_local_dev() -> bool:
    return os.getenv("LOCAL_DEV") == "True"


def get_version():
    """Get the current r2c-cli version based on __init__"""
    return __version__


def load_creds() -> Dict[str, str]:
    """return creds as a mapping from org to token"""
    cred_file = os.path.join(LOCAL_CONFIG_DIR, CREDS_FILENAME)
    try:
        with open(cred_file) as fp:
            return json.load(fp)
    except Exception as e:
        logger.info(f"unable to read token file from {cred_file}: {e}")
        return {}


def save_creds(creds: Dict[str, str]) -> bool:
    """save creds to disk. Return True if successful. False otherwise"""
    Path(LOCAL_CONFIG_DIR).mkdir(parents=True, exist_ok=True)
    cred_file = os.path.join(LOCAL_CONFIG_DIR, CREDS_FILENAME)
    try:
        save_json(creds, cred_file)
        return True
    except Exception as e:
        logger.info(f"unable to save cred file to {cred_file}: {e}")
        return False


def load_config() -> Dict[str, str]:
    """load config from disk"""
    config_file = os.path.join(LOCAL_CONFIG_DIR, CONFIG_FILENAME)
    try:
        with open(config_file) as fp:
            return json.load(fp)
    except Exception as e:
        logger.info(f"unable to read config from {config_file}: {e}")
        return {}


def get_default_org() -> Optional[str]:
    """Return the default org as stored in the config. Return None if not set."""
    config = load_config()
    return config.get(DEFAULT_ORG_KEY)


def save_config(config: Dict[str, str]) -> bool:
    """save config to disk. Return True if successful. False otherwise"""
    Path(LOCAL_CONFIG_DIR).mkdir(parents=True, exist_ok=True)
    config_file = os.path.join(LOCAL_CONFIG_DIR, CONFIG_FILENAME)
    try:
        save_json(config, config_file)
        return True
    except Exception as e:
        logger.info(f"unable to save config file to {config_file}: {e}")
        return False


def save_config_creds(org: str, token: str) -> bool:
    """save org as the new defaultOrg and store the token in the creds store. Return True if successful. False otherwise"""
    old_config = load_config()
    new_config = {**old_config, DEFAULT_ORG_KEY: org}
    saved_successfully = True
    saved_successfully = save_config(new_config) and saved_successfully
    old_creds = load_creds()
    new_creds = {**old_creds, org: token}
    return save_creds(new_creds) and saved_successfully


def delete_creds(org: Optional[str] = None) -> bool:
    """delete creds for a given org. If org is None, delete all creds. Return True if successful. False otherwise"""
    creds = load_creds()
    if org is None:
        # let's delete all creds since org is None
        return save_creds({})
    if org in creds:
        del creds[org]
    return save_creds(creds)


def delete_default_org() -> bool:
    """delete the defaultOrg from the config. Return True if successful. False otherwise"""
    config = load_config()
    if DEFAULT_ORG_KEY in config:
        del config[DEFAULT_ORG_KEY]
    return save_config(config)


def get_default_token() -> Optional[str]:
    """Return the auth token for the default org as stored in the config. Return None if not found or default org is not set."""
    org = get_default_org()
    if org:
        return get_token_for_org(org)
    else:
        return None


def get_token_for_org(org: str) -> Optional[str]:
    """Return the token for a given org. None if a token isn't found for that org"""
    creds = load_creds()
    return creds.get(org)


def save_json(obj: Any, filepath: str) -> None:
    """save object to filepath. Throws exceptions"""
    with open(filepath, "w") as fp:
        json.dump(obj, fp, indent=4, sort_keys=True)


def print_msg(message: str, err: bool = True) -> None:
    click.echo(message, err=err)


def print_success(message: str, err: bool = True) -> None:
    click.echo(click.style(f"✅ {message}", fg="green"), err=err)


def print_warning(message: str, err: bool = True) -> None:
    click.echo(click.style(f"⚠️  {message}", fg="yellow"), err=err)


def print_error(message: str, err: bool = True) -> None:
    click.echo(click.style(f"❌ {message}", fg="red"), err=err)


def print_error_exit(message: str, status_code: int = 1, err: bool = True) -> None:
    click.echo(click.style(f"❌ {message}", fg="red"), err=err)
    sys.exit(status_code)


def log_manifest_not_found_then_die():
    print_error_exit(
        "Couldn't find an analyzer.json for this analyzer. Check that you're currently in an analyzer directory, or make sure the --analyzer-directory path contains an analyzer.json"
    )
