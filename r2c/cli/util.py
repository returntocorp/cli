import itertools
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

from r2c.cli.errors import ManifestNotFoundError, ReadmeNotFoundError
from r2c.cli.logger import (
    get_logger,
    log_manifest_not_found,
    print_error,
    print_error_exit,
    set_debug_log_level,
    set_verbose_log_level,
)
from r2c.lib.manifest import AnalyzerManifest, MalformedManifestException

LOCAL_CONFIG_DIR = os.path.join(Path.home(), ".r2c")
CONFIG_FILENAME = "config.json"
CREDS_FILENAME = "credentials.json"
DEFAULT_ORG_KEY = "defaultOrg"
DEFAULT_MANIFEST_TRAVERSAL_LIMIT = 50  # number of dirs to climb before giving up

logger = get_logger()


def set_debug_flag(ctx: Any, debug: bool) -> None:
    if debug:
        set_debug_log_level()
    ctx.obj["DEBUG"] = debug


def set_verbose_flag(ctx: Any, verbose: bool) -> None:
    if verbose:
        set_verbose_log_level()
    ctx.obj["VERBOSE"] = verbose


def get_version():
    """Get the current r2c-cli version based on __init__"""
    from r2c.cli import __version__

    return __version__


def parse_remaining(pairs: str) -> Dict:
    """
    Given a string of remaining arguments (after the "--"), that looks like "['x=y', 'a=b'] return a dict of { 'x': 'y' }
    """
    return {pair.split("=")[0]: pair.split("=")[1] for pair in pairs}


def load_creds() -> Dict[str, str]:
    """return creds as a mapping from org to token"""
    cred_file = os.path.join(LOCAL_CONFIG_DIR, CREDS_FILENAME)
    try:
        with open(cred_file) as fp:
            return json.load(fp)
    except Exception as e:
        logger.debug(f"unable to read token file from {cred_file}: {e}")
        return {}


def load_params(params: str) -> Dict:
    try:
        parameter_obj = json.loads(params)
    except ValueError as e:
        print_error(
            f'Failed to parse parameter string:"{params}" as json. Parse Error: {e}'
        )
        parameter_obj = {}
    return parameter_obj


def save_creds(creds: Dict[str, str]) -> bool:
    """save creds to disk. Return True if successful. False otherwise"""
    Path(LOCAL_CONFIG_DIR).mkdir(parents=True, exist_ok=True)
    cred_file = os.path.join(LOCAL_CONFIG_DIR, CREDS_FILENAME)
    try:
        save_json(creds, cred_file)
        return True
    except Exception as e:
        logger.debug(f"unable to save cred file to {cred_file}: {e}")
        return False


def load_config() -> Dict[str, str]:
    """load config from disk"""
    config_file = os.path.join(LOCAL_CONFIG_DIR, CONFIG_FILENAME)
    try:
        with open(config_file) as fp:
            return json.load(fp)
    except Exception as e:
        logger.debug(f"unable to read config from {config_file}: {e}")
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
        logger.debug(f"unable to save config file to {config_file}: {e}")
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


def _find_analyzer_readme_path(path: str, parent_limit: int) -> str:
    """Finds an analyzer readme file starting at PATH and ascending up the dir tree.

    Arguments:
        path: where to start looking for README.md
        parent_limit: limit on the number of directories to ascend

    Returns:
        path to README.md
    """

    for path in itertools.islice(climb_dir_tree(path), parent_limit):
        readme_path = os.path.join(path, "README.md")
        if os.path.exists(readme_path):
            return readme_path

    raise ReadmeNotFoundError()


def get_manifest_traversal_limit(ctx):
    return 1 if ctx.obj["NO_TRAVERSE_MANIFEST"] else DEFAULT_MANIFEST_TRAVERSAL_LIMIT


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
    except ManifestNotFoundError as e:
        log_manifest_not_found()
        raise e

    logger.debug(f"Found analyzer.json at {manifest_path}")

    with open(manifest_path, encoding="utf-8") as f:
        try:
            raw_manifest = f.read()
            logger.debug(f"Contents of analyzer.json:\n{raw_manifest}")
            return (AnalyzerManifest.from_json_str(raw_manifest), manifest_parent_dir)
        except MalformedManifestException as e:
            print_error_exit(
                f"The analyzer.json at {manifest_path} does not conform to the schema: {e}"
            )
            raise e


def find_and_open_analyzer_readme(path: str, ctx: Any = None) -> Optional[str]:
    """Returns the readme discovered by starting at `path` and ascending up

    """
    try:
        readme_path = _find_analyzer_readme_path(
            path,
            parent_limit=get_manifest_traversal_limit(ctx)
            if ctx
            else DEFAULT_MANIFEST_TRAVERSAL_LIMIT,
        )
    except ReadmeNotFoundError as e:
        logger.debug("Readme not found")
        return None

    logger.debug(f"Found readme at {readme_path}")

    with open(readme_path, encoding="utf-8") as f:
        raw_readme = f.read()
        logger.debug(f"Contents of README.md:\n{raw_readme}")
        return raw_readme


def get_org_from_analyzer_name(analyzer_name: str) -> str:
    """Given a '/' separated name of analyzer, e.g. r2c/typeflow, returns the org name which is 'r2c'
    """
    names = analyzer_name.split("/")
    assert (
        len(names) == 2
    ), f"Make sure you specified org and analyzer_name as `org/analyzer_name` in your analyzer.json"
    return names[0]
