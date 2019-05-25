import base64
import logging
import os
import signal
import stat
import subprocess
import sys
import tempfile
from collections import OrderedDict
from functools import cmp_to_key
from operator import itemgetter as i
from pathlib import Path

from semantic_version import Version

logger = logging.getLogger(__name__)


class Timeout:
    """
        Helper class to wrap calls in a timeout

        Args:
            seconds (Int): number of seconds before timing out
            error_message (String): error message pass through when raising a TimeoutError. Default="Timeout"

        Return:
            Timeout object

        Raises:
            TimeoutError
    """

    def __init__(self, seconds=1, error_message="Timeout"):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        if self.seconds > 0:
            if os.name == "nt":
                logger.warning("Timeouts not supported on Windows yet!")
            else:
                signal.signal(signal.SIGALRM, self.handle_timeout)
                signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        if self.seconds > 0 and os.name != "nt":
            signal.alarm(0)


def sort_two_levels(iterable):
    # iterable is a list of dicts
    # [{ "C": 33, "A": 1, "B": 2 }, { "C": 33, "D": 1, "Z": 2 }] -> "
    # we need to create ordered dicts
    inner = [OrderedDict([(k, v) for k, v in sorted(x.items())]) for x in iterable]
    # should be valid for the sort to be on check_id and path, we're not
    # (currently) expecting duplicates of those
    return multikeysort(inner, ["check_id", "path"])


def multikeysort(items, columns):
    """
    Given an iterable of dicts, sort it by the columns (keys) specified in `columns` in order they appear.
    c.f. https://stackoverflow.com/questions/1143671/python-sorting-list-of-dictionaries-by-multiple-keys
    """

    # cmp was builtin in python2, have to add it for python3
    def cmp(a, b):
        return (a > b) - (a < b)

    comparers = [
        ((i(col[1:].strip()), -1) if col.startswith("-") else (i(col.strip()), 1))
        for col in columns
    ]

    def comparer(left, right):
        comparer_iter = (cmp(fn(left), fn(right)) * mult for fn, mult in comparers)
        return next((result for result in comparer_iter if result), 0)

    return sorted(items, key=cmp_to_key(comparer))


# TODO encapsualte encodings/key namings
def url_to_repo_id(git_url):
    """
        Returns repo_id used to identify GIT_URL in SQS and S3

        Reverse folder name for better cloud performance
        (otherwise prefixes are similar)
    """
    return base64.b64encode(git_url.encode("utf-8")).decode("utf-8")[::-1]


def repo_id_to_url(repo_id):
    """
        Inverse of url_to_repo_id. Returns GIT_URL from repo_id
    """
    return base64.b64decode(repo_id[::-1]).decode("utf-8")


def cloned_key(git_url):
    """
        Key code of GIT_URL was uploaded to S3 with
    """
    repo_id = url_to_repo_id(git_url)
    key = "{}.tar.gz".format(repo_id)
    return key


def run_streaming(cmd):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    for line in iter(process.stdout.readline, ""):
        sys.stdout.write(line)
    process.stdout.close()
    rc = process.wait()
    if rc:
        raise subprocess.CalledProcessError(rc, cmd)


def symlink_exists(dir: str) -> bool:
    for (cur_path, dirnames, filenames) in os.walk(dir):
        dirpaths = [os.path.join(cur_path, dirname) for dirname in dirnames]
        filepaths = [os.path.join(cur_path, filename) for filename in filenames]
        children = dirpaths + filepaths

        any_child_is_symlink = any(Path(child).is_symlink() for child in children)
        if any_child_is_symlink:
            print(f"Found symlink on child on {cur_path}")
            return True

    return False


def handle_readonly_fix(func, path, execinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def get_tmp_dir():
    """Wrapper around tempfile to handle MacOS specific issues. See #2733"""
    # for MacOS lets use /tmp, not /var
    if os.name == "posix" and sys.platform == "darwin":
        return "/tmp"
    return tempfile.gettempdir()


def get_unique_semver(version: Version) -> Version:
    """ Give a unique semver version of the given version """
    # TODO find a better way to do this
    return Version(f"9.9.9-alpha999")
