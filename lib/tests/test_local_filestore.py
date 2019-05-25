import os
from unittest.mock import MagicMock

import pytest

from r2c.lib.filestore import LocalFileStore
from r2c.lib.specified_analyzer import SpecifiedAnalyzer

GIT_URL = "https://github.com/userblah/testrepo"
COMMIT_HASH = "3b272807b973f1af322856f61f70539707d59b20"
SPECIFIED_ANALYZER = MagicMock()
OBJ_STR = "This is a test string hello testing 123"


class LocalFileStoreSub(LocalFileStore):
    def __init__(self) -> None:
        super().__init__("/tmp/test_output")

    @staticmethod
    def _key(
        git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> str:
        return f"{commit_hash}"


@pytest.fixture
def local_filestore_sub():
    local_filestore_sub = LocalFileStoreSub()
    local_filestore_sub.delete_all()
    return local_filestore_sub


def test_nonexistent_get(local_filestore_sub, tmpdir):
    destination = os.path.join(tmpdir, "dst")
    assert not local_filestore_sub.get(
        GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, destination
    )


def test_nonexistent_read(local_filestore_sub):
    assert local_filestore_sub.read(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER) is None


def test_nonexistent_exits(local_filestore_sub):
    assert not local_filestore_sub.contains(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER)


def test_put_get(local_filestore_sub, tmpdir):
    source = os.path.join(tmpdir, "src")
    with open(source, "w") as f:
        f.write(OBJ_STR)
    local_filestore_sub.put(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, source)

    destination = os.path.join(tmpdir, "dst")
    local_filestore_sub.get(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, destination)
    with open(destination, "r") as f:
        read = f.read()
    assert read == OBJ_STR


def test_put_read(local_filestore_sub, tmpdir):
    source = os.path.join(tmpdir, "src")
    with open(source, "w") as f:
        f.write(OBJ_STR)
    local_filestore_sub.put(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, source)

    read = local_filestore_sub.read(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER)
    assert read == OBJ_STR


def test_put_contains(local_filestore_sub, tmpdir):
    source = os.path.join(tmpdir, "src")
    with open(source, "w") as f:
        f.write(OBJ_STR)
    local_filestore_sub.put(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, source)

    assert local_filestore_sub.contains(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER)


def test_write_get(local_filestore_sub, tmpdir):
    local_filestore_sub.write(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, OBJ_STR)

    destination = os.path.join(tmpdir, "dst")
    local_filestore_sub.get(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, destination)
    with open(destination, "r") as f:
        read = f.read()
    assert read == OBJ_STR


def test_write_read(local_filestore_sub):
    local_filestore_sub.write(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, OBJ_STR)
    read = local_filestore_sub.read(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER)
    assert read == OBJ_STR


def test_write_contains(local_filestore_sub):
    local_filestore_sub.write(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, OBJ_STR)
    assert local_filestore_sub.contains(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER)


def test_delete(local_filestore_sub):
    local_filestore_sub.write(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER, OBJ_STR)
    assert local_filestore_sub.contains(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER)
    local_filestore_sub.delete(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER)
    assert not local_filestore_sub.contains(GIT_URL, COMMIT_HASH, SPECIFIED_ANALYZER)
