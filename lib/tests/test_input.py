import pytest
from r2c.lib.input import (
    INPUT_TYPE_KEY,
    AnalyzerInput,
    GitRepoCommit,
    InvalidAnalyzerInputException,
    InvalidStorageKeyException,
)

TEST_REPO_URL = "https://github.com/lodash/lodash"
TEST_COMMIT = "c68170b336acc2892093994cc4d508c2ccb7a3b5"


def test_from_json():
    repo_commit = AnalyzerInput.from_json(
        {
            INPUT_TYPE_KEY: "GitRepoCommit",
            "repo_url": TEST_REPO_URL,
            "commit_hash": TEST_COMMIT,
        }
    )
    assert repo_commit.repo_url == TEST_REPO_URL
    assert repo_commit.commit_hash == TEST_COMMIT


def test_from_invalid_json():
    # no input key
    with pytest.raises(InvalidAnalyzerInputException):
        repo_commit = AnalyzerInput.from_json(
            {"repo_url": TEST_REPO_URL, "commit_hash": TEST_COMMIT}
        )

    # missing key
    with pytest.raises(InvalidAnalyzerInputException):
        repo_commit = AnalyzerInput.from_json(
            {INPUT_TYPE_KEY: "GitRepoCommit", "commit_hash": TEST_COMMIT}
        )

    # invalid key
    with pytest.raises(InvalidAnalyzerInputException):
        repo_commit = AnalyzerInput.from_json(
            {
                INPUT_TYPE_KEY: "GitRepoCommit",
                "repo": TEST_REPO_URL,
                "commit_hash": TEST_COMMIT,
            }
        )

    # extra key
    with pytest.raises(InvalidAnalyzerInputException):
        repo_commit = AnalyzerInput.from_json(
            {
                INPUT_TYPE_KEY: "GitRepoCommit",
                "repo_url": TEST_REPO_URL,
                "commit_hash": TEST_COMMIT,
                "extra_key": "some_value",
            }
        )
