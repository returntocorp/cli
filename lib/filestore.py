import abc
import json
import os
import shutil
from pathlib import Path
from typing import Optional

from r2c.lib.constants import (
    DEFAULT_LOCAL_RUN_DIR_SUFFIX,
    S3_ANALYSIS_BUCKET_NAME,
    S3_ANALYSIS_LOG_BUCKET_NAME,
)
from r2c.lib.specified_analyzer import SpecifiedAnalyzer
from r2c.lib.util import get_tmp_dir, url_to_repo_id


class FileStore(metaclass=abc.ABCMeta):
    """
        Abstract base class for something that stores and retrieves files
    """

    @abc.abstractmethod
    def put(
        self,
        git_url: str,
        commit_hash: str,
        specified_analyzer: SpecifiedAnalyzer,
        source: str,  # Path,
    ) -> None:
        """
            Stores the file/directory in SOURCE so that it is retreivable given
            GIT_URL, COMMIT_HASH, and SPECIFIED_ANALYZER
        """

    @abc.abstractmethod
    def write(
        self,
        git_url: str,
        commit_hash: str,
        specified_analyzer: SpecifiedAnalyzer,
        obj_str: str,
    ) -> None:
        """
            Would be equivalent if obj_str was written to a file and self.put was
            called on that file
        """

    @abc.abstractmethod
    def get(
        self,
        git_url: str,
        commit_hash: str,
        specified_analyzer: SpecifiedAnalyzer,
        destination: str,  # Path,
    ) -> bool:
        """
            Retieved file/directory previously stored and writes it to DESITINATION

            Returns True if file was retrieved, False if file did not exist
        """

    @abc.abstractmethod
    def read(
        self, git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> Optional[str]:
        """
            Reads the file stored as a string. Returns None if file does not exist
        """

    @abc.abstractmethod
    def contains(
        self, git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> bool:
        """
            Returns true if file/directory exists in filestore
        """

    @staticmethod
    @abc.abstractmethod
    def _key(
        git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> str:
        """
            Key used to identify the file stored
        """


def get_default_local_filestore_dir():
    return os.path.join(get_tmp_dir(), DEFAULT_LOCAL_RUN_DIR_SUFFIX)


class LocalFileStore(FileStore):
    def __init__(self, path: str) -> None:
        self._directory = os.path.join(get_default_local_filestore_dir(), path)
        Path(os.path.join(self._directory, "metadata")).mkdir(
            parents=True, exist_ok=True
        )
        Path(os.path.join(self._directory, "data")).mkdir(parents=True, exist_ok=True)

    def delete(
        self, git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> None:
        key = self._key(git_url, commit_hash, specified_analyzer)
        if os.path.isfile(os.path.join(self._directory, "data", key)):
            os.remove(os.path.join(self._directory, "data", key))
        if os.path.isfile(os.path.join(self._directory, "metadata", key)):
            os.remove(os.path.join(self._directory, "metadata", key))

    def delete_all(self):
        shutil.rmtree(self._directory)
        Path(os.path.join(self._directory, "metadata")).mkdir(
            parents=True, exist_ok=True
        )
        Path(os.path.join(self._directory, "data")).mkdir(parents=True, exist_ok=True)

    def put(
        self,
        git_url: str,
        commit_hash: str,
        specified_analyzer: SpecifiedAnalyzer,
        source: str,  # Path,
    ) -> None:
        key = self._key(git_url, commit_hash, specified_analyzer)

        # For now metadata is unused
        metadata_path = os.path.join(self._directory, "metadata", key)
        with open(metadata_path, "w") as f:
            f.write(json.dumps({}))

        target_path = os.path.join(self._directory, "data", key)
        shutil.copy(source, target_path)

    def write(
        self,
        git_url: str,
        commit_hash: str,
        specified_analyzer: SpecifiedAnalyzer,
        obj_str: str,
    ) -> None:
        key = self._key(git_url, commit_hash, specified_analyzer)

        # always create empty metadata object so metadata dir reflects data dir 1:1
        with open(os.path.join(self._directory, "metadata", key), "w") as f:
            pass

        with open(os.path.join(self._directory, "data", key), "w") as f:
            f.write(obj_str)

    def get(
        self,
        git_url: str,
        commit_hash: str,
        specified_analyzer: SpecifiedAnalyzer,
        destination: str,  # Path,
    ) -> bool:
        key = self._key(git_url, commit_hash, specified_analyzer)
        try:
            shutil.copy(os.path.join(self._directory, "data", key), destination)
            return True
        except FileNotFoundError as e:
            return False
        except Exception as e:
            raise e

    def read(
        self, git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> Optional[str]:
        key = self._key(git_url, commit_hash, specified_analyzer)
        try:
            with open(os.path.join(self._directory, "data", key), "r") as f:
                contents = f.read()
                return contents
        except FileNotFoundError as e:
            return None
        except Exception as e:
            raise e

    def contains(
        self, git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> bool:
        key = self._key(git_url, commit_hash, specified_analyzer)
        return Path(os.path.join(self._directory, "data", key)).exists()

    @staticmethod
    @abc.abstractmethod
    def _key(
        git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> str:
        """
            Key used to identify the file stored
        """


class LocalJsonOutputStore(LocalFileStore):
    def __init__(self) -> None:
        super().__init__("analysis_output")

    @staticmethod
    def _key(
        git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> str:
        repo_id = url_to_repo_id(git_url)
        analyzer_name = specified_analyzer.versioned_analyzer.name
        version = specified_analyzer.versioned_analyzer.version

        if len(specified_analyzer.parameters) == 0:
            analyzer_part = f"{analyzer_name}/{version}"
        else:
            param_part = ""
            for param_name in sorted(specified_analyzer.parameters):
                param_part += (
                    f"{param_name}:{specified_analyzer.parameters[param_name]}"
                )
            analyzer_part = f"{analyzer_name}/{version}/{param_part}"

        target_part = f"{repo_id}/{commit_hash}/output.json"

        key = f"{analyzer_part}/{target_part}"
        return key.replace("/", "___")


class LocalFilesystemOutputStore(LocalFileStore):
    def __init__(self) -> None:
        super().__init__("analysis_output")

    @staticmethod
    def _key(
        git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> str:
        repo_id = url_to_repo_id(git_url)
        analyzer_name = specified_analyzer.versioned_analyzer.name
        version = specified_analyzer.versioned_analyzer.version

        if len(specified_analyzer.parameters) == 0:
            analyzer_part = f"{analyzer_name}/{version}"
        else:
            param_part = ""
            for param_name in sorted(specified_analyzer.parameters):
                param_part += (
                    f"{param_name}:{specified_analyzer.parameters[param_name]}"
                )
            analyzer_part = f"{analyzer_name}/{version}/{param_part}"

        target_part = f"{repo_id}/{commit_hash}/output.tar.gz"

        key = f"{analyzer_part}/{target_part}"
        return key.replace("/", "___")


class LocalLogStore(LocalFileStore):
    def __init__(self) -> None:
        super().__init__("analysis_log")

    @staticmethod
    def _key(
        git_url: str, commit_hash: str, specified_analyzer: SpecifiedAnalyzer
    ) -> str:
        analyzer_name = specified_analyzer.versioned_analyzer.name
        version = specified_analyzer.versioned_analyzer.version
        repo_id = url_to_repo_id(git_url)
        key = f"{analyzer_name}/{version}/{repo_id}/{commit_hash}/container.log"
        return key.replace("/", "___")
