import abc
import json
import logging
import os
import shutil
import tempfile
from typing import Iterator, List, Optional, Tuple

from r2c.lib.constants import (
    DEFAULT_LOCAL_RUN_DIR_SUFFIX,
    S3_ANALYSIS_BUCKET_NAME,
    S3_ANALYSIS_LOG_BUCKET_NAME,
    S3_CODE_BUCKET_NAME,
    S3_ORG_REGISTRY_BUCKET_NAME,
    S3_PUBLIC_REGISTRY_BUCKET_NAME,
)
from r2c.lib.message import Message
from r2c.lib.util import get_tmp_dir, handle_readonly_fix


class Infrastructure(metaclass=abc.ABCMeta):
    """
        Base class for all interactions with the batch backend infrastructure
    """

    @abc.abstractmethod
    def get_message(self, src: str, block: bool) -> Optional[Message]:
        """
            Get the next message from a queue identified by SRC.
            Repolls until a message is received if BLOCK is true.

            Args:
                src (String): identifier for queue
                block (Boolean): if true will only return is a message is received
                                 if false will return None if no message

            Returns:
                None if
                Some message object
        """
        pass

    @abc.abstractmethod
    def put_message(self, dst: str, message: Message) -> None:
        """
            Send MESSAGE to DST

            Args:
                dst (String): identifier for destination
        """
        pass

    @abc.abstractmethod
    def get_file(self, src: str, key: str, name: str) -> bool:
        pass

    @abc.abstractmethod
    def read_file(self, src: str, key: str) -> Optional[str]:
        """
            Returns the contents of file KEY in SRC as a string
            Returns None if key does not exist in SRC
        """
        pass

    @abc.abstractclassmethod
    def read_objects(self, src: str, prefix: str) -> Iterator:
        pass

    @abc.abstractclassmethod
    def read_keys(self, src: str, prefix: str) -> Iterator:
        pass

    @abc.abstractmethod
    def put_file(self, dst: str, filename: str, key: str) -> None:
        pass

    def contains_file(self, src: str, key: str) -> bool:
        return self.get_file_metadata(src, key) is not None

    @abc.abstractmethod
    def get_file_metadata(self, src: str, key: str) -> Optional[dict]:
        pass

    @abc.abstractmethod
    def put_object(self, dst: str, obj: str, key: str) -> None:
        pass

    @abc.abstractmethod
    def put_notify(self, dst: str, message: Message) -> None:
        pass


def get_default_local_run_dir():
    return os.path.join(get_tmp_dir(), DEFAULT_LOCAL_RUN_DIR_SUFFIX)


class LocalDirInfra(Infrastructure):
    def __init__(self, directory=get_default_local_run_dir()):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._directory = directory

    def key_to_filename(self, key):
        return key.replace("/", "___")

    def filename_to_key(self, filename):
        return filename.replace("___", "/")

    def get_message(self, src: str, block: bool = False) -> Optional[Message]:
        raise NotImplementedError("Local Dir Infras don't support queue operations")

    def put_message(self, dst: str, message: Message) -> None:
        raise NotImplementedError("Local Dir Infras don't support queue operations")

    def get_file(self, src: str, key: str, name: str) -> bool:
        """
            Tries to copy file associated with KEY from the bucket named SRC
            On success copies to NAME and returns true.
            Returns false on failure (no file associated with KEY in SRC)

            Args:
                src (String): name of directory
                key (String): name of file within the directory
                name (String): filename file will be copied to

            Returns:
                bool True if successfully downloaded file
        """
        try:
            shutil.copy(
                os.path.join(self._directory, "data", src, self.key_to_filename(key)),
                name,
            )
            return True
        except FileNotFoundError as e:
            self._logger.error(e)
            return False
        except Exception as e:
            raise e

    def read_file(self, src: str, key: str) -> Optional[str]:
        try:
            with open(
                os.path.join(self._directory, "data", src, self.key_to_filename(key)),
                "r",
            ) as f:
                contents = f.read()
                return contents
        except FileNotFoundError as e:
            return None
        except Exception as e:
            raise e

    def read_objects(self, src: str, prefix: str) -> Iterator[Tuple[str, str]]:
        """
        Generator that iterates over all files in a given src directory with a prefix.
        prefix="" iterates over all objects.

        Args:
            src (String): name of directory within self._directory
            prefix (String): key prefix of files to be iterated

        Returns:
            tuples of (filename, content)
        """
        for filename in sorted(os.listdir(os.path.join(self._directory, "data", src))):
            if filename.startswith(self.key_to_filename(prefix)):
                with open(
                    os.path.join(self._directory, "data", src, filename), "r"
                ) as f:
                    yield self.filename_to_key(filename), f.read()

    def read_keys(self, src: str, prefix: str) -> Iterator[str]:
        """
        Generator that iterates over all files in a given src directory with a prefix.
        prefix="" iterates over all objects.

        Args:
            src (String): name of directory within self._directory
            prefix (String): key prefix of files to be iterated

        Returns:
            filenames
        """
        for filename in sorted(os.listdir(os.path.join(self._directory, "data", src))):
            if filename.startswith(self.key_to_filename(prefix)):
                yield self.filename_to_key(filename)

    def put_file(
        self, dst: str, filename: str, key: str, metadata: Optional[dict] = None
    ) -> None:
        """
            Copy file identified by FILENAME to DST with key KEY.
            Include all key,value pairs in METADATA to FILENAME/KEY's metadata

            Args:
                dst: name of S3 bucket
                filename: name of file to be uploaded
                key: key to name uploaded file in the bucket
                metadata: dictionary of key,value pairs we wnat to be included as
                          metadata for uploaded file
        """
        metadata_path = os.path.join(
            self._directory, "metadata", dst, self.key_to_filename(key)
        )
        # persist metadata
        with open(metadata_path, "w") as f:
            if metadata:
                f.write(json.dumps(metadata))

        target_path = os.path.join(
            self._directory, "data", dst, self.key_to_filename(key)
        )
        shutil.copy(filename, target_path)

    def get_file_metadata(self, src: str, key: str) -> Optional[dict]:
        """
            Gets metadata. None if key does not exist in bucketname
        """
        try:
            with open(
                os.path.join(
                    self._directory, "metadata", src, self.key_to_filename(key)
                ),
                "r",
            ) as f:
                contents = f.read()
                if len(contents) > 0:
                    return json.loads(contents)
                return {}
        except FileNotFoundError as e:
            return None
        except Exception:
            raise

    def put_object(self, dst: str, obj: str, key: str) -> None:
        # always create empty metadata object so metadata dir reflects data dir 1:1
        with open(
            os.path.join(self._directory, "metadata", dst, self.key_to_filename(key)),
            "w",
        ) as f:
            pass

        with open(
            os.path.join(self._directory, "data", dst, self.key_to_filename(key)), "w"
        ) as f:
            f.write(obj)

    def put_notify(self, dst: str, message: Message) -> None:
        raise NotImplementedError(
            "Local Dir Infras don't support notification operations"
        )

    def reset(self):
        def reset_bucket(name):
            """
                Deletes all objects in bucket
            """
            data_path = os.path.join(self._directory, "data", name)
            if os.path.exists(data_path):
                shutil.rmtree(data_path, onerror=handle_readonly_fix)

            metadata_path = os.path.join(self._directory, "metadata", name)
            if os.path.exists(metadata_path):
                shutil.rmtree(metadata_path, onerror=handle_readonly_fix)

            self._create_bucket(name)

        reset_bucket(S3_CODE_BUCKET_NAME)
        reset_bucket(S3_ANALYSIS_BUCKET_NAME)
        reset_bucket(S3_ANALYSIS_LOG_BUCKET_NAME)
        reset_bucket(S3_PUBLIC_REGISTRY_BUCKET_NAME)
        reset_bucket(S3_ORG_REGISTRY_BUCKET_NAME)

    def _create_bucket(self, bucket_name: str) -> None:
        if not os.path.exists(os.path.join(self._directory, "data", bucket_name)):
            os.makedirs(os.path.join(self._directory, "data", bucket_name))

        if not os.path.exists(os.path.join(self._directory, "metadata", bucket_name)):
            os.makedirs(os.path.join(self._directory, "metadata", bucket_name))
