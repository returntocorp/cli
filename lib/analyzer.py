#!/usr/bin/env python3
import abc
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import threading
from datetime import datetime
from typing import Dict, NewType, Optional, Tuple, Union

import docker
import jsonschema

from r2c.lib.constants import (
    DEFAULT_ANALYSIS_WORKING_TEMPDIR_SUFFIX,
    S3_ANALYSIS_BUCKET_NAME,
    S3_ANALYSIS_LOG_BUCKET_NAME,
    SPECIAL_ANALYZERS,
)
from r2c.lib.filestore import (
    FileStore,
    LocalFilesystemOutputStore,
    LocalJsonOutputStore,
    LocalLogStore,
)
from r2c.lib.manifest import AnalyzerManifest, AnalyzerOutputType, AnalyzerType
from r2c.lib.registry import RegistryData
from r2c.lib.specified_analyzer import SpecifiedAnalyzer
from r2c.lib.util import Timeout, get_tmp_dir, handle_readonly_fix, url_to_repo_id
from r2c.lib.versioned_analyzer import VersionedAnalyzer

MEMORY_LIMIT = (
    "1536m"
)  # clean t2.small with unbuntu 18.04 has Mem:           1991          92        1514           0         385        1752

# We need a very small Linux image so we can do some filesystem stuff through
# Docker.
ALPINE_IMAGE = "alpine:3.9"

ContainerLog = NewType("ContainerLog", str)


def watch_log(stream, is_stdout):
    """Helper function that we run in a thread to preserve stdout/stderr distinction from the docker container
    """
    for line in stream:
        if is_stdout:
            sys.stdout.write(line.decode("utf-8"))
        else:
            sys.stderr.write(line.decode("utf-8"))


class AnalyzerNonZeroExitError(Exception):
    """
        Thrown when analyzer docker container exists with non-zero exit code
    """

    def __init__(self, status_code, log):
        self._status_code = status_code
        self._log = log

    @property
    def log(self):
        return self._log

    @property
    def status_code(self):
        return self._status_code

    def __str__(self):
        return f"Docker container finished with non-zero exit code: {self._status_code}.\n Container log {self._log}"


class AnalyzerImagePullFail(Exception):
    """
        Thrown when analyzer image fails to pull
    """


class UnsupportedAnalyzerType(Exception):
    """
        Thrown when unsupported analyzer type is encountered
    """


class InvalidAnalyzerOutput(Exception):
    """Thrown when the analyzer's output doesn't conform to its schema."""

    def __init__(
        self, inner: Union[jsonschema.ValidationError, json.JSONDecodeError]
    ) -> None:
        self.inner = inner


class InvalidAnalyzerIntegrationTestDefinition(Exception):
    """Thrown when the analyzer's integration test doesn't conform to its schema."""

    def __init__(
        self, inner: Union[jsonschema.ValidationError, json.JSONDecodeError]
    ) -> None:
        self.inner = inner


class UnspecifiedCommitString(Exception):
    """
        Thrown when analyzer MPU is given commit string that is not a commit hash
    """


def get_default_analyzer_working_dir():
    return os.path.join(get_tmp_dir(), DEFAULT_ANALYSIS_WORKING_TEMPDIR_SUFFIX)


class Analyzer:
    def __init__(
        self,
        registry_data: RegistryData,
        json_output_store: FileStore,
        filesystem_output_store: FileStore,
        log_store: FileStore,
        localrun: bool = False,
        timeout: int = 1200,
        workdir: str = get_default_analyzer_working_dir(),
    ) -> None:
        self._registry_data = registry_data
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(logging.INFO)
        self._docker_client = docker.from_env()
        self._timeout = timeout

        self._json_output_store = json_output_store
        self._filesystem_output_store = filesystem_output_store
        self._log_store = log_store

        # TODO remove once cloner analyzer doesn't need to checkout
        self._localrun = localrun

        # Local run working dir. For analyzer use only.
        # THE CONTENTS OF THIS DIRECTORY MAY BE ERASED OR MODIFIED WITHOUT WARNING
        self._workdir = workdir
        self._registry_data = registry_data

    def reset_registry_data(self, registry_data: RegistryData) -> None:
        self._registry_data = registry_data

    @staticmethod
    def container_log_key(git_url: str, commit_hash: str, image_id: str) -> str:
        """
            Returns key that docker container log is stored with
        """
        analyzer = VersionedAnalyzer.from_image_id(image_id)
        repo_id = url_to_repo_id(git_url)
        return (
            f"{analyzer.name}/{analyzer.version}/{repo_id}/{commit_hash}/container.log"
        )

    @staticmethod
    def _get_analyzer_output_extension(output_type: AnalyzerOutputType) -> str:
        """For an analyzer of this output type, what is the file extension of the single-file output?

        """

        if output_type == AnalyzerOutputType.json:
            return ".json"
        elif output_type == AnalyzerOutputType.filesystem:
            return ".tar.gz"
        elif output_type == AnalyzerOutputType.both:
            return ""
        else:
            raise RuntimeError(
                f"non-implemented; don't know filename extension for analyzer with output type: {output_type}"
            )

    @staticmethod
    def get_analyzer_output_path(
        mount_folder: str, output_type: AnalyzerOutputType
    ) -> str:
        """For an analyzer of this output type, where does the single-file output live?

        """
        BASE_DIR = "output"
        if output_type == AnalyzerOutputType.json:
            return os.path.join(
                mount_folder,
                BASE_DIR,
                "output" + Analyzer._get_analyzer_output_extension(output_type),
            )
        elif output_type == AnalyzerOutputType.filesystem:
            return os.path.join(
                mount_folder,
                BASE_DIR,
                "fs" + Analyzer._get_analyzer_output_extension(output_type),
            )
        else:
            raise RuntimeError(
                f"non-implemented; don't know where to find output for analyzer with output type: {output_type}"
            )

    def analysis_key(
        self,
        git_url: str,
        commit_hash: str,
        specified_analyzer: SpecifiedAnalyzer,
        output_type: Optional[AnalyzerOutputType] = None,
    ) -> str:
        """
            Key analysis report was uploaded with

            Args:
                git_url: Url of repo analyzed
                commit_hash: hash analyzed
                specified_analyzer: unique identifier of analysis container w/ parameters
                output_type: type of output we want to retrieve from SPECIFIED_ANALYZER if None then
                we lookup the output type of the analyzer in the registry

            Returns:
                key of report in S3 bucket
        """

        manifest = self._registry_data.manifest_for(
            specified_analyzer.versioned_analyzer
        )
        analyzer_type = manifest.analyzer_type

        repo_id = url_to_repo_id(git_url)

        if output_type is None:
            output_type = manifest.output_type
        extension = self._get_analyzer_output_extension(output_type)

        if len(specified_analyzer.parameters) == 0:
            analyzer_part = f"{manifest.analyzer_name}/{manifest.version}"
        else:
            param_part = ""
            for param_name in sorted(specified_analyzer.parameters):
                param_part += (
                    f"{param_name}:{specified_analyzer.parameters[param_name]}"
                )
            analyzer_part = f"{manifest.analyzer_name}/{manifest.version}/{param_part}"

        if analyzer_type == AnalyzerType.git:
            # for now, we also include the commit_hash to make other parts of the pipelie
            # treat git analyzers similar to commit analyzers.
            # TODO: figure out a good way of actually deisgning for this,fingerprinting
            # the repo and keeping our determinism guarantee
            target_part = f"{repo_id}/{commit_hash}/output{extension}"
        elif analyzer_type == AnalyzerType.commit:
            target_part = f"{repo_id}/{commit_hash}/output{extension}"
        else:
            raise UnsupportedAnalyzerType(analyzer_type)

        key = f"{analyzer_part}/{target_part}"
        return key

    def full_analyze_request(
        self,
        git_url: str,
        commit_string: Optional[str],
        specified_analyzer: SpecifiedAnalyzer,
        force: bool,
        pass_analyzer_output: bool,
        interactive_index: Optional[int] = None,
        interactive_name: Optional[str] = None,
        memory_limit: Optional[str] = None,
        env_args_dict: Optional[dict] = None,
    ) -> dict:
        """
            Handle an analysis request and uploading output.

            Args:
                specified_analyzer: unique identifier for analyzer container to run w/ parameter
                git_url: Git repository to analyze
                commit_string: if not supplied, it will default to HEAD.
                force: if true, the analysis will proceed even if there is already a cached result for this request.
                interactive_index: if set, the analyzer in the execution graph (defaults to last if interactive_index not specified)  will drop into shell rather than running automatically.
                pass_analyzer_output: if true, the analyzer's stdout and stderr will be passed to the current process stdout and stderr, respectively

            Returns:
                A dict with information about the final output last analyzer in the dependency graph to run.
        """

        # Analyze head commit by default
        if not commit_string or "HEAD" in commit_string:
            raise UnspecifiedCommitString(commit_string)

        commit_hash = commit_string

        skipped = True

        execution_order = self._registry_data.sorted_deps(specified_analyzer)

        analyzer_execution_str = "".join(
            [f"\n\t{i}: {analyzer}" for i, analyzer in enumerate(execution_order)]
        )
        self._logger.info(
            f"All analyzers that will be run, in order: {analyzer_execution_str }"
        )

        container_output_path = ""
        for dependency_index, specified_dependency in enumerate(execution_order):
            if interactive_index or interactive_index == 0:
                try:
                    is_interactive_dependency = (
                        execution_order[interactive_index] == specified_dependency
                    )

                except IndexError as e:
                    self._logger.error(
                        f"{interactive_index} could not be used as interactive shell index. Stopping Analysis."
                    )
                    raise Exception(
                        f"Could not create interactive shell into dependency at {interactive_index}."
                    )
            elif (
                interactive_name
                and interactive_name in specified_dependency.versioned_analyzer.name
            ):
                is_interactive_dependency = True
            else:
                is_interactive_dependency = False

            if is_interactive_dependency:
                print(
                    f"Calling `docker exec` into analyzer with name {specified_dependency}"
                )

            dependency = specified_dependency.versioned_analyzer
            output_s3_key = self.analysis_key(
                git_url, commit_hash, specified_dependency
            )

            output_type = self._registry_data.manifest_for(
                specified_dependency.versioned_analyzer
            ).output_type

            if output_type == AnalyzerOutputType.both:
                json_exists = self._json_output_store.contains(
                    git_url, commit_hash, specified_dependency
                )
                filesystem_exists = self._filesystem_output_store.contains(
                    git_url, commit_hash, specified_dependency
                )
                dependency_exists = json_exists and filesystem_exists
            elif output_type == AnalyzerOutputType.json:
                dependency_exists = self._json_output_store.contains(
                    git_url, commit_hash, specified_dependency
                )
            elif output_type == AnalyzerOutputType.filesystem:
                dependency_exists = self._filesystem_output_store.contains(
                    git_url, commit_hash, specified_dependency
                )
            else:
                raise Exception()

            if (
                # TODO check freshness here
                dependency_exists
                and not force
                and interactive_index is None
                and interactive_name is None
            ):
                # use cache when non-interactive, non-forcing, dependency
                self._logger.info(
                    f"Analysis for {git_url} {commit_string} {specified_dependency} already exists. Keeping old analysis report"
                )
            else:
                self._logger.info(
                    f"Running: {dependency.name}, {dependency.version}..."
                )

                try:
                    mount_folder, container_log = self._analyze(
                        specified_dependency,
                        git_url,
                        commit_hash,
                        interactive=is_interactive_dependency,
                        pass_analyzer_output=pass_analyzer_output,
                        memory_limit=memory_limit,
                        env_args_dict=env_args_dict,
                    )
                except AnalyzerNonZeroExitError as e:
                    # Upload log then raise
                    self._logger.info(
                        "AnalyzerNonZeroExitError caught. Uploading Container Log."
                    )
                    container_log = e.log
                    self._log_store.write(
                        git_url, commit_hash, specified_dependency, container_log
                    )
                    raise e

                self._logger.info("Analyzer finished running.")
                self._logger.info("Uploading analyzer log")
                self._log_store.write(
                    git_url, commit_hash, specified_dependency, container_log
                )

                self._logger.info("Uploading analyzer output")
                container_output_path = self.upload_output(
                    specified_dependency, git_url, commit_hash, mount_folder
                )

                self._logger.info(f"Deleting {mount_folder}")
                shutil.rmtree(mount_folder, onerror=handle_readonly_fix)
                skipped = False

        return {
            "skipped": skipped,
            "commit_hash": commit_hash,
            "s3_key": output_s3_key,
            "container_output_path": container_output_path,
        }

    def _validate_output(self, manifest: AnalyzerManifest, mount_folder: str) -> None:
        """Validates the output, then migrates it to the latest schema.

        Note that if the analyzer's output is not JSON, this does nothing since
        we don't have a way to validate non-JSON outputs.

        Throws:
            InvalidAnalyzerOutput: If validation fails.

        """
        if manifest.output_type != AnalyzerOutputType.json:
            return

        path = self.get_analyzer_output_path(mount_folder, manifest.output_type)
        with open(path) as f:
            try:
                output = json.load(f)
            except json.JSONDecodeError as err:
                raise InvalidAnalyzerOutput(err)

        try:
            manifest.output.validator(output).validate(output)
        except jsonschema.ValidationError as err:
            raise InvalidAnalyzerOutput(err) from err
        except Exception as err:
            raise RuntimeError(
                f"There was an error validating your output. Please check that you're outputing a valid output and try again: {err}"
            )

    def upload_output(
        self,
        specified_analyzer: SpecifiedAnalyzer,
        git_url: str,
        commit_hash: str,
        mount_folder: str,
    ) -> str:
        """
            Upload analyzer results

            Args:
                specified_analyzer: uniquely identifies analyzer container w/ parameters
                git_url: url of code analyzed
                commit_hash: hash of code analyzed
                mount_folder: volume mounted during analysis. Assumes output lives in
                mount_folder/output/output.json or mount_folder/output/fs

            Returns:
                The inside-container path to the analyzer output that was uploaded.

            Raises:
                InvalidAnalyzerOutput: if output fails to validate
                                       note that output is still uploaded
        """
        manifest = self._registry_data.manifest_for(
            specified_analyzer.versioned_analyzer
        )
        output_type = manifest.output_type
        if output_type == AnalyzerOutputType.json:
            output_s3_key = self.analysis_key(git_url, commit_hash, specified_analyzer)
            output_file_path = self.get_analyzer_output_path(mount_folder, output_type)
            self._logger.info(
                f"Uploading {output_file_path} to {S3_ANALYSIS_BUCKET_NAME} with key {output_s3_key}"
            )
            self._json_output_store.put(
                git_url, commit_hash, specified_analyzer, output_file_path
            )
        elif output_type == AnalyzerOutputType.filesystem:
            output_s3_key = self.analysis_key(git_url, commit_hash, specified_analyzer)
            output_file_path = self.get_analyzer_output_path(mount_folder, output_type)
            self._logger.info("Filesystem output type. Tarring output for uploading...")
            with tarfile.open(output_file_path, "w:gz") as tar:
                tar.add(
                    mount_folder + "/output/fs",
                    arcname=specified_analyzer.versioned_analyzer.name,
                )
            self._logger.info(
                f"Uploading {output_file_path} to {S3_ANALYSIS_BUCKET_NAME} with key {output_s3_key}"
            )
            self._filesystem_output_store.put(
                git_url, commit_hash, specified_analyzer, output_file_path
            )
        elif output_type == AnalyzerOutputType.both:
            filesystem_output_s3_key = self.analysis_key(
                git_url, commit_hash, specified_analyzer, AnalyzerOutputType.filesystem
            )
            filesystem_output_file_path = self.get_analyzer_output_path(
                mount_folder, AnalyzerOutputType.filesystem
            )
            self._logger.info("Both output type. Tarring output for uploading...")
            with tarfile.open(filesystem_output_file_path, "w:gz") as tar:
                tar.add(
                    mount_folder + "/output/fs",
                    arcname=specified_analyzer.versioned_analyzer.name,
                )

            json_output_s3_key = self.analysis_key(
                git_url, commit_hash, specified_analyzer, AnalyzerOutputType.json
            )
            json_output_file_path = self.get_analyzer_output_path(
                mount_folder, AnalyzerOutputType.json
            )
            self._logger.info(
                f"Uploading {json_output_file_path} to {S3_ANALYSIS_BUCKET_NAME} with key {json_output_s3_key}"
            )
            self._json_output_store.put(
                git_url, commit_hash, specified_analyzer, json_output_file_path
            )

            self._logger.info(
                f"Uploading {filesystem_output_file_path} to {S3_ANALYSIS_BUCKET_NAME} with key {filesystem_output_s3_key}"
            )
            self._filesystem_output_store.put(
                git_url, commit_hash, specified_analyzer, filesystem_output_file_path
            )

            output_file_path = json_output_file_path
        else:
            raise RuntimeError(
                f"non-implemented analyzer output handler for output type: {output_type}"
            )

        # Invalid outputs should still be uploaded, but we want to
        # count them as failing.
        self._validate_output(manifest, mount_folder)
        return output_file_path

    def prepare_mount_volume(
        self, specified_analyzer: SpecifiedAnalyzer, git_url: str, commit_hash: str
    ) -> str:
        """
            Prepares directory to be mounted to docker container IMAGE_ID to
            run analysis on GIT_URL on COMMIT_HASH. Raises exception when cannot
            prepare directory with necessary dependencies.

            Args:
                specified_analyzer: uniquely identifies analyzer container w/ parameters
                git_url: url of code
                commit_hash: hash to analyze code at

            Returns:
                mount_folder: path to root of volume prepared. For analyzer spec v3 this is
                the parent directory containing inputs/ and output/
        """
        now_ts = datetime.utcnow().isoformat().replace(":", "").replace("-", "")
        image_id = specified_analyzer.versioned_analyzer.image_id
        safe_image_id = image_id.split("/")[-1].replace(":", "__")
        mount_folder = os.path.join(self._workdir, f"{safe_image_id}__{now_ts}")

        self._logger.info("Setting up volumes for analyzer container.")
        self._logger.info(f"Will mount: {mount_folder}")
        if pathlib.Path(mount_folder).exists():
            self._logger.debug(f"cleaning up old folder {mount_folder}")
            shutil.rmtree(mount_folder)

        input_dir = os.path.join(mount_folder, "inputs")
        output_dir = os.path.join(mount_folder, "output")
        pathlib.Path(input_dir).mkdir(parents=True, exist_ok=True)
        pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)
        os.chmod(output_dir, 0o777)
        # TODO why should this only be done if we expect fs?
        fs_dir = os.path.join(output_dir, "fs")
        pathlib.Path(fs_dir).mkdir(parents=True, exist_ok=True)
        os.chmod(fs_dir, 0o777)

        # Setup Parameters
        with open(os.path.join(input_dir, "parameters.json"), "w") as parameters_file:
            json.dump(specified_analyzer.parameters, parameters_file)

        dependencies = self._registry_data.get_direct_dependencies(
            specified_analyzer.versioned_analyzer
        )

        if specified_analyzer.versioned_analyzer.name in SPECIAL_ANALYZERS:
            with open(input_dir + "/cloner-input.json", "w") as argument_file:
                arguments = {"git_url": git_url, "commit_hash": commit_hash}
                json.dump(arguments, argument_file)
                success = True

        if specified_analyzer.versioned_analyzer.name == "r2c/full-cloner":
            with open(input_dir + "/cloner-input.json", "w") as argument_file:
                arguments = {"git_url": git_url}
                json.dump(arguments, argument_file)
                success = True

        self._logger.info(f"Loading dependencies' outputs: {dependencies}")
        for specified_dependency in dependencies:
            self._logger.info(f"Loading output of {specified_dependency}")

            output_type = self._registry_data.manifest_for(
                specified_dependency.versioned_analyzer
            ).output_type
            dependency_key = self.analysis_key(
                git_url, commit_hash, specified_dependency
            )
            self._logger.info(
                f"Retrieving dependency output from s3 with key {dependency_key}"
            )

            # Ensure Target Location Exists
            pathlib.Path(
                os.path.join(input_dir, specified_dependency.versioned_analyzer.name)
            ).mkdir(parents=True, exist_ok=True)

            if output_type == AnalyzerOutputType.json:
                success = self._json_output_store.get(
                    git_url,
                    commit_hash,
                    specified_dependency,
                    f"{input_dir}/{specified_dependency.versioned_analyzer.name}.json",
                )
            elif output_type == AnalyzerOutputType.filesystem:
                fs_input_tar = os.path.join(input_dir, "output.tar.gz")
                if self._filesystem_output_store.get(
                    git_url, commit_hash, specified_dependency, fs_input_tar
                ):
                    self._logger.info(f"Extracting filesystem dependency")
                    with tarfile.open(fs_input_tar) as tar:
                        tar.extractall(input_dir)
                    os.remove(fs_input_tar)
                    success = True
                else:
                    success = False
            elif output_type == AnalyzerOutputType.both:
                json_output_s3_key = self.analysis_key(
                    git_url, commit_hash, specified_dependency, AnalyzerOutputType.json
                )
                json_success = self._json_output_store.get(
                    git_url,
                    commit_hash,
                    specified_dependency,
                    f"{input_dir}/{specified_dependency.versioned_analyzer.name}.json",
                )

                filesystem_output_s3_key = self.analysis_key(
                    git_url,
                    commit_hash,
                    specified_dependency,
                    AnalyzerOutputType.filesystem,
                )
                fs_input_tar = os.path.join(input_dir, "output.tar.gz")
                if self._filesystem_output_store.get(
                    git_url, commit_hash, specified_dependency, fs_input_tar
                ):
                    self._logger.info(f"Extracting filesystem dependency")
                    with tarfile.open(fs_input_tar) as tar:
                        tar.extractall(input_dir)
                    os.remove(fs_input_tar)
                    filesystem_success = True
                else:
                    filesystem_success = False

                success = json_success and filesystem_success

            else:
                raise RuntimeError(
                    f"unimplemented; output extractor for analyzer output type: {output_type}"
                )

            if success:
                self._logger.info(
                    f"Done setting up output of dependency {specified_dependency}."
                )
            else:
                self._logger.error(
                    f"{dependency_key} could not be found. Failed to setup dependencies. Stopping Analysis."
                )
                raise Exception(
                    f"Could not prepare dependency: {specified_dependency} does not exist."
                )

        return mount_folder

    def run_image_on_folder(
        self,
        image_id: str,
        mount_folder: str,
        interactive: bool,
        pass_analyzer_output: bool,
        memory_limit: Optional[str],
        env_args_dict: Optional[dict] = None,
    ) -> ContainerLog:
        """
            Mount MOUNT_FOLDER as /analysis in docker container and run IMAGE_ID on it

            Args:
                image_id: uniquely identifies docker image
                mount_folder: path to directory we will mount as /analysis. In analyzer spec v3
                this is the directory that contains inputs/ and output. Assumes this directory is
                properly prepared
                interactive: if true, change the run command so that it drops into bash shell. Useful for debugging.
                memory_limit: memory limit for container, e.g. '2G'
            Raises:
                AnalyzerImagePullFail: if IMAGE_ID is not available and fails to pull
                TimeoutError: on timeout
                AnalyzerNonZeroExitError: when container exits with non-zero exit code
            Returns:
                container_log: stdout and err of container as a string
        """
        if not any(i for i in self._docker_client.images.list() if image_id in i.tags):
            self._logger.info(f"Image {image_id} not found. Pulling.")
            try:
                self._docker_client.images.pull(image_id)
            except Exception as e:
                raise AnalyzerImagePullFail(str(e))
        self._docker_client.images.pull(ALPINE_IMAGE)
        container = None

        VOLUME_MOUNT_IN_DOCKER = "/analysis"

        # we can't use volume mounting with remote docker (for example, on
        # CircleCI), have to docker cp
        is_remote_docker = os.environ.get("DOCKER_HOST") is not None

        if is_remote_docker:
            self._logger.info("Remote docker client; using docker cp")
            manager: AbstractDockerFileManager = RemoteDockerFileManager(
                self._docker_client, mount_folder
            )
        else:
            manager = LocalDockerFileManager(self._docker_client, mount_folder)

        if is_remote_docker and interactive:
            self._logger.error("Wait for start not supported with remote docker client")
            interactive = False

        env_vars = (
            " ".join([f"-e {k}={v}" for k, v in env_args_dict.items()])
            if env_args_dict
            else ""
        )
        self._logger.info(
            f"""Running container {image_id} (memory limit: {memory_limit}): \n\t: debug with docker run {env_vars} --volume "{mount_folder}:{VOLUME_MOUNT_IN_DOCKER}" {image_id}"""
        )

        try:
            with Timeout(self._timeout):
                container = self._docker_client.containers.create(
                    image_id,
                    volumes=manager.volumes(),
                    command="tail -f /dev/null" if interactive else None,
                    mem_limit=memory_limit if memory_limit else None,
                    environment=env_args_dict,
                )

                # Set up the VOLUME_MOUNT_IN_DOCKER.
                manager.copy_input()

                container.start()

                if interactive:
                    self._logger.info(
                        f"\n\nYour container is ready: running \n\tdocker exec -i -t {container.id} /bin/sh"
                    )
                    subprocess.call(
                        f"docker exec -i -t {container.id} /bin/sh", shell=True
                    )
                    sys.exit(1)

                # launch two threads to display stdout and stderr while the container is running
                if pass_analyzer_output:
                    stdout_watch = threading.Thread(
                        target=watch_log,
                        args=(
                            container.logs(stdout=True, stderr=False, stream=True),
                            True,
                        ),
                    )
                    stderr_watch = threading.Thread(
                        target=watch_log,
                        args=(
                            container.logs(stdout=False, stderr=True, stream=True),
                            False,
                        ),
                    )
                    stdout_watch.start()
                    stderr_watch.start()

                # Block until completion
                # We run with container detached so we can kill on timeout
                status = container.wait()

                # Retrieve status code and logs before removing container
                status_code = status.get("StatusCode")

                # full, merged stdout + stderr log
                container_log = container.logs(stdout=True, stderr=True).decode("utf-8")
                # self._logger.info(f"Container output: {container_log}")

                manager.copy_output()
                manager.teardown()

                container.remove()
                container = None

            if status_code != 0:
                self._logger.exception(
                    f"Docker Container Finished with non-zero exit code: {status_code}"
                )
                raise AnalyzerNonZeroExitError(status_code, container_log)

        except Exception as e:
            self._logger.exception(f"There was an error running {image_id}: {e}")

            if container:
                self._logger.info(f"killing container {container.id}")
                try:
                    # Kill and Remove Container as well as associated volumes
                    container.remove(v=True, force=True)
                    self._logger.info(f"successfully killed container {container.id}")
                except Exception:
                    self._logger.exception("error killing container")

            if os.path.exists(mount_folder):
                self._logger.info(f"deleting {mount_folder}")
                manager._set_permissions()

                shutil.rmtree(mount_folder, ignore_errors=True)

            manager.teardown()

            raise e

        return ContainerLog(container_log)

    def _analyze(
        self,
        specified_analyzer: SpecifiedAnalyzer,
        git_url: str,
        commit_hash: str,
        interactive: bool,
        pass_analyzer_output: bool,
        memory_limit: Optional[str],
        env_args_dict: Optional[dict] = None,
    ) -> Tuple[str, ContainerLog]:
        """
            Run IMAGE_ID analyzer on GIT_URL @ COMMIT_HASH, retreiving dependencies cache
            as necessary.

            Args:
                specified_analyzer: uniquely identifies docker container to run w/ args
                git_url: url of code
                commit_hash: hash of code to analyze at
                interactive: See run_image_on_folder
                pass_analyzer_output: See run_image_on_folder
                memory_limit: See run_image_on_folder
                env_args_dict: See run_image_on_folder

            Returns:
                (mount_folder, container_log):

                mount_folder: path to root of volume mounted. For analyzer spec v3 this is
                the parent directory containing inputs/ and output/

                container_log: str combined output of stdout and stderr of analyzer container

        """
        mount_folder = self.prepare_mount_volume(
            specified_analyzer, git_url, commit_hash
        )
        container_log = self.run_image_on_folder(
            image_id=specified_analyzer.versioned_analyzer.image_id,
            mount_folder=mount_folder,
            interactive=interactive,
            pass_analyzer_output=pass_analyzer_output,
            memory_limit=memory_limit,
            env_args_dict=env_args_dict,
        )
        return (mount_folder, container_log)


VOLUME_MOUNT_IN_DOCKER = "/analysis"


class AbstractDockerFileManager(abc.ABC):
    """Base class for helpers for analyzer input/output."""

    @abc.abstractmethod
    def copy_input(self):
        """Copies the input from the host to the container."""

    @abc.abstractmethod
    def copy_output(self):
        """Copies the input from the host to the container."""

    def _set_permissions(self):
        """Makes everything in the volume/bind mount world-readable."""
        self._docker_client.containers.run(
            ALPINE_IMAGE,
            f'chmod -R 0777 "{VOLUME_MOUNT_IN_DOCKER}"',
            volumes=self.volumes(),
        )

    @abc.abstractmethod
    def volumes(self) -> Dict[str, dict]:
        """The volumes to be mounted."""

    @abc.abstractmethod
    def teardown(self):
        """Must be called when we're done with docker."""


class LocalDockerFileManager(AbstractDockerFileManager):
    """Bind-mounts a local file. Fast, but does not work with remote docker."""

    def __init__(self, docker_client, mount_folder):
        """mount_folder is the host folder to be mounted in the container."""
        self._docker_client = docker_client
        self._mount_folder = mount_folder

    # Since we use a bind mount, we don't need to do anything special to copy files.
    def copy_input(self):
        self._set_permissions()

    def copy_output(self):
        self._set_permissions()

    def volumes(self) -> Dict[str, dict]:
        return {self._mount_folder: {"bind": VOLUME_MOUNT_IN_DOCKER, "mode": "rw"}}

    def teardown(self):
        pass


class RemoteDockerFileManager(AbstractDockerFileManager):
    """Explicitly sets up a volume. Slower, but works with remote docker."""

    def __init__(self, docker_client, mount_folder):
        """mount_folder is the host folder to be mounted in the container."""
        self._docker_client = docker_client
        self._mount_folder = mount_folder
        self._volume = self._docker_client.volumes.create()
        # A Docker container that we'll use to copy files in and out.
        self._dummy = self._docker_client.containers.create(
            ALPINE_IMAGE,
            command=f'chmod -R 0777 "{VOLUME_MOUNT_IN_DOCKER}"',
            volumes=self.volumes(),
        )

    def copy_input(self):
        # Weirdly, there doesn't appear to be a nice way to do this
        # from within the Python API.
        subprocess.check_output(
            [
                "docker",
                "cp",
                f"{self._mount_folder}/.",
                f"{self._dummy.id}:{VOLUME_MOUNT_IN_DOCKER}",
            ]
        )
        self._set_permissions()

    def copy_output(self):
        self._set_permissions()
        # Weirdly, there doesn't appear to be a nice way to do this
        # from within the Python API.
        subprocess.check_output(
            [
                "docker",
                "cp",
                f"{self._dummy.id}:{VOLUME_MOUNT_IN_DOCKER}/.",
                f"{self._mount_folder}",
            ]
        )
        self._set_permissions()

    def volumes(self) -> Dict[str, dict]:
        return {self._volume.name: {"bind": VOLUME_MOUNT_IN_DOCKER, "mode": "rw"}}

    def teardown(self):
        self._dummy.remove()
