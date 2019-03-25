#!/usr/bin/env python3
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import traceback
from datetime import datetime
from typing import NewType, Optional, Tuple, Union

import docker
import git
import jsonschema

from r2c.lib import schemas
from r2c.lib.constants import (
    DEFAULT_ANALYSIS_WORKING_TEMPDIR_SUFFIX,
    S3_ANALYSIS_BUCKET_NAME,
    S3_ANALYSIS_LOG_BUCKET_NAME,
    S3_CODE_BUCKET_NAME,
    SPECIAL_ANALYZERS,
)
from r2c.lib.infrastructure import Infrastructure
from r2c.lib.manifest import AnalyzerManifest, AnalyzerOutputType, AnalyzerType
from r2c.lib.registry import RegistryData
from r2c.lib.specified_analyzer import SpecifiedAnalyzer
from r2c.lib.util import (
    Timeout,
    cloned_key,
    get_tmp_dir,
    handle_readonly_fix,
    recursive_chmod_777,
    url_to_repo_id,
)
from r2c.lib.versioned_analyzer import VersionedAnalyzer

MEMORY_LIMIT = (
    "1536m"
)  # clean t2.small with unbuntu 18.04 has Mem:           1991          92        1514           0         385        1752

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
        return f"Docker container finished with non-zero exit code: {self._status_code}"


class NotFoundInCodeBucket(Exception):
    """
        Thrown when cannot find file in code bucket
    """

    pass


class MalformedCodeBucketFile(Exception):
    """
        Thrown when file downloaded from code bucket fails to extract
        or is in an invalid state
    """

    pass


class AnalyzerImagePullFail(Exception):
    """
        Thrown when analyzer image fails to pull
    """

    pass


class UnsupportedAnalyzerType(Exception):
    """
        Thrown when unsupported analyzer type is encountered
    """

    pass


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


def get_default_analyzer_working_dir():
    return os.path.join(get_tmp_dir(), DEFAULT_ANALYSIS_WORKING_TEMPDIR_SUFFIX)


class Analyzer:
    def __init__(
        self,
        infra: Infrastructure,
        registry_data: RegistryData,
        localrun: bool = False,
        timeout: int = 1200,
        workdir: str = get_default_analyzer_working_dir(),
    ) -> None:
        self._infra = infra
        self._registry_data = registry_data
        self._logger = logging.getLogger("analyzer")
        self._docker_client = docker.from_env()
        self._timeout = timeout

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

    def resolve_commit_string(self, git_url: str, commit_string: str) -> str:
        """
            Return commit hash of checking out COMMIT_STRING in GIT_URL
            where commit_string can be tag, HEAD~1 etc.
        """
        if self._localrun:
            return commit_string

        # TODO do this without downloading repo
        repo_id = url_to_repo_id(git_url)
        repo_dir_name = os.path.join(self._workdir, "data", repo_id)
        self.get_code(git_url, repo_dir_name)

        repo = None
        try:
            repo = git.Repo(repo_dir_name)
        except Exception as e:
            raise MalformedCodeBucketFile(str(e))

        self._logger.info(f"Checking out {commit_string}")
        repo.git.checkout(commit_string)
        commit_hash = repo.head.object.hexsha
        self._logger.info(f"Has commit hash: {commit_hash}")
        self._logger.info(f"deleting {repo_dir_name}")
        shutil.rmtree(repo_dir_name)
        self._logger.info(f"Commit String {commit_string} has hash {commit_hash}")
        return commit_hash

    def full_analyze_request(
        self,
        git_url: str,
        commit_string: Optional[str],
        specified_analyzer: SpecifiedAnalyzer,
        force: bool,
        pass_analyzer_output: bool,
        wait_for_start: bool = False,
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
                wait_for_start: if true, the last analyzer in the execution graph will wait for user input rather than running automatically.
                pass_analyzer_output: if true, the analyzer's stdout and stderr will be passed to the current process stdout and stderr, respectively

            Returns:
                A dict with information about the final output last analyzer in the dependency graph to run.
        """

        # Analyze head commit by default
        if not commit_string:
            commit_string = "HEAD"

        commit_hash = self.resolve_commit_string(git_url, commit_string)

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
            is_last_dependency = dependency_index == len(execution_order) - 1
            dependency = specified_dependency.versioned_analyzer
            dependency_id = dependency.image_id
            output_s3_key = self.analysis_key(
                git_url, commit_hash, specified_dependency
            )

            if self._get_manifest(dependency_id).output_type == AnalyzerOutputType.both:
                json_output_s3_key = f"{output_s3_key}{self._get_analyzer_output_extension(AnalyzerOutputType.json)}"
                filesystem_output_s3_key = f"{output_s3_key}{self._get_analyzer_output_extension(AnalyzerOutputType.filesystem)}"
                dependency_exists = self._infra.contains_file(
                    S3_ANALYSIS_BUCKET_NAME, json_output_s3_key
                ) and self._infra.contains_file(
                    S3_ANALYSIS_BUCKET_NAME, filesystem_output_s3_key
                )
            else:
                dependency_exists = self._infra.contains_file(
                    S3_ANALYSIS_BUCKET_NAME, output_s3_key
                )

            if (
                # TODO check freshness here
                dependency_exists
                and not force
            ):
                self._logger.info(
                    f"Analysis for {git_url} {commit_string} {dependency_id} already exists. Keeping old analysis report"
                )
            else:
                self._logger.info(
                    f"Running: {dependency.name}, {dependency.version}..."
                )
                mount_folder, container_log = self._analyze(
                    specified_dependency,
                    git_url,
                    commit_hash,
                    wait_for_start=wait_for_start and is_last_dependency,
                    pass_analyzer_output=pass_analyzer_output,
                    memory_limit=memory_limit,
                    env_args_dict=env_args_dict,
                )

                self._logger.info("Analyzer finished running.")
                self._logger.info("Uploading analyzer log")
                log_key = self.container_log_key(
                    git_url, commit_hash, dependency.image_id
                )
                self._infra.put_object(
                    S3_ANALYSIS_LOG_BUCKET_NAME, container_log, log_key
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
        image_id = specified_analyzer.versioned_analyzer.image_id
        output_type = self._get_manifest(image_id).output_type
        if output_type == AnalyzerOutputType.json:
            output_s3_key = self.analysis_key(git_url, commit_hash, specified_analyzer)
            output_file_path = self.get_analyzer_output_path(mount_folder, output_type)
            self._logger.info(
                f"Uploading {output_file_path} to {S3_ANALYSIS_BUCKET_NAME} with key {output_s3_key}"
            )
            self._infra.put_file(
                S3_ANALYSIS_BUCKET_NAME, output_file_path, output_s3_key
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
            self._infra.put_file(
                S3_ANALYSIS_BUCKET_NAME, output_file_path, output_s3_key
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
            self._infra.put_file(
                S3_ANALYSIS_BUCKET_NAME, json_output_file_path, json_output_s3_key
            )

            self._logger.info(
                f"Uploading {filesystem_output_file_path} to {S3_ANALYSIS_BUCKET_NAME} with key {filesystem_output_s3_key}"
            )
            self._infra.put_file(
                S3_ANALYSIS_BUCKET_NAME,
                filesystem_output_file_path,
                filesystem_output_s3_key,
            )

            output_file_path = json_output_file_path
        else:
            raise RuntimeError(
                f"non-implemented analyzer output handler for output type: {output_type}"
            )

        # Invalid outputs should still be uploaded, but we want to
        # count them as failing.
        self._validate_output(self._get_manifest(image_id), mount_folder)
        return output_file_path

    def get_code(self, git_url, dst):
        """
            Gets code for REPO_ID from S3, unzips, deletes zip file

            Raises:
                NotFoundInCodeBucket: if code for GIT_URL is not found in S3_CODE_BUCKET_NAME
                MalformedCodeBucketFile: if code found does not extract properly
        """
        repo_id = url_to_repo_id(git_url)
        repo_tar_name = os.path.join(self._workdir, f"{repo_id}.tar.gz")
        repo_s3_key = cloned_key(git_url)

        # Repo should not already exist. Probably invalid state. Best to just clean
        if pathlib.Path(repo_tar_name).exists():
            self._logger.info(f"{repo_tar_name} already exists. Deleting.")
            os.remove(repo_tar_name)
        if pathlib.Path(dst).exists():
            self._logger.info(f"{dst} already exists. Deleting")
            shutil.rmtree(dst)

        self._logger.info(
            f"Downloading {repo_s3_key} from {S3_CODE_BUCKET_NAME} to {repo_tar_name}"
        )
        if not self._infra.get_file(S3_CODE_BUCKET_NAME, repo_s3_key, repo_tar_name):
            self._logger.error(f"key {repo_s3_key} not found in {S3_CODE_BUCKET_NAME}")
            raise NotFoundInCodeBucket(
                f"key {repo_s3_key} not found in {S3_CODE_BUCKET_NAME}"
            )

        self._logger.info(f"Extracting to {dst}")

        try:
            with tarfile.open(repo_tar_name) as tar:
                tar.extractall(os.path.join(self._workdir, "data"))
                # This is only because the thing extracted from the tar is in a
                # directory named repo_id. Cloner should be changed to just have it
                # not have an extra directory level
                os.rename(os.path.join(self._workdir, "data", repo_id), dst)
        except Exception as e:
            raise MalformedCodeBucketFile(str(e))

        os.remove(repo_tar_name)

    @staticmethod
    def analyzer_name(image_id):
        """

        """
        return VersionedAnalyzer.from_image_id(image_id).name

    @staticmethod
    def analyzer_version(image_id):
        """
        """
        return VersionedAnalyzer.from_image_id(image_id).version

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
        mount_folder = os.path.join(
            self._workdir, f"{safe_image_id}__{commit_hash}__{now_ts}"
        )

        self._logger.info("Setting up volumes for analyzer container.")
        self._logger.info(f"Will mount: {mount_folder}")
        if pathlib.Path(mount_folder).exists():
            self._logger.debug(f"cleaning up old folder {mount_folder}")
            shutil.rmtree(mount_folder)

        input_dir = os.path.join(mount_folder, "inputs")
        output_dir = os.path.join(mount_folder, "output")
        pathlib.Path(input_dir).mkdir(parents=True, exist_ok=True)
        pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)
        # TODO why should this only be done if we expect fs?
        pathlib.Path(os.path.join(mount_folder, "output", "fs")).mkdir(
            parents=True, exist_ok=True
        )

        # Setup Parameters
        with open(os.path.join(input_dir, "parameters.json"), "w") as parameters_file:
            json.dump(specified_analyzer.parameters, parameters_file)

        dependencies = self._registry_data.get_direct_dependencies(
            specified_analyzer.versioned_analyzer
        )

        if self.analyzer_name(image_id) in SPECIAL_ANALYZERS:
            with open(input_dir + "/cloner-input.json", "w") as argument_file:
                arguments = {"git_url": git_url, "commit_hash": commit_hash}
                json.dump(arguments, argument_file)
                success = True

        if self.analyzer_name(image_id) == "r2c/full-cloner":
            with open(input_dir + "/cloner-input.json", "w") as argument_file:
                arguments = {"git_url": git_url}
                json.dump(arguments, argument_file)
                success = True

        self._logger.info(f"Loading dependencies' outputs: {dependencies}")
        for specified_dependency in dependencies:
            self._logger.info(f"Loading output of {specified_dependency}")
            self._logger.info(
                f"Has image_id: {specified_dependency.versioned_analyzer.image_id}"
            )

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
                success = self._infra.get_file(
                    S3_ANALYSIS_BUCKET_NAME,
                    dependency_key,
                    f"{input_dir}/{specified_dependency.versioned_analyzer.name}.json",
                )
            elif output_type == AnalyzerOutputType.filesystem:
                fs_input_tar = os.path.join(input_dir, "output.tar.gz")
                if self._infra.get_file(
                    S3_ANALYSIS_BUCKET_NAME, dependency_key, fs_input_tar
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
                json_success = self._infra.get_file(
                    S3_ANALYSIS_BUCKET_NAME,
                    json_output_s3_key,
                    f"{input_dir}/{specified_dependency.versioned_analyzer.name}.json",
                )

                filesystem_output_s3_key = self.analysis_key(
                    git_url,
                    commit_hash,
                    specified_dependency,
                    AnalyzerOutputType.filesystem,
                )
                fs_input_tar = os.path.join(input_dir, "output.tar.gz")
                if self._infra.get_file(
                    S3_ANALYSIS_BUCKET_NAME, filesystem_output_s3_key, fs_input_tar
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
        wait_for_start: bool,
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
                wait_for_start: if true, change the run command so that it will wait infinitely instead of running the original Dockerfile CMD. Useful for debugging.
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
        container = None

        # Prepare mount_folder to mount as volume to docker
        self._logger.info("Setup volume permissions")

        if self._localrun:
            recursive_chmod_777(mount_folder)
        else:
            # Still need sudo? https://github.com/returntocorp/echelon-backend/issues/2690
            subprocess.call(["sudo", "chmod", "-R", "777", mount_folder])

        volumes = {}
        VOLUME_MOUNT_IN_DOCKER = "/analysis"
        volumes[mount_folder] = {"bind": VOLUME_MOUNT_IN_DOCKER, "mode": "rw"}

        # we can't use volume mounting with remote docker (for example, on
        # CircleCI), have to docker cp
        is_remote_docker = os.environ.get("DOCKER_HOST") is not None

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
                if is_remote_docker:
                    self._logger.warning(
                        "Remote docker client, so volume mounts will not work--falling back to docker shell and cp'ing files"
                    )
                    if wait_for_start:
                        self._logger.error(
                            "Wait for start not supported with remote docker client"
                        )
                    container = self._docker_client.containers.create(
                        image_id,
                        volumes=None,
                        mem_limit=memory_limit if memory_limit else None,
                        environment=env_args_dict,
                    )
                    subprocess.check_output(
                        f'''docker cp "{mount_folder}/." {container.id}:"{VOLUME_MOUNT_IN_DOCKER}"''',
                        shell=True,
                    )
                    subprocess.check_output(f"docker start {container.id}", shell=True)
                else:
                    container = self._docker_client.containers.run(
                        image_id,
                        volumes=volumes,
                        detach=True,
                        command="tail -f /dev/null" if wait_for_start else None,
                        mem_limit=memory_limit if memory_limit else None,
                        environment=env_args_dict,
                    )

                if wait_for_start:
                    self._logger.info(
                        f"\n\nYour action required, container is ready: run\n\tdocker exec -i -t {container.id} /bin/bash"
                    )

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

                if is_remote_docker:
                    self._logger.warning(
                        "Remote docker client, so volume mounts will not work--using cp to copying files out of container"
                    )
                    # c.f. https://docs.docker.com/engine/reference/commandline/cp/#extended-description for significance of /.
                    subprocess.check_output(
                        f'docker cp {container.id}:"{VOLUME_MOUNT_IN_DOCKER}/." "{mount_folder}"',
                        shell=True,
                    )

                container.remove()
                container = None

                # Change permissions of any new file added by container
                if self._localrun:
                    recursive_chmod_777(mount_folder)
                else:
                    # Still need sudo? https://github.com/returntocorp/echelon-backend/issues/2690
                    subprocess.call(["sudo", "chmod", "-R", "777", mount_folder])

            if status_code != 0:
                self._logger.exception(
                    f"Docker Container Finished with non-zero exit code: {status_code}"
                )
                raise AnalyzerNonZeroExitError(status_code, container_log)

        except Exception as e:
            self._logger.exception(f"There was an error running {image_id}: {e}")

            if os.path.exists(mount_folder):
                self._logger.info(f"deleting {mount_folder}")
                # Change permissions of any new file added by container
                if self._localrun:
                    recursive_chmod_777(mount_folder)
                else:
                    # Still need sudo? https://github.com/returntocorp/echelon-backend/issues/2690
                    subprocess.call(["sudo", "chmod", "-R", "777", mount_folder])

                shutil.rmtree(mount_folder, ignore_errors=True)

            if container:
                self._logger.info(f"killing container {container.id}")
                try:
                    # Kill and Remove Container as well as associated volumes
                    container.remove(v=True, force=True)
                    self._logger.info(f"successfully killed container {container.id}")
                except Exception:
                    self._logger.exception("error killing container")

            raise e

        return ContainerLog(container_log)

    def _analyze(
        self,
        specified_analyzer: SpecifiedAnalyzer,
        git_url: str,
        commit_hash: str,
        wait_for_start: bool,
        pass_analyzer_output: bool,
        memory_limit: Optional[str],
        env_args_dict: Optional[dict] = None,
    ) -> Tuple[str, ContainerLog]:
        """
            Run IMAGE_ID analyzer on GIT_URL @ COMMIT_HASH, retreiving dependencies from self._infra
            as necessary.

            Args:
                specified_analyzer: uniquely identifies docker container to run w/ args
                git_url: url of code
                commit_hash: hash of code to analyze at
                wait_for_start: See run_image_on_folder
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
            wait_for_start=wait_for_start,
            pass_analyzer_output=pass_analyzer_output,
            memory_limit=memory_limit,
            env_args_dict=env_args_dict,
        )
        return (mount_folder, container_log)

    def _get_manifest(self, image_id: str) -> AnalyzerManifest:
        """The manifest for this analyzer."""
        analyzer = VersionedAnalyzer.from_image_id(image_id)
        return self._registry_data.manifest_for(analyzer)
