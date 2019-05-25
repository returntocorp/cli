from unittest.mock import MagicMock, mock_open, patch
import json
import tarfile

from r2c.lib.analyzer import Analyzer, InvalidAnalyzerOutput
from r2c.lib.manifest import AnalyzerOutputType
from r2c.lib.specified_analyzer import SpecifiedAnalyzer
from r2c.lib.versioned_analyzer import AnalyzerName, VersionedAnalyzer

import pytest
from semantic_version import Version


def test_nonjson_validator():
    """
        Checks that non json analyzers are not validated
    """
    json_output_store = MagicMock()
    filesystem_output_store = MagicMock()
    log_store = MagicMock()
    registry_data = MagicMock()

    analyzer = Analyzer(
        registry_data, json_output_store, filesystem_output_store, log_store
    )

    # Filesystem Output validates
    manifest = MagicMock(output_type=AnalyzerOutputType.filesystem)
    analyzer._validate_output(manifest, "UNUSED")


def test_invalidjson_validator():
    """
        Checks that invalid json does not validate
    """
    json_output_store = MagicMock()
    filesystem_output_store = MagicMock()
    log_store = MagicMock()
    registry_data = MagicMock()

    analyzer = Analyzer(
        registry_data, json_output_store, filesystem_output_store, log_store
    )

    manifest = MagicMock(output_type=AnalyzerOutputType.json)

    # Non Json Raises
    open_invalid_json = mock_open(read_data="[}]asdfasdf")
    with patch("builtins.open", open_invalid_json) as m:
        with pytest.raises(InvalidAnalyzerOutput):
            analyzer._validate_output(manifest, "test_mount_folder")

        m.assert_called_once_with("test_mount_folder/output/output.json")


def test_upload_on_failure():
    """
        Checks that upload still uploads file even on invalid output
    """

    def raise_invalid_output(a, b):
        raise InvalidAnalyzerOutput(json.JSONDecodeError)

    registry_data = MagicMock()

    manifest = MagicMock(output_type=AnalyzerOutputType.json)
    registry_data.manifest_for = MagicMock(return_value=manifest)

    json_output_store = MagicMock()
    filesystem_output_store = MagicMock()
    log_store = MagicMock()

    analyzer = Analyzer(
        registry_data, json_output_store, filesystem_output_store, log_store
    )
    analyzer._validate_output = MagicMock(side_effect=raise_invalid_output)
    analyzer.analysis_key = MagicMock(return_value="key")

    with pytest.raises(InvalidAnalyzerOutput):
        analyzer.upload_output(
            SpecifiedAnalyzer(
                VersionedAnalyzer(AnalyzerName("massive-r2c/test"), Version("1.0.0"))
            ),
            "git_url",
            "commit_hash",
            "folder",
        )

    json_output_store.put.assert_called_once()


MOUNT_FOLDER = "mount_folder"
ROOT_KEY = "key"
JSON_KEY = f"{ROOT_KEY}.json"
FILESYSTEM_KEY = f"{ROOT_KEY}.tar.gz"


def test_upload_json():
    registry_data = MagicMock()

    manifest = MagicMock(output_type=AnalyzerOutputType.json)
    registry_data.manifest_for = MagicMock(return_value=manifest)
    json_output_store = MagicMock()
    filesystem_output_store = MagicMock()
    log_store = MagicMock()

    analyzer = Analyzer(
        registry_data, json_output_store, filesystem_output_store, log_store
    )
    analyzer.analysis_key = MagicMock(return_value=JSON_KEY)
    analyzer._validate_output = MagicMock()

    specified_analyzer = SpecifiedAnalyzer(
        VersionedAnalyzer(AnalyzerName("massive-r2c/test"), Version("1.0.0"))
    )
    analyzer.upload_output(specified_analyzer, "git_url", "commit_hash", MOUNT_FOLDER)

    json_output_store.put.assert_called_once_with(
        "git_url",
        "commit_hash",
        specified_analyzer,
        f"{MOUNT_FOLDER}/output/output.json",
    )


def test_upload_filesystem():
    registry_data = MagicMock()

    manifest = MagicMock(output_type=AnalyzerOutputType.filesystem)
    registry_data.manifest_for = MagicMock(return_value=manifest)

    json_output_store = MagicMock()
    filesystem_output_store = MagicMock()
    log_store = MagicMock()

    with patch.object(tarfile.TarFile, "add") and patch.object(tarfile, "open"):
        analyzer = Analyzer(
            registry_data, json_output_store, filesystem_output_store, log_store
        )
        analyzer.analysis_key = MagicMock(return_value=FILESYSTEM_KEY)
        analyzer._validate_output = MagicMock()
        specified_analyzer = SpecifiedAnalyzer(
            VersionedAnalyzer(AnalyzerName("massive-r2c/test"), Version("1.0.0"))
        )
        analyzer.upload_output(
            specified_analyzer, "git_url", "commit_hash", MOUNT_FOLDER
        )

        tarfile.open.assert_called_once()

    filesystem_output_store.put.assert_called_once_with(
        "git_url", "commit_hash", specified_analyzer, f"{MOUNT_FOLDER}/output/fs.tar.gz"
    )


def test_upload_both():
    def analysis_key_mock(git_url, commit_hash, specified_analyzer, output_type):
        if output_type is AnalyzerOutputType.json:
            return JSON_KEY
        elif output_type is AnalyzerOutputType.filesystem:
            return FILESYSTEM_KEY
        else:
            raise Exception

    registry_data = MagicMock()
    json_output_store = MagicMock()
    filesystem_output_store = MagicMock()
    log_store = MagicMock()

    manifest = MagicMock(output_type=AnalyzerOutputType.both)
    registry_data.manifest_for = MagicMock(return_value=manifest)

    with patch.object(tarfile.TarFile, "add") and patch.object(tarfile, "open"):
        analyzer = Analyzer(
            registry_data, json_output_store, filesystem_output_store, log_store
        )
        analyzer.analysis_key = MagicMock(side_effect=analysis_key_mock)
        analyzer._validate_output = MagicMock()
        specified_analyzer = SpecifiedAnalyzer(
            VersionedAnalyzer(AnalyzerName("massive-r2c/test"), Version("1.0.0"))
        )
        analyzer.upload_output(
            specified_analyzer, "git_url", "commit_hash", MOUNT_FOLDER
        )

        tarfile.open.assert_called_once()

    json_output_store.put.assert_called_once_with(
        "git_url",
        "commit_hash",
        specified_analyzer,
        f"{MOUNT_FOLDER}/output/output.json",
    )
    filesystem_output_store.put.assert_called_once_with(
        "git_url", "commit_hash", specified_analyzer, f"{MOUNT_FOLDER}/output/fs.tar.gz"
    )
