from unittest.mock import MagicMock, mock_open, patch
import json
import tarfile

from r2c.lib.analyzer import Analyzer, InvalidAnalyzerOutput
from r2c.lib.manifest import AnalyzerOutputType
from r2c.lib.specified_analyzer import SpecifiedAnalyzer
from r2c.lib.versioned_analyzer import AnalyzerName, VersionedAnalyzer
from r2c.lib.constants import S3_ANALYSIS_BUCKET_NAME

import pytest
from semantic_version import Version


def test_nonjson_validator():
    """
        Checks that non json analyzers are not validated
    """
    infra = MagicMock()
    registry_data = MagicMock()

    analyzer = Analyzer(infra, registry_data)

    # Filesystem Output validates
    manifest = MagicMock(output_type=AnalyzerOutputType.filesystem)
    analyzer._validate_output(manifest, "UNUSED")


def test_invalidjson_validator():
    """
        Checks that invalid json does not validate
    """
    infra = MagicMock()
    registry_data = MagicMock()

    analyzer = Analyzer(infra, registry_data)

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

    infra = MagicMock()
    registry_data = MagicMock()

    manifest = MagicMock(output_type=AnalyzerOutputType.json)
    with patch.object(Analyzer, "_get_manifest", return_value=manifest):
        analyzer = Analyzer(infra, registry_data)
        analyzer._validate_output = MagicMock(side_effect=raise_invalid_output)
        analyzer.analysis_key = MagicMock(return_value="key")

        with pytest.raises(InvalidAnalyzerOutput):
            analyzer.upload_output(
                SpecifiedAnalyzer(
                    VersionedAnalyzer(
                        AnalyzerName("massive-r2c/test"), Version("1.0.0")
                    )
                ),
                "git_url",
                "commit_hash",
                "folder",
            )

    infra.put_file.assert_called_once()


MOUNT_FOLDER = "mount_folder"
ROOT_KEY = "key"
JSON_KEY = f"{ROOT_KEY}.json"
FILESYSTEM_KEY = f"{ROOT_KEY}.tar.gz"


def test_upload_json():
    infra = MagicMock()
    registry_data = MagicMock()

    manifest = MagicMock(output_type=AnalyzerOutputType.json)
    with patch.object(Analyzer, "_get_manifest", return_value=manifest):
        analyzer = Analyzer(infra, registry_data)
        analyzer.analysis_key = MagicMock(return_value=JSON_KEY)
        analyzer._validate_output = MagicMock()
        analyzer.upload_output(
            SpecifiedAnalyzer(
                VersionedAnalyzer(AnalyzerName("massive-r2c/test"), Version("1.0.0"))
            ),
            "git_url",
            "commit_hash",
            MOUNT_FOLDER,
        )

    infra.put_file.assert_called_once_with(
        S3_ANALYSIS_BUCKET_NAME, f"{MOUNT_FOLDER}/output/output.json", JSON_KEY
    )


def test_upload_filesystem():
    infra = MagicMock()
    registry_data = MagicMock()

    manifest = MagicMock(output_type=AnalyzerOutputType.filesystem)
    with patch.object(Analyzer, "_get_manifest", return_value=manifest):
        with patch.object(tarfile.TarFile, "add") and patch.object(tarfile, "open"):
            analyzer = Analyzer(infra, registry_data)
            analyzer.analysis_key = MagicMock(return_value=FILESYSTEM_KEY)
            analyzer._validate_output = MagicMock()
            analyzer.upload_output(
                SpecifiedAnalyzer(
                    VersionedAnalyzer(
                        AnalyzerName("massive-r2c/test"), Version("1.0.0")
                    )
                ),
                "git_url",
                "commit_hash",
                MOUNT_FOLDER,
            )

            tarfile.open.assert_called_once()

    infra.put_file.assert_called_once_with(
        S3_ANALYSIS_BUCKET_NAME, f"{MOUNT_FOLDER}/output/fs.tar.gz", FILESYSTEM_KEY
    )


def test_upload_both():
    def analysis_key_mock(git_url, commit_hash, specified_analyzer, output_type):
        if output_type is AnalyzerOutputType.json:
            return JSON_KEY
        elif output_type is AnalyzerOutputType.filesystem:
            return FILESYSTEM_KEY
        else:
            raise Exception

    infra = MagicMock()
    registry_data = MagicMock()

    manifest = MagicMock(output_type=AnalyzerOutputType.both)
    with patch.object(Analyzer, "_get_manifest", return_value=manifest):
        with patch.object(tarfile.TarFile, "add") and patch.object(tarfile, "open"):
            analyzer = Analyzer(infra, registry_data)
            analyzer.analysis_key = MagicMock(side_effect=analysis_key_mock)
            analyzer._validate_output = MagicMock()
            analyzer.upload_output(
                SpecifiedAnalyzer(
                    VersionedAnalyzer(
                        AnalyzerName("massive-r2c/test"), Version("1.0.0")
                    )
                ),
                "git_url",
                "commit_hash",
                MOUNT_FOLDER,
            )

            tarfile.open.assert_called_once()

    infra.put_file.assert_any_call(
        S3_ANALYSIS_BUCKET_NAME, f"{MOUNT_FOLDER}/output/output.json", JSON_KEY
    )
    infra.put_file.assert_any_call(
        S3_ANALYSIS_BUCKET_NAME, f"{MOUNT_FOLDER}/output/fs.tar.gz", FILESYSTEM_KEY
    )
