import json
import os
import shutil
from hashlib import sha256
from subprocess import CalledProcessError, check_call, check_output
from typing import Any, Dict, List

import pytest
from semantic_version import Version

from r2c.lib.constants import PREFIX
from r2c.lib.manifest import AnalyzerDependency, AnalyzerManifest
from r2c.lib.registry import AnalyzerDataJson, RegistryData
from r2c.lib.specified_analyzer import SpecifiedAnalyzer
from r2c.lib.util import get_tmp_dir, get_unique_semver
from r2c.lib.versioned_analyzer import AnalyzerName, VersionedAnalyzer

TMP_DIR = get_tmp_dir()

# TODO figure out best way to do this within semver
B_VERSION = "0.0.2"
UNIQUE_VERSION = str(get_unique_semver(B_VERSION))

ANALYZER_B = {
    "analyzer_name": "test-org-name/b",
    "version": B_VERSION,
    "spec_version": "2.1.0",
    "dependencies": {"test-org-name/d": "*"},
    "type": "commit",
    "output": {"type": "json"},
    "deterministic": True,
}


LINKED_ANALYZER_A = {
    "analyzer_name": "test-org-name/a",
    "version": "0.0.1",
    "spec_version": "2.1.0",
    "dependencies": {
        "test-org-name/c": "0.0.1",
        "test-org-name/b": {"version": UNIQUE_VERSION, "path": f"{TMP_DIR}"},
    },
    "type": "commit",
    "output": {"type": "json"},
    "deterministic": True,
}


VALID_DATA: Dict[str, AnalyzerDataJson] = {
    "test-org-name/a": {
        "versions": {
            "0.0.1": {
                "manifest": {
                    "analyzer_name": "test-org-name/a",
                    "version": "0.0.1",
                    "spec_version": "2.1.0",
                    "dependencies": {
                        "test-org-name/c": "0.0.1",
                        "test-org-name/b": "0.0.2",
                    },
                    "type": "commit",
                    "output": {"type": "json"},
                    "deterministic": True,
                },
                "pending": False,
            }
        },
        "public": True,
    },
    "test-org-name/c": {
        "versions": {
            "0.0.1": {
                "manifest": {
                    "analyzer_name": "test-org-name/c",
                    "version": "0.0.1",
                    "spec_version": "2.1.0",
                    "dependencies": {"test-org-name/b": "0.0.2"},
                    "type": "commit",
                    "output": {"type": "json"},
                    "deterministic": True,
                },
                "pending": False,
            }
        },
        "public": True,
    },
    "test-org-name/b": {
        "versions": {"0.0.2": {"manifest": ANALYZER_B, "pending": False}},
        "public": True,
    },
    "test-org-name/d": {
        "versions": {
            "0.0.1": {
                "manifest": {
                    "analyzer_name": "test-org-name/d",
                    "version": "0.0.1",
                    "spec_version": "2.1.0",
                    "dependencies": {},
                    "type": "commit",
                    "output": {"type": "json"},
                    "deterministic": True,
                },
                "pending": False,
            }
        },
        "public": True,
    },
}


def test_add_manifest_force():
    registry_data = RegistryData.from_json(VALID_DATA)
    LOCAL = ANALYZER_B.copy()
    LOCAL["version"] = UNIQUE_VERSION

    registry_data = registry_data.add_pending_manifest(
        AnalyzerManifest.from_json(LOCAL), force=True
    )
    registry_data = registry_data.add_pending_manifest(
        AnalyzerManifest.from_json(LINKED_ANALYZER_A), force=True
    )

    assert registry_data._resolve("test-org-name/a", "0.0.1")
    sorted_deps = registry_data.sorted_deps(
        SpecifiedAnalyzer(
            VersionedAnalyzer(AnalyzerName("test-org-name/a"), Version("0.0.1"))
        )
    )
    assert (
        SpecifiedAnalyzer(
            VersionedAnalyzer(AnalyzerName("test-org-name/b"), Version(UNIQUE_VERSION))
        )
        in sorted_deps
    )
    assert (
        SpecifiedAnalyzer(
            VersionedAnalyzer(AnalyzerName("test-org-name/c"), Version("0.0.1"))
        )
        in sorted_deps
    )
    # test that linking is local: Overriding A->B edge does not overried C->B edge
    sorted_deps = registry_data.sorted_deps(
        SpecifiedAnalyzer(
            VersionedAnalyzer(AnalyzerName("test-org-name/c"), Version("0.0.1"))
        )
    )
    assert (
        SpecifiedAnalyzer(
            VersionedAnalyzer(AnalyzerName("test-org-name/b"), Version("0.0.2"))
        )
        in sorted_deps
    )


def test_r2c_run():
    TEST_ANALYZER_A = "aa"
    TEST_ANALYZER_B = "bb"
    if os.path.exists(TEST_ANALYZER_A):
        shutil.rmtree(TEST_ANALYZER_A)
    if os.path.exists(TEST_ANALYZER_B):
        shutil.rmtree(TEST_ANALYZER_B)
    check_call(["r2c", "--version"])
    # create new analyzer
    check_call(
        [
            "r2c",
            "init",
            "--analyzer-name",
            TEST_ANALYZER_A,
            "--author-name",
            "tester",
            "--author-email",
            "tester",
            "--run-on",
            "commit",
            "--output-type",
            "json",
            "--org",
            PREFIX,
        ]
    )
    # create new analyzer
    check_call(
        [
            "r2c",
            "init",
            "--analyzer-name",
            TEST_ANALYZER_B,
            "--author-name",
            "tester",
            "--author-email",
            "tester",
            "--run-on",
            "commit",
            "--output-type",
            "json",
            "--org",
            PREFIX,
        ]
    )

    # add B as linked dependency of A
    analyzer_json_dict = {
        "analyzer_name": f"{PREFIX}/{TEST_ANALYZER_A}",
        "author_name": "tester",
        "author_email": "tester",
        "version": "0.0.1",
        "spec_version": "2.1.0",
        "dependencies": {
            f"{PREFIX}/{TEST_ANALYZER_B}": {
                "version": "*",
                "path": os.path.relpath(TEST_ANALYZER_B, TEST_ANALYZER_A),
            }
        },
        "type": "commit",
        "output": {"type": "json"},
        "deterministic": True,
    }
    with open(os.path.join(TEST_ANALYZER_A, "analyzer.json"), "w") as fp:
        json.dump(analyzer_json_dict, fp, indent=4)

    check_call(
        [
            "r2c",
            "run",
            "--no-login",
            "--debug",
            ".",
            "--analyzer-directory",
            TEST_ANALYZER_A,
        ]
    )
    # verify output for analyzer B exists
    # run again and verify local infra timestamp was reset
    local_path_to_output = (
        check_output(
            [
                "find",
                "/tmp/local-infra/analysis_output/data",
                "-name",
                f"*{TEST_ANALYZER_B}*output.*",
            ]
        )
        .decode("utf-8")
        .strip()
    )
    assert local_path_to_output
    # cleanup
    shutil.rmtree(TEST_ANALYZER_A)
    shutil.rmtree(TEST_ANALYZER_B)
