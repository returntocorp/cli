from r2c.lib.manifest import AnalyzerManifest

MANIFEST_1 = """
{
  "analyzer_name": "r2c/filter-typeflow",
  "version": "0.1.3",
  "spec_version": "1.0.0",
  "dependencies": {
    "r2c/typeflow": "*",
    "r2c/npm-packer": "1.3.*",
    "r2c/js-test-finder": "2.1.1"
  },
  "type": "commit",
  "output": "json",
  "deterministic": true
}
"""

MANIFEST_2 = """
{
  "analyzer_name": "r2c/filter-typeflow",
  "version": "0.1.3",
  "spec_version": "2.0.0",
  "dependencies": {
    "r2c/typeflow": {
        "version": "*",
        "parameters": {
            "test1": 21,
            "test2": "testtesttest"
        }
    },
    "r2c/npm-packer": "1.3.*",
    "r2c/js-test-finder": "2.1.1"
  },
  "type": "commit",
  "output": {
    "type": "json"
  },
  "deterministic": true
}

"""

MANIFEST_3 = """
{
  "analyzer_name": "r2c/filter-typeflow",
  "version": "0.1.3",
  "spec_version": "2.1.0",
  "dependencies": {
    "r2c/typeflow": {
        "version": "*",
        "path": "a/b/c"
    },
    "r2c/npm-packer": "1.3.*",
    "r2c/js-test-finder": "2.1.1"
  },
  "type": "commit",
  "output": {
    "type": "json"
  },
  "deterministic": true
}

"""


def test_dependencies():
    manifest_1 = AnalyzerManifest.from_json_str(MANIFEST_1)

    dependencies = manifest_1.dependencies
    assert dependencies is not None
    assert len(dependencies) == 3
    # TODO dict not guranteed ordered
    assert dependencies[0].name == "r2c/typeflow"
    assert dependencies[0].wildcard_version == "*"
    assert len(dependencies[0].parameters) == 0

    assert dependencies[1].name == "r2c/npm-packer"
    assert dependencies[1].wildcard_version == "1.3.*"
    assert len(dependencies[1].parameters) == 0

    assert dependencies[2].name == "r2c/js-test-finder"
    assert dependencies[2].wildcard_version == "2.1.1"
    assert len(dependencies[2].parameters) == 0

    # manifest_2 = AnalyzerManifest.from_json_str(MANIFEST_2)

    # dependencies = manifest_2.dependencies
    # assert dependencies is not None
    # assert len(dependencies) == 3
    # # TODO dict not guranteed ordered
    # assert dependencies[0].name == "r2c/typeflow"
    # assert dependencies[0].wildcard_version == "*"
    # assert len(dependencies[0].parameters) == 2
    # assert dependencies[0].parameters["test1"] == 21
    # assert dependencies[0].parameters["test2"] == "testtesttest"

    # assert dependencies[1].name == "r2c/npm-packer"
    # assert dependencies[1].wildcard_version == "1.3.*"
    # assert len(dependencies[1].parameters) == 0

    # assert dependencies[2].name == "r2c/js-test-finder"
    # assert dependencies[2].wildcard_version == "2.1.1"
    # assert len(dependencies[2].parameters) == 0


def test_dependencies_with_path_override():
    manifest_3 = AnalyzerManifest.from_json_str(MANIFEST_3)

    dependencies = manifest_3.dependencies
    assert dependencies is not None
    assert dependencies[0].name == "r2c/typeflow"
    assert dependencies[0].wildcard_version == "*"
    assert dependencies[0].path == "a/b/c"
