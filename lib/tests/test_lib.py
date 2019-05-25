import pytest

from r2c.lib.manifest import AnalyzerManifest, IncompatibleManifestException
from r2c.lib.manifest_migrations import migrate


def test_migrate_to_1_1_0():
    original_spec = {
        "analyzer_name": "com.returntocorp.identify-language",
        "version": "0.5.4",
        "spec_version": "1.0.0",
        "dependencies": {"com.returntocorp.cloner": "*"},
        "type": "commit",
        "output": "json",
        "deterministic": True,
    }
    expected = {
        "analyzer_name": "com.returntocorp.identify-language",
        "version": "0.5.4",
        "spec_version": "2.1.0",
        "dependencies": {"com.returntocorp.cloner": "*"},
        "type": "commit",
        "output": {"type": "json"},
        "deterministic": True,
        "_original_spec_version": "1.0.0",
    }
    assert migrate(original_spec) == expected


def test_migrate_input_is_latest():
    spec = {
        "analyzer_name": "com.returntocorp.identify-language",
        "version": "0.5.4",
        "spec_version": "2.1.0",
        "dependencies": {"com.returntocorp.cloner": "*"},
        "type": "commit",
        "output": {"type": "json"},
        "deterministic": True,
    }
    assert migrate(spec) == spec


def test_migrate_multiple_times_preserves_original_version():
    spec = {
        "analyzer_name": "com.returntocorp.identify-language",
        "version": "0.5.4",
        "spec_version": "1.0.0",
        "dependencies": {"com.returntocorp.cloner": "*"},
        "type": "commit",
        "output": "json",
        "deterministic": True,
    }
    assert migrate(spec)["_original_spec_version"] == "1.0.0"
    assert migrate(migrate(spec))["_original_spec_version"] == "1.0.0"


def test_spec_using_version_later_than_latest():
    spec = {
        "analyzer_name": "com.returntocorp.identify-language",
        "version": "0.5.4",
        "spec_version": "999.999.999",
        "dependencies": {"public/source-code": "*"},
        "type": "commit",
        "output": {"type": "json"},
        "deterministic": True,
    }
    with pytest.raises(IncompatibleManifestException):
        manifest = AnalyzerManifest.from_json(spec)
