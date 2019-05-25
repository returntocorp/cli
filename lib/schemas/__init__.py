"""A package where we store all of our JSON schemas.

In general you don't need to look at the files within this directory, only the
methods that this exposes.
"""

import copy
import json
import logging
import urllib.parse
from typing import Optional

import jsonschema
from importlib_resources import open_text
from semantic_version import Version

# from importlib import resources -- TODO, enable this on Python 3.7 and higher


logger = logging.getLogger(__name__)

SPEC_VERSION = Version("2.1.0")

_MANIFEST_SCHEMAS = {
    Version("1.0.0"): json.load(open_text(__name__, "manifest.1.0.0.json")),
    Version("1.1.0"): json.load(open_text(__name__, "manifest.1.1.0.json")),
    Version("1.2.0"): json.load(open_text(__name__, "manifest.1.2.0.json")),
    Version("2.0.0"): json.load(open_text(__name__, "manifest.2.0.0.json")),
    Version("2.1.0"): json.load(open_text(__name__, "manifest.2.1.0.json")),
}

# 1.0.0 and 1.1.0 both have the same output schema.

_ANALYZER_OUTPUT_SCHEMAS = {
    # 0.1.0 is a 'fake' version; some analyzers with spec version 1.0.0 output
    # something with a 0.1.0 spec_version that has some extra fields.
    Version("0.1.0"): json.load(open_text(__name__, "analyzer_output.0.1.0.json")),
    Version("1.0.0"): json.load(open_text(__name__, "analyzer_output.1.0.0.json")),
    Version("1.1.0"): json.load(open_text(__name__, "analyzer_output.1.0.0.json")),
    Version("1.2.0"): json.load(open_text(__name__, "analyzer_output.1.0.0.json")),
    Version("2.0.0"): json.load(open_text(__name__, "analyzer_output.1.0.0.json")),
    Version("2.1.0"): json.load(open_text(__name__, "analyzer_output.1.0.0.json")),
}

# The integration test schemas refer to the analyzer schema, so they maintain the same versioning (integeration test schema X is always 1-to-1 with output schema X)
_ANALYZER_INTEGRATION_TEST_SCHEMAS = {
    Version("1.0.0"): json.load(open_text(__name__, "integration_test.1.0.0.json")),
    Version("1.1.0"): json.load(open_text(__name__, "integration_test.1.0.0.json")),
    Version("1.2.0"): json.load(open_text(__name__, "integration_test.1.0.0.json")),
    Version("2.0.0"): json.load(open_text(__name__, "integration_test.2.0.0.json")),
    Version("2.1.0"): json.load(open_text(__name__, "integration_test.2.0.0.json")),
}


def local_resolver(schema):
    """Constructs a RefResolver for the schema that resolves refs locally.

    Specifically, it defines a handler for the file: URI schemes, which
    looks for schemas in this directory (r2c/schema), and defines handlers for
    all unsafe schemes that would normally be passed to urllib/requests that
    just throws a ValueError instead.

    This is necessary because jsonschema's default behavior allows arbitrary
    requests to external URIs.
    """

    def bad_uri_handler(uri):
        raise ValueError("URI {} uses an insecure scheme".format(uri))

    def file_handler(uri):
        # Need to remove the first character since it'll start with a forward
        # slash.
        filename = urllib.parse.urlparse(uri).path[1:]
        return json.load(open_text(__name__, filename))

    handlers = {
        # We have to *explicitly* register handlers for unsafe schemes.
        "http": bad_uri_handler,
        "https": bad_uri_handler,
        "ftp": bad_uri_handler,
        "file": file_handler,
    }
    return jsonschema.RefResolver.from_schema(schema, handlers=handlers)


def analyzer_output_validator(
    output: dict,
    finding_schema: Optional[dict] = None,
    error_schema: Optional[dict] = None,
) -> jsonschema.Draft7Validator:
    """A validator for the output of the analyzer with the given manifest.

    Only works on the latest manifest version, so run migrations *before*
    calling this.

    In particular, this plugs in any declared schemas for the 'extra' fields on
    the results/errors into the standard analyzer output schema, then
    constructs a validator that validates against the new schema.
    """
    spec_version = Version(output.get("spec_version", "1.0.0"))
    schema = copy.deepcopy(_ANALYZER_OUTPUT_SCHEMAS[spec_version])
    if finding_schema is not None:
        schema["definitions"]["result"]["properties"]["extra"] = finding_schema
    if error_schema is not None:
        schema["definitions"]["error"]["properties"]["extra"] = error_schema
    return jsonschema.Draft7Validator(schema, resolver=local_resolver(schema))


def manifest_validator(manifest: dict) -> Optional[jsonschema.Draft7Validator]:
    """Returns a validator for the given manifest, or None."""
    version = Version(manifest["spec_version"])
    if version > SPEC_VERSION:
        logging.warning(
            f"Input spec_version {version} is greater than any we know about; assuming latest known version {SPEC_VERSION} instead"
        )
        version = SPEC_VERSION
    schema = _MANIFEST_SCHEMAS.get(version)

    if schema is None:
        return None
    return jsonschema.Draft7Validator(schema, resolver=local_resolver(schema))


def integration_test_validator(output: dict) -> jsonschema.Draft7Validator:
    """Returns a validator for the given manifest, or None."""
    spec_version = Version(output.get("spec_version", "1.0.0"))
    schema = copy.deepcopy(_ANALYZER_INTEGRATION_TEST_SCHEMAS[spec_version])
    return jsonschema.Draft7Validator(schema, resolver=local_resolver(schema))
