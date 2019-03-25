"""
Tests for the schema validation logic (i.e., not the individual schemas).
"""

import jsonschema
import pytest

import r2c.lib.schemas

# DO NOT SUBMIT: actually inject the evil ref into the
# finding_extra_schema/error_extra_schema


@pytest.mark.parametrize("scheme", ["http", "https", "ftp", "file"])
def test_insecure_scheme(scheme):
    schema = {"$ref": f"{scheme}://example.example#"}
    resolver = r2c.lib.schemas.local_resolver(schema)
    with pytest.raises(jsonschema.RefResolutionError):
        jsonschema.Draft7Validator(schema, resolver=resolver).validate({})
