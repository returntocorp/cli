"""
Converts an analyzer manifest from one spec version to a later one.
"""
import copy

from semantic_version import Version

from r2c.lib import schemas

# The _to_MAJOR_MINOR_PATCH versions convert specs from the immediately
# previous version to MAJOR.MINOR.PATCH by mutating their input. They don't
# update the spec_version field; we do that at the end.


def _to_1_1_0(spec: dict) -> None:
    spec["output"] = {"type": spec["output"]}


def _to_1_2_0(spec: dict) -> None:
    # this is left intentionally blank because the 1.2.0 of manifest is backwards
    # compatible with 1.1.0 in that is just allows for extra field
    pass


def _to_2_0_0(spec: dict) -> None:
    # 2.0.0 just adds parameter support
    pass


def _to_2_1_0(spec: dict) -> None:
    # this is left intentionally blank because the 2.1.0 of manifest is backwards
    # compatible with 2.0.0 in that `path` is optional field
    pass


# A list of (version, function) pairs. Each function should take a schema of
# the previous version as input and migrate it to be compliant with the given
# version.
_MIGRATORS = [
    (Version("1.1.0"), _to_1_1_0),
    (Version("1.2.0"), _to_1_2_0),
    (Version("2.0.0"), _to_2_0_0),
    (Version("2.1.0"), _to_2_1_0),
]


def migrate(spec: dict) -> dict:
    """Migrate an analyzer spec to the latest version."""
    spec_version = Version(spec["spec_version"])
    if spec_version == schemas.SPEC_VERSION:
        return spec

    # If we migrate multiple times, we want to preserve the
    # _original_spec_version field.
    original_spec_version = spec.get("_original_spec_version") or spec.get(
        "spec_version"
    )
    spec = copy.deepcopy(spec)
    for migrator_output_version, migrator in _MIGRATORS:
        if migrator_output_version > spec_version:
            migrator(spec)
    spec["spec_version"] = str(schemas.SPEC_VERSION)
    spec["_original_spec_version"] = original_spec_version
    return spec
