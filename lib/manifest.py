import json
import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import jsonschema
from mypy_extensions import TypedDict
from semantic_version import Version

from r2c.lib import manifest_migrations, schemas
from r2c.lib.schemas import SPEC_VERSION
from r2c.lib.versioned_analyzer import AnalyzerName

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)


class AnalyzerType(Enum):
    constant = 1
    commit = 2
    git = 3

    @classmethod
    def from_name(cls, name):
        for t in AnalyzerType:
            if t.name == name:
                return t
        raise ValueError("{} is not a valid analyzer type".format(name))


class AnalyzerOutputType(Enum):
    json = 1
    filesystem = 2
    both = 3

    @classmethod
    def from_name(cls, name):
        for t in AnalyzerOutputType:
            if t.name == name:
                return t
        raise ValueError("{} is not a valid analyzer output type".format(name))


class _AnalyzerOutputJsonBase(TypedDict):
    type: str


class AnalyzerOutputJson(_AnalyzerOutputJsonBase, total=False):
    finding_extra_schema: Dict[str, Any]
    error_extra_schema: Dict[str, Any]


class _AnalyzerManifestJsonBase(TypedDict):
    analyzer_name: str
    version: str
    spec_version: str
    dependencies: Dict[str, Any]
    type: str
    output: AnalyzerOutputJson
    deterministic: bool


class AnalyzerManifestJson(_AnalyzerManifestJsonBase, total=False):
    author_name: Optional[str]
    author_email: Optional[str]
    _original_spec_version: str
    extra: Optional[Dict[str, Any]]


class AnalyzerDependency:
    def __init__(
        self,
        name: AnalyzerName,
        wildcard_version: str,
        parameters: Any = {},
        path: str = None,
    ) -> None:
        self._name = name
        self._wildcard_version = wildcard_version
        self._parameters = parameters
        self._path = path

    @property
    def name(self) -> AnalyzerName:
        return self._name

    @property
    def wildcard_version(self) -> str:
        return self._wildcard_version

    @property
    def parameters(self) -> Any:
        return self._parameters

    @property
    def path(self) -> Optional[str]:
        return self._path

    @path.setter
    def path(self, path: str) -> None:
        self._path = path

    def __str__(self) -> str:
        dep_str = f"{self.name}:{self.wildcard_version}"
        if self.parameters:
            dep_str += f"--- params: {self.parameters}"
        if self.path:
            dep_str += f"--- path: {self.path}"
        return dep_str


class AnalyzerOutput:
    def __init__(
        self,
        output_type: AnalyzerOutputType,
        finding_extra_schema: Optional[Dict[str, Any]],
        error_extra_schema: Optional[Dict[str, Any]],
    ):
        self._output_type = output_type
        self._finding_extra_schema = finding_extra_schema
        self._error_extra_schema = error_extra_schema

    @property
    def output_type(self) -> AnalyzerOutputType:
        return self._output_type

    @property
    def finding_extra_schema(self) -> Optional[Dict[str, Any]]:
        return self._finding_extra_schema

    @property
    def error_extra_schema(self) -> Optional[Dict[str, Any]]:
        return self._error_extra_schema

    @classmethod
    def from_json(cls, json_obj: AnalyzerOutputJson) -> "AnalyzerOutput":
        """Constructs from a JSON object. Does not validate the JSON."""
        return AnalyzerOutput(
            AnalyzerOutputType.from_name(json_obj["type"]),
            json_obj.get("finding_extra_schema", None),
            json_obj.get("error_extra_schema", None),
        )

    def to_json(self) -> AnalyzerOutputJson:
        json_obj: AnalyzerOutputJson = {"type": self._output_type.name}
        if self._finding_extra_schema:
            json_obj["finding_extra_schema"] = self._finding_extra_schema
        if self._error_extra_schema:
            json_obj["error_extra_schema"] = self._error_extra_schema
        return json_obj

    def validator(self, output: dict) -> jsonschema.Draft7Validator:
        """A validator that validates against the output schema, if any."""
        if self.output_type != AnalyzerOutputType.json:
            raise ValueError("Cannot get a validator for a non-JSON analyzer")
        return schemas.analyzer_output_validator(
            output,
            finding_schema=self.finding_extra_schema,
            error_schema=self.error_extra_schema,
        )

    def integration_test_validator(self, output: dict) -> jsonschema.Draft7Validator:
        """A validator for integration tests for the output schema, if any."""
        if self.output_type != AnalyzerOutputType.json:
            raise ValueError("Cannot get a validator for a non-JSON analyzer")
        return schemas.integration_test_validator(output)


class AnalyzerManifest:
    def __init__(
        self,
        analyzer_name: AnalyzerName,
        author_email: Optional[str],
        author_name: Optional[str],
        version: Version,
        spec_version: str,
        dependencies: List[AnalyzerDependency],
        analyzer_type: AnalyzerType,
        output: AnalyzerOutput,
        deterministic: bool,
        original_json: Dict[str, Any],
        original_spec_version: Optional[Version],
        extra: Optional[Dict[str, Any]],
    ) -> None:
        self._analyzer_name = analyzer_name
        self._author_email = author_email
        self._author_name = author_name
        self._version = version
        self._spec_version = spec_version
        self._dependencies = dependencies
        self._analyzer_type = analyzer_type
        self._output = output
        self._deterministic = deterministic
        # The original JSON object. Useful for dumping out the original, in
        # case this got migrated. Should be `None` if this was synthesized
        # internally.
        self._original_json = original_json
        self._extra = extra
        # The original spec version of this manifest.
        self._original_spec_version = original_spec_version or Version(spec_version)

    @property
    def analyzer_name(self) -> AnalyzerName:
        return self._analyzer_name

    @property
    def version(self) -> Version:
        return self._version

    @version.setter
    def version(self, version: Version) -> None:
        self._version = version

    @property
    def original_spec_version(self) -> Version:
        return self._original_spec_version

    @property
    def dependencies(self) -> List[AnalyzerDependency]:
        """
            The dependencies defined in this analyzer's manifest.
            These can be absolute versions or ranges and must be resolved.
        """
        return self._dependencies

    @dependencies.setter
    def dependencies(self, dependencies: List[AnalyzerDependency]) -> None:
        """ Setter for _dependencies """
        self._dependencies = dependencies

    @property
    def analyzer_type(self) -> AnalyzerType:
        return self._analyzer_type

    @property
    def output(self) -> AnalyzerOutput:
        return self._output

    @property
    def output_type(self) -> AnalyzerOutputType:
        return self._output.output_type

    @property
    def deterministic(self) -> bool:
        return self._deterministic

    @property
    def is_locally_linked(self) -> bool:
        """ Return if any dependency is locally linked """
        return any([dep.path for dep in self._dependencies])

    def to_json(self) -> Dict[str, Any]:
        """A JSON representation of this manifest.

        If this was constructed from a JSON object via `from_json`, that object
        is returned. If constructed via the constructor, creates a new JSON
        object and returns that.
        """
        if self._original_json is not None:
            return self._original_json

        dependencies: Dict[str, Any] = {}
        for dependency in self._dependencies:
            if len(dependency.parameters) == 0:
                dependencies[dependency.name] = dependency.wildcard_version
            else:
                dependencies[dependency.name] = {
                    "version": dependency.wildcard_version,
                    "parameters": dependency.parameters,
                }

        json_obj: Dict[str, Any] = {
            "analyzer_name": str(self._analyzer_name),
            "version": str(self._version),
            "spec_version": self._spec_version,
            "dependencies": dependencies,
            "type": self._analyzer_type.name,
            "output": self._output.to_json(),
            "deterministic": self._deterministic,
        }
        if self.original_spec_version != schemas.SPEC_VERSION:
            json_obj["_original_spec_version"] = str(self._original_spec_version)
        if self._author_email:
            json_obj["author_email"] = self._author_email
        if self._author_name:
            json_obj["author_name"] = self._author_name
        if self._extra:
            json_obj["extra"] = self._extra
        return json_obj

    @classmethod
    def from_json(cls, json_obj: Dict[str, Any]) -> "AnalyzerManifest":
        # The type of the json_obj argument is a bit of a hack, since in
        # r2c.lib.registry we cast an arbitrary dict to an AnalyzerManifestJson
        # before calling this.

        spec_version = json_obj.get("spec_version")
        if spec_version is None:
            raise MalformedManifestException(
                json_obj, "Must specify a spec_version field"
            )

        if Version(spec_version).major > SPEC_VERSION.major:
            logger.error(
                f"Trying to parse manifest for analyzer {json_obj['analyzer_name']}:{json_obj['version']}"
                f" with spec_version: {spec_version}, but that spec_version is"
                f" too new and not compatible with the latest supported: {SPEC_VERSION}."
            )
            raise IncompatibleManifestException(
                f"Can't parse manifest for analyzer {json_obj['analyzer_name']}:{json_obj['version']}"
                f" with spec_version: {spec_version}. The spec_version is"
                f" incompatible with the latest supported: {SPEC_VERSION}."
            )

        validator = schemas.manifest_validator(json_obj)
        if validator is None:
            raise MalformedManifestException(
                json_obj,
                "Could not find a schema for the given spec_version {}".format(
                    spec_version
                ),
            )
        try:
            validator.validate(json_obj)
        except jsonschema.ValidationError as err:
            raise MalformedManifestException(json_obj, err.message) from err

        original_json_obj = json_obj

        json_obj = manifest_migrations.migrate(json_obj)
        original_version = (
            Version(json_obj["_original_spec_version"])
            if json_obj.get("_original_spec_version")
            else Version(json_obj["spec_version"])
        )

        dependencies = []
        for dependency_name, value in json_obj["dependencies"].items():
            if isinstance(value, str):
                # if value is string, assume its Semver version
                dependencies.append(
                    AnalyzerDependency(
                        AnalyzerName(dependency_name), wildcard_version=value
                    )
                )
            else:
                # If value is an object, parse it for params, version, path
                dependencies.append(
                    AnalyzerDependency(
                        AnalyzerName(dependency_name),
                        value.get("version"),
                        value.get("parameters"),
                        value.get("path"),
                    )
                )
        return cls(
            json_obj["analyzer_name"],
            json_obj.get("author_email"),
            json_obj.get("author_name"),
            Version(json_obj["version"]),
            json_obj["spec_version"],
            dependencies,
            AnalyzerType.from_name(json_obj["type"]),
            AnalyzerOutput.from_json(json_obj["output"]),
            json_obj["deterministic"],
            original_json_obj,
            original_version,
            json_obj.get("extra"),
        )

    @classmethod
    def from_json_str(cls, json_str: str) -> "AnalyzerManifest":
        try:
            json_obj = json.loads(json_str)
        except:
            raise MalformedManifestException(json_str, "Can't parse json string")

        return AnalyzerManifest.from_json(json_obj)


class MalformedManifestException(Exception):
    def __init__(self, manifest: Union[str, Dict[str, Any]], message: str) -> None:
        self._manifest = manifest
        self._message = message

    def __str__(self) -> str:
        return "MalformedManifestException: could not parse {}. \n {}".format(
            self._manifest, self._message
        )


class InvalidManifestException(Exception):
    pass


class ManifestNotFoundException(Exception):
    pass


class IncompatibleManifestException(Exception):
    pass


# Local-linking specific exceptions
class InvalidLocalPathException(Exception):
    pass


class LinkedAnalyzerNameMismatch(Exception):
    pass
