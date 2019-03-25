import json
from typing import NewType

from mypy_extensions import TypedDict

from r2c.lib.constants import ECR_URL
from semantic_version import Version

AnalyzerName = NewType("AnalyzerName", str)

VersionedAnalyzerJson = TypedDict(
    "VersionedAnalyzerJson", {"name": str, "version": str}
)


class VersionedAnalyzer:
    """
        Class to represent an analyzer and resolved version
    """

    def __init__(self, name: AnalyzerName, version: Version) -> None:
        self._name = name
        self._version = version

    @property
    def name(self) -> AnalyzerName:
        return self._name

    @property
    def version(self) -> Version:
        return self._version

    @property
    def image_id(self) -> str:
        """
            ECR Tag of a Versioned Analyzer
        """
        if "/" in self._name:
            return f"{ECR_URL}/massive-{str(self._name)}:{str(self._version)}"
        # HACK: old legacy java-style names (tracked in https://github.com/returntocorp/echelon-backend/issues/2486)
        return f"{ECR_URL}/analyzer/{str(self.name)}:{str(self._version)}"

    @classmethod
    def from_image_id(cls, image_id: str) -> "VersionedAnalyzer":
        """
            Return VersionAnalyzer given image_id
        """
        analyzer_name_full, version = image_id.split(":")
        if "massive-" not in analyzer_name_full:
            # HACK: old legacy java-style names (tracked in https://github.com/returntocorp/echelon-backend/issues/2486)
            name = AnalyzerName(analyzer_name_full.split("/")[-1])
        else:
            parts = analyzer_name_full.split("massive-")
            if len(parts) < 2:
                raise Exception(
                    f"Can't parse image ID for full analyzer name: {analyzer_name_full}"
                )

            name = AnalyzerName(parts[1])

        return cls(name, Version(version))

    def to_json(self) -> VersionedAnalyzerJson:
        return {"name": str(self._name), "version": str(self._version)}

    @classmethod
    def from_json_str(cls, json_str: str) -> "VersionedAnalyzer":
        obj = json.loads(json_str)
        return cls.from_json(obj)

    @classmethod
    def from_json(cls, json_obj: VersionedAnalyzerJson) -> "VersionedAnalyzer":
        if "name" not in json_obj or "version" not in json_obj:
            raise Exception(
                f"Can't parse {json_obj} as a versioned analyzer. Need 'name' and 'version' keys."
            )
        return cls(AnalyzerName(json_obj["name"]), Version(json_obj["version"]))

    def __hash__(self):
        return ":".join([self._name, str(self._version)]).__hash__()

    def __eq__(self, other):
        if other:
            return self._name == other.name and self._version == other.version
        return False

    def __repr__(self):
        return self._name + ":" + str(self._version)

    # this is just because of a quirk of the toposort lib we're using, namely
    # that it attemps to sort values before printing an exception string
    def __lt__(self, other):
        if other:
            if self.name == other.name:
                return self.version < other.version
            return self.name < other.name
        return NotImplementedError(f"Can't compare {self} to None")


def build_fully_qualified_name(org: str, analyzer_name: str) -> AnalyzerName:
    return AnalyzerName("/".join([org, analyzer_name]))
