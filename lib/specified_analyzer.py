import json
from typing import Dict, NewType, Optional

from mypy_extensions import TypedDict

from r2c.lib.versioned_analyzer import (
    AnalyzerName,
    VersionedAnalyzer,
    VersionedAnalyzerJson,
)

AnalyzerParameters = NewType("AnalyzerParameters", Dict[str, str])


class SpecifiedAnalyzerJson(TypedDict):
    versioned_analyzer: VersionedAnalyzerJson
    parameters: AnalyzerParameters


class SpecifiedAnalyzer:
    """
        Class to represent a specific instance of an analyzer. This includes
        any parameters.

        Contains all necessary information to run an analyzer minus the target of analysis
    """

    def __init__(
        self,
        versioned_analyzer: VersionedAnalyzer,
        parameters: Optional[AnalyzerParameters] = None,
    ) -> None:
        if parameters is None:
            parameters = AnalyzerParameters({})

        self._parameters = parameters
        self._versioned_analyzer = versioned_analyzer

    @property
    def parameters(self) -> AnalyzerParameters:
        return self._parameters

    @property
    def versioned_analyzer(self) -> VersionedAnalyzer:
        return self._versioned_analyzer

    @classmethod
    def from_json_str(cls, json_str: str) -> "SpecifiedAnalyzer":
        obj = json.loads(json_str)
        if "parameters" in obj:
            parameters = AnalyzerParameters(obj["parameters"])
        else:
            parameters = AnalyzerParameters({})
        va = VersionedAnalyzer.from_json(obj["versioned_analyzer"])
        return cls(va, parameters)

    def to_json(self) -> SpecifiedAnalyzerJson:
        return {
            "versioned_analyzer": self._versioned_analyzer.to_json(),
            "parameters": self._parameters,
        }

    def __hash__(self):
        return self.__repr__().__hash__()

    def __eq__(self, other):
        if other and isinstance(other, SpecifiedAnalyzer):
            # Same number of parameters
            if len(self.parameters) != len(other.parameters):
                return False

            # Same Parameters
            for k in self.parameters:
                if self.parameters[k] != other.parameters[k]:
                    return False

            return self.versioned_analyzer == other.versioned_analyzer
        return False

    def __repr__(self):
        repr_str = str(self.versioned_analyzer)
        if self._parameters:
            repr_str += " parameters:" + str(self._parameters)
        return repr_str

    # this is just because of a quirk of the toposort lib we're using, namely
    # that it attemps to sort values before printing an exception string
    def __lt__(self, other):
        if other:
            return self.versioned_analyzer < other.versioned_analyzer
        return NotImplementedError(f"Can't compare {self} to None")
