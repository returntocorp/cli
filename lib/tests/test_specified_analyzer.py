import json

from r2c.lib.specified_analyzer import SpecifiedAnalyzer, AnalyzerParameters
from r2c.lib.versioned_analyzer import AnalyzerName, VersionedAnalyzer

from semantic_version import Version


ANALYZER_NAME = AnalyzerName("r2c/test-analyzer")
VERSION = Version("1.2.3")
VERSIONED_ANALYZER = VersionedAnalyzer(ANALYZER_NAME, VERSION)
PARAMETERS = AnalyzerParameters({})


def test_constructor():
    sa = SpecifiedAnalyzer(VERSIONED_ANALYZER, PARAMETERS)
    assert ANALYZER_NAME == sa.versioned_analyzer.name
    assert VERSION == sa.versioned_analyzer.version
    assert sa.parameters is not None
    for parameter in sa.parameters:
        assert PARAMETERS[parameter] == sa.parameters[parameter]


def test_json_conversion():
    sa = SpecifiedAnalyzer(VERSIONED_ANALYZER, PARAMETERS)
    sa2 = SpecifiedAnalyzer.from_json_str(json.dumps(sa.to_json()))

    assert sa.versioned_analyzer.name == sa2.versioned_analyzer.name
    assert sa.versioned_analyzer.version == sa2.versioned_analyzer.version

    # Parameters Match
    assert sa.parameters is not None
    assert sa2.parameters is not None
    assert len(sa.parameters) == len(sa2.parameters)
    for parameter_name in sa.parameters:
        assert sa.parameters[parameter_name] == sa2.parameters[parameter_name]


def test_equality():
    sa = SpecifiedAnalyzer(VERSIONED_ANALYZER, PARAMETERS)

    # Constructing from new objects
    sa2 = SpecifiedAnalyzer(
        VersionedAnalyzer(AnalyzerName("r2c/test-analyzer"), Version("1.2.3")),
        AnalyzerParameters({}),
    )

    assert sa == sa2
