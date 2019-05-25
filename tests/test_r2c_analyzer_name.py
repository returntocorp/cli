from r2c.cli.commands.init import validate_analyzer_name


def test_r2c_analyzer_name():
    assert validate_analyzer_name("my_name_is_analyzer")
    assert validate_analyzer_name("my-name_is_analyzer")
    assert not validate_analyzer_name("Dan-Ulzii")
    assert validate_analyzer_name("ulzii-1")
    assert not validate_analyzer_name("ulzii-1%*^")
