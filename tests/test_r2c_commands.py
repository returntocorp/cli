import os
import shutil
from subprocess import check_call, check_output


def test_r2c_run():
    test_analyzer = "test_analyzer"
    check_call(["r2c", "--version"])
    # init empty analyzer
    check_call(
        [
            "r2c",
            "init",
            "--analyzer-name",
            test_analyzer,
            "--author-name",
            "tester",
            "--author-email",
            "tester",
            "--run-on",
            "commit",
            "--output-type",
            "json",
        ]
    )
    # cd into test analyzer dir
    os.chdir(test_analyzer)
    # run without cache
    check_call(["r2c", "run", "-v", "--no-login", "--reset-cache", "."])

    # run again and verify local infra timestamp was reset
    local_path_to_output = (
        check_output(
            [
                "find",
                "/tmp/local-infra/analysis_output/data",
                "-name",
                f"*{test_analyzer}*output.*",
            ]
        )
        .decode("utf-8")
        .strip()
    )
    print(local_path_to_output)
    ts_before = os.path.getmtime(local_path_to_output)
    # run with cache
    check_call(["r2c", "run", "--no-login", "."])
    ts_after = os.path.getmtime(local_path_to_output)
    assert not ts_before == ts_after
    # cleanup
    os.chdir("..")
    shutil.rmtree(test_analyzer)
