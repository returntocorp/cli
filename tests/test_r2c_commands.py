import os
import shutil
from subprocess import PIPE, Popen, check_call


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
    # run
    check_call(["r2c", "run", "--no-login", "."])
    # cleanup
    os.chdir("..")
    shutil.rmtree(test_analyzer)
