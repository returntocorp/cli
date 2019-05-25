import json
import os
import sys
from pathlib import Path
from typing import Optional

import click

from r2c.cli import R2C_SUPPORT_EMAIL
from r2c.lib.constants import PLATFORM_ANALYZER_PREFIX

DOCKER_FILE = """FROM ubuntu:17.10

RUN groupadd -r analysis && useradd -m --no-log-init --gid analysis analysis

USER analysis
COPY src /analyzer

WORKDIR /
CMD ["/analyzer/analyze.sh"]"""

UNITTEST_SH = """#!/bin/bash

echo "⚠️ Empty unittest!"
"""

ANALYZE_SH = """#!/bin/bash

set -e
CODE_DIR="/analysis/inputs/public/source-code"

echo "{\\"results\\": []}" > /analysis/output/output.json"""

README = """# Analyzer name: {}
# Author name: {}
# Description: TODO
"""


def create_file(path, content):
    with open(path, "w", newline="\n", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, 0o775)


def create_template_analyzer(
    org: Optional[str],
    analyzer_name: str,
    author_name: str,
    author_email: str,
    run_on: str,
    output_type: str,
) -> None:

    template_prefix = org or PLATFORM_ANALYZER_PREFIX

    analyzer_json_dict = {
        # TODO get from default org
        "analyzer_name": f"{template_prefix}/{analyzer_name}",
        "author_name": author_name,
        "author_email": author_email,
        "version": "0.0.1",
        "spec_version": "1.2.0",
        "dependencies": {"public/source-code": "*"},
        "type": run_on,
        "output": {"type": output_type},
        "deterministic": True,
    }
    try:
        Path(os.path.join(analyzer_name, "src")).mkdir(parents=True)
        analyzer_json_path = os.path.join(analyzer_name, "analyzer.json")
        with open(analyzer_json_path, "w", newline="\n", encoding="utf-8") as fp:
            json.dump(analyzer_json_dict, fp, indent=4)
        dockerfile_path = os.path.join(analyzer_name, "Dockerfile")
        with open(dockerfile_path, "w", newline="\n", encoding="utf-8") as fp:
            fp.write(DOCKER_FILE)
        create_file(os.path.join(analyzer_name, "src", "analyze.sh"), ANALYZE_SH)
        create_file(os.path.join(analyzer_name, "src", "unittest.sh"), UNITTEST_SH)

        readme = README.format(analyzer_name, author_name)
        create_file(os.path.join(analyzer_name, "README.md"), readme)

    except FileExistsError as e:
        click.echo(
            f"❌ {analyzer_name} already exists. Please delete and run again", err=True
        )
        sys.exit(1)
    except Exception as e:
        click.echo(
            f"❌ Error creating template. Please contact us at {R2C_SUPPORT_EMAIL} with the following information: {e}",
            err=True,
        )
        sys.exit(1)
