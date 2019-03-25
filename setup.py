import codecs
import os
import re

import setuptools

# The following implementation to get __version__ from the __init__.py is
# borrowed from aws-cli implementation at https://github.com/aws/aws-cli/blob/develop/setup.py
here = os.path.abspath(os.path.dirname(__file__))

# reads file specified by path paths
def read(*parts):
    return codecs.open(os.path.join(here, *parts), "r").read()


# from aws-cli setup.py
def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


with open("README.md", "r") as fh:
    long_description = fh.read()


with open("requirements.txt", "r") as fh:
    install_requires = fh.read().splitlines()
# I apologize in advance, but this issue https://github.com/pypa/pipenv/issues/3305
# makes me very very sad
print("raw requirements", install_requires)
cleaned_requirements = [
    line
    for line in install_requires
    if not line.startswith("-i") and not "r2c_lib" in line
]
print("cleaned requirements", cleaned_requirements)


all_deps = ["r2c-lib==0.0.10"] + cleaned_requirements

setuptools.setup(
    name="r2c-cli",
    version=find_version("r2c/cli", "__init__.py"),
    author="R2C",
    author_email="cli@ret2.co",
    description="A CLI for R2C",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://ret2.co",
    install_requires=all_deps,
    packages=["r2c", "r2c.cli"],
    include_package_data=True,
    license="Proprietary",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
    ],
    scripts=["bin/r2c", "bin/r2c.cmd"],
)
