import abc
import base64
import copy
import json
from inspect import signature
from typing import Any, Dict, List, Optional, Type

INPUT_TYPE_KEY = "input_type"


class AnalyzerInput(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def __init__(self, *args):
        raise NotImplementedError()

    @classmethod
    def subclass_from_name(cls, input_type: str) -> Optional[Type["AnalyzerInput"]]:
        for class_obj in cls.__subclasses__():
            if class_obj.__name__ == input_type:
                return class_obj
        return None

    @classmethod
    def input_keys(cls) -> List[str]:
        """
            Returns a list of string keys that this type of input contains. Uses the subclass's __init__ method to find these keys. This will suffice until we support more flexible json schemas.
            When constructing storage keys, Filestore concatenates the values corresponding to these keys in this order, so this ordering determines storage hierarchy.
        """
        sig = signature(cls.__init__)
        return [param.name for param in sig.parameters.values() if param.name != "self"]

    def to_json(self) -> Dict[str, Any]:
        """
            Returns: the json data representing this analyzer input
        """
        return {k: v for k, v in self.__dict__.items() if k in self.input_keys()}

    @classmethod
    def from_json(cls, json_obj: Dict[str, Any]) -> "AnalyzerInput":
        if not INPUT_TYPE_KEY in json_obj:
            raise InvalidAnalyzerInputException(
                f"Failed to parse json {json_obj} as an instance of AnalyzerInput."
                f"Couldn't find key {INPUT_TYPE_KEY} to determine input type"
            )
        subclass = cls.subclass_from_name(json_obj[INPUT_TYPE_KEY])
        if subclass is None:
            raise InvalidAnalyzerInputException(
                f"Failed to parse json {json_obj} as an instance of {cls}. "
                f"Input type must be one of {AnalyzerInput.__subclasses__()}"
            )

        # we don't need input type anymore
        json_obj = {k: v for k, v in json_obj.items() if k != INPUT_TYPE_KEY}

        # make sure the number of keys is right
        if not len(json_obj.keys()) == len(subclass.input_keys()):
            raise InvalidAnalyzerInputException(
                f"Failed to parse json {json_obj} as an instance of {subclass}. "
                f"Must contain keys: {subclass.input_keys() } but instead contains {list(json_obj.keys())}"
            )

        # make sure it contains all the keys
        for key in subclass.input_keys():
            if not key in json_obj:
                raise InvalidAnalyzerInputException(
                    f"Failed to parse json {json_obj} as an instance of {subclass}. "
                    f"Must contain keys: {subclass.input_keys()}"
                )

        # sort json keys by their order in input_keys
        key_value_pairs = sorted(
            json_obj.items(),
            key=lambda t: subclass.input_keys().index(t[0]) if subclass else -1,
        )
        return subclass(*[key_value_pair[1] for key_value_pair in key_value_pairs])


class GitRepoCommit(AnalyzerInput):
    def __init__(self, repo_url, commit_hash):
        self.repo_url = repo_url
        self.commit_hash = commit_hash


class GitRepo(AnalyzerInput):
    def __init__(self, repo_url):
        self.repo_url = repo_url


class PackageVersion(AnalyzerInput):
    def __init__(self, package_name, version):
        self.package_name = package_name
        self.version = version


class InvalidAnalyzerInputException(Exception):
    pass


class InvalidStorageKeyException(Exception):
    pass
