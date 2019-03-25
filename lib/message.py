import abc
import json


class MalformedMessageException(Exception):
    def __init__(self, message: str, cls_name: str) -> None:
        self.message = message
        self._cls_name = cls_name

    @property
    def cls_name(self) -> str:
        return self._cls_name

    def __str__(self) -> str:
        return "MalformedMessageException: could not parse {} as {}".format(
            self.message, self._cls_name
        )


class Message(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def from_json_str(cls, json_str: str) -> "Message":
        """
            Deserialize json string into a Message object.
            Raise MalformedMessageException if JSON_STR cannot be parsed correctly
        """
        pass

    @abc.abstractmethod
    def to_json(self):
        """
            Convert Message object to dictionary containing everything needed such that object
            can be reconstructed using from_json_str()
        """
        pass

    def __str__(self):
        """
            Serialize Message to json string
        """
        return json.dumps(self.to_json())
