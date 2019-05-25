import abc
from typing import Callable, Dict

from r2c.lib.errors import ApiErrorType


class ManifestNotFoundError(Exception):
    """Couldn't find analyzer manifest on the local filesystem, even after traversal"""


class ReadmeNotFoundError(Exception):
    """Couldn't find analyzer readme on the local filesystem, even after traversal"""


class CliError(Exception, metaclass=abc.ABCMeta):
    """A user facing CLI error"""

    def __init__(self, message: str):
        self.message = message


class FetchDependenciesCliError(CliError):
    pass


class ReadLocalCredentialsCliError(CliError):
    pass


class ReadLocalOrgCredentialCliError(CliError):
    pass


class ReadLocalOrgCliError(CliError):
    pass


class BadAuthTokenCliError(CliError):
    pass


class AuthTokenValidationCliError(CliError):
    pass


class UploadAnalyzerCliError(CliError):
    pass


class AnalyzerNotFoundCliError(CliError):
    pass


class AnalyzerMalformedManifestCliError(CliError):
    pass


class DuplicateAnalyzerCliError(CliError):
    pass


class GetDockerCredentialsCliError(CliError):
    pass


class DockerAuthCliError(CliError):
    pass


class UploadImageCliError(CliError):
    pass


class ConfirmUploadCliError(CliError):
    pass


class ParseDependenciesCliError(CliError):
    pass


class ResolveVersionCliError(CliError):
    pass


class UnexpectedCliError(CliError):
    pass


API_ERROR_TYPE_TO_CLI_ERROR: Dict[str, Callable] = {
    # jwt token related
    ApiErrorType.TOKEN_MISSING.name: BadAuthTokenCliError,
    ApiErrorType.TOKEN_EXPIRED.name: AuthTokenValidationCliError,
    # errors for analyzer.json
    ApiErrorType.VERSION_ERROR.name: ResolveVersionCliError,
    ApiErrorType.ANALYZER_NOT_FOUND.name: AnalyzerNotFoundCliError,
    ApiErrorType.MALFORMED_MANIFEST.name: AnalyzerMalformedManifestCliError,
    ApiErrorType.DUPLICATE_ANALYZER.name: DuplicateAnalyzerCliError,
    # registry related
    ApiErrorType.ANALYZER_MISSING_IN_REGISTRY.name: AnalyzerNotFoundCliError,
    ApiErrorType.ANALYZER_IMAGE_MISSING.name: UploadImageCliError,
    ApiErrorType.MISSING_REGISTRY.name: UnexpectedCliError,
    ApiErrorType.ANALYZER_MARK_UPLOAD_ERROR.name: ConfirmUploadCliError,
    ApiErrorType.WRONG_ORG_SUBMITTED.name: ReadLocalOrgCliError,
    # ecr/boto related
    ApiErrorType.ECR_ERROR.name: UnexpectedCliError,
    # locally linked analyzer push
    ApiErrorType.LINKED_ANALYZER_ERROR.name: UploadAnalyzerCliError,
}


def get_cli_error_for_api_error(api_error: str, msg: str) -> CliError:
    return API_ERROR_TYPE_TO_CLI_ERROR.get(api_error, UnexpectedCliError)(msg)
