from enum import Enum


class ApiErrorType(Enum):
    # jwt token related
    TOKEN_EXPIRED = 0
    TOKEN_MISSING = 1

    # errors for analyzer.json
    VERSION_ERROR = 2
    ANALYZER_NOT_FOUND = 3
    MALFORMED_MANIFEST = 4
    DUPLICATE_ANALYZER = 5

    # registry related
    ANALYZER_MISSING_IN_REGISTRY = 6
    ANALYZER_IMAGE_MISSING = 7
    MISSING_REGISTRY = 8
    ANALYZER_MARK_UPLOAD_ERROR = 9
    WRONG_ORG_SUBMITTED = 10

    # ecr/boto related
    ECR_ERROR = 11
    # linked analyzer push
    LINKED_ANALYZER_ERROR = 12


class SymlinkNeedsElevationError(Exception):
    """
    Thrown when a symlink exists in a directory, which requires different behavior
    to handle when copying the contents of the directory
    """
