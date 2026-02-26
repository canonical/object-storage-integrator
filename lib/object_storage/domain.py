"""Module containing domain-specific classes and functions."""

from dataclasses import dataclass
from enum import Enum
from typing import List, TypedDict, TypeVar, Union


class Scope(Enum):
    """Peer relations scope."""

    APP = "app"
    UNIT = "unit"


# Marker classes for backend types
class S3:
    """Marker class for S3 backend type."""


class GCS:
    """Marker class for GCS backend type."""


class AzureStorage:
    """Marker class for Azure backend type."""


# TypeVar for generic backend types
StorageBackend = TypeVar("StorageBackend", bound=Union[S3, GCS, AzureStorage])


@dataclass(frozen=True)
class StorageContract:
    """Define Contract describing what the requirer and provider exchange in the Storage relation.

    Args:
        required_info: Keys that must be present in the provider's application
            databag before the relation is considered "ready". This may include
            non-secret fields such as bucket-name, container and secret fields
            such as secret-key, access-key.
        secret_fields: Keys in the provider's databag that represent Juju secret
            references (URIs, labels, or IDs). The library will automatically
            register and track these secrets for the requirer.
    """

    required_info: list[str]
    secret_fields: list[str]


S3Info = TypedDict(
    "S3Info",
    {
        "access-key": str,
        "secret-key": str,
        "region": str,
        "storage-class": str,
        "attributes": str,
        "bucket": str,
        "endpoint": str,
        "path": str,
        "s3-api-version": str,
        "s3-uri-style": str,
        "tls-ca-chain": str,
        "delete-older-than-days": str,
    },
    total=False,
)

GcsInfo = TypedDict(
    "GcsInfo",
    {
        "bucket": str,
        "secret-key": str,
        "storage-class": str,
        "path": str,
    },
    total=False,
)

AzureStorageInfo = TypedDict(
    "AzureStorageInfo",
    {
        "container": str,
        "storage-account": str,
        "secret-key": str,
        "connection-protocol": str,
        "path": str,
        "endpoint": str,
        "resource-group": str,
    },
    total=False,
)
