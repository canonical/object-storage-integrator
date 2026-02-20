#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module that exports the public API of the object storage integrators."""

from object_storage.azure_storage import AzureStorageProvider, AzureStorageRequirer
from object_storage.events import (
    StorageConnectionInfoChangedEvent,
    StorageConnectionInfoGoneEvent,
    StorageConnectionInfoRequestedEvent,
)
from object_storage.exceptions import (
    PrematureDataAccessError,
)
from object_storage.gcs import (
    GcsStorageProviderData,
    GcsStorageProviderEventHandlers,
    GcsStorageRequires,
)
from object_storage.s3 import S3Provider, S3Requirer

__all__ = [
    # S3 classes
    "S3Provider",
    "S3Requirer",
    # Azure classes
    "AzureStorageProvider",
    "AzureStorageRequirer",
    # GCS classes
    "GcsStorageRequires",
    "GcsStorageProviderData",
    "GcsStorageProviderEventHandlers",
    # Events
    "StorageConnectionInfoRequestedEvent",
    "StorageConnectionInfoChangedEvent",
    "StorageConnectionInfoGoneEvent",
    # Exceptions
    "PrematureDataAccessError",
]
