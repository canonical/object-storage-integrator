# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""File containing constants to be used in the charm."""


PEER_RELATION_NAME = "object-storage-integrator-peers"
AZURE_RELATION_NAME = "azure-credentials"


AZURE_OPTIONS = [
    "container",
    "storage-account",
    "secret-key",
    "path"
]
AZURE_MANDATORY_OPTIONS = [
    "container",
    "storage-account",
    "secret-key"
]

KEYS_LIST = ["secret-key"]