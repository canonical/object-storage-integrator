import os

import pytest

from ..helpers import get_s3_charm_path
from .helpers import CharmSpec

# S3 Integrator charm built from current code
S3_INTEGRATOR_V1 = CharmSpec(
    charm=str(get_s3_charm_path()),
    app="s3v1",
)

# VM charms
POSTGRESQL_14_VM = CharmSpec(
    charm="postgresql",
    app="postgresv0",
    channel="14/stable",
)
MYSQL_8_VM = CharmSpec(
    charm="mysql",
    app="mysqlv0",
    channel="8.0/stable",
)
MONGODB_8_VM = CharmSpec(
    charm="mongodb",
    app="mongodbv0",
    channel="8/stable",
)
OPENSEARCH_2_VM = CharmSpec(
    charm="opensearch",
    app="opensearchv0",
    channel="2/stable",
)


# K8s charms
POSTGRESQL_14_K8S = CharmSpec(
    charm="postgresql-k8s",
    app="postgresv0",
    channel="14/stable",
    trust=True,
)
POSTGRESQL_16_K8S = CharmSpec(
    charm="postgresql-k8s",
    app="postgresv0",
    channel="16/edge",
    trust=True,
)
MYSQL_8_K8S = CharmSpec(
    charm="mysql-k8s",
    app="mysqlv0",
    channel="8.0/stable",
    trust=True,
)
MONGODB_8_K8S = CharmSpec(
    charm="mongodb-k8s",
    app="mongodbv0",
    channel="8/stable",
    trust=True,
)


VM_TEST_MATRIX = [
    pytest.param(S3_INTEGRATOR_V1, charm)
    for charm in [
        POSTGRESQL_14_VM,
        # https://github.com/canonical/mysql-operators/issues/92
        # TODO: use AWS S3 for MySQL test
        # MYSQL_8_VM,
        MONGODB_8_VM,
        OPENSEARCH_2_VM,
    ]
]

K8S_TEST_MATRIX = [
    pytest.param(
        S3_INTEGRATOR_V1,
        charm,
    )
    for charm in [
        POSTGRESQL_14_K8S,
        POSTGRESQL_16_K8S,
        # https://github.com/canonical/mysql-operators/issues/92
        # TODO: use AWS S3 for MySQL test
        # MYSQL_8_K8S,
        MONGODB_8_K8S,
    ]
]


def build_test_matrix():
    """Build test matrix based on substrate environment variable."""
    substrate = os.environ.get("SUBSTRATE", "microk8s")

    if substrate == "vm":
        return VM_TEST_MATRIX
    else:  # microk8s
        return K8S_TEST_MATRIX


TEST_MATRIX = build_test_matrix()
