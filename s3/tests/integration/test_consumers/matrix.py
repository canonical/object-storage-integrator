import os

import pytest

from .helpers import CharmSpec

S3_INTEGRATOR_V1 = CharmSpec(
    charm="s3-integrator",
    app="s3v1",
    channel="2/edge",
    revision=341,
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


def _get_substrate() -> str:
    """Get the substrate from environment variable (set by spread task.yaml)."""
    return os.environ.get("SUBSTRATE", "microk8s")


def _build_test_matrix():
    """Build test matrix based on substrate environment variable."""
    substrate = _get_substrate()

    if substrate == "vm":
        return [
            pytest.param(
                S3_INTEGRATOR_V1,
                POSTGRESQL_14_VM,
                id="s3v1-postgres14-vm",
            ),
            pytest.param(
                S3_INTEGRATOR_V1,
                MYSQL_8_VM,
                id="s3v1-mysql8-vm",
            ),
            pytest.param(
                S3_INTEGRATOR_V1,
                MONGODB_8_VM,
                id="s3v1-mongodb8-vm",
            ),
        ]
    else:  # microk8s
        return [
            pytest.param(
                S3_INTEGRATOR_V1,
                POSTGRESQL_14_K8S,
                id="s3v1-postgres14-k8s",
            ),
            pytest.param(
                S3_INTEGRATOR_V1,
                POSTGRESQL_16_K8S,
                id="s3v1-postgres16-k8s",
            ),
            pytest.param(
                S3_INTEGRATOR_V1,
                MYSQL_8_K8S,
                id="s3v1-mysql8-k8s",
            ),
            pytest.param(
                S3_INTEGRATOR_V1,
                MONGODB_8_K8S,
                id="s3v1-mongodb8-k8s",
            ),
        ]


TEST_MATRIX = _build_test_matrix()
