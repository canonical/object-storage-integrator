import dataclasses
import os

import jubilant
import pytest
from domain import S3ConnectionInfo


@dataclasses.dataclass
class CharmSpec:
    charm: str
    app: str
    channel: str = "stable"
    trust: bool = False
    num_units: int = 1
    revision: int | None = None
    plain_config: dict = dataclasses.field(default_factory=dict)
    secret_config: dict = dataclasses.field(default_factory=dict)
    secret_config_name: str = "credentials"


def _get_substrate() -> str:
    """Get the substrate from environment variable (set by spread task.yaml)."""
    return os.environ.get("SUBSTRATE", "microk8s")


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
    channel="16/stable",
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
            # pytest.param(
            #     S3_INTEGRATOR_V1,
            #     MYSQL_8_VM,
            #     id="s3v1-mysql8-vm",
            # ),
            # pytest.param(
            #     S3_INTEGRATOR_V1,
            #     MONGODB_8_VM,
            #     id="s3v1-mongodb8-vm",
            # ),
        ]
    else:  # microk8s
        return [
            pytest.param(
                S3_INTEGRATOR_V1,
                POSTGRESQL_14_K8S,
                id="s3v1-postgres14-k8s",
            ),
            # pytest.param(
            #     S3_INTEGRATOR_V1,
            #     POSTGRESQL_16_K8S,
            #     id="s3v1-postgres16-k8s",
            # ),
            # pytest.param(
            #     S3_INTEGRATOR_V1,
            #     MYSQL_8_K8S,
            #     id="s3v1-mysql8-k8s",
            # ),
            # pytest.param(
            #     S3_INTEGRATOR_V1,
            #     MONGODB_8_K8S,
            #     id="s3v1-mongodb8-k8s",
            # ),
        ]


TEST_MATRIX = _build_test_matrix()


@pytest.fixture
def s3_charm(
    request: pytest.FixtureRequest, s3_root_user: S3ConnectionInfo, bucket_name: str
) -> CharmSpec:
    spec: CharmSpec = request.param
    return dataclasses.replace(
        spec,
        plain_config={
            **spec.plain_config,
            "bucket": bucket_name,
            "endpoint": s3_root_user.endpoint,
            "region": s3_root_user.region,
            "tls-ca-chain": s3_root_user.tls_ca_chain,
            "s3-uri-style": "path",
        },
        secret_config={
            **spec.secret_config,
            "access-key": s3_root_user.access_key,
            "secret-key": s3_root_user.secret_key,
        },
    )


@pytest.fixture(scope="function")
def juju(request: pytest.FixtureRequest):
    keep_models = bool(request.config.getoption("--keep-models"))

    with jubilant.temp_model(keep=keep_models) as juju:
        juju.wait_timeout = 10 * 60

        yield juju  # run the test

        if request.session.testsfailed:
            log = juju.debug_log(limit=30)
            print(log, end="")


@pytest.fixture
def requirer_charm(request: pytest.FixtureRequest) -> CharmSpec:
    return request.param


def deploy_and_configure_charm(juju: jubilant.Juju, charm: CharmSpec):
    """Deploy a charm from given spec."""
    juju.deploy(
        charm=charm.charm,
        app=charm.app,
        channel=charm.channel,
        revision=charm.revision,
        trust=charm.trust,
        num_units=charm.num_units,
    )
    charm_config = charm.plain_config
    if charm.secret_config:
        secret_uri = juju.add_secret(
            name=f"{charm.app}-secret",
            content=charm.secret_config,
        )
        juju.grant_secret(identifier=secret_uri, app=charm.app)
        charm_config[charm.secret_config_name] = secret_uri
    if charm_config:
        juju.config(app=charm.app, values=charm_config)
    juju.wait(
        lambda status: jubilant.all_active(status) and jubilant.all_agents_idle(status), delay=5
    )


def integrate_charms(juju: jubilant.Juju, provider: CharmSpec, requirer: CharmSpec):
    """Integrate provider and requirer charms."""
    juju.integrate(f"{provider.app}:s3-credentials", requirer.app)
    juju.wait(
        lambda status: jubilant.all_active(status) and jubilant.all_agents_idle(status),
        delay=60,
    )


@pytest.mark.parametrize("s3_charm, requirer_charm", TEST_MATRIX, indirect=True)
def test_compat(juju: jubilant.Juju, s3_charm: CharmSpec, requirer_charm: CharmSpec):
    """Test charm compatibility across versions."""
    # Deploy applications
    deploy_and_configure_charm(juju, s3_charm)
    deploy_and_configure_charm(juju, requirer_charm)

    # Integrate applications
    integrate_charms(juju, s3_charm, requirer_charm)

    # Do sanity checks on the requirer charm
    # perform_sanity_checks(juju, requirer_charm)
