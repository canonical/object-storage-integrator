import random
import string
from pathlib import Path

import jubilant
import pytest

from ..domain import S3ConnectionInfo
from .helpers import CharmSpec


def pytest_addoption(parser):
    group = parser.getgroup("charm options", "Charm selection and configuration options")
    group.addoption(
        "--charm",
        action="store",
        required=True,
        help="Name of the charm to test (required)",
    )
    group.addoption(
        "--channel-v0",
        action="store",
        required=True,
        help="Channel for v0 charm (required)",
    )
    group.addoption(
        "--revision-v0",
        action="store",
        default=None,
        help="Revision for v0 charm (default: None)",
    )
    group.addoption(
        "--channel-v1",
        action="store",
        required=True,
        help="Channel for v1 charm (required)",
    )
    group.addoption(
        "--revision-v1",
        action="store",
        default=None,
        help="Revision for v1 charm (default: None)",
    )
    group.addoption(
        "--trust",
        action="store_true",
        default=False,
        help="Whether to use --trust when deploying charms (default: False)",
    )


@pytest.fixture(scope="function")
def juju(request: pytest.FixtureRequest):
    """A Juju fixture for a functional scope."""
    keep_models = bool(request.config.getoption("--keep-models"))

    with jubilant.temp_model(keep=keep_models) as juju:
        juju.wait_timeout = 10 * 60

        yield juju  # run the test

        if request.session.testsfailed:
            log = juju.debug_log(limit=30)
            print(log, end="")


@pytest.fixture(scope="function")
def bucket_name() -> str:
    return f"s3-integrator-{''.join(random.sample(string.ascii_lowercase, 6))}"


@pytest.fixture
def provider_charm_v1(
    s3_charm: Path,
    s3_root_user: S3ConnectionInfo,
    bucket_name: str,
) -> CharmSpec:
    return CharmSpec(
        charm=s3_charm,
        app="s3-integrator-v1",
        config={
            "bucket": bucket_name,
            "endpoint": s3_root_user.endpoint,
            "region": s3_root_user.region,
            "tls-ca-chain": s3_root_user.tls_ca_chain,
            "s3-uri-style": "path",
            "path": "custompath/",
        },
        secret_config={
            "credentials": {
                "access-key": s3_root_user.access_key,
                "secret-key": s3_root_user.secret_key,
            },
        },
    )


@pytest.fixture
def provider_charm_v0(
    request: pytest.FixtureRequest, s3_root_user: S3ConnectionInfo, bucket_name: str
) -> CharmSpec:
    return CharmSpec(
        charm="s3-integrator",
        app="s3-integrator-v0",
        channel="1/stable",
        config={
            "bucket": bucket_name,
            "endpoint": s3_root_user.endpoint,
            "region": s3_root_user.region,
            "tls-ca-chain": s3_root_user.tls_ca_chain,
            "s3-uri-style": "path",
            "path": "custompath/",
        },
        action_config={
            "sync-s3-credentials": {
                "access-key": s3_root_user.access_key,
                "secret-key": s3_root_user.secret_key,
            },
        },
    )


@pytest.fixture
def requirer_charm_v0(request: pytest.FixtureRequest) -> CharmSpec:
    channel = request.config.getoption("--channel-v0")
    revision = request.config.getoption("--revision-v0")
    trust = request.config.getoption("--trust")
    charm = request.config.getoption("--charm")
    return CharmSpec(
        charm=charm,
        app=f"{charm}-v0",
        channel=channel,
        trust=trust,
        revision=int(revision) if revision else None,
    )


@pytest.fixture
def requirer_charm_v1(request: pytest.FixtureRequest) -> CharmSpec:
    charm = request.config.getoption("--charm")
    channel = request.config.getoption("--channel-v1")
    revision = request.config.getoption("--revision-v1")
    trust = request.config.getoption("--trust")
    return CharmSpec(
        charm=charm,
        app=f"{charm}-v1",
        channel=channel,
        trust=trust,
        revision=int(revision) if revision else None,
    )
