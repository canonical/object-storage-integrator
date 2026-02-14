import dataclasses

import jubilant
import pytest
from domain import S3ConnectionInfo

from .helpers import CharmSpec


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
def provider_charm(
    request: pytest.FixtureRequest, s3_root_user: S3ConnectionInfo, bucket_name: str
) -> CharmSpec:
    spec: CharmSpec = request.param
    return dataclasses.replace(
        spec,
        config={
            **spec.config,
            "bucket": bucket_name,
            "endpoint": s3_root_user.endpoint,
            "region": s3_root_user.region,
            "tls-ca-chain": s3_root_user.tls_ca_chain,
            "s3-uri-style": "path",
        },
        secret_config={
            **spec.secret_config,
            "credentials": {
                "access-key": s3_root_user.access_key,
                "secret-key": s3_root_user.secret_key,
            },
        }
        if spec.channel.startswith("2/")
        else {},
        action_config={
            **spec.action_config,
            "sync-s3-credentials": {
                "access-key": s3_root_user.access_key,
                "secret-key": s3_root_user.secret_key,
            },
        }
        if spec.channel.startswith("1/")
        else {},
    )


@pytest.fixture
def requirer_charm(request: pytest.FixtureRequest) -> CharmSpec:
    return request.param
