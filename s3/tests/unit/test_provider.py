#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import dataclasses
import json
from pathlib import Path
from unittest.mock import patch

import yaml
from ops import ActiveStatus, BlockedStatus
from ops.testing import Context, Relation, Secret, State

from src.charm import S3IntegratorCharm
from src.core.domain import parse_ca_chain
from src.utils.secrets import decode_secret_key

CONFIG = yaml.safe_load(Path("./config.yaml").read_text())
ACTIONS = yaml.safe_load(Path("./actions.yaml").read_text())
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
SCHEMA_VERSION_FIELD = "version"


@patch("utils.secrets.decode_secret_key_with_retry", decode_secret_key)
@patch("events.provider.S3ProviderEvents.ensure_bucket", return_value=True)
def test_provider_data_no_config_bucket_and_no_bucket_requests(
    mock_ensure_bucket,
    charm_configuration: dict,
    base_state: State,
    valid_ca_chain: bytes,
) -> None:
    """Check the char behavior when bucket is not set in config and no bucket is requested by consumer."""
    # Given
    credentials_secret = Secret(
        tracked_content={"access-key": "my-access-key", "secret-key": "my-secret-key"}
    )
    charm_configuration["options"]["credentials"]["default"] = credentials_secret.id

    # This CA chain is valid
    ca_chain_encoded = base64.b64encode(valid_ca_chain).decode()
    charm_configuration["options"]["tls-ca-chain"]["default"] = ca_chain_encoded
    ctx = Context(
        S3IntegratorCharm,
        meta=METADATA,
        config=charm_configuration,
        actions=ACTIONS,
        unit_id=0,
    )

    # Given
    state_in = dataclasses.replace(base_state, secrets=[credentials_secret])

    # When
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # Then
    assert isinstance(state_out.unit_status, ActiveStatus)

    relations = list(state_out.relations)
    s3_provider_relation = Relation(
        endpoint="s3-credentials",
        remote_app_data={
            "requested-secrets": '["foobar"]',
            SCHEMA_VERSION_FIELD: "1",
        },  # No bucket request from requirer
    )
    relations.append(s3_provider_relation)

    # Given
    state_in = dataclasses.replace(state_out, relations=relations)

    # When
    state_out = ctx.run(ctx.on.relation_changed(s3_provider_relation), state_in)

    # Then
    provider_data = state_out.get_relation(s3_provider_relation.id).local_app_data
    assert "bucket" not in provider_data
    assert provider_data["access-key"] == "my-access-key"
    assert provider_data["secret-key"] == "my-secret-key"
    assert provider_data["tls-ca-chain"] == json.dumps(parse_ca_chain(valid_ca_chain.decode()))


@patch("utils.secrets.decode_secret_key_with_retry", decode_secret_key)
@patch("events.provider.S3ProviderEvents.ensure_bucket", return_value=False)
def test_provider_when_ensure_bucket_unsuccessful(
    mock_ensure_bucket,
    charm_configuration: dict,
    base_state: State,
    valid_ca_chain: bytes,
) -> None:
    """Check charm behavior when the ensure_bucket operation by s3-integrator is unsuccessful."""
    # Given
    credentials_secret = Secret(
        tracked_content={"access-key": "my-access-key", "secret-key": "my-secret-key"}
    )
    charm_configuration["options"]["bucket"]["default"] = "config-bucket"
    charm_configuration["options"]["credentials"]["default"] = credentials_secret.id

    # This CA chain is valid
    ca_chain_encoded = base64.b64encode(valid_ca_chain).decode()
    charm_configuration["options"]["tls-ca-chain"]["default"] = ca_chain_encoded
    ctx = Context(
        S3IntegratorCharm,
        meta=METADATA,
        config=charm_configuration,
        actions=ACTIONS,
        unit_id=0,
    )

    # Given
    state_in = dataclasses.replace(base_state, secrets=[credentials_secret])

    # When
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # Then
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert "Could not ensure bucket(s): 'config-bucket'" in state_out.unit_status.message

    relations = list(state_out.relations)
    s3_provider_relation = Relation(
        endpoint="s3-credentials",
        remote_app_data={"bucket": "relation-bucket", "requested-secrets": '["foobar"]'},
    )
    relations.append(s3_provider_relation)

    # Given
    state_in = dataclasses.replace(state_out, relations=relations)

    # When
    state_out = ctx.run(ctx.on.relation_changed(s3_provider_relation), state_in)

    # Then
    provider_data = state_out.get_relation(s3_provider_relation.id).local_app_data
    assert provider_data == {}


@patch("utils.secrets.decode_secret_key_with_retry", decode_secret_key)
@patch("managers.s3.S3Manager.s3_resource", side_effect=ValueError("Invalid endpoint"))
def test_provider_empty_endpoint_manager_init_failure_does_not_crash(
    mock_s3_resource,
    charm_configuration: dict,
    base_state: State,
    valid_ca_chain: bytes,
) -> None:
    """Check provider gracefully degrades when S3 manager initialization fails with empty endpoint."""
    # Given
    credentials_secret = Secret(
        tracked_content={"access-key": "my-access-key", "secret-key": "my-secret-key"}
    )
    charm_configuration["options"]["bucket"]["default"] = "config-bucket"
    charm_configuration["options"]["endpoint"]["default"] = ""
    charm_configuration["options"]["credentials"]["default"] = credentials_secret.id

    ca_chain_encoded = base64.b64encode(valid_ca_chain).decode()
    charm_configuration["options"]["tls-ca-chain"]["default"] = ca_chain_encoded
    ctx = Context(
        S3IntegratorCharm,
        meta=METADATA,
        config=charm_configuration,
        actions=ACTIONS,
        unit_id=0,
    )
    state_in = dataclasses.replace(base_state, secrets=[credentials_secret])

    # When
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # Then: no exception from reconcile path and blocked status instead of crash
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert "Could not ensure bucket(s): 'config-bucket'" in state_out.unit_status.message


@patch("utils.secrets.decode_secret_key_with_retry", decode_secret_key)
@patch("managers.s3.S3Manager.get_bucket", return_value=True)
def test_provider_config_bucket_takes_priority_over_relation_bucket(
    mock_get_bucket,
    charm_configuration: dict,
    base_state: State,
    valid_ca_chain: bytes,
) -> None:
    """Check that bucket requested over the relation takes priority over the one in config."""
    # Given
    credentials_secret = Secret(
        tracked_content={"access-key": "my-access-key", "secret-key": "my-secret-key"}
    )
    charm_configuration["options"]["bucket"]["default"] = "config-bucket"
    charm_configuration["options"]["credentials"]["default"] = credentials_secret.id

    # This CA chain is valid
    ca_chain_encoded = base64.b64encode(valid_ca_chain).decode()
    charm_configuration["options"]["tls-ca-chain"]["default"] = ca_chain_encoded
    ctx = Context(
        S3IntegratorCharm, meta=METADATA, config=charm_configuration, actions=ACTIONS, unit_id=0
    )
    # Given
    state_in = dataclasses.replace(base_state, secrets=[credentials_secret])

    # When
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # Then
    assert isinstance(state_out.unit_status, ActiveStatus)

    s3_provider_relation = Relation(
        endpoint="s3-credentials",
        remote_app_data={"bucket": "relation-bucket", "requested-secrets": '["foobar"]'},
    )

    # Given
    state_in = dataclasses.replace(state_out, relations=[s3_provider_relation])

    # When
    state_out = ctx.run(ctx.on.relation_changed(s3_provider_relation), state_in)

    # Then
    provider_data = state_out.get_relation(s3_provider_relation.id).local_app_data
    assert provider_data["bucket"] == "config-bucket"
    assert provider_data["access-key"] == "my-access-key"
    assert provider_data["secret-key"] == "my-secret-key"
    assert provider_data["tls-ca-chain"] == json.dumps(parse_ca_chain(valid_ca_chain.decode()))


@patch("utils.secrets.decode_secret_key_with_retry", decode_secret_key)
@patch("managers.s3.S3Manager.get_bucket", return_value=True)
def test_recompute_statuses_config_bucket_ignores_relation_buckets(
    mock_get_bucket,
    charm_configuration: dict,
    base_state: State,
) -> None:
    """When a config bucket is set, recompute must ignore relation-requested buckets.

    The config bucket takes precedence and overwrites any requested bucket, so the
    recomputed status should never reference a relation-requested bucket.
    """
    # Given
    credentials_secret = Secret(
        tracked_content={"access-key": "my-access-key", "secret-key": "my-secret-key"}
    )
    charm_configuration["options"]["bucket"]["default"] = "config-bucket"
    charm_configuration["options"]["credentials"]["default"] = credentials_secret.id
    ctx = Context(
        S3IntegratorCharm, meta=METADATA, config=charm_configuration, actions=ACTIONS, unit_id=0
    )

    s3_provider_relation = Relation(
        endpoint="s3-credentials",
        remote_app_data={"bucket": "relation-bucket", "requested-secrets": '["foobar"]'},
    )
    relations = list(base_state.relations) + [s3_provider_relation]
    state_in = dataclasses.replace(base_state, secrets=[credentials_secret], relations=relations)

    # When: the config bucket is available, but the relation bucket would be unavailable.
    with ctx(ctx.on.update_status(), state_in) as manager:
        manager.run()
        charm = manager.charm

        # get_bucket returns True (config bucket available) -> ACTIVE, and the
        # relation-requested bucket is never evaluated.
        def only_config_bucket(bucket_name, path=""):
            return bucket_name == "config-bucket"

        mock_get_bucket.side_effect = only_config_bucket
        statuses = charm.s3_provider_events.get_statuses(scope="app", recompute=True)

    # Then
    assert all(s.status == "active" for s in statuses)
    assert not any("relation-bucket" in (s.message or "") for s in statuses)


@patch("utils.secrets.decode_secret_key_with_retry", decode_secret_key)
def test_recompute_statuses_deduplicates_missing_buckets(
    charm_configuration: dict,
    base_state: State,
) -> None:
    """Recompute must not report the same unavailable bucket more than once.

    When multiple requirers request the same bucket and no config bucket is set,
    the emitted status should list the bucket name a single time.
    """
    # Given
    credentials_secret = Secret(
        tracked_content={"access-key": "my-access-key", "secret-key": "my-secret-key"}
    )
    charm_configuration["options"]["credentials"]["default"] = credentials_secret.id
    ctx = Context(
        S3IntegratorCharm, meta=METADATA, config=charm_configuration, actions=ACTIONS, unit_id=0
    )

    first_relation = Relation(
        endpoint="s3-credentials",
        remote_app_data={"bucket": "mlpipeline", "requested-secrets": '["foobar"]'},
    )
    second_relation = Relation(
        endpoint="s3-credentials",
        remote_app_data={"bucket": "mlpipeline", "requested-secrets": '["foobar"]'},
    )
    relations = list(base_state.relations) + [first_relation, second_relation]
    state_in = dataclasses.replace(base_state, secrets=[credentials_secret], relations=relations)

    # When: no config bucket set and the requested bucket is unavailable.
    with patch("managers.s3.S3Manager.get_bucket", return_value=None):
        with ctx(ctx.on.update_status(), state_in) as manager:
            manager.run()
            charm = manager.charm
            statuses = charm.s3_provider_events.get_statuses(scope="app", recompute=True)

    # Then
    unavailable = [s for s in statuses if "Could not ensure bucket(s)" in (s.message or "")]
    assert len(unavailable) == 1
    assert unavailable[0].message == "Could not ensure bucket(s): 'mlpipeline'"


@patch("utils.secrets.decode_secret_key_with_retry", decode_secret_key)
@patch("managers.s3.S3Manager.get_bucket", return_value=True)
def test_provider_compatibility_with_requirer_v0(
    mock_get_bucket,
    charm_configuration: dict,
    base_state: State,
    valid_ca_chain: bytes,
) -> None:
    """Check that the provider still works when requirer side uses v0 of S3 lib."""
    # Given
    credentials_secret = Secret(
        tracked_content={"access-key": "my-access-key", "secret-key": "my-secret-key"}
    )
    charm_configuration["options"]["bucket"]["default"] = "config-bucket"
    charm_configuration["options"]["credentials"]["default"] = credentials_secret.id

    # This CA chain is valid
    ca_chain_encoded = base64.b64encode(valid_ca_chain).decode()
    charm_configuration["options"]["tls-ca-chain"]["default"] = ca_chain_encoded
    ctx = Context(
        S3IntegratorCharm, meta=METADATA, config=charm_configuration, actions=ACTIONS, unit_id=0
    )
    # Given
    state_in = dataclasses.replace(base_state, secrets=[credentials_secret])

    # When
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # Then
    assert isinstance(state_out.unit_status, ActiveStatus)

    s3_provider_relation = Relation(
        endpoint="s3-credentials",
        # v0 does not have 'requested-secrets' and also puts a dummy name as 'bucket'
        remote_app_data={"bucket": "relation-17"},
        local_app_data={"lib-version": "1.0"},
    )

    # Given
    state_in = dataclasses.replace(state_out, relations=[s3_provider_relation])

    # When
    state_out = ctx.run(ctx.on.relation_changed(s3_provider_relation), state_in)

    # Then
    provider_data = state_out.get_relation(s3_provider_relation.id).local_app_data
    assert provider_data["bucket"] == "config-bucket"
    assert provider_data["access-key"] == "my-access-key"
    assert provider_data["secret-key"] == "my-secret-key"
    assert provider_data["tls-ca-chain"] == json.dumps(parse_ca_chain(valid_ca_chain.decode()))
