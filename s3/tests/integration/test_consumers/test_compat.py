#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
import pytest

from .helpers import (
    CharmSpec,
    create_backup,
    deploy_and_configure_charm,
    integrate_charms,
    list_backups,
    remove_charm_relations,
    restore_backup,
    upgrade_charm,
)


def backup_operations(
    juju: jubilant.Juju,
    database_charm: CharmSpec,
    restore: bool = False,
    assert_backup_ids: list[str] | None = None,
) -> str:
    """Test backup and restore operations on the requirer charm."""
    # List backups before creating new one
    backups_before = list_backups(juju, database_charm)
    if assert_backup_ids:
        for assert_backup_id in assert_backup_ids:
            assert assert_backup_id in backups_before, (
                f"Expected backup ID {assert_backup_id} not found in existing backups: {backups_before}"
            )

    # Create backup and expect it to succeed
    create_backup(juju, database_charm)

    # List backups again and expect to find the newly created backup
    backups_after = list_backups(juju, database_charm)
    assert len(backups_after) == len(backups_before) + 1, (
        f"Expected {len(backups_before) + 1} backup after creation, but found: {backups_after}"
    )

    backup_id = backups_after[0]
    if restore:
        # Restore the backup and expect it to succeed
        restore_backup(juju, database_charm, backup_id)
    return backup_id


def verify_cross_compatibility(juju, provider: CharmSpec, requirer: CharmSpec):
    """Test intercompatibility between provider and requirer charms."""
    # Deploy applications
    deploy_and_configure_charm(juju, provider)
    deploy_and_configure_charm(juju, requirer)

    # Integrate applications
    integrate_charms(juju, provider, requirer)

    # Do sanity checks on the requirer charm
    backup_operations(juju, requirer, restore=True)

    # Remove charm relation
    remove_charm_relations(juju, provider, requirer)


def verify_upgrade_scenario(
    juju, provider0: CharmSpec, requirer0: CharmSpec, provider1: CharmSpec, requirer1: CharmSpec
):
    """Test the upgrade scenario for requirer using v0 to using v1."""
    # Deploy applications on v0
    deploy_and_configure_charm(juju, provider0)
    deploy_and_configure_charm(juju, requirer0)

    # Integrate applications on v0
    integrate_charms(juju, provider0, requirer0)
    backup_s3v0 = backup_operations(juju, requirer0)

    # Deploy s3-integrator-v1 charm (with same set of config as v0)
    provider1.config = provider0.config
    deploy_and_configure_charm(juju, provider1)

    remove_charm_relations(juju, provider0, requirer0)
    integrate_charms(juju, provider1, requirer0)
    backup_s3v1 = backup_operations(juju, requirer0, assert_backup_ids=[backup_s3v0])

    # Upgrade requirer charm to newer lib version
    requirer1.app = requirer0.app
    upgrade_charm(juju, requirer0, requirer1)
    backup_reqv1 = backup_operations(juju, requirer1, assert_backup_ids=[backup_s3v0, backup_s3v1])

    # Remove S3 relation and add it again
    remove_charm_relations(juju, provider1, requirer1)
    integrate_charms(juju, provider1, requirer1)
    backup_operations(
        juju, requirer1, assert_backup_ids=[backup_s3v0, backup_s3v1, backup_reqv1], restore=True
    )


def test_provider_v1_compat_with_requirer_v1(
    juju: jubilant.Juju,
    s3_integrator_v1: CharmSpec,
    requirer_charm_v1: CharmSpec | None,
    should_test_upgrade: bool,
):
    """Test the requirer v1 charm with provider v1 charm."""
    if not requirer_charm_v1:
        pytest.skip("No requirer-v1 charm specified, skipping test.")
    if should_test_upgrade:
        pytest.skip(
            "Upgrade tests are enabled, skipping provider-v1 <> requirer-v1 test,"
            " as it is covered in the upgrade scenario test."
        )
    verify_cross_compatibility(juju, s3_integrator_v1, requirer_charm_v1)


def test_provider_v1_compat_with_requirer_v0(
    juju: jubilant.Juju,
    s3_integrator_v1: CharmSpec,
    requirer_charm_v0: CharmSpec | None,
    should_test_upgrade: bool,
):
    """Test the requirer v0 charm with provider v1 charm."""
    if not requirer_charm_v0:
        pytest.skip("No requirer-v0 charm specified, skipping test.")
    if should_test_upgrade:
        pytest.skip(
            "Upgrade tests are enabled, skipping provider-v1 <> requirer-v0 test,"
            " as it is covered in the upgrade scenario test."
        )
    verify_cross_compatibility(juju, s3_integrator_v1, requirer_charm_v0)


def test_provider_v0_compat_with_requirer_v1(
    juju: jubilant.Juju,
    s3_integrator_v0: CharmSpec,
    requirer_charm_v1: CharmSpec | None,
):
    """Test the requirer v1 charm with provider v0 charm."""
    if not requirer_charm_v1:
        pytest.skip("No requirer-v1 charm specified, skipping test.")
    verify_cross_compatibility(juju, s3_integrator_v0, requirer_charm_v1)


def test_upgrade_scenario(
    juju: jubilant.Juju,
    s3_integrator_v0: CharmSpec,
    s3_integrator_v1: CharmSpec,
    requirer_charm_v0: CharmSpec | None,
    requirer_charm_v1: CharmSpec | None,
    should_test_upgrade: bool,
):
    """Test the requirer v1 charm with provider v0 charm."""
    if not should_test_upgrade:
        pytest.skip("Upgrade scenario not enabled, skipping test.")
    if not (requirer_charm_v1 and requirer_charm_v0):
        pytest.skip(
            "Both requirer-v0 and requirer-v1 charms must be specified for upgrade scenario, skipping test."
        )
    verify_upgrade_scenario(
        juju, s3_integrator_v0, requirer_charm_v0, s3_integrator_v1, requirer_charm_v1
    )
