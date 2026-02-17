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
)


def perform_sanity_checks(juju: jubilant.Juju, provider: CharmSpec, requirer: CharmSpec):
    """Perform sanity checks after integration."""
    # List backups and expect none initially
    backups = list_backups(juju, requirer)
    assert len(backups) == 0, f"Expected no backups, but found: {backups}"

    # Create backup and expect it to succeed
    create_backup(juju, requirer)

    # List backups again and expect to find the newly created backup
    backups = list_backups(juju, requirer)
    assert len(backups) == 1, f"Expected 1 backup after creation, but found: {backups}"

    # Restore the backup and expect it to succeed
    backup_id = backups[0]
    restore_backup(juju, requirer, backup_id)


def verify_cross_compatibility(juju, provider: CharmSpec, requirer: CharmSpec):
    """Test intercompatibility between provider and requirer charms."""
    # Deploy applications
    deploy_and_configure_charm(juju, provider)
    deploy_and_configure_charm(juju, requirer)

    # Integrate applications
    integrate_charms(juju, provider, requirer)

    # Do sanity checks on the requirer charm
    perform_sanity_checks(juju, provider, requirer)

    # Remove charm relation
    remove_charm_relations(juju, provider, requirer)


def test_provider_v1_compat_with_requirer_v1(
    juju: jubilant.Juju,
    s3_integrator_v1: CharmSpec,
    requirer_charm_v1: CharmSpec | None,
):
    """Test the requirer v1 charm with provider v1 charm."""
    if not requirer_charm_v1:
        pytest.skip("No requirer-v1 charm specified, skipping test.")
    verify_cross_compatibility(juju, s3_integrator_v1, requirer_charm_v1)


def test_provider_v1_compat_with_requirer_v0(
    juju: jubilant.Juju,
    s3_integrator_v1: CharmSpec,
    requirer_charm_v0: CharmSpec | None,
):
    """Test the requirer v0 charm with provider v1 charm."""
    if not requirer_charm_v0:
        pytest.skip("No requirer-v0 charm specified, skipping test.")
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
