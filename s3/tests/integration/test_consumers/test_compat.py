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
from .matrix import TEST_MATRIX


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


@pytest.mark.parametrize("provider_charm, requirer_charm", TEST_MATRIX, indirect=True)
def test_compat(juju: jubilant.Juju, provider_charm: CharmSpec, requirer_charm: CharmSpec):
    """Test charm compatibility across versions."""
    # Deploy applications
    deploy_and_configure_charm(juju, provider_charm)
    deploy_and_configure_charm(juju, requirer_charm)

    # Integrate applications
    integrate_charms(juju, provider_charm, requirer_charm)
    # Do sanity checks on the requirer charm
    perform_sanity_checks(juju, provider_charm, requirer_charm)

    # Remove charm relation
    remove_charm_relations(juju, provider_charm, requirer_charm)
