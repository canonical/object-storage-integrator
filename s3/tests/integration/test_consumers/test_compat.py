import jubilant

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


def test_compat(
    juju: jubilant.Juju,
    provider_charm_v0: CharmSpec,
    provider_charm_v1: CharmSpec,
    requirer_charm_v0: CharmSpec,
    requirer_charm_v1: CharmSpec,
):
    """Test charm compatibility across versions."""
    # Deploy applications
    deploy_and_configure_charm(juju, provider_charm_v1)
    deploy_and_configure_charm(juju, requirer_charm_v0)

    # Integrate applications
    integrate_charms(juju, provider_charm_v1, requirer_charm_v0)

    # Do sanity checks on the requirer charm
    perform_sanity_checks(juju, provider_charm_v1, requirer_charm_v0)

    # Remove charm relation
    remove_charm_relations(juju, provider_charm_v1, requirer_charm_v0)


# def test_upgrade(
#     juju: jubilant.Juju,
#     provider_charm_v0: CharmSpec,
#     provider_charm_v1: CharmSpec,
#     requirer_charm_v0: CharmSpec,
#     requirer_charm_v1: CharmSpec,
# ):
#     """Test charm compatibility across versions."""
#     # Deploy applications on v0
#     deploy_and_configure_charm(juju, provider_charm_v0)
#     deploy_and_configure_charm(juju, requirer_charm_v0)

#     # Integrate applications on v0
#     integrate_charms(juju, provider_charm_v0, requirer_charm_v0)

#     # Perform sanity checks
#     perform_sanity_checks(juju, provider_charm_v0, requirer_charm_v0)

#     # Upgrade provider charm to v1
#     upgrade_charm(juju, provider_charm_v0, provider_charm_v1)

#     # Perform sanity checks after provider upgrade
#     perform_sanity_checks(juju, provider_charm_v1, requirer_charm_v0)

#     # Upgrade requirer charm to v1
#     upgrade_charm(juju, requirer_charm_v0, requirer_charm_v1)

#     # Perform sanity checks after requirer upgrade
#     perform_sanity_checks(juju, provider_charm_v1, requirer_charm_v1)

#     # Remove charm relation
#     remove_charm_relations(juju, provider_charm_v1, requirer_charm_v1)
