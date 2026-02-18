import dataclasses
import re

import jubilant


@dataclasses.dataclass
class CharmSpec:
    charm: str
    app: str
    base: str | None = None
    channel: str | None = None
    trust: bool = False
    num_units: int = 1
    revision: int | None = None
    config: dict = dataclasses.field(default_factory=dict)
    secret_config: dict[str, dict[str, str]] = dataclasses.field(default_factory=dict)
    action_config: dict[str, dict[str, str]] = dataclasses.field(default_factory=dict)
    constraints: dict[str, str] = dataclasses.field(default_factory=dict)
    tls: bool = False

    def __str__(self):
        """Provide a human-readable string representation."""
        return f"{self.charm}-{self.channel.replace('/', '-')}"

    def __repr__(self):
        """Provide a concise representation for debugging."""
        return f"CharmSpec(charm={self.charm}, channel={self.channel}, revision={self.revision})"


def wait_active_idle(juju: jubilant.Juju, delay: int = 5):
    """Wait for all applications to be active and all agents to be idle."""
    juju.wait(
        lambda status: jubilant.all_active(status) and jubilant.all_agents_idle(status),
        delay=delay,
    )


def deploy_and_configure_charm(juju: jubilant.Juju, charm: CharmSpec):
    """Deploy a charm from given spec."""
    juju.deploy(
        charm=charm.charm,
        base=charm.base,
        app=charm.app,
        channel=charm.channel,
        revision=charm.revision,
        trust=charm.trust,
        num_units=charm.num_units,
        constraints=charm.constraints,
    )
    juju.wait(jubilant.all_agents_idle, delay=5)
    charm_config = charm.config
    for config_name, secret_content in charm.secret_config.items():
        secret_uri = juju.add_secret(
            name=f"{charm.app}-{config_name}",
            content=secret_content,
        )
        juju.grant_secret(identifier=secret_uri, app=charm.app)
        charm_config[config_name] = secret_uri
    if charm_config:
        juju.config(app=charm.app, values=charm_config)
    for action_name, params in charm.action_config.items():
        juju.wait(jubilant.all_agents_idle, delay=5)
        juju.run(f"{charm.app}/0", action_name, params)

    if charm.tls:
        certificates = CharmSpec(
            charm="self-signed-certificates",
            app="certificates",
            channel="1/stable",
        )
        juju.deploy(
            charm=certificates.charm,
            app=certificates.app,
            channel=certificates.channel,
        )
        juju.wait(jubilant.all_agents_idle, delay=5)
        juju.integrate(certificates.app, f"{charm.app}:certificates")
        wait_active_idle(juju, delay=10)

    wait_active_idle(juju)


def integrate_charms(juju: jubilant.Juju, provider: CharmSpec, requirer: CharmSpec):
    """Integrate provider and requirer charms."""
    juju.integrate(f"{provider.app}:s3-credentials", requirer.app)
    wait_active_idle(juju, delay=15)


def remove_charm_relations(juju: jubilant.Juju, provider: CharmSpec, requirer: CharmSpec):
    """Remove the relation between provider and requirer charms."""
    juju.remove_relation(f"{provider.app}:s3-credentials", requirer.app)
    wait_active_idle(juju, delay=15)


def list_backups(juju: jubilant.Juju, database: CharmSpec) -> list[str]:
    """List backups using the requirer charm's action."""
    action = juju.run(f"{database.app}/0", "list-backups")
    assert action.return_code == 0, f"list-backups action failed: {action.stderr}"
    lines = action.results["backups"].splitlines()
    idx = next(i for i, line in enumerate(lines) if re.match(r"^-{5,}$", line.strip()))
    backup_lines = [line for line in lines[idx + 1 :] if line.strip()]
    backup_ids = [line.split()[0] for line in backup_lines if len(line.split()) > 0]
    return backup_ids


def create_backup(juju: jubilant.Juju, database: CharmSpec) -> str:
    """Create a backup using the requirer charm's action and return the backup ID."""
    action = juju.run(f"{database.app}/0", "create-backup")
    assert action.return_code == 0, f"create-backup action failed: {action.stderr}"
    wait_active_idle(juju)


def restore_backup(juju: jubilant.Juju, database: CharmSpec, backup_id: str):
    """Restore a backup using the requirer charm's action."""
    action = juju.run(f"{database.app}/0", "restore", {"backup-id": backup_id})
    assert action.return_code == 0, f"restore-backup action failed: {action.stderr}"
    wait_active_idle(juju, delay=10)


def upgrade_charm(juju: jubilant.Juju, old_charm: CharmSpec, new_charm: CharmSpec):
    """Upgrade a charm from old spec to new spec."""
    juju.refresh(
        app=old_charm.app,
        channel=new_charm.channel,
        revision=new_charm.revision,
        trust=new_charm.trust,
    )
    wait_active_idle(juju, delay=60)
