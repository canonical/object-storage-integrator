"""Module containing decorators."""

import logging

from .exceptions import SecretsUnavailableError

logger = logging.getLogger(__name__)


def leader_only(f):
    """Decorator to ensure that only leader can perform given operation."""

    def wrapper(self, *args, **kwargs):
        if self.component == self.local_app and not self.local_unit.is_leader():
            logger.error(
                "This operation (%s()) can only be performed by the leader unit", f.__name__
            )
            return
        return f(self, *args, **kwargs)

    wrapper.leader_only = True
    return wrapper


def juju_secrets_only(f):
    """Decorator to ensure that certain operations would be only executed on Juju3."""

    def wrapper(self, *args, **kwargs):
        if not self.secrets_enabled:
            raise SecretsUnavailableError("Secrets unavailable on current Juju version")
        return f(self, *args, **kwargs)

    return wrapper
