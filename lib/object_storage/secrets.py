"""Helper functions to interact with Juju Secrets."""

import logging
from typing import Dict, Optional, Union

from ops import (
    Application,
    Model,
    ModelError,
    Relation,
    Secret,
    SecretInfo,
    SecretNotFoundError,
    Unit,
)

from .exceptions import SecretAlreadyExistsError, SecretsUnavailableError

MODEL_ERRORS = {
    "not_leader": "this unit is not the leader",
    "no_label_and_uri": "ERROR either URI or label should be used for getting an owned secret but not both",
    "owner_no_refresh": "ERROR secret owner cannot use --refresh",
}

logger = logging.getLogger(__name__)


class SecretGroup(str):
    """Secret groups specific type."""


class SecretGroupsAggregate(str):
    """Secret groups with option to extend with additional constants."""

    def __init__(self):
        self.EXTRA = SecretGroup("extra")

    def __setattr__(self, name, value):
        """Setting internal constants."""
        if name in self.__dict__:
            raise RuntimeError("Can't set constant!")
        else:
            super().__setattr__(name, SecretGroup(value))

    def groups(self) -> list:
        """Return the list of stored SecretGroups."""
        return list(self.__dict__.values())

    def get_group(self, group: str) -> Optional[SecretGroup]:
        """If the input str translates to a group name, return that."""
        return SecretGroup(group) if group in self.groups() else None


SECRET_GROUPS = SecretGroupsAggregate()


class CachedSecret:
    """Locally cache a secret.

    The data structure is precisely reusing/simulating as in the actual Secret Storage
    """

    KNOWN_MODEL_ERRORS = [MODEL_ERRORS["no_label_and_uri"], MODEL_ERRORS["owner_no_refresh"]]

    def __init__(
        self,
        model: Model,
        component: Union[Application, Unit],
        label: str,
        secret_uri: Optional[str] = None,
    ):
        self._secret_meta: Optional[Secret] = None
        self._secret_content: Dict[str, str] = {}
        self._secret_uri = secret_uri
        self.label = label
        self._model = model
        self.component = component
        self.current_label = None

    @property
    def meta(self) -> Optional[Secret]:
        """Getting cached secret meta-information."""
        if not self._secret_meta:
            if not (self._secret_uri or self.label):
                return None

            try:
                self._secret_meta = self._model.get_secret(label=self.label)
            except SecretNotFoundError:
                pass

            # If still not found, to be checked by URI, to be labelled with the proposed label
            if not self._secret_meta and self._secret_uri:
                self._secret_meta = self._model.get_secret(id=self._secret_uri, label=self.label)
        return self._secret_meta

    ##########################################################################
    # Public functions
    ##########################################################################

    def add_secret(
        self,
        content: Dict[str, str],
        relation: Optional[Relation] = None,
        label: Optional[str] = None,
    ) -> Secret:
        """Create a new secret."""
        if self._secret_uri:
            raise SecretAlreadyExistsError(
                "Secret is already defined with uri %s", self._secret_uri
            )

        label = self.label if not label else label

        secret = self.component.add_secret(content, label=label)
        if relation and relation.app != self._model.app:
            # If it's not a peer relation, grant is to be applied
            secret.grant(relation)
        self._secret_uri = secret.id
        self._secret_meta = secret
        return secret

    def get_content(self) -> Dict[str, str]:
        """Getting cached secret content."""
        if not self._secret_content:
            if self.meta:
                try:
                    self._secret_content = self.meta.get_content(refresh=True)
                except (ValueError, ModelError) as err:
                    # https://bugs.launchpad.net/juju/+bug/2042596
                    # Only triggered when 'refresh' is set
                    if isinstance(err, ModelError) and not any(
                        msg in str(err) for msg in self.KNOWN_MODEL_ERRORS
                    ):
                        raise
                    # Due to: ValueError: Secret owner cannot use refresh=True
                    self._secret_content = self.meta.get_content()
        return self._secret_content

    def set_content(self, content: Dict[str, str]) -> None:
        """Setting cached secret content."""
        if not self.meta:
            return

        # DPE-4182: do not create new revision if the content stay the same
        if content == self.get_content():
            return

        if content:
            self.meta.set_content(content)
            self._secret_content = content
        else:
            self.meta.remove_all_revisions()

    def get_info(self) -> Optional[SecretInfo]:
        """Wrapper function to apply the corresponding call on the Secret object within CachedSecret if any."""
        if self.meta:
            return self.meta.get_info()
        return None

    def remove(self) -> None:
        """Remove secret."""
        if not self.meta:
            raise SecretsUnavailableError("Non-existent secret was attempted to be removed.")
        try:
            self.meta.remove_all_revisions()
        except SecretNotFoundError:
            pass
        self._secret_content = {}
        self._secret_meta = None
        self._secret_uri = None


class SecretCache:
    """A data structure storing CachedSecret objects."""

    def __init__(self, model: Model, component: Union[Application, Unit]):
        self._model = model
        self.component = component
        self._secrets: Dict[str, CachedSecret] = {}

    def get(self, label: str, uri: Optional[str] = None) -> Optional[CachedSecret]:
        """Getting a secret from Juju Secret store or cache."""
        if not self._secrets.get(label):
            secret = CachedSecret(self._model, self.component, label, uri)
            if secret.meta:
                self._secrets[label] = secret
        return self._secrets.get(label)

    def add(self, label: str, content: Dict[str, str], relation: Relation) -> CachedSecret:
        """Adding a secret to Juju Secret."""
        if self._secrets.get(label):
            raise SecretAlreadyExistsError(f"Secret {label} already exists")

        secret = CachedSecret(self._model, self.component, label)
        secret.add_secret(content, relation)
        self._secrets[label] = secret
        return self._secrets[label]

    def remove(self, label: str) -> None:
        """Remove a secret from the cache."""
        if secret := self.get(label):
            try:
                secret.remove()
                self._secrets.pop(label)
            except (SecretsUnavailableError, KeyError):
                pass
            else:
                return
        logger.debug("Non-existing Juju Secret was attempted to be removed %s", label)
