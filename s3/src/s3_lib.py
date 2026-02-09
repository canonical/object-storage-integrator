# Copyright 2025 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

r"""A library for communicating with the S3 credentials providers and consumers.

This library provides the relevant interface code implementing the communication
specification for fetching, retrieving, triggering, and responding to events related to
the S3 provider charm and its consumers.


### Provider charm

The provider is implemented in the `s3-integrator` charm which is meant to be deployed
alongside one or more consumer charms. The provider charm is serving the s3 credentials and
metadata needed to communicate and work with an S3 compatible backend.

Example:
```python

from s3_lib import (
    S3ProviderData,
    S3ProviderEventHandlers,
    StorageConnectionInfoRequestedEvent,
)

class ExampleProviderCharm(CharmBase):
    def __init__(self, *args) -> None:
        super().__init__(*args)

        self.s3_provider_data = S3ProviderData(self.charm.model, S3_RELATION_NAME)
        self.s3_provider = S3ProviderEventHandlers(self.charm, self.s3_provider_data)

        self.framework.observe(
            self.s3_provider.on.storage_connection_info_requested,
            self._on_s3_connection_info_requested,
        )

    def _on_s3_connection_info_requested(self, _: StorageConnectionInfoRequestedEvent) -> None:
        if not self.charm.unit.is_leader():
            return

        bucket_name = self.charm.config.get("bucket")
        if not bucket_name:
            self.logger.warning("Bucket is setup by the requirer application!")

        self.s3_provider_data.update({})


if __name__ == "__main__":
    main(ExampleProviderCharm)


### Requirer charm

The requirer charm is the charm requiring the S3 credentials.
An example of requirer charm is the following:

Example:
```python

from s3_lib import S3Requires, StorageConnectionInfoChangedEvent, StorageConnectionInfoGoneEvent

class ExampleRequirerCharm(CharmBase):

    def __init__(self, *args):
        super().__init__(*args)

         bucket_name = "test-bucket"
        # if bucket name is not provided the bucket name will be generated
        # e.g., ('relation-{relation.id}')

        self.s3_client = S3Requires(self, "s3-credentials", bucket_name)

        self.framework.observe(self.s3_client.on.s3_connection_info_changed, self._on_credential_changed)
        self.framework.observe(self.s3_client.on.s3_connection_info_gone, self._on_credential_gone)

    def _on_credential_changed(self, event: StorageConnectionInfoChangedEvent):

        # access single parameter credential
        secret_key = event.secret_key
        access_key = event.access_key

    def _on_credential_gone(self, event: StorageConnectionInfoGoneEvent):
        # credentials are removed
        pass

 if __name__ == "__main__":
    main(ExampleRequirerCharm)
```
"""

import copy
import json
import logging
from abc import ABC, abstractmethod
from collections import UserDict, namedtuple
from enum import Enum
from typing import (
    Callable,
    Dict,
    ItemsView,
    KeysView,
    List,
    Optional,
    Set,
    Tuple,
    Union,
    ValuesView,
)  # using py38-style typing

from ops import (
    Application,
    JujuVersion,
    Model,
    ModelError,
    Object,
    RelationCreatedEvent,
    Secret,
    SecretInfo,
    SecretNotFoundError,
    Unit,
)
from ops.charm import (
    CharmBase,
    CharmEvents,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationEvent,
    RelationJoinedEvent,
    SecretChangedEvent,
)
from ops.framework import EventSource
from ops.model import Relation

# The unique Charmhub library identifier, never change it
LIBID = "fca396f6254246c9bfa565b1f85ab528"

# Increment this major API version when introducing breaking changes
LIBAPI = 1

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 0


logger = logging.getLogger(__name__)


S3_REQUIRED_OPTIONS = ["access-key", "secret-key"]
S3_LIB_VERSION_FIELD = "lib-version"


Diff = namedtuple("Diff", "added changed deleted")
Diff.__doc__ = """
A tuple for storing the diff between two data mappings.

added - keys that were added
changed - keys that still exist but have new values
deleted - key that were deleted"""

ENTITY_USER = "USER"
ENTITY_GROUP = "GROUP"

PROV_SECRET_PREFIX = "secret-"
PROV_SECRET_FIELDS = "provided-secrets"
REQ_SECRET_FIELDS = "requested-secrets"

MODEL_ERRORS = {
    "not_leader": "this unit is not the leader",
    "no_label_and_uri": "ERROR either URI or label should be used for getting an owned secret but not both",
    "owner_no_refresh": "ERROR secret owner cannot use --refresh",
}


##############################################################################
# Exceptions
##############################################################################


class DataInterfacesError(Exception):
    """Common ancestor for DataInterfaces related exceptions."""


class SecretError(DataInterfacesError):
    """Common ancestor for Secrets related exceptions."""


class SecretAlreadyExistsError(SecretError):
    """A secret that was to be added already exists."""


class SecretsUnavailableError(SecretError):
    """Secrets aren't yet available for Juju version used."""


class SecretsIllegalUpdateError(SecretError):
    """Secrets aren't yet available for Juju version used."""


class IllegalOperationError(DataInterfacesError):
    """To be used when an operation is not allowed to be performed."""


class PrematureDataAccessError(DataInterfacesError):
    """To be raised when the Relation Data may be accessed (written) before protocol init complete."""


##############################################################################
# Global helpers / utilities
##############################################################################

##############################################################################
# Databag handling and comparison methods
##############################################################################


def get_encoded_dict(
    relation: Relation, member: Union[Unit, Application], field: str
) -> Optional[Dict[str, str]]:
    """Retrieve and decode an encoded field from relation data."""
    data = json.loads(relation.data[member].get(field, "{}"))
    if isinstance(data, dict):
        return data
    logger.error("Unexpected datatype for %s instead of dict.", str(data))


def get_encoded_list(
    relation: Relation, member: Union[Unit, Application], field: str
) -> Optional[List[str]]:
    """Retrieve and decode an encoded field from relation data."""
    data = json.loads(relation.data[member].get(field, "[]"))
    if isinstance(data, list):
        return data
    logger.error("Unexpected datatype for %s instead of list.", str(data))


def set_encoded_field(
    relation: Relation,
    member: Union[Unit, Application],
    field: str,
    value: Union[str, list, Dict[str, str]],
) -> None:
    """Set an encoded field from relation data."""
    relation.data[member].update({field: json.dumps(value)})


def diff(event: RelationChangedEvent, bucket: Optional[Union[Unit, Application]]) -> Diff:
    """Retrieves the diff of the data in the relation changed databag.

    Args:
        event: relation changed event.
        bucket: bucket of the databag (app or unit)

    Returns:
        a Diff instance containing the added, deleted and changed
            keys from the event relation databag.
    """
    # Retrieve the old data from the data key in the application relation databag.
    if not bucket:
        return Diff([], [], [])

    old_data = get_encoded_dict(event.relation, bucket, "data")

    if not old_data:
        old_data = {}

    # Retrieve the new data from the event relation databag.
    new_data = (
        {key: value for key, value in event.relation.data[event.app].items() if key != "data"}
        if event.app
        else {}
    )

    # These are the keys that were added to the databag and triggered this event.
    added = new_data.keys() - old_data.keys()  # pyright: ignore [reportAssignmentType]
    # These are the keys that were removed from the databag and triggered this event.
    deleted = old_data.keys() - new_data.keys()  # pyright: ignore [reportAssignmentType]
    # These are the keys that already existed in the databag,
    # but had their values changed.
    changed = {
        key
        for key in old_data.keys() & new_data.keys()  # pyright: ignore [reportAssignmentType]
        if old_data[key] != new_data[key]  # pyright: ignore [reportAssignmentType]
    }
    # Convert the new_data to a serializable format and save it for a next diff check.
    set_encoded_field(event.relation, bucket, "data", new_data)

    # Return the diff with all possible changes.
    return Diff(added, changed, deleted)


##############################################################################
# Module decorators
##############################################################################


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


##############################################################################
# Helper classes
##############################################################################


class Scope(Enum):
    """Peer relations scope."""

    APP = "app"
    UNIT = "unit"


class SecretGroup(str):
    """Secret groups specific type."""


class SecretGroupsAggregate(str):
    """Secret groups with option to extend with additional constants."""

    def __init__(self):
        self.USER = SecretGroup("user")
        self.TLS = SecretGroup("tls")
        self.MTLS = SecretGroup("mtls")
        self.ENTITY = SecretGroup("entity")
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
        legacy_labels: List[str] = [],
    ):
        self._secret_meta = None
        self._secret_content = {}
        self._secret_uri = secret_uri
        self.label = label
        self._model = model
        self.component = component
        self.legacy_labels = legacy_labels
        self.current_label = None

    @property
    def meta(self) -> Optional[Secret]:
        """Getting cached secret meta-information."""
        if not self._secret_meta:
            if not (self._secret_uri or self.label):
                return

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
        return self._secret_meta

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

    def get(
        self, label: str, uri: Optional[str] = None, legacy_labels: List[str] = []
    ) -> Optional[CachedSecret]:
        """Getting a secret from Juju Secret store or cache."""
        if not self._secrets.get(label):
            secret = CachedSecret(
                self._model, self.component, label, uri, legacy_labels=legacy_labels
            )
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
        logging.debug("Non-existing Juju Secret was attempted to be removed %s", label)


################################################################################
# Relation Data base/abstract ancestors (i.e. parent classes)
################################################################################


# Base Data


class DataDict(UserDict):
    """Python Standard Library 'dict' - like representation of Relation Data."""

    def __init__(self, relation_data: "Data", relation_id: int):
        self.relation_data = relation_data
        self.relation_id = relation_id

    @property
    def data(self) -> Dict[str, str]:
        """Return the full content of the Abstract Relation Data dictionary."""
        result = self.relation_data.fetch_my_relation_data([self.relation_id])
        try:
            result_remote = self.relation_data.fetch_relation_data([self.relation_id])
        except NotImplementedError:
            result_remote = {self.relation_id: {}}
        if result:
            result_remote[self.relation_id].update(result[self.relation_id])
        return result_remote.get(self.relation_id, {})

    def __setitem__(self, key: str, item: str) -> None:
        """Set an item of the Abstract Relation Data dictionary."""
        self.relation_data.update_relation_data(self.relation_id, {key: item})

    def __getitem__(self, key: str) -> str:
        """Get an item of the Abstract Relation Data dictionary."""
        result = None

        # Avoiding "leader_only" error when cross-charm non-leader unit, not to report useless error
        if (
            not hasattr(self.relation_data.fetch_my_relation_field, "leader_only")
            or self.relation_data.component != self.relation_data.local_app
            or self.relation_data.local_unit.is_leader()
        ):
            result = self.relation_data.fetch_my_relation_field(self.relation_id, key)

        if not result:
            try:
                result = self.relation_data.fetch_relation_field(self.relation_id, key)
            except NotImplementedError:
                pass

        if not result:
            raise KeyError
        return result

    def __eq__(self, d: dict) -> bool:
        """Equality."""
        return self.data == d

    def __repr__(self) -> str:
        """String representation Abstract Relation Data dictionary."""
        return repr(self.data)

    def __len__(self) -> int:
        """Length of the Abstract Relation Data dictionary."""
        return len(self.data)

    def __delitem__(self, key: str) -> None:
        """Delete an item of the Abstract Relation Data dictionary."""
        self.relation_data.delete_relation_data(self.relation_id, [key])

    def has_key(self, key: str) -> bool:
        """Does the key exist in the Abstract Relation Data dictionary?"""
        return key in self.data

    def update(self, items: Dict[str, str]):
        """Update the Abstract Relation Data dictionary."""
        self.relation_data.update_relation_data(self.relation_id, items)

    def keys(self) -> KeysView[str]:
        """Keys of the Abstract Relation Data dictionary."""
        return self.data.keys()

    def values(self) -> ValuesView[str]:
        """Values of the Abstract Relation Data dictionary."""
        return self.data.values()

    def items(self) -> ItemsView[str, str]:
        """Items of the Abstract Relation Data dictionary."""
        return self.data.items()

    def pop(self, item: str) -> str:
        """Pop an item of the Abstract Relation Data dictionary."""
        result = self.relation_data.fetch_my_relation_field(self.relation_id, item)
        if not result:
            raise KeyError(f"Item {item} doesn't exist.")
        self.relation_data.delete_relation_data(self.relation_id, [item])
        return result

    def __contains__(self, item: str) -> bool:
        """Does the Abstract Relation Data dictionary contain item?"""
        return item in self.data.values()

    def __iter__(self):
        """Iterate through the Abstract Relation Data dictionary."""
        return iter(self.data)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Safely get an item of the Abstract Relation Data dictionary."""
        try:
            if result := self[key]:
                return result
        except KeyError:
            return default


class Data(ABC):
    """Base relation data manipulation (abstract) class."""

    SCOPE = Scope.APP

    # Local map to associate mappings with secrets potentially as a group
    SECRET_LABEL_MAP = {}

    SECRET_FIELDS = []

    def __init__(
        self,
        model: Model,
        relation_name: str,
    ) -> None:
        self._model = model
        self.local_app = self._model.app
        self.local_unit = self._model.unit
        self.relation_name = relation_name
        self._jujuversion = None
        self.component = self.local_app if self.SCOPE == Scope.APP else self.local_unit
        self.secrets = SecretCache(self._model, self.component)
        self.data_component = None
        self._local_secret_fields = []
        self._remote_secret_fields = list(self.SECRET_FIELDS)

    @property
    def relations(self) -> List[Relation]:
        """The list of Relation instances associated with this relation_name."""
        return self._model.relations[self.relation_name]

    @property
    def secrets_enabled(self):
        """Is this Juju version allowing for Secrets usage?"""
        if not self._jujuversion:
            self._jujuversion = JujuVersion.from_environ()
        return self._jujuversion.has_secrets

    @property
    def secret_label_map(self):
        """Exposing secret-label map via a property -- could be overridden in descendants!"""
        return self.SECRET_LABEL_MAP

    @property
    def local_secret_fields(self) -> Optional[List[str]]:
        """Local access to secrets field, in case they are being used."""
        if self.secrets_enabled:
            return self._local_secret_fields

    @property
    def remote_secret_fields(self) -> Optional[List[str]]:
        """Local access to secrets field, in case they are being used."""
        if self.secrets_enabled:
            return self._remote_secret_fields

    @property
    def my_secret_groups(self) -> Optional[List[SecretGroup]]:
        """Local access to secrets field, in case they are being used."""
        if self.secrets_enabled:
            return [
                self.SECRET_LABEL_MAP[field]
                for field in self._local_secret_fields
                if field in self.SECRET_LABEL_MAP
            ]

    # Mandatory overrides for internal/helper methods

    @juju_secrets_only
    def _get_relation_secret(
        self, relation_id: int, group_mapping: SecretGroup, relation_name: Optional[str] = None
    ) -> Optional[CachedSecret]:
        """Retrieve a Juju Secret that's been stored in the relation databag."""
        if not relation_name:
            relation_name = self.relation_name

        label = self._generate_secret_label(relation_name, relation_id, group_mapping)
        if secret := self.secrets.get(label):
            return secret

        relation = self._model.get_relation(relation_name, relation_id)
        if not relation:
            return

        if secret_uri := self.get_secret_uri(relation, group_mapping):
            return self.secrets.get(label, secret_uri)

    # Mandatory overrides for requirer and peer, implemented for Provider
    # Requirer uses local component and switched keys
    # _local_secret_fields -> PROV_SECRET_FIELDS
    # _remote_secret_fields -> REQ_SECRET_FIELDS
    # provider uses remote component and
    # _local_secret_fields -> REQ_SECRET_FIELDS
    # _remote_secret_fields -> PROV_SECRET_FIELDS
    @abstractmethod
    def _load_secrets_from_databag(self, relation: Relation) -> None:
        """Load secrets from the databag."""
        raise NotImplementedError

    def _fetch_specific_relation_data(
        self, relation: Relation, fields: Optional[List[str]]
    ) -> Dict[str, str]:
        """Fetch data available (directily or indirectly -- i.e. secrets) from the relation (remote app data)."""
        if not relation.app:
            return {}
        self._load_secrets_from_databag(relation)
        return self._fetch_relation_data_with_secrets(
            relation.app, self.remote_secret_fields, relation, fields
        )

    def _fetch_my_specific_relation_data(
        self, relation: Relation, fields: Optional[List[str]]
    ) -> dict:
        """Fetch our own relation data."""
        # load secrets
        self._load_secrets_from_databag(relation)
        return self._fetch_relation_data_with_secrets(
            self.local_app,
            self.local_secret_fields,
            relation,
            fields,
        )

    def _update_relation_data(self, relation: Relation, data: Dict[str, str]) -> None:
        """Set values for fields not caring whether it's a secret or not."""
        self._load_secrets_from_databag(relation)

        _, normal_fields = self._process_secret_fields(
            relation,
            self.local_secret_fields,
            list(data),
            self._add_or_update_relation_secrets,
            data=data,
        )

        normal_content = {k: v for k, v in data.items() if k in normal_fields}
        self._update_relation_data_without_secrets(self.local_app, relation, normal_content)

    def _add_or_update_relation_secrets(
        self,
        relation: Relation,
        group: SecretGroup,
        secret_fields: Set[str],
        data: Dict[str, str],
        uri_to_databag=True,
    ) -> bool:
        """Update contents for Secret group. If the Secret doesn't exist, create it."""
        if self._get_relation_secret(relation.id, group):
            return self._update_relation_secret(relation, group, secret_fields, data)

        return self._add_relation_secret(relation, group, secret_fields, data, uri_to_databag)

    @juju_secrets_only
    def _add_relation_secret(
        self,
        relation: Relation,
        group_mapping: SecretGroup,
        secret_fields: Set[str],
        data: Dict[str, str],
        uri_to_databag=True,
    ) -> bool:
        """Add a new Juju Secret that will be registered in the relation databag."""
        if uri_to_databag and self.get_secret_uri(relation, group_mapping):
            logging.error("Secret for relation %s already exists, not adding again", relation.id)
            return False

        content = self._content_for_secret_group(data, secret_fields, group_mapping)

        label = self._generate_secret_label(self.relation_name, relation.id, group_mapping)
        secret = self.secrets.add(label, content, relation)

        if uri_to_databag:
            # According to lint we may not have a Secret ID
            if not secret.meta or not secret.meta.id:
                logging.error("Secret is missing Secret ID")
                raise SecretError("Secret added but is missing Secret ID")

            self.set_secret_uri(relation, group_mapping, secret.meta.id)

        # Return the content that was added
        return True

    @juju_secrets_only
    def _update_relation_secret(
        self,
        relation: Relation,
        group_mapping: SecretGroup,
        secret_fields: Set[str],
        data: Dict[str, str],
    ) -> bool:
        """Update the contents of an existing Juju Secret, referred in the relation databag."""
        secret = self._get_relation_secret(relation.id, group_mapping)

        if not secret:
            logging.error("Can't update secret for relation %s", relation.id)
            return False

        content = self._content_for_secret_group(data, secret_fields, group_mapping)

        old_content = secret.get_content()
        full_content = copy.deepcopy(old_content)
        full_content.update(content)
        secret.set_content(full_content)

        # Return True on success
        return True

    @juju_secrets_only
    def _delete_relation_secret(
        self, relation: Relation, group: SecretGroup, secret_fields: List[str], fields: List[str]
    ) -> bool:
        """Update the contents of an existing Juju Secret, referred in the relation databag."""
        secret = self._get_relation_secret(relation.id, group)

        if not secret:
            logging.error("Can't delete secret for relation %s", str(relation.id))
            return False

        old_content = secret.get_content()
        new_content = copy.deepcopy(old_content)
        for field in fields:
            try:
                new_content.pop(field)
            except KeyError:
                logging.debug(
                    "Non-existing secret was attempted to be removed %s, %s",
                    str(relation.id),
                    str(field),
                )
                return False

        # Remove secret from the relation if it's fully gone
        if not new_content:
            field = self._generate_secret_field_name(group)
            try:
                relation.data[self.component].pop(field)
            except KeyError:
                pass
            label = self._generate_secret_label(self.relation_name, relation.id, group)
            self.secrets.remove(label)
        else:
            secret.set_content(new_content)

        # Return the content that was removed
        return True

    def _delete_relation_data(self, relation: Relation, fields: List[str]) -> None:
        """Delete data available (directily or indirectly -- i.e. secrets) from the relation for owner/this_app."""
        if relation.app:
            self._load_secrets_from_databag(relation)

        _, normal_fields = self._process_secret_fields(
            relation, self.local_secret_fields, fields, self._delete_relation_secret, fields=fields
        )
        self._delete_relation_data_without_secrets(self.local_app, relation, list(normal_fields))

    def _register_secret_to_relation(
        self, relation_name: str, relation_id: int, secret_id: str, group: SecretGroup
    ):
        """Fetch secrets and apply local label on them.

        [MAGIC HERE]
        If we fetch a secret using get_secret(id=<ID>, label=<arbitraty_label>),
        then <arbitraty_label> will be "stuck" on the Secret object, whenever it may
        appear (i.e. as an event attribute, or fetched manually) on future occasions.

        This will allow us to uniquely identify the secret on Provider side (typically on
        'secret-changed' events), and map it to the corresponding relation.
        """
        label = self._generate_secret_label(relation_name, relation_id, group)

        # Fetching the Secret's meta information ensuring that it's locally getting registered with
        CachedSecret(self._model, self.component, label, secret_id).meta

    def _register_secrets_to_relation(self, relation: Relation, params_name_list: List[str]):
        """Make sure that secrets of the provided list are locally 'registered' from the databag.

        More on 'locally registered' magic is described in _register_secret_to_relation() method
        """
        if not relation.app:
            return

        for group in SECRET_GROUPS.groups():
            secret_field = self._generate_secret_field_name(group)
            if secret_field in params_name_list and (
                secret_uri := self.get_secret_uri(relation, group)
            ):
                self._register_secret_to_relation(relation.name, relation.id, secret_uri, group)

    # Internal helper methods

    @staticmethod
    def _is_secret_field(field: str) -> bool:
        """Is the field in question a secret reference (URI) field or not?"""
        return field.startswith(PROV_SECRET_PREFIX)

    @staticmethod
    def _generate_secret_label(
        relation_name: str, relation_id: int, group_mapping: SecretGroup
    ) -> str:
        """Generate unique group_mappings for secrets within a relation context."""
        return f"{relation_name}.{relation_id}.{group_mapping}.secret"

    def _generate_secret_field_name(self, group_mapping: SecretGroup) -> str:
        """Generate unique group_mappings for secrets within a relation context."""
        return f"{PROV_SECRET_PREFIX}{group_mapping}"

    def _relation_from_secret_label(self, secret_label: str) -> Optional[Relation]:
        """Retrieve the relation that belongs to a secret label."""
        contents = secret_label.split(".")

        if not (contents and len(contents) >= 3):
            return

        contents.pop()  # ".secret" at the end
        contents.pop()  # Group mapping
        relation_id = contents.pop()
        try:
            relation_id = int(relation_id)
        except ValueError:
            return

        # In case '.' character appeared in relation name
        relation_name = ".".join(contents)

        try:
            return self.get_relation(relation_name, relation_id)
        except ModelError:
            return

    def _group_secret_fields(self, secret_fields: List[str]) -> Dict[SecretGroup, List[str]]:
        """Helper function to arrange secret mappings under their group.

        NOTE: All unrecognized items end up in the 'extra' secret bucket.
        Make sure only secret fields are passed!
        """
        secret_fieldnames_grouped = {}
        for key in secret_fields:
            if group := self.secret_label_map.get(key):
                secret_fieldnames_grouped.setdefault(group, []).append(key)
            else:
                secret_fieldnames_grouped.setdefault(SECRET_GROUPS.EXTRA, []).append(key)
        return secret_fieldnames_grouped

    def _get_group_secret_contents(
        self,
        relation: Relation,
        group: SecretGroup,
        secret_fields: Union[Set[str], List[str]] = [],
    ) -> Dict[str, str]:
        """Helper function to retrieve collective, requested contents of a secret."""
        if (secret := self._get_relation_secret(relation.id, group)) and (
            secret_data := secret.get_content()
        ):
            return {
                k: v for k, v in secret_data.items() if not secret_fields or k in secret_fields
            }
        return {}

    def _content_for_secret_group(
        self, content: Dict[str, str], secret_fields: Set[str], group_mapping: SecretGroup
    ) -> Dict[str, str]:
        """Select <field>: <value> pairs from input, that belong to this particular Secret group."""
        if group_mapping == SECRET_GROUPS.EXTRA:
            return {
                k: v
                for k, v in content.items()
                if k in secret_fields and k not in self.secret_label_map.keys()
            }

        return {
            k: v
            for k, v in content.items()
            if k in secret_fields and self.secret_label_map.get(k) == group_mapping
        }

    @juju_secrets_only
    def _get_relation_secret_data(
        self, relation_id: int, group_mapping: SecretGroup, relation_name: Optional[str] = None
    ) -> Optional[Dict[str, str]]:
        """Retrieve contents of a Juju Secret that's been stored in the relation databag."""
        secret = self._get_relation_secret(relation_id, group_mapping, relation_name)
        if secret:
            return secret.get_content()

    # Core operations on Relation Fields manipulations (regardless whether the field is in the databag or in a secret)
    # Internal functions to be called directly from transparent public interface functions (+closely related helpers)

    def _process_secret_fields(
        self,
        relation: Relation,
        req_secret_fields: Optional[List[str]],
        impacted_rel_fields: List[str],
        operation: Callable,
        *args,
        **kwargs,
    ) -> Tuple[Dict[str, str], Set[str]]:
        """Isolate target secret fields of manipulation, and execute requested operation by Secret Group."""
        result = {}

        # If the relation started on a databag, we just stay on the databag
        # (Rolling upgrades may result in a relation starting on databag, getting secrets enabled on-the-fly)
        # self.local_app is sufficient to check (ignored if Requires, never has secrets -- works if Provider)
        fallback_to_databag = (
            req_secret_fields
            and (self.local_unit == self._model.unit and self.local_unit.is_leader())
            and set(req_secret_fields) & set(relation.data[self.component])
        )
        normal_fields = set(impacted_rel_fields)
        if req_secret_fields and self.secrets_enabled and not fallback_to_databag:
            normal_fields = normal_fields - set(req_secret_fields)
            secret_fields = set(impacted_rel_fields) - set(normal_fields)

            secret_fieldnames_grouped = self._group_secret_fields(list(secret_fields))

            for group in secret_fieldnames_grouped:
                # operation() should return nothing when all goes well
                if group_result := operation(relation, group, secret_fields, *args, **kwargs):
                    # If "meaningful" data was returned, we take it. (Some 'operation'-s only return success/failure.)
                    if isinstance(group_result, dict):
                        result.update(group_result)
                else:
                    # If it wasn't found as a secret, let's give it a 2nd chance as "normal" field
                    # Needed when Juju3 Requires meets Juju2 Provider
                    normal_fields |= set(secret_fieldnames_grouped[group])
        return (result, normal_fields)

    def _fetch_relation_data_without_secrets(
        self, component: Union[Application, Unit], relation: Relation, fields: Optional[List[str]]
    ) -> Dict[str, str]:
        """Fetching databag contents when no secrets are involved.

        Since the Provider's databag is the only one holding secrest, we can apply
        a simplified workflow to read the Require's side's databag.
        This is used typically when the Provider side wants to read the Requires side's data,
        or when the Requires side may want to read its own data.
        """
        if component not in relation.data or not relation.data[component]:
            return {}

        if fields:
            return {
                k: relation.data[component][k] for k in fields if k in relation.data[component]
            }
        else:
            return dict(relation.data[component])

    def _fetch_relation_data_with_secrets(
        self,
        component: Union[Application, Unit],
        req_secret_fields: Optional[List[str]],
        relation: Relation,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Fetching databag contents when secrets may be involved.

        This function has internal logic to resolve if a requested field may be "hidden"
        within a Relation Secret, or directly available as a databag field. Typically
        used to read the Provider side's databag (eigher by the Requires side, or by
        Provider side itself).
        """
        result = {}
        normal_fields = []

        if not fields:
            if component not in relation.data:
                return {}

            all_fields = list(relation.data[component].keys())
            normal_fields = [field for field in all_fields if not self._is_secret_field(field)]
            fields = normal_fields + req_secret_fields if req_secret_fields else normal_fields

        if fields:
            result, normal_fields = self._process_secret_fields(
                relation, req_secret_fields, fields, self._get_group_secret_contents
            )

        # Processing "normal" fields. May include leftover from what we couldn't retrieve as a secret.
        # (Typically when Juju3 Requires meets Juju2 Provider)
        if normal_fields:
            result.update(
                self._fetch_relation_data_without_secrets(component, relation, list(normal_fields))
            )
        return result

    def _update_relation_data_without_secrets(
        self, component: Union[Application, Unit], relation: Relation, data: Dict[str, str]
    ) -> None:
        """Updating databag contents when no secrets are involved."""
        if component not in relation.data or relation.data[component] is None:
            return

        if relation:
            relation.data[component].update(data)

    def _delete_relation_data_without_secrets(
        self, component: Union[Application, Unit], relation: Relation, fields: List[str]
    ) -> None:
        """Remove databag fields 'fields' from Relation."""
        if component not in relation.data or relation.data[component] is None:
            return

        for field in fields:
            try:
                relation.data[component].pop(field)
            except KeyError:
                logger.debug(
                    "Non-existing field '%s' was attempted to be removed from the databag (relation ID: %s)",
                    str(field),
                    str(relation.id),
                )
                pass

    # Public interface methods
    # Handling Relation Fields seamlessly, regardless if in databag or a Juju Secret

    def as_dict(self, relation_id: int) -> UserDict:
        """Dict behavior representation of the Abstract Data."""
        return DataDict(self, relation_id)

    def get_relation(self, relation_name, relation_id) -> Relation:
        """Safe way of retrieving a relation."""
        relation = self._model.get_relation(relation_name, relation_id)

        if not relation:
            raise DataInterfacesError(
                "Relation %s %s couldn't be retrieved", relation_name, relation_id
            )

        return relation

    def get_secret_uri(self, relation: Relation, group: SecretGroup) -> Optional[str]:
        """Get the secret URI for the corresponding group."""
        secret_field = self._generate_secret_field_name(group)
        # if the secret is not managed by this component,
        # we need to fetch it from the other side

        # Fix for the linter
        if self.my_secret_groups is None:
            raise DataInterfacesError("Secrets are not enabled for this component")
        component = self.component if group in self.my_secret_groups else relation.app
        return relation.data[component].get(secret_field)

    def set_secret_uri(self, relation: Relation, group: SecretGroup, secret_uri: str) -> None:
        """Set the secret URI for the corresponding group."""
        secret_field = self._generate_secret_field_name(group)
        relation.data[self.component][secret_field] = secret_uri

    def fetch_relation_data(
        self,
        relation_ids: Optional[List[int]] = None,
        fields: Optional[List[str]] = None,
        relation_name: Optional[str] = None,
    ) -> Dict[int, Dict[str, str]]:
        """Retrieves data from relation.

        This function can be used to retrieve data from a relation
        in the charm code when outside an event callback.
        Function cannot be used in `*-relation-broken` events and will raise an exception.

        Returns:
            a dict of the values stored in the relation data bag
                for all relation instances (indexed by the relation ID).
        """
        if not relation_name:
            relation_name = self.relation_name

        relations = []
        if relation_ids:
            relations = [
                self.get_relation(relation_name, relation_id) for relation_id in relation_ids
            ]
        else:
            relations = self.relations

        data = {}
        for relation in relations:
            if not relation_ids or (relation_ids and relation.id in relation_ids):
                data[relation.id] = self._fetch_specific_relation_data(relation, fields)
        return data

    def fetch_relation_field(
        self, relation_id: int, field: str, relation_name: Optional[str] = None
    ) -> Optional[str]:
        """Get a single field from the relation data."""
        return (
            self.fetch_relation_data([relation_id], [field], relation_name)
            .get(relation_id, {})
            .get(field)
        )

    def fetch_my_relation_data(
        self,
        relation_ids: Optional[List[int]] = None,
        fields: Optional[List[str]] = None,
        relation_name: Optional[str] = None,
    ) -> Optional[Dict[int, Dict[str, str]]]:
        """Fetch data of the 'owner' (or 'this app') side of the relation.

        NOTE: Since only the leader can read the relation's 'this_app'-side
        Application databag, the functionality is limited to leaders
        """
        if not relation_name:
            relation_name = self.relation_name

        relations = []
        if relation_ids:
            relations = [
                self.get_relation(relation_name, relation_id) for relation_id in relation_ids
            ]
        else:
            relations = self.relations

        data = {}
        for relation in relations:
            if not relation_ids or relation.id in relation_ids:
                data[relation.id] = self._fetch_my_specific_relation_data(relation, fields)
        return data

    def fetch_my_relation_field(
        self, relation_id: int, field: str, relation_name: Optional[str] = None
    ) -> Optional[str]:
        """Get a single field from the relation data -- owner side.

        NOTE: Since only the leader can read the relation's 'this_app'-side
        Application databag, the functionality is limited to leaders
        """
        if relation_data := self.fetch_my_relation_data([relation_id], [field], relation_name):
            return relation_data.get(relation_id, {}).get(field)

    @leader_only
    def update_relation_data(self, relation_id: int, data: dict) -> None:
        """Update the data within the relation."""
        relation_name = self.relation_name
        relation = self.get_relation(relation_name, relation_id)
        return self._update_relation_data(relation, data)

    @leader_only
    def delete_relation_data(self, relation_id: int, fields: List[str]) -> None:
        """Remove field from the relation."""
        relation_name = self.relation_name
        relation = self.get_relation(relation_name, relation_id)
        return self._delete_relation_data(relation, fields)


class EventHandlers(Object):
    """Requires-side of the relation."""

    def __init__(self, charm: CharmBase, relation_data: Data, unique_key: str = ""):
        """Manager of base client relations."""
        if not unique_key:
            unique_key = relation_data.relation_name
        super().__init__(charm, unique_key)

        self.charm = charm
        self.relation_data = relation_data

        self.framework.observe(
            charm.on[self.relation_data.relation_name].relation_changed,
            self._on_relation_changed_event,
        )

        self.framework.observe(
            self.charm.on[relation_data.relation_name].relation_created,
            self._on_relation_created_event,
        )

        self.framework.observe(
            charm.on.secret_changed,
            self._on_secret_changed_event,
        )

    # Event handlers

    def _on_relation_created_event(self, event: RelationCreatedEvent) -> None:
        """Event emitted when the relation is created."""
        pass

    @abstractmethod
    def _on_relation_changed_event(self, event: RelationChangedEvent) -> None:
        """Event emitted when the relation data has changed."""
        raise NotImplementedError

    @abstractmethod
    def _on_secret_changed_event(self, event: SecretChangedEvent) -> None:
        """Event emitted when the relation data has changed."""
        raise NotImplementedError

    def _diff(self, event: RelationChangedEvent) -> Diff:
        """Retrieves the diff of the data in the relation changed databag.

        Args:
            event: relation changed event.

        Returns:
            a Diff instance containing the added, deleted and changed
                keys from the event relation databag.
        """
        return diff(event, self.relation_data.data_component)


# Base ProviderData and RequiresData


class ProviderData(Data):
    """Base provides-side of the data products relation."""

    RESOURCE_FIELD = "database"

    def __init__(
        self,
        model: Model,
        relation_name: str,
    ) -> None:
        super().__init__(model, relation_name)
        self.data_component = self.local_app
        self._local_secret_fields = []
        self._remote_secret_fields = list(self.SECRET_FIELDS)

    def _update_relation_data(self, relation: Relation, data: Dict[str, str]) -> None:
        """Set values for fields not caring whether it's a secret or not."""
        keys = set(data.keys())
        if self.fetch_relation_field(relation.id, self.RESOURCE_FIELD) is None and keys:
            raise PrematureDataAccessError(
                "Premature access to relation data, update is forbidden before the connection is initialized."
            )
        super()._update_relation_data(relation, data)

    # Public functions -- inherited

    fetch_my_relation_data = leader_only(Data.fetch_my_relation_data)
    fetch_my_relation_field = leader_only(Data.fetch_my_relation_field)

    def _load_secrets_from_databag(self, relation: Relation) -> None:
        """Load secrets from the databag."""
        requested_secrets = get_encoded_list(relation, relation.app, REQ_SECRET_FIELDS)
        provided_secrets = get_encoded_list(relation, relation.app, PROV_SECRET_FIELDS)
        if requested_secrets is not None:
            self._local_secret_fields = requested_secrets

        if provided_secrets is not None:
            self._remote_secret_fields = provided_secrets


class RequirerData(Data):
    """Requirer-side of the relation."""

    SECRET_FIELDS = []

    def __init__(
        self,
        model,
        relation_name: str,
        additional_secret_fields: Optional[List[str]] = [],
    ):
        """Manager of base client relations."""
        super().__init__(model, relation_name)

        self._remote_secret_fields = list(self.SECRET_FIELDS)
        self._local_secret_fields = [
            field
            for field in self.SECRET_LABEL_MAP.keys()
            if field not in self._remote_secret_fields
        ]
        if additional_secret_fields:
            self._remote_secret_fields += additional_secret_fields
        self.data_component = self.local_unit

    # Public functions -- inherited

    fetch_my_relation_data = leader_only(Data.fetch_my_relation_data)
    fetch_my_relation_field = leader_only(Data.fetch_my_relation_field)

    def _load_secrets_from_databag(self, relation: Relation) -> None:
        """Load secrets from the databag."""
        requested_secrets = get_encoded_list(relation, self.local_unit, REQ_SECRET_FIELDS)
        provided_secrets = get_encoded_list(relation, self.local_unit, PROV_SECRET_FIELDS)
        if requested_secrets:
            self._remote_secret_fields = requested_secrets

        if provided_secrets:
            self._local_secret_fields = provided_secrets


class RequirerEventHandlers(EventHandlers):
    """Requires-side of the relation."""

    def __init__(self, charm: CharmBase, relation_data: RequirerData, unique_key: str = ""):
        """Manager of base client relations."""
        super().__init__(charm, relation_data, unique_key)

    def _on_relation_created_event(self, event: RelationCreatedEvent) -> None:
        """Event emitted when the relation is created."""
        if not self.relation_data.local_unit.is_leader():
            return

        if self.relation_data.remote_secret_fields:
            if self.relation_data.SCOPE == Scope.APP:
                set_encoded_field(
                    event.relation,
                    self.relation_data.local_app,
                    REQ_SECRET_FIELDS,
                    self.relation_data.remote_secret_fields,
                )

            set_encoded_field(
                event.relation,
                self.relation_data.local_unit,
                REQ_SECRET_FIELDS,
                self.relation_data.remote_secret_fields,
            )

        if self.relation_data.local_secret_fields:
            if self.relation_data.SCOPE == Scope.APP:
                set_encoded_field(
                    event.relation,
                    self.relation_data.local_app,
                    PROV_SECRET_FIELDS,
                    self.relation_data.local_secret_fields,
                )
            set_encoded_field(
                event.relation,
                self.relation_data.local_unit,
                PROV_SECRET_FIELDS,
                self.relation_data.local_secret_fields,
            )


class ProviderEventHandlers(EventHandlers):
    """Provider-side of the relation."""

    def __init__(self, charm: CharmBase, relation_data: ProviderData, unique_key: str = ""):
        """Manager of base client relations."""
        super().__init__(charm, relation_data, unique_key)

    def _on_relation_changed_event(self, event: RelationChangedEvent) -> None:
        """Event emitted when the relation data has changed."""
        requested_secrets = get_encoded_list(event.relation, event.relation.app, REQ_SECRET_FIELDS)
        provided_secrets = get_encoded_list(event.relation, event.relation.app, PROV_SECRET_FIELDS)
        if requested_secrets is not None:
            self.relation_data._local_secret_fields = requested_secrets

        if provided_secrets is not None:
            self.relation_data._remote_secret_fields = provided_secrets


class BucketEvent(RelationEvent):
    """Base class for bucket events."""

    @property
    def bucket(self) -> Optional[str]:
        """Returns the bucket was requested."""
        if not self.relation.app:
            return None

        return self.relation.data[self.relation.app].get("bucket", "")

    @property
    def path(self) -> Optional[str]:
        """Returns the path that was requested."""
        if not self.relation.app:
            return None

        return self.relation.data[self.relation.app].get("path", "")


class StorageConnectionInfoRequestedEvent(BucketEvent):
    """Event emitted when S3 credentials are requested on this relation."""


class StorageConnectionInfoChangedEvent(BucketEvent):
    """Event emitted when S3 credentials are changed for this relation."""


class StorageConnectionInfoGoneEvent(RelationEvent):
    """Event emitted when S3 credentials must be removed from this relation."""


class S3ProviderEvents(CharmEvents):
    """Events for the S3Provider side implementation."""

    storage_connection_info_requested = EventSource(StorageConnectionInfoRequestedEvent)


class S3RequirerEvents(CharmEvents):
    """Events for the S3Requirer side implementation."""

    s3_connection_info_changed = EventSource(StorageConnectionInfoChangedEvent)
    s3_connection_info_gone = EventSource(StorageConnectionInfoGoneEvent)


class S3RequirerData(RequirerData):
    """Requires-side data."""

    SECRET_FIELDS = ["access-key", "secret-key"]

    def __init__(self, model, relation_name: str, bucket: str, path: str) -> None:
        super().__init__(
            model,
            relation_name,
        )
        self._local_secret_fields: list[str] = []
        self.bucket = bucket
        self.path = path


class S3RequirerEventHandlers(RequirerEventHandlers):
    """Event handlers for for requirer side of S3 relation."""

    on = S3RequirerEvents()  # type: ignore

    def __init__(self, charm: CharmBase, relation_data: S3RequirerData):
        super().__init__(charm, relation_data)

        self.relation_name = relation_data.relation_name
        self.charm = charm
        self.local_app = self.charm.model.app
        self.local_unit = self.charm.unit

        self.framework.observe(
            self.charm.on[self.relation_name].relation_joined, self._on_relation_joined_event
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_relation_changed_event
        )

        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken,
            self._on_relation_broken_event,
        )

    def _on_relation_joined_event(self, event: RelationJoinedEvent) -> None:
        """Event emitted when the S3 relation is joined."""
        logger.debug(f"S3 relation ({event.relation.name}) joined...")
        event_data = {
            "bucket": self.relation_data.bucket,
            "path": self.relation_data.path,
            S3_LIB_VERSION_FIELD: f"{LIBAPI}.{LIBPATCH}",
        }
        self.relation_data.update_relation_data(event.relation.id, event_data)

    def get_s3_connection_info(self) -> Dict[str, str]:
        """Return the S3 connection info as a dictionary."""
        for relation in self.relations:
            if relation and relation.app:
                info = self.relation_data.fetch_relation_data([relation.id])[relation.id]
                if set(S3_REQUIRED_OPTIONS) - set(info):
                    continue
                info.pop(S3_LIB_VERSION_FIELD, None)
                return info
        return {}

    def _on_relation_changed_event(self, event: RelationChangedEvent) -> None:
        """Notify the charm about the presence of S3 credentials."""
        logger.debug(f"S3 relation ({event.relation.name}) changed...")

        diff = self._diff(event)
        if any(newval for newval in diff.added if self.relation_data._is_secret_field(newval)):
            self.relation_data._register_secrets_to_relation(event.relation, diff.added)

        is_provider_v0 = False
        provider_data = self.relation_data.fetch_relation_data([event.relation.id])[
            event.relation.id
        ]
        if len(provider_data) > 0 and S3_LIB_VERSION_FIELD not in provider_data:
            # This means that provider has written something on its part of relation data,
            # but that something is not its version -- this means provider will never write its version
            # because that's something the provider is meant to write first (on relation-created)!!!
            is_provider_v0 = True
        elif (
            S3_LIB_VERSION_FIELD in provider_data
            and float(provider_data[S3_LIB_VERSION_FIELD]) < 1
        ):
            is_provider_v0 = True

        if is_provider_v0 and not self.relation_data.fetch_my_relation_field(
            event.relation.id, "bucket"
        ):
            # The following line exists here due to compatibility for v1 requirer to work with v0 provider
            # The v0 provider will still wait for `bucket` to appear in the databag, and if it does not exist,
            # the provider will simply not write any data to the databag.
            bucket_name = f"relation-{event.relation.id}"
            self.relation_data.update_relation_data(event.relation.id, {"bucket": bucket_name})
            logger.info(
                f"s3_lib v1 detected that the provider is on v0, thus writing bucket={bucket_name} and exiting for now..."
            )
            return

        # check if the mandatory options are in the relation data
        contains_required_options = True
        credentials = self.get_s3_connection_info()
        missing_options = []
        for configuration_option in S3_REQUIRED_OPTIONS:
            if configuration_option not in credentials:
                contains_required_options = False
                missing_options.append(configuration_option)

        # emit credential change event only if all mandatory fields are present
        if contains_required_options:
            getattr(self.on, "s3_connection_info_changed").emit(
                event.relation, app=event.app, unit=event.unit
            )
        else:
            logger.warning(
                f"Some mandatory fields: {missing_options} are not present, do not emit credential change event!"
            )

    def _on_secret_changed_event(self, event: SecretChangedEvent) -> None:
        """Event handler for handling a new value of a secret."""
        if not event.secret.label:
            return

        relation = self.relation_data._relation_from_secret_label(event.secret.label)
        if not relation:
            logger.info(
                f"Received secret {event.secret.label} but couldn't parse, seems irrelevant."
            )
            return

        if event.secret.label != self.relation_data._generate_secret_label(
            relation.name,
            relation.id,
            "extra",
        ):
            logger.info("Secret is not relevant for us.")
            return

        if relation.app == self.charm.app:
            logger.info("Secret changed event ignored for Secret Owner")
            return

        remote_unit = None
        for unit in relation.units:
            if unit.app != self.charm.app:
                remote_unit = unit
                break
        else:
            return

        # check if the mandatory options are in the relation data
        contains_required_options = True
        credentials = self.get_s3_connection_info()
        missing_options = []
        for configuration_option in S3_REQUIRED_OPTIONS:
            if configuration_option not in credentials:
                contains_required_options = False
                missing_options.append(configuration_option)

        # emit credential change event only if all mandatory fields are present
        if contains_required_options:
            getattr(self.on, "s3_connection_info_changed").emit(
                relation, app=relation.app, unit=remote_unit
            )
        else:
            logger.warning(
                f"Some mandatory fields: {missing_options} are not present, do not emit credential change event!"
            )

    def _on_relation_broken_event(self, event: RelationBrokenEvent) -> None:
        """Event handler for handling relation_broken event."""
        logger.debug("S3 relation broken...")
        getattr(self.on, "s3_connection_info_gone").emit(
            event.relation, app=event.app, unit=event.unit
        )

    @property
    def relations(self) -> List[Relation]:
        """The list of Relation instances associated with this relation_name."""
        return list(self.charm.model.relations[self.relation_name])


class S3Requires(S3RequirerData, S3RequirerEventHandlers):
    """The requirer side of S3 relation."""

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
        bucket: str = "",
        path: str = "",
    ):
        S3RequirerData.__init__(self, charm.model, relation_name, bucket, path)
        S3RequirerEventHandlers.__init__(self, charm, self)


class S3ProviderData(ProviderData):
    """The Data abstraction of the provider side of S3 relation."""

    RESOURCE_FIELD = "bucket"

    def __init__(self, model: Model, relation_name: str) -> None:
        super().__init__(model, relation_name)

    def fetch_relation_data(
        self,
        relation_ids: list[int] | None = None,
        fields: list[str] | None = None,
        relation_name: str | None = None,
    ):
        """Override the behavior of `fetch_relation_data` to remove `bucket` field if request is from LIBAPI=0.

        This is required because LIBAPI=0 requirer automatically sets a bucket name as `relation-id-xxx` which used
        to be ignored by LIBAPI=1 provider when providing S3 credentials. The same behavior is expected from LIBAPI=1,
        if the request is from s3 lib with LIBAPI=0.
        """
        secret_fields = super().fetch_relation_data(
            relation_ids, [REQ_SECRET_FIELDS], relation_name
        )
        return_data = {}
        for relation_id, relation_data in (
            super()
            .fetch_relation_data(
                relation_ids=relation_ids, fields=fields, relation_name=relation_name
            )
            .items()
        ):
            return_data[relation_id] = relation_data
            if not secret_fields.get(relation_id, {}).get(REQ_SECRET_FIELDS):
                # This means the request is coming from S3 LIBAPI=0
                logger.info(
                    "The requirer is using s3 lib LIBAPI=0, thus discarding the 'bucket' parameter."
                )
                return_data[relation_id].pop("bucket", None)
        return return_data

    def _update_relation_data(self, relation: Relation, data: Dict[str, str]) -> None:
        """Override `update_relation_data` to bypass the parent's validation that raises PrematureDataAccessError."""
        relation_id = relation.id
        data_from_requirer = super().fetch_relation_data(
            [relation.id], [S3_LIB_VERSION_FIELD, self.RESOURCE_FIELD], relation.name
        )
        keys = set(data.keys())
        if (
            keys - {S3_LIB_VERSION_FIELD}
            and data_from_requirer.get(relation_id, {}).get(S3_LIB_VERSION_FIELD) is None
            and data_from_requirer.get(relation_id, {}).get(self.RESOURCE_FIELD) is None
        ):
            # The logic here is that the provider should not start writing S3 data to the databag
            # before the requirer has asked for it (during their relation-joined) with either:
            #           RESOURCE_FIELD: a field guaranteed to be there if LIBAPI=0
            #       OR  S3_LIB_VERSION_FIELD: a field guaranteed to be there if LIBAPI=1
            raise PrematureDataAccessError(
                "Premature access to relation data, update is forbidden before the connection is initialized."
            )
        super(ProviderData, self)._update_relation_data(relation, data)


class S3ProviderEventHandlers(EventHandlers):
    """The event handlers related to provider side of S3 relation."""

    on = S3ProviderEvents()  # type: ignore

    def __init__(self, charm: CharmBase, relation_data: S3ProviderData, unique_key: str = ""):
        super().__init__(charm, relation_data, unique_key)
        self.relation_data = relation_data

    def _on_relation_created_event(self, event: RelationJoinedEvent) -> None:
        """Event emitted when the S3 relation is created."""
        logger.debug(f"S3 relation ({event.relation.name}) created on provider side...")
        event_data = {
            S3_LIB_VERSION_FIELD: f"{LIBAPI}.{LIBPATCH}",
        }
        self.relation_data.update_relation_data(event.relation.id, event_data)

    def _on_relation_changed_event(self, event: RelationChangedEvent):
        if not self.charm.unit.is_leader():
            return
        self.on.storage_connection_info_requested.emit(
            event.relation, app=event.app, unit=event.unit
        )

    def _on_secret_changed_event(self, event: SecretChangedEvent) -> None:
        """Event emitted when the secret has changed.

        This method is called by the event handler on `secret-changed` event due to being registered in
        the parent class.If this method is overridden, `secret-changed` event need not be observed separately.
        """
        pass


class S3Provides(S3ProviderData, S3ProviderEventHandlers):
    """The provider side of the S3 relation."""

    def __init__(self, charm: CharmBase, relation_name: str) -> None:
        S3ProviderData.__init__(self, charm.model, relation_name)
        S3ProviderEventHandlers.__init__(self, charm, self)
