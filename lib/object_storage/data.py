#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The base interface classes common for all object storage integrators."""

from __future__ import annotations

import copy
import json
import logging
from abc import ABC, abstractmethod
from typing import (
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Set,
    Tuple,
    Union,
    overload,
)  # using py38-style typing

from ops import (
    Application,
    JujuVersion,
    Model,
    ModelError,
    Unit,
)
from ops.model import Relation

from .constants import SCHEMA_VERSION_FIELD
from .decorators import juju_secrets_only, leader_only
from .domain import (
    GCS,
    S3,
    AzureStorage,
    AzureStorageInfo,
    GcsInfo,
    S3Info,
    Scope,
    StorageBackend,
    StorageContract,
)
from .exceptions import (
    DataInterfacesError,
    PrematureDataAccessError,
    SecretError,
)
from .secrets import SECRET_GROUPS, CachedSecret, SecretCache, SecretGroup
from .utils import get_encoded_list

ENTITY_USER = "USER"
ENTITY_GROUP = "GROUP"

PROV_SECRET_PREFIX = "secret-"
PROV_SECRET_FIELDS = "provided-secrets"
REQ_SECRET_FIELDS = "requested-secrets"


logger = logging.getLogger(__name__)


class Data(ABC):
    """Base relation data manipulation (abstract) class."""

    SCOPE = Scope.APP

    # Local map to associate mappings with secrets potentially as a group
    SECRET_LABEL_MAP: Dict[str, SecretGroup] = {}

    SECRET_FIELDS: List[str] = []

    def __init__(
        self,
        model: Model,
        relation_name: str,
    ) -> None:
        self._model = model
        self.local_app = self._model.app
        self.local_unit = self._model.unit
        self.relation_name = relation_name
        self._jujuversion: Optional[JujuVersion] = None
        self.component = self.local_app if self.SCOPE == Scope.APP else self.local_unit
        self.secrets = SecretCache(self._model, self.component)
        self.data_component: Optional[Union[Unit, Application]] = None
        self._local_secret_fields: List[str] = []
        self._remote_secret_fields = list(self.SECRET_FIELDS)

    @property
    def relations(self) -> List[Relation]:
        """The list of Relation instances associated with this relation_name."""
        return self._model.relations[self.relation_name]

    @property
    def secrets_enabled(self) -> bool:
        """Is this Juju version allowing for Secrets usage?"""
        if not self._jujuversion:
            self._jujuversion = JujuVersion.from_environ()
        return self._jujuversion.has_secrets

    @property
    def secret_label_map(self) -> Dict[str, SecretGroup]:
        """Exposing secret-label map via a property -- could be overridden in descendants!"""
        return self.SECRET_LABEL_MAP

    @property
    def local_secret_fields(self) -> Optional[List[str]]:
        """Local access to secrets field, in case they are being used."""
        if self.secrets_enabled:
            return self._local_secret_fields
        return None

    @property
    def remote_secret_fields(self) -> Optional[List[str]]:
        """Local access to secrets field, in case they are being used."""
        if self.secrets_enabled:
            return self._remote_secret_fields
        return None

    @property
    def my_secret_groups(self) -> Optional[List[SecretGroup]]:
        """Local access to secrets field, in case they are being used."""
        if self.secrets_enabled:
            return [
                self.SECRET_LABEL_MAP[field]
                for field in self._local_secret_fields
                if field in self.SECRET_LABEL_MAP
            ]
        return None

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
            return None

        if secret_uri := self.get_secret_uri(relation, group_mapping):
            return self.secrets.get(label, secret_uri)

        return None

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
            return None

        contents.pop()  # ".secret" at the end
        contents.pop()  # Group mapping
        relation_id_str = contents.pop()
        try:
            relation_id = int(relation_id_str)
        except ValueError:
            return None

        # In case '.' character appeared in relation name
        relation_name = ".".join(contents)

        try:
            return self.get_relation(relation_name, relation_id)
        except ModelError:
            return None

    def _group_secret_fields(self, secret_fields: List[str]) -> Dict[SecretGroup, List[str]]:
        """Helper function to arrange secret mappings under their group.

        NOTE: All unrecognized items end up in the 'extra' secret bucket.
        Make sure only secret fields are passed!
        """
        secret_fieldnames_grouped: Dict[SecretGroup, List[str]] = {}
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
        return None

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
        result: Dict[str, str] = {}
        normal_fields: List[str] = []

        if not fields:
            if component not in relation.data:
                return {}

            all_fields = list(relation.data[component].keys())
            normal_fields = [field for field in all_fields if not self._is_secret_field(field)]
            fields = normal_fields + req_secret_fields if req_secret_fields else normal_fields

        if fields:
            result, normal_fields_set = self._process_secret_fields(
                relation, req_secret_fields, fields, self._get_group_secret_contents
            )
            normal_fields = list(normal_fields_set)

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
        return None

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


class StorageRequirerData(Data, Generic[StorageBackend]):
    """Helper for managing requirer-side storage connection data and secrets.

    This class encapsulates reading/writing relation data, tracking which
    fields are considered secret, and mapping secret fields to Juju secret
    labels/IDs. It is typically configured from a Contract
    so different backends (S3, Azure, GCS) can reuse the same flow.
    """

    SECRET_LABEL_MAP = {}

    def __init__(
        self,
        model: Model,
        relation_name: str,
        contract: StorageContract,
    ) -> None:
        """Create a new requirer data manager for a given relation.

        Initializes the instance with the provided backend using the
        available contract.

        Args:
            model: The Juju model instance from the charm.
            relation_name : Relation endpoint name used by this requirer.
            contract: StorageContract instance describing the storage contract.
        """
        self.contract = contract

        # PASS secret-fields PER INSTANCE; do not touch class variables.
        super().__init__(
            model=model,
            relation_name=relation_name,
        )

        self._remote_secret_fields = list(self.contract.secret_fields)
        self._local_secret_fields = [
            field
            for field in self.SECRET_LABEL_MAP.keys()
            if field not in self._remote_secret_fields
        ]
        self.data_component = self.local_unit

    # Public functions

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

    @overload
    def get_storage_connection_info(
        self: StorageRequirerData[S3], relation: Relation | None = None
    ) -> S3Info: ...

    @overload
    def get_storage_connection_info(
        self: StorageRequirerData[GCS], relation: Relation | None = None
    ) -> GcsInfo: ...

    @overload
    def get_storage_connection_info(
        self: StorageRequirerData[AzureStorage], relation: Relation | None = None
    ) -> AzureStorageInfo: ...

    def get_storage_connection_info(self, relation: Relation | None = None):  # type: ignore
        """Assemble the storage connection info for a relation.

        Combines the provider-published relation data and any readable secrets
        to produce a flat dictionary usable by the requirer.

        Args:
            relation: Relation object to read from.

        Returns:
            dict[str, str]: Connection info (may be empty if relation/app does not exist).
        """
        info = {}
        if not relation:
            relation = next(iter(self.relations), None)
        if relation and relation.app:
            for key, value in self.fetch_relation_data([relation.id])[relation.id].items():
                try:
                    info[key] = json.loads(value)
                except (json.decoder.JSONDecodeError, TypeError):
                    info[key] = value
            info.pop(SCHEMA_VERSION_FIELD, None)
        return info  # type: ignore


class StorageProviderData(Data):
    """Responsible for publishing provider-owned connection information to the relation databag."""

    PROTOCOL_INITIATOR_FIELD = SCHEMA_VERSION_FIELD

    def __init__(self, model: Model, relation_name: str) -> None:
        """Initialize the provider data helper.

        Args:
            model (Model): The Juju model instance.
            relation_name (str): Provider relation endpoint name.
        """
        super().__init__(model, relation_name)
        self._local_secret_fields = []
        self._remote_secret_fields = list(self.SECRET_FIELDS)

    def is_protocol_ready(self, relation: Relation) -> bool:
        """Check whether the protocol has been initialized by the requirer.

        This means that the requirer has set up the necessary data, and now
        the provider is ready to start sharing the data.

        Args:
            relation (Relation): The relation to check.

        Returns:
            bool: True if the protocol has been initialized, False otherwise.
        """
        return self.fetch_relation_field(relation.id, self.PROTOCOL_INITIATOR_FIELD) is not None

    def _update_relation_data(self, relation: Relation, data: Dict[str, str]) -> None:
        """Set values for fields not caring whether it's a secret or not."""
        keys = set(data.keys())

        if not self.is_protocol_ready(relation) and not keys.issubset({SCHEMA_VERSION_FIELD}):
            # Schema version is allowed to be written before protocol is ready, but no other field should be written before that.
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
