#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The base interface classes common for all object storage integrators."""

from __future__ import annotations

import json
import logging
from abc import abstractmethod
from typing import (
    Any,
    Dict,
    Iterable,
    Optional,
    cast,
)  # using py38-style typing

from ops import (
    Object,
    RelationCreatedEvent,
    Unit,
)
from ops.charm import (
    CharmBase,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationJoinedEvent,
    SecretChangedEvent,
)
from ops.model import Relation

from .constants import SCHEMA_VERSION, SCHEMA_VERSION_FIELD
from .data import Data, StorageProviderData, StorageRequirerData
from .domain import (
    Scope,
)
from .events import StorageProviderEvents, StorageRequirerEvents
from .utils import Diff, diff, get_encoded_list, set_encoded_field

ENTITY_USER = "USER"
ENTITY_GROUP = "GROUP"

PROV_SECRET_PREFIX = "secret-"
PROV_SECRET_FIELDS = "provided-secrets"
REQ_SECRET_FIELDS = "requested-secrets"


logger = logging.getLogger(__name__)


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
            self.charm.on[relation_data.relation_name].relation_created,
            self._on_relation_created_event,
        )
        self.framework.observe(
            charm.on[self.relation_data.relation_name].relation_joined,
            self._on_relation_joined_event,
        )
        self.framework.observe(
            charm.on[self.relation_data.relation_name].relation_changed,
            self._on_relation_changed_event,
        )
        self.framework.observe(
            charm.on[self.relation_data.relation_name].relation_broken,
            self._on_relation_broken_event,
        )
        self.framework.observe(
            charm.on.secret_changed,
            self._on_secret_changed_event,
        )

    # Event handlers

    def _on_relation_created_event(self, event: RelationCreatedEvent) -> None:
        """Event emitted when the relation is created."""
        pass

    def _on_relation_joined_event(self, event: RelationJoinedEvent) -> None:
        """Event emitted when the relation is joined."""
        pass

    @abstractmethod
    def _on_relation_changed_event(self, event: RelationChangedEvent) -> None:
        """Event emitted when the relation data has changed."""
        raise NotImplementedError

    def _on_relation_broken_event(self, event: RelationBrokenEvent) -> None:
        """Event emitted when the relation is broken."""
        pass

    def _on_secret_changed_event(self, event: SecretChangedEvent) -> None:
        """Event emitted when secret data has changed."""
        pass

    def _diff(self, event: RelationChangedEvent) -> Diff:
        """Retrieves the diff of the data in the relation changed databag.

        Args:
            event: relation changed event.

        Returns:
            a Diff instance containing the added, deleted and changed
                keys from the event relation databag.
        """
        return diff(event, self.relation_data.data_component)


class StorageRequirerEventHandlers(EventHandlers):
    """Bind the requirer lifecycle to the relation's events.

    Validates that all required and secret fields are present, registers newly discovered secret
    keys, and emits higher-level requirer events.

    Emits:
        StorageRequirerEvents.storage_connection_info_changed:
            When all required + secret fields are present or become present.
        StorageRequirerEvents.storage_connection_info_gone:
            When the relation is broken (connection info no longer available).

    Args:
        charm (CharmBase): The charm being configured.
        relation_data (StorageRequirerData): Helper for relation data and secrets.
        overrides (Dict): The key-value pairs that being overridden in the relation data.
    """

    on = StorageRequirerEvents()  # pyright: ignore[reportAssignmentType]

    def __init__(
        self,
        charm: CharmBase,
        relation_data: StorageRequirerData,
        overrides: dict[str, str] | None = None,
    ):
        """Initialize the requirer event handlers.

        Subscribes to relation_joined, relation_changed, relation_broken,
        and secret_changed events to coordinate data and secret flow.

        Args:
            charm (CharmBase): The parent charm instance.
            relation_data (StorageRequirerData): Requirer-side relation data helper.
            overrides (Dict): The key-value pairs that being overridden in the relation data.
        """
        super().__init__(charm, relation_data)

        self.relation_name = relation_data.relation_name
        self.charm = charm
        self.local_app = self.charm.model.app
        self.local_unit = self.charm.unit
        self.contract = relation_data.contract
        self.overrides = overrides
        self._last_overrides: dict[str, str] = {}

    def _active_relations(self) -> list[Relation]:
        return list(self.charm.model.relations.get(self.relation_name, []))

    def _all_required_info_present(self, relation: Relation) -> bool:
        info = cast(StorageRequirerData, self.relation_data).get_storage_connection_info(relation)
        if self.contract:
            return all(k in info for k in self.contract.required_info)
        return False

    def _missing_fields(self, relation: Relation) -> list[str]:
        info = cast(StorageRequirerData, self.relation_data).get_storage_connection_info(relation)
        missing = []
        if self.contract:
            for k in self.contract.required_info:
                if k not in info:
                    missing.append(k)
        return missing

    @staticmethod
    def _get_keys_as_set(obj) -> set[str]:
        if obj is None:
            return set()
        if isinstance(obj, dict):
            return set(obj.keys())
        if isinstance(obj, Iterable) and not isinstance(obj, (str, bytes)):
            return set(obj)
        return set()

    def _register_new_secrets(self, event: RelationChangedEvent) -> None:
        diff = self._diff(event)

        candidate = self._get_keys_as_set(getattr(diff, "added", None)) | self._get_keys_as_set(
            getattr(diff, "changed", None)
        )
        if not candidate:
            return

        # Get keys which are declared as secret in the contract
        secret_keys = [k for k in candidate if self.relation_data._is_secret_field(k)]
        if not secret_keys:
            return

        self.relation_data._register_secrets_to_relation(event.relation, secret_keys)

    def set_overrides(
        self,
        overrides: dict[str, str] | None,
        *,
        push: bool = True,
        relation_id: int | None = None,
    ) -> None:
        """Update default overrides for all relations using push True.

        Args:
          overrides: New overrides (None means {}).
          push: If True, also write to existing relation(s) now.
          relation_id: Limit pushing to a specific relation id.
        """
        new_overrides = (overrides or {}).copy()
        if new_overrides == self._last_overrides == self.overrides:
            return
        self.overrides = new_overrides

        if not push:
            return

        if relation_id is not None:
            self.write_overrides(new_overrides, relation_id=relation_id)
        else:
            for rel in self._active_relations():
                self.write_overrides(new_overrides, relation_id=rel.id)

        self._last_overrides = new_overrides.copy()

    def write_overrides(
        self,
        overrides: dict[str, str],
        relation_id: int | None = None,
    ) -> None:
        """Write/merge override keys into the requirer app databag.

        Only the leader writes. ``None`` values are ignored.

        Args:
            overrides (dict[str, str]): Keys/values to merge into app databag.
            relation_id (int | None): Specific relation id to target; if omitted,
                applies to all active relations for this endpoint.
        """
        if not overrides:
            return
        if not self.charm.unit.is_leader():
            return

        payload = {k: v for k, v in overrides.items() if v is not None}
        self.relation_data.update_relation_data(relation_id, payload)

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

    def _on_relation_joined_event(self, event: RelationJoinedEvent) -> None:
        """Handle relation-joined, apply optional requirer-side overrides."""
        logger.info(f"Storage relation ({event.relation.name}) joined...")
        if not self.overrides or not self.charm.unit.is_leader():
            return

        payload = {k: v for k, v in self.overrides.items() if v is not None}
        payload[SCHEMA_VERSION_FIELD] = str(SCHEMA_VERSION)
        self.relation_data.update_relation_data(event.relation.id, payload)

    def _on_relation_changed_event(self, event: RelationChangedEvent) -> None:
        """Validate fields on relation-changed and emit requirer events."""
        logger.info("Storage relation (%s) changed", event.relation.name)
        self._register_new_secrets(event)

        if self._all_required_info_present(event.relation):
            getattr(self.on, "storage_connection_info_changed").emit(
                relation=event.relation, app=event.app, unit=event.unit
            )
        else:
            missing = self._missing_fields(event.relation)
            logger.warning(
                "Some mandatory fields: %s are not present, do not emit credential change event!",
                ",".join(missing),
            )

    def _on_secret_changed_event(self, event: SecretChangedEvent) -> None:
        """React to secret changes by re-validating and emitting if complete."""
        if not event.secret.label:
            return
        relation = self.relation_data._relation_from_secret_label(event.secret.label)
        if not relation:
            logger.info(
                "Received secret-changed for label %s, but no matching relation was found; ignoring.",
                event.secret.label,
            )
            return

        if relation.name != self.relation_name:
            logger.info(
                "Ignoring secret-changed from endpoint %s (expected %s)",
                relation.name,
                self.relation_name,
            )
            return

        if relation.app == self.charm.app:
            logger.info("Secret changed event ignored for Secret Owner")
            return

        remote_unit: Optional[Unit] = None
        for unit in relation.units:
            if unit.app != self.charm.app:
                remote_unit = unit
                break

        if self._all_required_info_present(relation):
            getattr(self.on, "storage_connection_info_changed").emit(
                relation=relation, app=relation.app, unit=remote_unit
            )
        else:
            missing = self._missing_fields(relation)
            logger.warning(
                "Some mandatory fields: %s are not present, do not emit credential change event!",
                ",".join(missing),
            )

    def _on_relation_broken_event(self, event: RelationBrokenEvent) -> None:
        """Emit gone when the relation is broken."""
        logger.info("Storage relation broken...")
        getattr(self.on, "storage_connection_info_gone").emit(
            relation=event.relation, app=event.app, unit=event.unit
        )


class StorageProviderEventHandlers(EventHandlers):
    """Listen for requirer changes and emits a higher-level events."""

    on = StorageProviderEvents()

    def __init__(
        self,
        charm: CharmBase,
        relation_data: StorageProviderData,
        unique_key: str = "",
    ):
        """Initialize provider event handlers.

        Args:
            charm (CharmBase): Parent charm.
            relation_data (StorageProviderData): Provider data helper.
            unique_key (str): Optional key used by the base handler for
                idempotency or uniq semantics.
        """
        super().__init__(charm, relation_data, unique_key)

    def _on_relation_created_event(self, event: RelationCreatedEvent) -> None:
        """Event emitted when the S3 relation is created."""
        logger.debug(f"S3 relation ({event.relation.name}) created on provider side...")
        event_data = {
            SCHEMA_VERSION_FIELD: str(SCHEMA_VERSION),
        }
        self.relation_data.update_relation_data(event.relation.id, event_data)

    def _on_relation_changed_event(self, event: RelationChangedEvent) -> None:
        """Emit a request for connection info when the requirer changes."""
        if not self.charm.unit.is_leader():
            return
        requested_secrets = get_encoded_list(event.relation, event.relation.app, REQ_SECRET_FIELDS)
        provided_secrets = get_encoded_list(event.relation, event.relation.app, PROV_SECRET_FIELDS)
        if requested_secrets is not None:
            self.relation_data._local_secret_fields = requested_secrets

        if provided_secrets is not None:
            self.relation_data._remote_secret_fields = provided_secrets

        if not cast(StorageProviderData, self.relation_data).is_protocol_ready(event.relation):
            logger.info(
                "Protocol not ready for relation %s, thus not emitting storage_connection_info_requested event.",
                event.relation.name,
            )
            return
        self.on.storage_connection_info_requested.emit(
            relation=event.relation, app=event.app, unit=event.unit
        )

    def set_storage_connection_info(self, relation_id: str, data: Dict[str, Any]) -> None:
        """Set the storage connection info for a relation.

        Args:
            relation_id: ID of relation to set storage connection info for.
            data: Connection info to set for the relation.
        """
        # Replace null values with empty strings, as Juju databag does not allow null values.
        data = {k: (v if v is not None else "") for k, v in data.items()}
        if data.get("tls-ca-chain"):
            data["tls-ca-chain"] = json.dumps(data["tls-ca-chain"])
        return self.relation_data.update_relation_data(relation_id=relation_id, data=data)
