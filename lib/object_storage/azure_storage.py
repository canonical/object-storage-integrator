"""Module containing Azure Storage specific relation classes."""

import logging
from typing import Optional

from ops import CharmBase, Relation, RelationChangedEvent

from object_storage.domain import AzureStorage, StorageContract

from .constants import SCHEMA_VERSION_FIELD
from .data import (
    StorageProviderData,
    StorageRequirerData,
)
from .event_handlers import (
    StorageProviderEventHandlers,
    StorageRequirerEventHandlers,
)

logger = logging.getLogger(__name__)

AZURE_STORAGE_CONTRACT = StorageContract(
    required_info=["container", "storage-account", "secret-key", "connection-protocol"],
    secret_fields=["secret-key"],
)


class AzureStorageRequirer(StorageRequirerData[AzureStorage], StorageRequirerEventHandlers):
    """Requirer helper preconfigured for the Azure Storage backend.

    Args:
        charm: Parent charm.
        relation_name: Relation endpoint
        container: Optional container name requested by the requirer.
    """

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
        container: str = "",
    ) -> None:
        StorageRequirerData.__init__(
            self, charm.model, relation_name, contract=AZURE_STORAGE_CONTRACT
        )
        StorageRequirerEventHandlers.__init__(
            self, charm, self, overrides={"container": container}
        )

    def is_provider_schema_v0(self, relation: Relation) -> bool:
        """Check if the Azure storage provider is using schema v0."""
        provider_data = self.relation_data.fetch_relation_data([relation.id])[relation.id]
        if len(provider_data) > 0 and SCHEMA_VERSION_FIELD not in provider_data:
            # This means that provider has written something on its part of relation data,
            # but that something is not the schema version -- this means provider will never write schema version
            # because that's the first thing the provider is meant to write in relation (on relation-created)!!!
            return True
        elif (
            SCHEMA_VERSION_FIELD in provider_data
            and float(provider_data[SCHEMA_VERSION_FIELD]) < 1
        ):
            return True
        return False

    def _on_relation_changed_event(self, event: RelationChangedEvent) -> None:
        if self.is_provider_schema_v0(
            event.relation
        ) and not self.relation_data.fetch_my_relation_field(event.relation.id, "container"):
            # The following line exists here due to compatibility for v1 requirer to work with v0 provider
            # The v0 provider will still wait for `container` to appear in the databag, and if it does not exist,
            # the provider will simply not write any data to the databag.
            container_name = f"relation-{event.relation.id}"
            self.relation_data.update_relation_data(
                event.relation.id, {"container": container_name}
            )
            logger.info(
                f"azure_storage_lib v1 detected that the provider is on v0, thus writing container={container_name} and exiting for now..."
            )
            return

        return super()._on_relation_changed_event(event)


class AzureStorageProvider(StorageProviderData, StorageProviderEventHandlers):
    """The provider class for Azure Storage relation."""

    LEGACY_PROTOCOL_INITIATOR_FIELD = "container"

    def __init__(self, charm: CharmBase, relation_name: str) -> None:
        StorageProviderData.__init__(self, charm.model, relation_name)
        StorageProviderEventHandlers.__init__(self, charm, self)

    def is_protocol_ready(self, relation: Relation) -> bool:
        """Check whether the protocol has been initialized by the requirer.

        Args:
            relation (Relation): The relation to check.

        Returns:
            bool: True if the protocol has been initialized, False otherwise.
        """
        # IMPORTANT!
        # Use super().fetch_relation_data instead of self.fetch_relation_data
        # to avoid the override in this class which discards the 'bucket' field
        data = super().fetch_relation_data(
            [relation.id],
            [self.PROTOCOL_INITIATOR_FIELD, self.LEGACY_PROTOCOL_INITIATOR_FIELD],
            relation.name,
        )
        return (
            data.get(relation.id, {}).get(self.PROTOCOL_INITIATOR_FIELD) is not None
            or data.get(relation.id, {}).get(self.LEGACY_PROTOCOL_INITIATOR_FIELD) is not None
        )

    def is_requirer_schema_v0(self, relation_id: int, relation_name: Optional[str]) -> bool:
        """Check if the Azure requirer is using older schema."""
        version_field = super().fetch_relation_data(
            [relation_id], [SCHEMA_VERSION_FIELD], relation_name
        )
        if not version_field.get(relation_id, {}).get(SCHEMA_VERSION_FIELD):
            return True
        return False

    def fetch_relation_data(
        self,
        relation_ids: list[int] | None = None,
        fields: list[str] | None = None,
        relation_name: str | None = None,
    ):
        """Override the behavior of `fetch_relation_data` to remove `container` field if request is from v0.

        This is required because v0 requirer automatically sets a container name as `relation-id-xxx` which used
        to be ignored by v0 provider when providing Azure Storage credentials. The same behavior is expected from v1,
        if the request is from azure_storage lib with v0.
        """
        data = super().fetch_relation_data(
            relation_ids=relation_ids, fields=fields, relation_name=relation_name
        )
        for relation_id in data:
            if self.is_requirer_schema_v0(relation_id, relation_name):
                logger.info(
                    "The requirer is using s3 lib schema v0, thus discarding the 'bucket' parameter."
                )
                data[relation_id].pop("bucket", None)
        return data
