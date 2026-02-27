"""Module containing GCS specific relation classes."""

import logging

from ops import CharmBase, Relation

from .data import (
    StorageProviderData,
    StorageRequirerData,
)
from .domain import GCS, StorageContract
from .event_handlers import (
    StorageProviderEventHandlers,
    StorageRequirerEventHandlers,
)

logger = logging.getLogger(__name__)

GCS_STORAGE_CONTRACT = StorageContract(
    required_info=["bucket", "secret-key"],
    secret_fields=["secret-key"],
)


class GcsStorageRequires(StorageRequirerData[GCS], StorageRequirerEventHandlers):
    """Requirer helper preconfigured for the GCS backend.

    Args:
        charm: Parent charm.
        relation_name: Relation endpoint
        overrides: Optional requirer-side overrides to write on join/push.
    """

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
        overrides: dict[str, str] | None = None,
    ) -> None:
        StorageRequirerData.__init__(
            self, charm.model, relation_name, contract=GCS_STORAGE_CONTRACT
        )
        StorageRequirerEventHandlers.__init__(self, charm, self, overrides=overrides)


class GcsStorageProviderData(StorageProviderData):
    """Define the resource fields which is provided by requirer, otherwise provider will not publish any payload."""

    LEGACY_PROTOCOL_INITIATOR_FIELD = "requested-secrets"

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


class GcsStorageProviderEventHandlers(StorageProviderEventHandlers):
    """Provider-side event handlers preconfigured for GCS.

    Args:
        charm (CharmBase): Parent charm.
        relation_name (str): Relation endpoint name.
        unique_key (str): Optional key used by the base handler for
            idempotency or uniq semantics
    """

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
        unique_key: str = "",
    ):
        super().__init__(
            charm=charm,
            relation_data=GcsStorageProviderData(charm.model, relation_name),
            unique_key=unique_key,
        )
