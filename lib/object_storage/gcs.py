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


class GCSRequirer(StorageRequirerData[GCS], StorageRequirerEventHandlers):
    """Requirer helper preconfigured for the GCS backend.

    Args:
        charm: Parent charm.
        relation_name: Relation endpoint
        bucket: Optional bucket name requested by the requirer charm.
    """

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
        bucket: str = "",
    ) -> None:
        StorageRequirerData.__init__(
            self, charm.model, relation_name, contract=GCS_STORAGE_CONTRACT
        )
        StorageRequirerEventHandlers.__init__(self, charm, self, requests={"bucket": bucket})

    def update_requests(
        self,
        relation_id: int | None = None,
        *,
        bucket: str | None = None,
    ) -> None:
        """Update bucket request for given relation or all active relations."""
        return super()._update_requests(relation_id=relation_id, bucket=bucket)


class GCSProvider(StorageProviderData, StorageProviderEventHandlers):
    """Provider helper preconfigured for the GCS backend.

    Args:
        charm: Parent charm.
        relation_name: Relation endpoint
    """

    LEGACY_PROTOCOL_INITIATOR_FIELD = "requested-secrets"

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
    ) -> None:
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
