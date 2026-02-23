"""Module containing S3 specific relation classes."""

import logging

from ops import CharmBase, Relation, RelationChangedEvent

from .constants import REQ_SECRET_FIELDS, SCHEMA_VERSION_FIELD
from .data import (
    StorageProviderData,
    StorageRequirerData,
)
from .domain import S3, StorageContract
from .event_handlers import (
    StorageProviderEventHandlers,
    StorageRequirerEventHandlers,
)

logger = logging.getLogger(__name__)

S3_STORAGE_CONTRACT = StorageContract(
    required_info=["access-key", "secret-key"],
    secret_fields=["access-key", "secret-key"],
)


class S3Requirer(StorageRequirerData[S3], StorageRequirerEventHandlers):
    """Requirer helper preconfigured for the S3 backend.

    Args:
        charm: Parent charm.
        relation_name: Relation endpoint
        overrides: Optional requirer-side overrides to write on join/push.
    """

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
        bucket: str = "",
        path: str = "",
    ):
        StorageRequirerData.__init__(
            self, charm.model, relation_name, contract=S3_STORAGE_CONTRACT
        )
        StorageRequirerEventHandlers.__init__(
            self, charm, self, overrides={"bucket": bucket, "path": path}
        )

    def is_provider_schema_v0(self, relation: Relation) -> bool:
        """Check if the S3 provider is using schema v0."""
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
        if (
            self.is_provider_schema_v0(event.relation)
            and self.charm.unit.is_leader()
            and not self.relation_data.fetch_my_relation_field(event.relation.id, "bucket")
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

        return super()._on_relation_changed_event(event)


class S3Provider(StorageProviderData, StorageProviderEventHandlers):
    """The provider class for S3 relation."""

    LEGACY_PROTOCOL_INITIATOR_FIELD = "bucket"

    def __init__(self, charm: CharmBase, relation_name: str) -> None:
        StorageProviderData.__init__(self, charm.model, relation_name)
        StorageProviderEventHandlers.__init__(self, charm, self)

    def is_protocol_ready(self, relation: Relation) -> bool:
        """Check whether the protocol has been initialized by the requirer.

        This means that the requirer has set up the necessary data, and now
        the provider is ready to start sharing the data.

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

    def is_requirer_schema_v0(self, relation_id: int, relation_name: str | None = None) -> bool:
        """Check if the S3 requirer is using schema v0."""
        secret_fields = super().fetch_relation_data(
            [relation_id], [REQ_SECRET_FIELDS], relation_name
        )
        if not secret_fields.get(relation_id, {}).get(REQ_SECRET_FIELDS):
            return True
        return False

    def fetch_relation_data(
        self,
        relation_ids: list[int] | None = None,
        fields: list[str] | None = None,
        relation_name: str | None = None,
    ):
        """Override the behavior of `fetch_relation_data` to remove `bucket` field if request is from v0.

        This is required because v0 requirer automatically sets a bucket name as `relation-id-xxx` which used
        to be ignored by v0 provider when providing S3 credentials. The same behavior is expected from v1,
        if the request is from s3 lib with v0.
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
