#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


"""Application charm that connects to object storage provider charm.

This charm is meant to be used only for testing
the s3 requires-provides relation.
"""

import logging


from object_storage import (
    StorageConnectionInfoChangedEvent, StorageConnectionInfoGoneEvent, S3Requirer
)
from ops.charm import CharmBase, RelationJoinedEvent
from ops import ActionEvent, main
from ops.model import ActiveStatus, WaitingStatus

logger = logging.getLogger(__name__)

S3_RELATION_NAME = "s3-credentials"

class ApplicationCharm(CharmBase):
    """Application charm that relates to S3 integrator."""

    def __init__(self, *args):
        super().__init__(*args)

        # Default charm events.
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

        # Events related to the requested database
        # (these events are defined in the database requires charm library).
        bucket = self.config.get("bucket", "")
        path = self.config.get("path", "")
        self.s3_requirer = S3Requirer(self, S3_RELATION_NAME, bucket=bucket, path=path)

        # add relation
        self.framework.observe(
            self.s3_requirer.on.storage_connection_info_changed,
            self._on_storage_connection_info_changed,
        )
        self.framework.observe(
            self.on[S3_RELATION_NAME].relation_joined, self._on_relation_joined
        )

        self.framework.observe(
            self.s3_requirer.on.storage_connection_info_gone,
            self._on_storage_connection_info_gone,
        )

        self.framework.observe(self.on.get_s3_connection_info_action, self._on_get_s3_connection_info_action)


    def _on_start(self, _) -> None:
        """Only sets an waiting status."""
        if self.model.get_relation(S3_RELATION_NAME):
            self.unit.status = ActiveStatus()
        else:
            self.unit.status = WaitingStatus("Waiting for relation")

    def _on_config_changed(self, _) -> None:
        bucket = self.config.get("bucket", "")
        path = self.config.get("path", "")
        if (rel := self.model.get_relation(S3_RELATION_NAME)):
            self.s3_requirer.update_relation_data(rel.id, {"bucket": bucket, "path": path})

    def _on_relation_joined(self, _: RelationJoinedEvent):
        """On s3 credential relation joined."""
        logger.info("S3 relation joined...")
        self.unit.status = ActiveStatus()

    def _on_storage_connection_info_changed(self, e: StorageConnectionInfoChangedEvent):
        credentials = self.s3_requirer.get_storage_connection_info()
        logger.info(f"S3 credentials have changed...")

    def _on_storage_connection_info_gone(self, _: StorageConnectionInfoGoneEvent):
        logger.info("S3 credentials gone...")
        self.unit.status = WaitingStatus("Waiting for relation")

    def _on_get_s3_connection_info_action(self, event: ActionEvent) -> None:
        event.set_results(self.s3_requirer.get_storage_connection_info())



if __name__ == "__main__":
    main(ApplicationCharm)
