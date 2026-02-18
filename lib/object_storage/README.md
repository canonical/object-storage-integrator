A lightweight library for communicating between Cloud storages provider and requirer charms.

This library implements a common object-storage contract and the relation/event plumbing to publish
and consume storage connection info.


### Provider charm

A provider publishes the payload when the requirer asks for it. It is needed to wire the handlers and
emit on demand.

Example:
```python

from charms.data_platform_libs.v0.object_storage import (
    StorageConnectionInfoRequestedEvent,
    S3Provider,
)

class ExampleProviderCharm(CharmBase):

    def __init__(self, charm: CharmBase):
        super().__init__(charm, "example-provider")

        self.s3_provider = S3Provider(self, S3_RELATION_NAME)
        self.framework.observe(
            self.s3_provider.on.storage_connection_info_requested,
            self._on_storage_connection_info_requested,
        )

    def _on_storage_connection_info_requested(
        self, event: StorageConnectionInfoRequestedEvent
    ) -> None:
        if not self.charm.unit.is_leader():
            return
        bucket_name = self.charm.config.get("bucket")
        access_key, secret_key = prepare_keys(self.charm.config.get("credentials"))

        self.s3_provider.update_relation_data(
            {"bucket": bucket_name, "access-key": access_key, "secret-key": secret_key}
        )


if __name__ == "__main__":
    main(ExampleProviderCharm)
```

### Requirer charm

A requirer consumes the published fields.

An example of requirer charm using S3 storage is the following:

Example:
```python

from s3_lib import S3Requirer, StorageConnectionInfoChangedEvent, StorageConnectionInfoGoneEvent

class ExampleRequirerCharm(CharmBase):

    def __init__(
        self,
        charm: CharmBase,
    ):
        super().__init__(charm, "s3-requirer")
        self.charm = charm
        self.s3_client = S3Requirer(
            charm, relation_name, bucket="test-bucket"
        )
        self.framework.observe(
            self.s3_client.on.storage_connection_info_changed, self._on_conn_info_changed
        )
        self.framework.observe(
            self.s3_client.on.storage_connection_info_gone, self._on_conn_info_gone
        )

    def _on_conn_info_changed(self, event: StorageConnectionInfoChangedEvent):
        # access data from the provider
        connection_info = self.s3_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_credential_gone(self, event: StorageConnectionInfoGoneEvent):
        # credentials are removed
        process_connection_info(None)

 if __name__ == "__main__":
    main(ExampleRequirerCharm)
```