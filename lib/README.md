# Object Storage Charmlib

The `object-storage-charmlib` is a Python charm interface library for communication between object storage integrator charms and the requirer charms that relate with it. This library implements a common object-storage contract and the relation/event plumbing to publish
and consume storage connection info.

The following object storage providers are currently supported:
1. AWS S3 (and S3 compliant providers)
2. Azure Blob Storage / Azure Data Lake Storage (ADLS)
3. Google Cloud Storage (GCS)

When two charms are related over an object storage relation interface, the one providing the object storage
credentials is termed as Provider and the one that consumes those credentials is termed as Requirer. A provider 
publishes the payload when the requirer asks for it.

## Usage: `S3Provider`
The `S3Provider` class can be used by the provider charm (eg, `s3-integrator`) to share S3 bucket and connection information to the requirer charm (eg, `postgresql`).

The provider needs to instantiate the `S3Provider` class, and then listen to `storage_connection_info_requested` custom event. When handling the event, the provider needs to set the S3 storage connection information using the function `set_storage_connection_info` in the `S3Provider` class.

```python

from object_storage import (
    StorageConnectionInfoRequestedEvent,
    S3Provider,
)

class ExampleProviderCharm(CharmBase):

    def __init__(self, charm: CharmBase):
        super().__init__(charm, "s3-provider")

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

        self.s3_provider.set_storage_connection_info(
            relation_id=event.relation.id,
            data={"bucket": bucket_name, "access-key": access_key, "secret-key": secret_key}
        )


if __name__ == "__main__":
    main(ExampleProviderCharm)
```


## Usage: `S3Requirer`

The `S3Requirer` class can be used by the requirier charm (eg, `postgresql`) to request and receive S3 bucket and credentials from the provider charm (eg, `s3-integrator`).

The requrier charm needs to instantiate the `S3Requirer` class -- optionally with additional request for a particular bucket and/or a path -- and then listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone`. When handling the event, the requirer charm can access the S3 storage connection information shared by the
provider charm using the function `get_storage_connection_info` in the `S3Requirer` class.


```python

from object_storage import (
    S3Requirer, 
    StorageConnectionInfoChangedEvent, 
    StorageConnectionInfoGoneEvent,
)

class ExampleRequirerCharm(CharmBase):

    def __init__(
        self,
        charm: CharmBase,
    ):
        super().__init__(charm, "s3-requirer")
        self.charm = charm
        self.s3_client = S3Requirer(
            charm, 
            relation_name, 
            requests={
                "bucket": "test-bucket",    # bucket requested by the requirer
                "path": "test-path",        # path requested by the requirer
            }
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



## Usage: `AzureStorageProvider`

The `AzureStorageProvider` class can be used by the provider charm (eg, `azure-storage-integrator`) to share Azure Blob Storage and Azure Data Lake Storage connection information to the requirer charm (eg, `mongodb`).

The provider needs to instantiate the `AzureStorageProvider` class, and then listen to `storage_connection_info_requested` custom event. When handling the event, the provider needs to set the Azure Storage connection information using the function `set_storage_connection_info` in the `AzureStorageProvider` class.

```python

from object_storage import (
    StorageConnectionInfoRequestedEvent,
    AzureStorageProvider,
)

class ExampleProviderCharm(CharmBase):

    def __init__(self, charm: CharmBase):
        super().__init__(charm, "example-provider")

        self.azure_storage_provider = AzureStorageProvider(self, AZURE_STORAGE_RELATION_NAME)
        self.framework.observe(
            self.azure_storage_provider.on.storage_connection_info_requested,
            self._on_storage_connection_info_requested,
        )

    def _on_storage_connection_info_requested(
        self, event: StorageConnectionInfoRequestedEvent
    ) -> None:
        if not self.charm.unit.is_leader():
            return
        container_name = self.charm.config.get("container")
        secret_key = prepare_keys(self.charm.config.get("credentials"))

        self.azure_storage_provider.set_storage_connection_info(
            relation_id=event.relation.id,
            data={"container": bucket_name, "secret-key": secret_key}
        )


if __name__ == "__main__":
    main(ExampleProviderCharm)
```


## Usage: `AzureStorageRequirer`

The `AzureStorageRequirer` class can be used by the requirer charm (eg, `mongodb`) to request and receive Azure Storage credentials from the provider charm (eg, `azure-storage-integrator`).

The requrier charm needs to instantiate the `AzureStorageRequirer` class -- optionally with additional request for a particular container -- and then listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone`. When handling the event, the requirer charm can access the Azure Storage connection information shared by the
provider charm using the function `get_storage_connection_info` in the `AzureStorageRequirer` class.


```python

from object_storage import (
    AzureStorageRequirer, 
    StorageConnectionInfoChangedEvent, 
    StorageConnectionInfoGoneEvent,
)

class ExampleRequirerCharm(CharmBase):

    def __init__(
        self,
        charm: CharmBase,
    ):
        super().__init__(charm, "azure-storage-requirer")
        self.charm = charm
        self.azure_storage_client = AzureStorageRequirer(
            charm, 
            relation_name, 
            requests={
                "container": "test-container",    # container requested by the requirer
            }
        )
        self.framework.observe(
            self.azure_storage_client.on.storage_connection_info_changed, self._on_conn_info_changed
        )
        self.framework.observe(
            self.azure_storage_client.on.storage_connection_info_gone, self._on_conn_info_gone
        )

    def _on_conn_info_changed(self, event: StorageConnectionInfoChangedEvent):
        # access data from the provider
        connection_info = self.azure_storage_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_credential_gone(self, event: StorageConnectionInfoGoneEvent):
        # credentials are removed
        process_connection_info(None)

 if __name__ == "__main__":
    main(ExampleRequirerCharm)
```


## Usage: `GCSProvider`

The `GCSProvider` class can be used by the provider charm (eg, `gcs-integrator`) to share Google Cloud Storage connection information to the requirer charm (eg, `opensearch`).

The provider needs to instantiate the `GCSProvider` class, and then listen to `storage_connection_info_requested` custom event. When handling the event, the provider needs to set the GCS connection information using the function `set_storage_connection_info` in the `GCSProvider` class.

```python

from object_storage import (
    StorageConnectionInfoRequestedEvent,
    GCSProvider,
)

class ExampleProviderCharm(CharmBase):

    def __init__(self, charm: CharmBase):
        super().__init__(charm, "example-provider")

        self.gcs_provider = GCSProvider(self, GCS_RELATION_NAME)
        self.framework.observe(
            self.gcs_provider.on.storage_connection_info_requested,
            self._on_storage_connection_info_requested,
        )

    def _on_storage_connection_info_requested(
        self, event: StorageConnectionInfoRequestedEvent
    ) -> None:
        if not self.charm.unit.is_leader():
            return
        bucket_name = self.charm.config.get("bucket")
        secret_key = prepare_keys(self.charm.config.get("credentials"))

        self.gcs_provider.set_storage_connection_info(
            relation_id=event.relation.id,
            data={"bucket": bucket_name, "secret-key": secret_key}
        )


if __name__ == "__main__":
    main(ExampleProviderCharm)
```


## Usage: `GCSRequirer`

The `GCSRequirer` class can be used by the requirier charm (eg, `opensearch`) to request and receive Google Cloud Storage credentials from the provider charm (eg, `gcs-integrator`).

The requrier charm needs to instantiate the `GCSRequirer` class -- optionally with additional request for a particular bucket -- and then listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone`. When handling the event, the requirer charm can access the GCS storage connection information shared by the provider charm using the function `get_storage_connection_info` in the `GCSRequirer` class.


```python

from object_storage import (
    GCSRequirer, 
    StorageConnectionInfoChangedEvent, 
    StorageConnectionInfoGoneEvent,
)

class ExampleRequirerCharm(CharmBase):

    def __init__(
        self,
        charm: CharmBase,
    ):
        super().__init__(charm, "gcs-requirer")
        self.charm = charm
        self.gcs_client = GCSRequirer(
            charm, 
            relation_name, 
            requests={
                "bucket": "test-bucket",    # bucket requested by the requirer
            }
        )
        self.framework.observe(
            self.gcs_client.on.storage_connection_info_changed, self._on_conn_info_changed
        )
        self.framework.observe(
            self.gcs_client.on.storage_connection_info_gone, self._on_conn_info_gone
        )

    def _on_conn_info_changed(self, event: StorageConnectionInfoChangedEvent):
        # access data from the provider
        connection_info = self.gcs_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_credential_gone(self, event: StorageConnectionInfoGoneEvent):
        # credentials are removed
        process_connection_info(None)

 if __name__ == "__main__":
    main(ExampleRequirerCharm)
```

