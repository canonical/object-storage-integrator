# Object Storage Charmlib

[![PyPI](https://img.shields.io/pypi/v/object-storage-charmlib)](https://pypi.python.org/pypi/object-storage-charmlib)

The `object-storage-charmlib` is a Python charm interface library for communication between object storage integrator charms and the requirer charms that relate with it. This library implements a common object-storage contract and the relation/event plumbing to publish
and consume storage connection info.

The following object storage providers are currently supported:
1. AWS S3 (and S3 compliant providers)
2. Azure Blob Storage / Azure Data Lake Storage (ADLS)
3. Google Cloud Storage (GCS)

When two charms are related over an object storage relation interface, the one providing the object storage
credentials is termed as Provider and the one that consumes those credentials is termed as Requirer. A provider 
publishes the payload when the requirer asks for it.

## Table of Contents

- [Installation](#installation)
- [Usage: `S3Provider`](#usage-s3provider)
- [Usage: `S3Requirer`](#usage-s3requirer)
- [Usage: `AzureStorageProvider`](#usage-azurestorageprovider)
- [Usage: `AzureStorageRequirer`](#usage-azurestoragerequirer)
- [Usage: `GCSProvider`](#usage-gcsprovider)
- [Usage: `GCSRequirer`](#usage-gcsrequirer)
- [Versioning and compatibility](#versioning-and-compatibility)
- [The `PrematureDataAccessError` Exception](#the-prematuredataaccesserror-exception)

## Installation

The lib can be installed from PyPI using `pip` as:

```bash
pip install object-storage-charmlib
```

If you're using Poetry as packaging tool in your charm project, you can add the lib to the charm dependencies as:

```toml
[tool.poetry.dependencies]
object-storage-charmlib = "^0.1.0"
```

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
```

The function `set_storage_connection_info` accepts a `relation_id` for the relation to which the data is to be updated, along with the `data` payload dictionary. To delete an existing field in the relation data, the value of the field should be set as an empty string (`""`) in the `data` payload dictionary.


## Usage: `S3Requirer`

The `S3Requirer` class can be used by the requirer charm (eg, `postgresql`) to request and receive S3 bucket and credentials from the provider charm (eg, `s3-integrator`).

The requirer charm needs to instantiate the `S3Requirer` class -- optionally with additional request for a particular bucket and/or a path -- and then listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone`. When handling the event, the requirer charm can access the S3 storage connection information shared by the
provider charm using the function `get_storage_connection_info` in the `S3Requirer` class.


```python

from object_storage import (
    StorageConnectionInfoChangedEvent, 
    StorageConnectionInfoGoneEvent,
    S3Info,
    S3Requirer, 
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
            bucket="test-bucket",           # bucket requested by the requirer
            path="test-path",               # path requested by the requirer
        )
        self.framework.observe(
            self.s3_client.on.storage_connection_info_changed, self._on_conn_info_changed
        )
        self.framework.observe(
            self.s3_client.on.storage_connection_info_gone, self._on_conn_info_gone
        )

    def _on_conn_info_changed(self, event: StorageConnectionInfoChangedEvent):
        # access data from the provider
        connection_info: S3Info = self.s3_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_conn_info_gone(self, event: StorageConnectionInfoGoneEvent):
        # credentials are removed
        process_connection_info(None)
```

The `get_storage_connection_info` function in `S3Requirer` returns a typed dictionary of type `S3Info` which has the following definition:

```python
S3Info = TypedDict(
    "S3Info",
    {
        "access-key": str,
        "secret-key": str,
        "region": str,
        "storage-class": str,
        "attributes": str,
        "bucket": str,
        "endpoint": str,
        "path": str,
        "s3-api-version": str,
        "s3-uri-style": str,
        "tls-ca-chain": List[str],
        "delete-older-than-days": str,
    },
    total=False,
)
```


## Usage: `AzureStorageProvider`

The `AzureStorageProvider` class can be used by the provider charm (eg, `azure-storage-integrator`) to share Azure Blob Storage and Azure Data Lake Storage connection information to the requirer charm (eg, `mongodb`).

The provider needs to instantiate the `AzureStorageProvider` class, and then listen to `storage_connection_info_requested` custom event. When handling the event, the provider needs to set the Azure Storage connection information using the function `set_storage_connection_info` in the `AzureStorageProvider` class.

```python

from object_storage import (
    AzureStorageProvider,
    StorageConnectionInfoRequestedEvent,
)

class ExampleProviderCharm(CharmBase):

    def __init__(self, charm: CharmBase):
        super().__init__(charm, "azure-storage-provider")

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
            data={"container": container_name, "secret-key": secret_key}
        )
```

The function `set_storage_connection_info` accepts a `relation_id` for the relation to which the data is to be updated, along with the `data` payload dictionary. To delete an existing field in the relation data, the value of the field should be set as an empty string (`""`) in the `data` payload dictionary.


## Usage: `AzureStorageRequirer`

The `AzureStorageRequirer` class can be used by the requirer charm (eg, `mongodb`) to request and receive Azure Storage credentials from the provider charm (eg, `azure-storage-integrator`).

The requirer charm needs to instantiate the `AzureStorageRequirer` class -- optionally with additional request for a particular container -- and then listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone`. When handling the event, the requirer charm can access the Azure Storage connection information shared by the
provider charm using the function `get_storage_connection_info` in the `AzureStorageRequirer` class.


```python

from object_storage import (
    AzureStorageInfo,
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
            container="test-container"    # container requested by the requirer
        )
        self.framework.observe(
            self.azure_storage_client.on.storage_connection_info_changed, self._on_conn_info_changed
        )
        self.framework.observe(
            self.azure_storage_client.on.storage_connection_info_gone, self._on_conn_info_gone
        )

    def _on_conn_info_changed(self, event: StorageConnectionInfoChangedEvent):
        # access data from the provider
        connection_info: AzureStorageInfo = self.azure_storage_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_conn_info_gone(self, event: StorageConnectionInfoGoneEvent):
        # credentials are removed
        process_connection_info(None)
```

The `get_storage_connection_info` function in `AzureStorageRequirer` returns a typed dictionary of type `AzureStorageInfo` which has the following definition:

```python
AzureStorageInfo = TypedDict(
    "AzureStorageInfo",
    {
        "container": str,
        "storage-account": str,
        "secret-key": str,
        "connection-protocol": str,
        "path": str,
        "endpoint": str,
        "resource-group": str,
    },
    total=False,
)
```


## Usage: `GCSProvider`

The `GCSProvider` class can be used by the provider charm (eg, `gcs-integrator`) to share Google Cloud Storage connection information to the requirer charm (eg, `opensearch`).

The provider needs to instantiate the `GCSProvider` class, and then listen to `storage_connection_info_requested` custom event. When handling the event, the provider needs to set the GCS connection information using the function `set_storage_connection_info` in the `GCSProvider` class.

```python

from object_storage import (
    GCSProvider,
    StorageConnectionInfoRequestedEvent,
)

class ExampleProviderCharm(CharmBase):

    def __init__(self, charm: CharmBase):
        super().__init__(charm, "gcs-provider")

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
```

The function `set_storage_connection_info` accepts a `relation_id` for the relation to which the data is to be updated, along with the `data` payload dictionary. To delete an existing field in the relation data, the value of the field should be set as an empty string (`""`) in the `data` payload dictionary.


## Usage: `GCSRequirer`

The `GCSRequirer` class can be used by the requirer charm (eg, `opensearch`) to request and receive Google Cloud Storage credentials from the provider charm (eg, `gcs-integrator`).

The requirer charm needs to instantiate the `GCSRequirer` class -- optionally with additional request for a particular bucket -- and then listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone`. When handling the event, the requirer charm can access the GCS storage connection information shared by the provider charm using the function `get_storage_connection_info` in the `GCSRequirer` class.


```python

from object_storage import (
    GCSInfo,
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
            bucket="test-bucket"    # bucket requested by the requirer
        )
        self.framework.observe(
            self.gcs_client.on.storage_connection_info_changed, self._on_conn_info_changed
        )
        self.framework.observe(
            self.gcs_client.on.storage_connection_info_gone, self._on_conn_info_gone
        )

    def _on_conn_info_changed(self, event: StorageConnectionInfoChangedEvent):
        # access data from the provider
        connection_info: GCSInfo = self.gcs_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_conn_info_gone(self, event: StorageConnectionInfoGoneEvent):
        # credentials are removed
        process_connection_info(None)
```

The `get_storage_connection_info` function in `GCSRequirer` returns a typed dictionary of type `GCSInfo` which has the following definition:

```python
GCSInfo = TypedDict(
    "GCSInfo",
    {
        "bucket": str,
        "secret-key": str,
        "storage-class": str,
        "path": str,
    },
    total=False,
)
```

## Versioning and compatibility

This library consolidates the `s3`, `azure_storage` and `gcs_storage` charm libs that previously existed as separate charm libs into a single common lib, such that the provider and requirer classes across all object storage relation interfaces can reuse a common codebase and be better maintained in the long run.

This library currently follows schema `v1` for relation payloads, and to distinguish this new schema with what existed before when the interface libs were separated, the older charmlib `s3`, `azure_storage` and `gcs_storage` are assumed to follow the schema `v0`.

### What's new in schema `v1`?

1. The provider now shares sensitive information over the relation as Juju secrets instead of plaintext. In the earlier `s3` lib, this was shared as plaintext. However, for compatibility, the provider will still send the data as plaintext if it detects the requirer is still using the old lib.
2. The provider as well as requirers now advertise the version of schema they're using in the relation databag. This is done so that the other side can know the schema version this side is currently using, and act accordingly to ensure compatibility.

### Compatibility notes

- `S3Provider` can detect older requirers and keep backward-compatible behavior.
- `S3Requirer` can detect older providers and apply compatibility fallbacks. This however makes an assumption on a specific order of execution of relation events, and hence it is still recommended to upgrade the provider to new version at the earliest timeframe possible.

### Migration guidance (old charmlibs to the new charmlib)

It is **highly recommended** that you first upgrade the storage integrator charm to the latest track and revision before you upgrade your charm to use the new object-storage-charmlib. Please follow the guide for `s3-integrator`, `azure-storage-integrator` and `gcs-integrator` respectively for this migration.

To upgrade your charms from using the old object storage charmlibs to the new lib, follow the following steps:

1. Update your charm's dependencies to include the `object-storage-charmlib` Python package.
2. Update charm codebase to use the new requirer classes, custom events and functions in the new lib from their old counterparts. Please follow the usage instructions for [`S3Requirer`](#usage-s3requirer), [`AzureStorageRequirer`](#usage-azurestoragerequirer) and [`GCSRequirer`](#usage-gcsrequirer) for this purpose. A few common changes (however not an exhaustive list) are:
    * Update the references of `S3Requirer`, `AzureStorageRequirer` and `GCSRequirer` to their counterparts from the new lib. 
    * Listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone` in the charm code instead of `s3_connection_info_changed`, `s3_connection_info_gone`, etc.
    * Update function calls like `get_s3_connection_info`, `get_azure_storage_connection_info` and `get_gcs_connection_info` to a more generic function `get_storage_connection_info`.
3. Delete the old charm lib inside the `lib` or `src` section of your charm codebase.
4. Update your charm's unit and integration tests to make them compatible with the newer lib.


### Dependency pinning recommendation

For production charms, pin `object-storage-charmlib` to a compatible minor version range (for example `^0.1.0`) and validate upgrades in integration tests before promoting to stable channels.


## The `PrematureDataAccessError` Exception

The `PrematureDataAccessError` exception is raised by the lib when the provider charm attempts to update the relation data before the relation protocol has been fully initialized.

There are valid use cases where the provider charm may want to update the connection information on charm lifecycle events like `config-changed`, etc. When the relation data is attempted to be updated when the relation is not completely initialized, there might be risks of the provider sharing secret data over plaintext, sharing data with incorrect schema with respect to the schema used by the requirer, etc. To prevent these edge cases, the lib raises `PrematureDataAccessError` when the `set_storage_connection_info` function is called while the relation is yet not fully initialized.

The calls to the function `set_storage_connection_info` in the handlers of events outside the context of the object storage relation should properly handle the `PrematureDataAccessError`, while deferring the event for execution later when the relation will have completed initialization. The following is an example of how this can be done, in the context of S3 interface.


```python
from object_storage import (
    PrematureDataAccessError,
    S3Provider,
)

class ExampleProviderCharm(CharmBase):

    def __init__(self, charm: CharmBase):
        super().__init__(charm, "s3-provider")

        self.s3_provider = S3Provider(self, S3_RELATION_NAME)
        self.framework.observe(
            charm.on.config_changed,
            self._on_config_changed,
        )
        ...

    def _on_config_changed(
        self, event
    ) -> None:
        if not self.charm.unit.is_leader():
            return
        bucket_name = self.charm.config.get("bucket")
        access_key, secret_key = prepare_keys(self.charm.config.get("credentials"))
        
        try:
            self.s3_provider.set_storage_connection_info(
                relation_id=event.relation.id,
                data={"bucket": bucket_name, "access-key": access_key, "secret-key": secret_key}
            )
        except PrematureDataAccessError:
            logging.error("Attempted to update relation data before relation is initialized.")
            event.defer()
            return
```
