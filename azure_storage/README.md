# Azure Storage Integrator

[![Charmhub](https://charmhub.io/azure-storage-integrator/badge.svg)](https://charmhub.io/azure-storage-integrator)
[![Release](https://github.com/canonical/object-storage-integrator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/object-storage-integrator/actions/workflows/release.yaml)
[![Tests](https://github.com/canonical/object-storage-integrator/actions/workflows/ci.yaml/badge.svg)](https://github.com/canonical/object-storage-integrator/actions/workflows/ci.yaml)

## Description

This is an operator charm providing an integrator for connecting to Azure Storage.

## Usage instructions

1. First of all, deploy the `azure-storage-integrator` charm:

    ```bash
    juju deploy azure-storage-integrator --channel latest/edge
    ```

2. Configure the Azure Storage Integrator charm:

    ```bash
    juju config azure-storage-integrator storage-account=stoacc container=conn
    ```

3. Add a new secret containing the storage account secret-key to Juju, and grant its permissions to azure-storage-integrator:

    ```bash
    juju add-secret mysecret secret-key=changeme
    juju grant-secret mysecret azure-storage-integrator
    ```

    The first command will return an ID like `secret:d0erdgfmp25c762i8np0`.

4. Configure the Azure Storage Integrator charm with the newly created secret:

    ```bash
    juju config azure-storage-integrator credentials=secret:d0erdgfmp25c762i8np0
    ```

5. Now the charm should be in active and idle condition. To relate it with a consumer charm, simply do:

    ```bash
    juju integrate azure-storage-integrator:azure-storage-credentials consumer-charm:some-interface
    ```

Now whenever the user changes the configuration options in azure-storage-integrator charm, appropriate event handlers are fired
so that the charms that consume the relation on the requirer side sees the latest information.

### Further configuration

Azure Storage Integrator charm supports the following configuration options:

| Configuration name | Description |
| --- | --- |
| `credentials` | (**Required**) The Juju secret ID that contains the storage account secret key used to connect to Azure Storage. |
| `storage-account` | (**Required**) The name of the Azure Storage account. |
| `container` | (**Required**) The name of the Azure Storage container to store objects. |
| `endpoint` | The endpoint URL for the Azure Storage account. If not specified, the enddpoint is inferred based on the given values of `container`, `storage-account` and `connection-protocol`. |
| `path` | The path inside the container to store objects. |
| `resource-group` | The name of the Azure resource group where the storage account is located. If not specified, the resource group is auto inferred as per default behavior of Azure Storage Blob SDK. |
| `connection-protocol` | The storage protocol to use when connecting to Azure Storage. Default value is `"abfss"`. Possible values are: `"wasb"`, `"wasbs"` for Azure Blob Storage, `"abfs"`, `"abfss"` for Azure Data Lake Storage Gen2 and `"http"`, `"https"` for Azure Blob/Files REST API access. |

## Integrating your charm with `azure-storage-integrator`

Charmed applications can enable the integration with the `azure-storage-integrator` charm over the `azure_storage` relation interface, allowing them to consume the Azure Storage connection information shared by the `azure-storage-integrator` charm over the Juju relation.

The first step towards enabling integration with `azure-storage-integrator` is to add a relation endpoint with interface name `azure_storage` to the `requires` section of your charm's metadata. For example, add the following section to your charm's `metadata.yaml`:

```yaml
name: foo-bar
description: A test charm

requires:
  azure-storage-credentials:
    interface: azure_storage
```

The recommended way for the requirer charms to consume the `azure_storage` interface is to use the `object-storage-charmlib` Python package. Add this package as a dependency to your charm. For example, add the following to the `pyproject.toml` file:

```toml
[tool.poetry.dependencies]
object-storage-charmlib = "^0.1.0"
```

Now in your charm code, you need to instantiate the `AzureStorageRequirer` class imported from the `object_storage` namespace, which also allows the requirer charm to optionally request a specific container name from the `azure-storage-integrator` charm. For example, add the following code block to your charm's `charm.py`:

```python
from object_storage import AzureStorageRequirer

class RequirerCharm(CharmBase):
   def __init__(self, charm: CharmBase):
      super().__init__(charm, "azure-storage-requirer")

      self.az_storage_client = AzureStorageRequirer(
         charm=charm,
         relation_name="azure-storage-credentials",
         container="test-container"    # container requested by the requirer
      )
```

Using this instance of class `AzureStorageRequirer`, the requirer charm then needs to listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone` and handle them appropriately in the charm code. The event `storage_connection_info_changed` is fired whenever the `azure-storage-integrator` has written new data to the relation databag, which needs to be handled by the requirer charm by updating its state with the new Azure Storage connection information. The event `storage_connection_info_gone` is fired when the relation with `azure-storage-integrator` is broken, which needs to be handled by the requirer charm by updating its state to not use the Azure Storage connection information anymore.

The latest Azure Storage connection information shared by the `azure-storage-integrator` over the relation can be fetched using the utility function `get_storage_connection_info` available in the `AzureStorageRequirer` instance. The following code example shows the usage of `get_storage_connection_info` function in the requirer charm code:

```python
from object_storage import (
    AzureStorageInfo,
    AzureStorageRequirer, 
    StorageConnectionInfoChangedEvent, 
    StorageConnectionInfoGoneEvent,
)

class RequirerCharm(CharmBase):
    def __init__(self, charm: CharmBase):
        super().__init__(charm, "azure-storage-requirer")

        self.az_storage_client = AzureStorageRequirer(
            charm=charm,
            relation_name="azure-storage-credentials",
            container="test-container"    # container requested by the requirer
        )

        # Observe custom events 
        self.framework.observe(
            self.az_storage_client.on.storage_connection_info_changed, 
            self._on_conn_info_changed
        ) 
        self.framework.observe(
            self.az_storage_client.on.storage_connection_info_gone, 
            self._on_conn_info_gone
        )


    def _on_conn_info_changed(self, event: StorageConnectionInfoChangedEvent):
        # access and consume data from the provider
        connection_info: AzureStorageInfo = self.az_storage_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_conn_info_gone(self, event: StorageConnectionInfoGoneEvent):
        # notify charm code that credentials are removed
        process_connection_info(None)
```

The utility function `get_storage_connection_info` in `AzureStorageRequirer` returns a typed dictionary of type `AzureStorageInfo`, which is defined as follows:

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

Once you have your charm built and deployed, you can then integrate with the `azure-storage-integrator` charm with the `juju integrate` command.

```bash
juju integrate azure-storage-integrator requirer-charm
```

## Security

Security issues in the Charmed Object Storage Integrator Operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File). Please do not file GitHub issues about security issues.

## Contributing

Please see the [Juju docs](https://documentation.ubuntu.com/juju) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/object-storage-integrator/blob/main/CONTRIBUTING.md) for developer guidance.
