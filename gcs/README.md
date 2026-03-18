# GCS-integrator
[![Charmhub](https://charmhub.io/gcs-integrator/badge.svg)](https://charmhub.io/gcs-integrator)
[![Release](https://github.com/canonical/object-storage-integrators/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/object-storage-integrator/actions/workflows/release.yaml)
[![Tests](https://github.com/canonical/object-storage-integrators/actions/workflows/ci.yaml/badge.svg)](https://github.com/canonical/object-storage-integrator/actions/workflows/ci.yaml)

## Description

This is an operator charm providing an integrator for connecting to Google Cloud Storage.

## Supported Architectures

This charm is released for AMD64 and ARM64.

## Creating a GCP Service Account key

The GCP Service Account can be created as from the Google Cloud Console as follows:

1. In the Google Cloud Console, go to IAM & Admin -> Service Accounts -> Create service account and create a service account with proper name (eg, gcs-integrator)

2. Grant the minimum roles your workload needs:

     - Read/write objects (recommended minimum): roles/storage.objectAdmin

     - Read-only objects: roles/storage.objectViewer

     - Manage buckets (only if needed): roles/storage.admin

3. Now go to Keys -> Add key -> Create new key -> JSON -> download and download the key. The downloaded file looks similar to the the one below:

    ```json
    {
        "type": "service_account",
        "project_id": "my-project-id",
        "private_key_id": "<private-key-id>",
        "private_key": "<private-key>",
        "client_email": "<client-email>",
        "client_id": "<client-id>",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "<client-x509-cert-url>",
        "universe_domain": "googleapis.com"
    }
    ```

## Usage Instructions

1.  First of all, deploy the `gcs-integrator` charm:
    ```bash
    juju deploy gcs-integrator
    ```

2. Configure the GCS Integrator charm as:
    ```bash
    juju config gcs-integrator bucket=foo
    ```

3. Add a new secret containing GCP service account key obtained from [this section](#creating-a-gcp-service-account-key) to Juju, and grant its permissions to gcs-integrator.
    ```
    juju add-secret mysecret secret-key#file=service_account.json
    juju grant-secret mysecret gcs-integrator
    ```
    The first command will return an ID like `secret:d0erdgfmp25c762i8np0`

4. Configure the GCS Integrator charm  with the newly created secret:
    ```
    juju config gcs-integrator credentials=secret:d0erdgfmp25c762i8np0
    ```

5. Now the charm should be in active and idle condition. To relate it with a consumer charm, simply do:
    ```
    juju integrate gcs-integrator:gcs-credentials consumer-charm:gcs-credentials
    ```

Now whenever the user changes the configuration options in gcs-integrator charm, appropriate event handlers are fired
so that the charms that consume the relation on the requirer side see the latest information.

### Further configuration

To further configure the GCS Integrator charm, you may provide the charm with additional configuration options. The following are the full list of configuration options supported by the charm:

| Configuration name | Description |
| --- | --- |
| `credentials` | (**Required**) The Juju secret ID that contains the GCP service account secret key used to connect to GCS. See [Creating a GCP Service Account key](#creating-a-gcp-service-account-key) for instructions on creating this key. |
| `bucket` | (**Required**) Target GCS bucket for snapshots/backups (3-63 chars, lowercase letters, digits, hyphens). |
| `storage-class` | The GCS storage class (`STANDARD`, `NEARLINE`, `COLDLINE`, `ARCHIVE`). Default value is `STANDARD`. |
| `path` | The path inside the GCS bucket to store objects (`<=1024` bytes, no NULL bytes). |


## Integrating your charm with `gcs-integrator`

Charmed applications can enable the integration with the `gcs-integrator` charm over the `gcs` relation interface, allowing them to consume the Google Cloud Storage connection information shared by the `gcs-integrator` charm over the Juju relation. 

The first step towards enabling integration with `gcs-integrator` is to add a relation endpoint with interface name `gcs` to the `requires` section of your charm's metadata. For example, add the following section to your charm's `metadata.yaml`:

```yaml
name: foo-bar
description: A test charm

requires:
  gcs-credentials:
    interface: gcs
```

The recommended way for the requirer charms to consume the `gcs` interface is to use the `object-storage-charmlib` Python package. Add this package as a dependency to your charm. For example, add the following to the `pyproject.toml` file:

```toml
[tool.poetry.dependencies]
object-storage-charmlib = "^0.1.0"
```

Now in your charm code, you need to instantiate the `GCSRequirer` class imported from the `object_storage` namespace, which also allows the requirer charm to optionally request a specific bucket name from the `gcs-integrator` charm. For example, add the following code block to your charm's `charm.py`:

```python
from object_storage import GCSRequirer

class RequirerCharm(CharmBase):
    def __init__(self, charm: CharmBase):
        super().__init__(charm, "gcs-requirer")

        self.gcs_client = GCSRequirer(
            charm=charm,
            relation_name="gcs-credentials",
            bucket="test-bucket"    # bucket requested by the requirer
        )
```

Using this instance of class `GCSRequirer`, the requirer charm then needs to listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone` and handle them appropriately in the charm code. The event `storage_connection_info_changed` is fired whenever the `gcs-integrator` has written new data to the relation databag, which needs to be handled by the requirer charm by updating its state with the new GCS connection information. The event `storage_connection_info_gone` is fired when the relation with `gcs-integrator` is broken, which needs to be handled by the requirer charm by updating its state to not use the GCS connection information anymore.

The latest GCS connection information shared by the `gcs-integrator` over the relation can be fetched using the utility function `get_storage_connection_info` available in the `GCSRequirer` instance. The following code example shows the usage of `get_storage_connection_info` function in the requirer charm code:

```python
from object_storage import (
    GCSInfo,
    GCSRequirer, 
    StorageConnectionInfoChangedEvent, 
    StorageConnectionInfoGoneEvent,

)

class RequirerCharm(CharmBase):
    def __init__(self, charm: CharmBase):
        super().__init__(charm, "gcs-requirer")

        self.gcs_client = GCSRequirer(
            charm=charm,
            relation_name="gcs-credentials",
            bucket="test-bucket"    # bucket requested by the requirer
        )

        # Observe custom events 
        self.framework.observe(
            self.gcs_client.on.storage_connection_info_changed, 
            self._on_conn_info_changed
        )
        self.framework.observe(
            self.gcs_client.on.storage_connection_info_gone, 
            self._on_conn_info_gone
        )


    def _on_conn_info_changed(self, event: StorageConnectionInfoChangedEvent):
        # access and consume data from the provider
        connection_info: GCSInfo = self.gcs_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_conn_info_gone(self, event: StorageConnectionInfoGoneEvent):
        # notify charm code that credentials are removed
        process_connection_info(None)
```

The utility function `get_storage_connection_info` in `GCSRequirer` returns a typed dictionary of type `GCSInfo`, which is defined as follows:

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

Once you have your charm built and deployed, you can then integrate with the `gcs-integrator` charm with the `juju integrate` command.

```bash
juju integrate gcs-integrator requirer-charm
```


## Security
Security issues in the GCS Integrator Operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File). Please do not file GitHub issues about security issues.


## Contributing

Please see the [Juju docs](https://documentation.ubuntu.com/juju/) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/object-storage-integrator/blob/main/CONTRIBUTING.md) for developer guidance.

