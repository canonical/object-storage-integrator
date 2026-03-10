# GCS-integrator
[![Charmhub](https://charmhub.io/gcs-integrator/badge.svg)](https://charmhub.io/gcs-integrator)
[![Release](https://github.com/canonical/object-storage-integrators/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/object-storage-integrators/actions/workflows/release.yaml)
[![Tests](https://github.com/canonical/object-storage-integrators/actions/workflows/ci.yaml/badge.svg)](https://github.com/canonical/object-storage-integrators/actions/workflows/ci.yaml)

## Description

This is an operator charm providing an integrator for connecting to Google Cloud Storage.

## Supported Architectures

This charm is released for AMD64 and ARM64.

## Instructions for Usage

1. Deploy the `gcs-integrator` charm:
    ```
    juju deploy gcs-integrator
    ```

2. Set the bucket name:
    ```
    juju config gcs-integrator bucket=foo
    ```
3. Create a service account key (service_account.json) via Console:

   1. IAM & Admin -> Service Accounts -> Create service account (e.g. gcs-integrator).

   2. Grant the minimum roles your workload needs:

     - Read/write objects (recommended minimum): roles/storage.objectAdmin

     - Read-only objects: roles/storage.objectViewer

     - Manage buckets (only if needed): roles/storage.admin

   3. Keys -> Add key -> Create new key -> JSON -> download.
    
    The file looks like the one in below:
```json
{
  "type": "service_account",
  "project_id": "my-project-id",
  "private_key_id": "abcdef1234567890abcdef1234567890abcdef12",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEv......\n-----END PRIVATE KEY-----\n",
  "client_email": "gcs-integrator@my-project-id.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/gcs-integrator%40my-project-id.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
 }
```

4. Add the JSON as a Juju secret and grant it to the integrator.
    ```
    juju add-secret mysecret secret-key#file=service_account.json

    juju grant-secret mysecret gcs-integrator
    ```

5. Configure the GCS Integrator charm by providing Juju secret ID:
    ```
    juju config gcs-integrator credentials=secret-xxxxxxxxxxxxxxxxxxxx
    ```

6. Wait until the charm is active and idle. Then, relate your consumer charm to the integrator:
    ```
    juju integrate gcs-integrator:gcs-credentials consumer-charm:gcs-credentials
    ```

Now whenever the user changes the configuration options in gcs-integrator charm, appropriate event handlers are fired
so that the charms that consume the relation on the requirer side see the latest information.


## Integrating your charm with `gcs-integrator`

Charmed applications can enable the integration with the `gcs-integrator` charm over the `gcs` relation interface, allowing them to consume the Google Cloud Storage connection information shared by the `gcs-integrator` charm over the Juju relation. 

The first step towards enabling integration with `gcs-integrator` is to add a relation endpoint with interface name `gcs` to the `requires` section of your charm's metadata.

```yaml
# file: metadata.yaml

name: foo-bar
description: A test charm

requires:
  gcs-credentials:
    interface: gcs

```

The recommended way for the requirer charms to consume the `gcs` interface is to use the `object-storage-charmlib` Python package. Add this package as a dependency to your charm (for example, to `pyproject.toml` as follows).

```toml
# file: pyproject.toml

[tool.poetry.dependencies]
object-storage-charmlib = "^0.1.0"
```

Now in your charm code, you need to instantiate the `GCSRequirer` class imported from the `object_storage` namespace, which also allows the requirer charm to optionally request a specific bucket name from the `gcs-integrator` charm.

```python
# file: charm.py

from object_storage import GCSRequirer

class RequirerCharm(CharmBase):
   def __init__(self, charm: CharmBase):
      super().__init__(charm, "gcs-requirer")

      self.s3_client = GCSRequirer(
         charm=charm,
         relation_name="gcs-credentials",
         requests={
            "bucket": "test-bucket",    # bucket requested by the requirer
         }
      )
```

Using this instance of class `GCSRequirer`, the requirer charm then needs to listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone` and handle them appropriately in the charm code. The event `storage_connection_info_changed` is fired whenever the `gcs-integrator` has written new data to the relation databag, which needs to be handled by the requirer charm by updating its state with the new GCS connection information. The event `storage_connection_info_gone` is fired when the relation with `gcs-integrator` is broken, which needs to be handled by the requirer charm by updating its state to not use the GCS connection information anymore.

The latest GCS connection information shared by the `gcs-integrator` over the relation can be fetched using the utility function `get_storage_connection_info` available in the `GCSRequirer` instance.

```python
# file: charm.py

from object_storage import GCSRequirer, StorageConnectionInfoChangedEvent, StorageConnectionInfoGoneEvent

class RequirerCharm(CharmBase):
    def __init__(self, charm: CharmBase):
        super().__init__(charm, "gcs-requirer")

        self.gcs_client = GCSRequirer(
            charm=charm,
            relation_name="gcs-credentials",
            requests={
            "bucket": "test-bucket",    # bucket requested by the requirer
            }
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
        connection_info = self.gcs_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_conn_info_gone(self, event: StorageConnectionInfoGoneEvent):
        # notify charm code that credentials are removed
        process_connection_info(None)

```

Once you have your charm built and deployed, you can then integrate with the `gcs-integrator` charm with the `juju integrate` command.

```bash
juju integrate gcs-integrator requirer-charm
```


## Security
Security issues in the GCS Integrator Operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File). Please do not file GitHub issues about security issues.


## Contributing

Please see the [Juju SDK docs](https://documentation.ubuntu.com/juju/3.6/) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/object-storage-integrators/blob/main/CONTRIBUTING.md) for developer guidance.

