# S3 Integrator

[![Charmhub](https://charmhub.io/s3-integrator/badge.svg?channel=2/edge)](https://charmhub.io/s3-integrator)
[![Release](https://github.com/canonical/object-storage-integrator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/object-storage-integrator/actions/workflows/release.yaml)
[![Tests](https://github.com/canonical/object-storage-integrator/actions/workflows/ci.yaml/badge.svg)](https://github.com/canonical/object-storage-integrator/actions/workflows/ci.yaml)

## Description

This is an operator charm providing an integrator for connecting to S3. Charmed applications that need an access to S3 cloud can integrate with this charm and then consume the S3 bucket, S3 connection parameters and credentials shared by the charm over the Juju relation.

> [!WARNING]
> This project is the Juju secrets based S3 Integrator charm on track `2`.
> The former action-based `s3-integrator` (on track `1`) lives in <https://github.com/canonical/s3-integrator>.
> [!WARNING]
> In-place refresh is not supported for `s3-integrator` from track `1` to track `2`,
> because the charms in these two tracks use different Ubuntu bases.

## Usage instructions

1. First of all, deploy the `s3-integrator` charm:

   ```bash
   juju deploy s3-integrator --channel=2/edge
   ```

2. Configure the S3 Integrator charm:

   ```bash
   juju config s3-integrator bucket=mybucket path=mypath endpoint=http://my-endpoint
   ```

3. Add a new secret containing S3 access-key and secret-key to Juju, and grant its permissions to s3-integrator:

   ```bash
   juju add-secret mysecret access-key=<ACCESS_KEY> secret-key=<SECRET_KEY>
   juju grant-secret mysecret s3-integrator
   ```

   The first command will return an ID like `secret:d0erdgfmp25c762i8np0`.

4. Configure the S3 Integrator charm with the newly created secret:

   ```bash
   juju config s3-integrator credentials=secret:d0erdgfmp25c762i8np0
   ```

5. Now the charm should be in active and idle condition. To relate it with a consumer charm, simply do:

   ```bash
   juju integrate s3-integrator:s3-credentials consumer-charm:some-interface
   ```

Now whenever the user changes the configuration options in s3-integrator charm, appropriate event handlers are fired
so that the charms that consume the relation on the requirer side see the latest information.

### Further configuration

S3 Integrator charm supports the following configuration options:

| Configuration name | Description |
| --- | --- |
| `credentials` | (**Required**) The Juju secret ID that contains the access key and secret key used to connect to S3. |
| `endpoint` | The endpoint used to connect to the S3 object storage. If not specified, the charm attempts to create and ensure bucket as per default `boto3` behavior for endpoint discovery. |
| `bucket` | The S3 bucket name delivered by the provider, creating it if it doesn't exist. |
| `region` | The region used to connect to the S3. |
| `path` | The path inside the S3 bucket to store objects. |
| `attributes` | The custom metadata (HTTP headers). The value needs to be specified in comma-separated format. |
| `s3-uri-style` | The S3 protocol specific bucket path lookup type. Examples are `host`, `path`, etc. |
| `s3-api-version` | The S3 protocol specific API signature. Can be either `2` or `4`. |
| `storage-class` | The storage class for objects uploaded to S3. |
| `tls-ca-chain` | The complete CA chain, which can be used for HTTPS validation. This needs to be a base64 encoded string of the original CA chain. |
| `experimental-delete-older-than-days` | The number of days after which full backups are eligible for deletion. EXPERIMENTAL option. |

To set the `tls-ca-chain` configuration, the value needs to be base64-encoded string of the original CA chain. Use the following command to configure the charm with a CA chain from a file:

```bash
juju config s3-integrator tls-ca-chain="$(base64 -w0 your_ca_chain.pem)"
```

If a configuration is not set in the `s3-integrator`, its value won't be shared to the requirer charm over the relation. However, the requirer may ask for a `bucket` and a `path` even if it is not configured in the `s3-integrator` charm. See [Consumer specific bucket and path configuration](#consumer-specific-bucket-and-path-configuration) for details.

## What's new in `s3-integrator` track `2`?

The S3 Integrator charm from track `2` is different from the same charm in track `1` in the following aspects:

### Auto creation of bucket

The S3 Integrator charm is now able to create a bucket on its own, if it finds that the specified bucket does not exist already in the S3 cloud. This is also applicable when the requirer charm integrated with `s3-integrator` requests for a bucket that doesn't exist already in S3.

### Ensure the usability of bucket

The S3 Integrator charm shares bucket information with integrated charms only after verifying that the bucket exists and is ready to use. To do this, the charm calls the `ListObjectsV2` action on the specified bucket and path combination. If this check fails, the charm does not share the bucket information.

## Versioning and compatibility

The S3 Integrator charm in this repository is released to track `2`, which supports charm configuration with Juju secrets and also sharing data over the relation using Juju secrets. The charm uses a newer version of relation data schema (`v1`) in comparison to the relation data schema (`v0`) used by the S3 Integrator on track `1`.

The new S3 Integrator is fully compatible and can be integrated with the consumer charms that are still on the older relation data schema `v0` (in other words, still using the old `s3` charmlib). This allows for mixed deployments where the S3 Integrator is updated to the latest track `2` while the consumer charm will later be upgraded to use the new charm lib (i.e. relation schema `v1`) in the suitable timeframe. Please refer to the [migration guide](#migration-strategy-from-track-1-to-2) for instructions to migrate S3 Integrator from track `1` to `2`.

## Integrating your charm with `s3-integrator`

Charmed applications can enable the integration with the `s3-integrator` charm over the `s3` relation interface, allowing them to consume the S3 bucket and connection information shared by the `s3-integrator` charm over the Juju relation.

The first step towards enabling integration with `s3-integrator` is to add a relation endpoint with interface name `s3` to the `requires` section of your charm's metadata. For example, add the following section to your charm's `metadata.yaml`:

```yaml
name: foo-bar
description: A test charm

requires:
  s3-credentials:
    interface: s3
```

The recommended way for the requirer charms to consume the `s3` interface is to use the `object-storage-charmlib` Python package. Add this package as a dependency to your charm. For example, add the following to the `pyproject.toml` file:

```toml
[tool.poetry.dependencies]
object-storage-charmlib = "^0.1.0"
```

Now in your charm code, you need to instantiate the `S3Requirer` class imported from the `object_storage` namespace, which also allows the requirer charm to optionally request a specific bucket name and path from the `s3-integrator` charm. For example, add the following code block to your charm's `charm.py`:

```python
from object_storage import S3Requirer

class RequirerCharm(CharmBase):
   def __init__(self, charm: CharmBase):
      super().__init__(charm, "s3-requirer")

      self.s3_client = S3Requirer(
         charm=charm,
         relation_name="s3-credentials",
         bucket="test-bucket",    # bucket requested by the requirer
         path="test-path"         # path requested by the requirer
      )
```

Using this instance of class `S3Requirer`, the requirer charm then needs to listen to custom events `storage_connection_info_changed` and `storage_connection_info_gone` and handle them appropriately in the charm code. The event `storage_connection_info_changed` is fired whenever the `s3-integrator` has written new data to the relation databag, which needs to be handled by the requirer charm by updating its state with the new S3 connection information. The event `storage_connection_info_gone` is fired when the relation with `s3-integrator` is broken, which needs to be handled by the requirer charm by updating its state to not use the S3 connection information anymore.

The latest S3 connection information shared by the `s3-integrator` over the relation can be fetched using the utility function `get_storage_connection_info` available in the `S3Requirer` instance. The following code example shows the usage of `get_storage_connection_info` function in the requirer charm code:

```python
from object_storage import (
   StorageConnectionInfoChangedEvent, 
   StorageConnectionInfoGoneEvent,
   S3Info,
   S3Requirer, 
)

class RequirerCharm(CharmBase):
   def __init__(self, charm: CharmBase):
      super().__init__(charm, "s3-requirer")

      self.s3_client = S3Requirer(
         charm=charm,
         relation_name="s3-credentials",
         bucket="test-bucket",    # bucket requested by the requirer
         path="test-path"         # path requested by the requirer
      )

      # Observe custom events 
      self.framework.observe(
         self.s3_client.on.storage_connection_info_changed, 
         self._on_conn_info_changed
      )
      self.framework.observe(
         self.s3_client.on.storage_connection_info_gone, 
         self._on_conn_info_gone
      )


    def _on_conn_info_changed(self, event: StorageConnectionInfoChangedEvent):
        # access and consume data from the provider
        connection_info: S3Info = self.s3_client.get_storage_connection_info()
        process_connection_info(connection_info)

    def _on_conn_info_gone(self, event: StorageConnectionInfoGoneEvent):
        # notify charm code that credentials are removed
        process_connection_info(None)
```

The utility function `get_storage_connection_info` in `S3Requirer` returns a typed dictionary of type `S3Info`, which is defined as follows:

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

Once you have your charm built and deployed, you can then integrate with the `s3-integrator` charm with the `juju integrate` command.

```bash
juju integrate s3-integrator requirer-charm
```

## Usage modes

The S3 Integrator charm from track `2` can be used in two different modes, each catering to its own unique use cases. The modes are:

1. Global bucket and path configuration.
2. Consumer specific bucket and path configuration.

### Global bucket and path configuration

In this mode, the bucket and/or path is set at the `s3-integrator` charm level, such that any related applications will always receive this bucket and/or path when they relate to `s3-integrator.`

To enforce a bucket globally for all charms related to the `s3-integrator`, set the `bucket` configuration option in `s3-integrator` charm.

```bash
juju config s3-integrator bucket=global-bucket
```

Similarly, to enforce a path globally for all charms related to `s3-integrator`, set the `path` configuration option in `s3-integrator` charm.

```bash
juju config s3-integrator path=global-path
```

When using `s3-integrator` in this mode, one S3 Integrator app is deployed per bucket, such that all requirer charms that need this bucket are integrated with this instance of S3 Integrator.

### Consumer specific bucket and path configuration

In this mode, the bucket and/or path is purposefully not set at the `s3-integrator` charm level, such that the related applications can request for a specific bucket and/or path from the `s3-integrator` charm when they relate to it.

To allow for the consumer charms to request bucket and/or path themselves, do not set the value of `bucket` and/or `path` configuration option at the `s3-integrator` charm level. The consumer charms can then make this request by specifying the `bucket` and/or `path` keyword argument in the charm code, when instantiating the `S3Requirer` class from `object-storage-charmlib`.

```python
from object_storage import S3Requirer

class MyCharm(CharmBase):
   def __init__(*args, **kwargs):
      s3_client = S3Requirer(
         self, 
         relation_name="s3-credentials", 
         bucket="custom-requested-bucket",    # bucket requested by the requirer
         path="custom-requested-path"         # path requested by the requirer
      )
```

In the case where the `bucket` and/or `path` is both specified at the `s3-integrator` charm level and requested by the consumer charm via the `S3Requirer` class, the value specified in the `s3-integrator` charm level will always take precedence and thus will overwrite the value requested by consumer charm.

Although S3 Integrator is capable of creating different buckets as per the requests of different consumer charms all integrated together with the same instance of S3 Integrator, it is still recommended that a separate instance of S3 Integrator is deployed per bucket, for the ease of maintenance.

## Migration strategy (from track `1` to `2`)

The S3 Integrator from track `2` is supported only on versions of Juju that support secrets, since the charm heavily relies on Juju secrets to configure keys and share data over the relation.

In-place refresh is not supported for `s3-integrator` from track `1` to track `2`, because the charms in these two tracks use different Ubuntu bases. The following are the instructions to migrate the charm from track `1` to track `2` using offline strategy:

1. Deploy a new instance of `s3-integrator` from track `2`.

   ```bash
   juju deploy s3-integrator --channel 2/edge
   ```

2. Configure it with the same set of original configurations done for the older s3-integrator.

   ```bash
   juju config s3-integrator endpoint=$ENDPOINT
   juju config s3-integrator region=$REGION
   juju config s3-integrator bucket=$BUCKET path=$PATH
   juju config s3-integrator s3-uri-style=$S3_URI_STYLE
   
   juju add-secret s3-credentials access-key=$ACCESS_KEY secret-key=$SECRET_KEY
   juju grant-secret s3-credentials s3-integrator
   juju config s3-integrator credentials=secret://<secret-id-of-s3-credentials>
   ```

3. Remove the relation between the old `s3-integrator` charm and the consumer charm (say, `s3-consumer`).

   ```bash
   juju remove-relation old-s3-integrator s3-consumer
   ```

4. Integrate the new `s3-integrator` with the consumer charm.

   ```bash
   juju integrate s3-integrator consumer-charm
   ```

5. Ensure the integration is successful with consumer charm's user acceptance tests.

6. Remove the old s3-integrator app from Juju model.

   ```bash
   juju remove-application old-s3-integrator
   ```

**Next steps:**

You'd probably want to upgrade the consumer charm next to use the newer `object-storage-charmlib`. Please follow [this guide](../lib/README.md#migration-guidance-old-charmlibs-to-the-new-charmlib) for this migration.

## Troubleshooting

The S3 Integrator charm implements the Advanced Charm Statuses lib, and thus is able to track multiple statuses at the same time. The details regarding various statuses and the recommended action for them can be viewed by running the action `status-detail` on the charm leader unit.

```bash
juju run s3-integrator/0 status-detail
```

One of the most common statuses reported by the S3 integrator charm is the charm being on blocked state with message `Could not ensure bucket(s): xxxxx`. This status is set by the charm when it cannot ensure the bucket for use, probably due to one of the following reasons:

1. The given connection parameters (eg, access key, secret key, endpoint, region, etc.) are not valid.
2. The charm cannot make a successful HTTP / HTTPS connection to the S3 endpoint (eg, due to proxy, invalid TLS certificate, etc.)
3. The IAM user (corresponding to access key and secret key) does not have enough permissions to call `ListObjectsV2` on the existing bucket.
4. The IAM user (corresponding to access key and secret key) does not have enough permissions to create a non-existent bucket.

In these cases, the first step to troubleshoot this is to check the `juju debug-log`, as the charm logs any failure to ensure the bucket there.

## Security

Security issues in the Charmed Object Storage Integrator Operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File). Please do not file GitHub issues about security issues.

## Contributing

Please see the [Juju docs](https://documentation.ubuntu.com/juju/) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/object-storage-integrator/blob/main/CONTRIBUTING.md) for developer guidance.
