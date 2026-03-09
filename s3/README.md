# S3-integrator

[![Charmhub](https://charmhub.io/s3-integrator/badge.svg)](https://charmhub.io/s3-integrator)

<!-- TODO(docs): Add the proper badge both here and in azure-storage -->
<!-- [![Release](https://github.com/canonical/object-storage-integrators/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/object-storage-integrators/actions/workflows/release.yaml) -->
<!-- [![Tests](https://github.com/canonical/object-storage-integrators/actions/workflows/ci.yaml/badge.svg)](https://github.com/canonical/object-storage-integrators/actions/workflows/ci.yaml) -->

## Description

This is an operator charm providing an integrator for connecting to S3.


> [!WARNING]
> This project is the Juju secrets based S3-integrator charm on track `2/`.
>
> The former action-based `s3-integrator` (on track `1/`) lives in https://github.com/canonical/s3-integrator.

> [!WARNING]
> In-place refresh is not supported for `s3-integrator` from track `1/` to track `2/`,
> because the charms in these two tracks use different Ubuntu bases.
>

## Instructions for Usage

<!-- TODO(release): figure out the channels -->

1. First off all, deploy the `s3-integrator` charm as:
   ```
   juju deploy s3-integrator --channel=<CHANNEL>
   ```

2. Configure the S3 Integrator charm as:
   ```
   juju config s3-integrator bucket=mybucket
   ```

3. Add a new secret to Juju, and grant its permissions to s3-integrator:
   ```
   juju add-secret mysecret access-key=<ACCESS_KEY> secret-key=<SECRET_KEY>
   juju grant-secret mysecret s3-integrator
   ```
   The first command will return an ID like `secret:d0erdgfmp25c762i8np0`

4. Configure the S3 Integrator charm credentials with the ID above:
   ```
   juju config s3-integrator credentials=secret:d0erdgfmp25c762i8np0
   ```

5. Now the charm should be in active and idle condition. To relate it with a consumer charm, simply do:
   ```
   juju integrate s3-integrator:s3-credentials consumer-charm:some-interface
   ```

Now whenever the user changes the configuration options in s3-integrator charm, appropriate event handlers are fired
so that the charms that consume the relation on the requirer side sees the latest information.

### Further configuration

To configure the S3 integrator charm, you may provide the following configuration options:
  
- `endpoint`: the endpoint used to connect to the object storage.
- `bucket`: the bucket/container name delivered by the provider (the bucket name can be specified also on the requirer application).
- `region`: the region used to connect to the object storage.
- `path`: the path inside the bucket/container to store objects.
- `attributes`: the custom metadata (HTTP headers).
- `s3-uri-style`: the S3 protocol specific bucket path lookup type.
- `storage-class`:the storage class for objects uploaded to the object storage.
- `tls-ca-chain`: the complete CA chain, which can be used for HTTPS validation.
- `s3-api-version`: the S3 protocol specific API signature.
- `experimental-delete-older-than-days`: the amount of day after which backups going to be deleted. EXPERIMENTAL option.

The only mandatory fields for the integrator are `access-key` and `secret-key`.

In order to set ca-chain certificate use the following command:

```bash
juju config s3-integrator tls-ca-chain="$(base64 -w0 your_ca_chain.pem)"
```

The config option `attributes` needs to be specified in comma-separated format. 

## What's new in `s3-integrator` track `2/`?

### Auto creation of bucket
The S3 Integrator charm is now able to create a bucket on its own, if it finds that the specified bucket does not exist already in the S3 cloud. This is also applicable when the requirer charm integrated with `s3-integrator` requests for a bucket that doesn't exist already in S3.

### Ensure the usability of bucket
The S3 Integrator charm will share the bucket information to the charms that are related to it only after ensuring the bucket exists and is ready for use. For this purpose, the charm will try to call `ListObjectsV2` action on the given bucket + path combination. If the charm finds that it cannot run this action on the given set of bucket and path, it won't share this bucket to the related charms.


## Usage Modes
The S3 Integrator charm from track `2/` can be used in two different modes, each catering to its own unique use cases
1. Global bucket and path configuration.
2. Consumer specific bucket and path configuration.

### Global bucket and path configuration
In this mode, the bucket and/or path is set at the `s3-integrator` charm level, such that any related applications will always receive this bucket and/or path when they relate to `s3-integrator.`

To enforce a bucket globally for all charms related to the `s3-integrator`, set the `bucket` config option in `s3-integrator` charm.

```
juju config s3-integrator bucket=global-bucket
```

Similarly, to enforce a path globally for all charms related to `s3-integrator`, set the `path` config option in `s3-integrator` charm.

```
juju config s3-integrator path=global-path
```


### Consumer specific bucket and path configuration
In this mode, the bucket and/or path is purposefully not set at the `s3-integrator` charm level, such that the related applications can request for a specific bucket and/or path from the `s3-integrator` charm when they relate to it.

To allow for the consumer charms to request bucket and/or path themselves, do not set the value of `bucket` and/or `path` config option at the `s3-integrator` charm level. The consumer charms can then make this request by specifying the `bucket` and/or `path` keyword argument in the charm code, when instantiating the `S3Requirer` class from `object-storage-charmlib`.

```python
from object_storage import S3Requirer

class MyCharm(CharmBase):
   def __init__(*args, **kwargs):
      s3_client = S3Requirer(
         self, 
         relation_name="s3", 
         bucket="custom-requested-bucket", # Bucket requested by the consumer charm
         path="custom-requested-path"      # Path requested by the consumer charm
      )
```

In the case where the `bucket` and/or `path` is both specified at the `s3-integrator` charm level and requested by the consumer charm via the `S3Requirer` class, the value specified in the `s3-integrator` charm level will always take precedence and thus will overwrite the value requested by consumer charm.

## Troubleshooting
The S3 Integrator charm implements the Advanced Charm Statuses lib, and thus is able to track multiple statuses at the same time. The details regarding various statuses and the recommended action for them can be viewed by running the action `status-detail` on the charm leader unit.

```
juju run s3-integrator/0 status-detail
```

One of the most common statuses reported by the S3 integrator charm is the charm being on blocked state with message `Could not ensure bucket(s): xxxxx`. This status is set by the charm when it cannot ensure the bucket for use, probably due to one of the following reasons:
1. The given connection parameters (eg, access key, secret key, endpoint, region, etc.) are not valid.
2. The charm cannot make a successful HTTP / HTTPS connection to the S3 endpoint (eg, due to proxy, invalid TLS certificate, etc.)
2. The IAM user (corresponding to access key and secret key) does not have enough permissions to call `ListObjectsv2` on the existing bucket.
3. The IAM user (corresponding to access key and secret key) does not have enough permissions to create a non-existent bucket.

In these cases, the first step to troubleshoot this is to check the `juju debug-log`, as the charm logs any failure to ensure the bucket there.

## Security

Security issues in the Charmed Object Storage Integrator Operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File). Please do not file GitHub issues about security issues.

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/object-storage-integrators/blob/main/CONTRIBUTING.md) for developer guidance.
