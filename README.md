# Object Storage Integrator Monorepo

[![PyPI](https://img.shields.io/pypi/v/object-storage-charmlib)](https://pypi.python.org/pypi/object-storage-charmlib)
[![Charmhub](https://charmhub.io/s3-integrator/badge.svg?channel=2/edge)](https://charmhub.io/s3-integrator)
[![Charmhub](https://charmhub.io/azure-storage-integrator/badge.svg)](https://charmhub.io/azure-storage-integrator)
[![Charmhub](https://charmhub.io/gcs-integrator/badge.svg)](https://charmhub.io/gcs-integrator)
[![Tests](https://github.com/canonical/object-storage-integrator/actions/workflows/ci.yaml/badge.svg)](https://github.com/canonical/object-storage-integrator/actions/workflows/ci.yaml)

This repository is a monorepo for the various object storage integrator charms and the shared charmlib used by those charms. Specifically, it hosts the following components:

1. [S3 Integrator (track `2/`)](./s3/README.md) -- a charm that is capable of creating S3 buckets on request, and then share the bucket and S3 connection information over the relation to the related charms.
2. [Azure Storage Integrator](./azure_storage/README.md) -- a charm that is meant to provide connection information to connect to Azure Blob Storage and Azure Data Lake Storage over the relation to the related charms.
3. [Google Cloud Storage (GCS) Integrator](./gcs/README.md) -- a charm that is meant to provide connection information to connect to Google Cloud Storage over the relation to the related charms.
4. [Object Storage Charmlib](./lib/README.md) -- a charmlib used by the aforementioned integrator charms, and also used by the consumer charms that want to relate to the aforementioned integrator charms.

Please refer to the README files in respective component subdirectories for the documentation on the specific component.

For older implementation of `s3-integrator` from track `1/`, please refer to <https://github.com/canonical/s3-integrator>.
