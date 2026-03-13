# Object Storage Integrator Monorepo

This repository is the monorepo for the various object storage integrator charms, and the charmlib that are used by those charms. Specifically, this monorepo hosts the following components:
1. [S3 Integrator (track `2/`)](./s3/README.md) -- a charm that is capable of creating S3 buckets on request, and then share the bucket and S3 connection information over the relation to the related charms.
2. [Azure Storage Integrator](./azure_storage/README.md) -- a charm that is meant to provide connection information to connect to Azure Blob Storage and Azure Data Lake Storage over the relation to the related charms.
3. [Google Cloud Storage (GCS) Integrator](./gcs/README.md) -- a charm that is meant to provide connection information to connect to Google Cloud Storage over the relation to the related charms.
4. [Object Storage Charmlib](./lib/README.md) -- a charmlib used by the aforementioned integrator charms, and also used by the consumer charms that want to relate to the aforementioned integrator charms.

Please refer to the README in respective component subdirectories for the documentation on the specific component.

For older implementation of `s3-integrator` from track `1/`, please refer to https://github.com/canonical/s3-integrator.
