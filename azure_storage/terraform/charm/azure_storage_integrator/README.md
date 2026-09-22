# Terraform module for azure-storage-integrator

This is a Terraform module facilitating the deployment of the Azure Storage integrator charm with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs).

## Requirements

| Name | Version |
|------|---------|
| `Terraform` | >= 1.6 |
| `Juju provider` | >= 1.0.0  |

## Providers

| Name | Version |
| ---- | ------- |
| `juju` | >= 1.0.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| `juju_application.azure_storage_integrator` | [Juju application](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) |
| `juju_offer.azure_storage_credentials` | [Juju offer](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/offer) |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `app_name` | Name to give the deployed application. | `string` | `"azure-storage-integrator"` | no |
| `base` | The operating system on which to deploy. E.g. `ubuntu@22.04`. | `string` | `null` | no |
| `channel` | Channel of the charm. | `string` | `"1/stable"` | no |
| `config` | Azure Storage integrator charm configuration options. | <pre>object({<br/>    connection-protocol = optional(string)<br/>    container           = optional(string)<br/>    credentials         = optional(string)<br/>    endpoint            = optional(string)<br/>    path                = optional(string)<br/>    resource-group      = optional(string)<br/>    storage-account     = optional(string)<br/>  })</pre> | `{}` | no |
| `constraints` | String listing constraints for this application. | `string` | `null` | no |
| `endpoint_bindings` | Set of endpoint bindings | <pre>set(object({<br/>    space    = string<br/>    endpoint = optional(string)<br/>  }))</pre> | `[]` | no |
| `machines` | List of machines for placement | `set(string)` | `[]` | no |
| `model_uuid` | Reference to an existing model uuid. | `string` | n/a | yes |
| `revision` | Revision number of the charm. | `number` | `null` | no |
| `storage_directives` | Map of storage directives (constraints) for the Juju application. | `map(string)` | `{}` | no |
| `units` | Unit count. | `number` | `1` | no |

### Azure Storage config options

| Name | Description |
|------|-------------|
| `connection-protocol` | Storage protocol used to connect to Azure Storage. Must be one of `wasb`, `wasbs` (Azure Blob Storage), `abfs`, `abfss` (Azure Data Lake Storage Gen2), `http`, or `https` (Azure Blob/Files REST API). The charm default is `abfss`. |
| `container` | Name of the Azure Storage container. |
| `credentials` | Juju Secret URI, such as `secret:xxxx`, containing the storage account secret key under `secret-key`. |
| `endpoint` | Optional endpoint URL for the storage account. Overrides the endpoint derived from `connection-protocol`, `container` and `storage-account`. |
| `path` | Optional path inside the container to store objects. |
| `resource-group` | Optional name of the Azure resource group where the storage account is located. |
| `storage-account` | Name of the Azure Storage account. |

## Outputs

| Name | Description |
|------|-------------|
| `application` | Object representing the deployed application. |
| `offers` | Map of all offers exposed by the single charm. |
| `provides` | Map of all "provides" endpoints. |
| `requires` | Map of all "requires" endpoints |


## Usage

Create a Juju secret containing the Azure Storage account secret key, pass its
URI to the module, and grant the deployed application access to it:

```hcl
resource "juju_secret" "azure_storage_credentials" {
  model_uuid = "<model-uuid>"
  name       = "azure-storage-credentials"
  value = {
    secret-key = "<azure-storage-account-secret-key>"
  }
}

module "azure_storage_integrator" {
  source = "git::https://github.com/canonical/object-storage-integrator.git//azure_storage/terraform/charm/azure_storage_integrator?ref=<revision>"

  model_uuid = "<model-uuid>"
  config = {
    container       = "<container-name>"
    storage-account = "<storage-account-name>"
    credentials     = juju_secret.azure_storage_credentials.secret_uri
  }
}

resource "juju_access_secret" "azure_storage_credentials" {
  model_uuid = "<model-uuid>"
  secret_id  = juju_secret.azure_storage_credentials.secret_id
  applications = [
    module.azure_storage_integrator.application.name
  ]
}
```
