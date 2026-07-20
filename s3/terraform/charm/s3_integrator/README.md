# Terraform module for s3-integrator

This is a Terraform module facilitating the deployment of the S3 integrator charm with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs).

## Requirements

| Name | Version |
|------|---------|
| `Terraform` | >= 1.6 |
| `Juju provider` | ~> 2.0  |

## Providers

| Name | Version |
| ---- | ------- |
| `juju` | ~> 2.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| `juju_application.s3_integrator` | [Juju application](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) |
| `juju_offer.s3_credentials` | [Juju offer](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/offer) |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `app_name` | Name to give the deployed application. | `string` | `"s3-integrator"` | no |
| `base` | The operating system on which to deploy. E.g. `ubuntu@22.04`. | `string` | `null` | no |
| `channel` | Channel of the charm. | `string` | `"2/stable"` | no |
| `config` | S3 Integrator charm configuration options. | <pre>object({<br/>    attributes                          = optional(string)<br/>    bucket                              = optional(string)<br/>    credentials                         = optional(string)<br/>    endpoint                            = optional(string)<br/>    experimental-delete-older-than-days = optional(number)<br/>    path                                = optional(string)<br/>    region                              = optional(string)<br/>    s3-api-version                      = optional(string)<br/>    s3-uri-style                        = optional(string)<br/>    storage-class                       = optional(string)<br/>    tls-ca-chain                        = optional(string)<br/>  })</pre> | `{}` | no |
| `constraints` | String listing constraints for this application. | `string` | `null` | no |
| `endpoint_bindings` | Set of endpoint bindings | <pre>set(object({<br/>    space    = string<br/>    endpoint = optional(string)<br/>  }))</pre> | `[]` | no |
| `machines` | List of machines for placement | `set(string)` | `[]` | no |
| `model_uuid` | Reference to an existing model uuid. | `string` | n/a | yes |
| `revision` | Revision number of the charm. | `number` | `null` | no |
| `storage_directives` | Map of storage directives (constraints) for the Juju application. | `map(string)` | `{}` | no |
| `units` | Unit count. | `number` | `1` | no |

### S3 config options

| Name | Description |
|------|-------------|
| `attributes` | Optional custom metadata sent as HTTP headers. |
| `bucket` | Bucket or container name delivered by the provider. |
| `credentials` | Juju Secret URI beginning with `secret:` and containing `access-key` and `secret-key`. |
| `endpoint` | Optional object-storage endpoint URI. |
| `experimental-delete-older-than-days` | Optional backup retention period from 1 to 9999999 days. |
| `path` | Optional path inside the bucket or container. |
| `region` | Optional object-storage region. |
| `s3-api-version` | Optional S3 API signature version: `2` or `4`. |
| `s3-uri-style` | Optional S3 bucket path lookup style. |
| `storage-class` | Optional storage class for uploaded objects. |
| `tls-ca-chain` | Optional complete CA chain used for HTTPS validation. |

## Outputs

| Name | Description |
|------|-------------|
| `application` | Object representing the deployed application. |
| `offers` | Map of all offers exposed by the single charm. |
| `provides` | Map of all "provides" endpoints. |
| `requires` | Map of all "requires" endpoints. |
