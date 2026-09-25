# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "application" {
  description = "Object representing the deployed application."
  value       = juju_application.azure_storage_integrator
}

output "offers" {
  description = "Map of all offers exposed by the single charm."
  value = {
    azure_storage_credentials = {
      kind = "offer"
      url  = juju_offer.azure_storage_credentials.url
    }
  }
}


output "provides" {
  description = "Provides endpoints."
  value = {
    azure_storage_credentials = {
      kind     = "endpoint"
      name     = juju_application.azure_storage_integrator.name
      endpoint = "azure-storage-credentials"
    }
  }
}

output "requires" {
  description = "Map of all \"requires\" endpoints"
  value       = {}
}
