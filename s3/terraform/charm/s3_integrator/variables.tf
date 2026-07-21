# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "app_name" {
  description = "Name to give the deployed application."
  type        = string
  default     = "s3-integrator"
  nullable    = false
}

variable "base" {
  description = "The operating system on which to deploy. E.g. ubuntu@22.04."
  type        = string
  default     = null
}

variable "channel" {
  description = "Channel of the charm."
  type        = string
  default     = "2/stable"
  nullable    = false
}

variable "config" {
  description = "S3 Integrator charm configuration options."
  type = object({
    attributes                          = optional(string)
    bucket                              = optional(string)
    credentials                         = optional(string)
    endpoint                            = optional(string)
    experimental-delete-older-than-days = optional(number)
    path                                = optional(string)
    region                              = optional(string)
    s3-api-version                      = optional(string)
    s3-uri-style                        = optional(string)
    storage-class                       = optional(string)
    tls-ca-chain                        = optional(string)
  })
  default = {}

  validation {
    condition = (
      var.config.credentials == null
      ? true
      : startswith(var.config.credentials, "secret:")
    )
    error_message = "config.credentials must be a Juju secret URI starting with 'secret:'."
  }

  validation {
    condition = (
      var.config["experimental-delete-older-than-days"] == null
      ? true
      : var.config["experimental-delete-older-than-days"] >= 1 && var.config["experimental-delete-older-than-days"] <= 9999999
    )
    error_message = "config.experimental-delete-older-than-days must be between 1 and 9999999."
  }

  validation {
    condition = (
      var.config["s3-api-version"] == null
      ? true
      : contains(["2", "4"], var.config["s3-api-version"])
    )
    error_message = "config.s3-api-version must be either 2 or 4."
  }
}


variable "constraints" {
  description = "String listing constraints for this application."
  type        = string
  default     = null
}

variable "endpoint_bindings" {
  description = "Map of endpoint bindings"
  type = set(object({
    space    = string
    endpoint = optional(string)
  }))
  default = []
}

variable "model_uuid" {
  description = "Reference to an existing model uuid."
  type        = string
  nullable    = false
}

variable "machines" {
  description = "List of machines for placement"
  type        = set(string)
  default     = []
}

variable "storage_directives" {
  description = "Map of storage directives (constraints) for the Juju application."
  type        = map(string)
  default     = {}
}

variable "revision" {
  description = "Revision number of the charm."
  type        = number
  default     = null
}

variable "units" {
  description = "Unit count."
  type        = number
  default     = 1
}
