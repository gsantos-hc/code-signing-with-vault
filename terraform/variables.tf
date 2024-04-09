# General configuration --------------------------------------------------------
variable "vault_addr" {
  description = "Vault address reachable by PKI Subscribers for certificate validation"
  type        = string
}

variable "namespace" {
  description = "Vault namespace in which to configure PKI resources"
  type        = string
  default     = "root"
}

# PKI mounts and roles ---------------------------------------------------------
variable "pki_base_name" {
  description = "Base name to use for Certificate Authorities"
  type        = string
}

variable "pki_country" {
  description = "Two-letter country code for the Certificate Authority and Code Signing certificates"
  type        = string
  default     = null
  
  validation {
    condition     = var.pki_country == null || length(var.pki_country) == 2
    error_message = "If specified, `pki_country` must be a two-letter country code."
  }
}

variable "pki_organization" {
  description = "Name of the organization for Certificate Authority and Code Signing certificates"
  type        = string
  default     = null
}

variable "pki_codesign_cert" {
  description = "PEM bundle of the Code Signing CA's certificate and the issuing CAs' certificates"
  type        = string
}

variable "code_sign_cert_ttl" {
  description = "TTL of short-lived code signing certificates"
  type        = string
  default     = "1h"
}

# GitHub Actions Auth ----------------------------------------------------------
variable "gh_actions_auth_mount_path" {
  description = "Mount path for the GitHub Actions JWT authentication backend"
  type        = string
  default     = "gh-actions"
}

variable "gh_actions_oidc_discovery_url" {
  description = "OIDC discovery URL for GitHub Actions"
  type        = string
  default     = "https://token.actions.githubusercontent.com"
}

variable "repository_owners" {
  description = "List of GitHub repository owners to which code signing certificates may be issued."
  type        = list(string)
}
