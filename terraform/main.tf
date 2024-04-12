terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 4.2.0"
    }
  }
}

provider "vault" {
  namespace = var.namespace
}

locals {
  api_base_path     = trimsuffix(join("/", [var.vault_addr, "v1", var.namespace]), "/")
  pki_codesign_path = "${local.api_base_path}/${vault_mount.pki_codesign.path}"
}

# Code Signing Issuing CA ------------------------------------------------------
locals {
  code_sign_cn       = trimspace("${var.pki_base_name} Code Signing CA")
  spiffe_id_template = "spiffe://github.com/{{ identity.entity.aliases.${vault_jwt_auth_backend.github_actions.accessor}.metadata.repository }}@{{ identity.entity.aliases.${vault_jwt_auth_backend.github_actions.accessor}.metadata.environment }}"
}

resource "vault_mount" "pki_codesign" {
  type        = "pki"
  path        = "pki-codesign"
  description = "Code Signing Issuing CA"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "code_sign_ca" {
  backend      = vault_mount.pki_codesign.path
  type         = "internal" # Do not allow private key to be exported from Vault
  common_name  = local.code_sign_cn
  organization = var.pki_organization
  country      = var.pki_country
  key_type     = "ec"
  key_bits     = 384
}

resource "vault_pki_secret_backend_intermediate_set_signed" "code_sign_ca" {
  count       = var.pki_codesign_cert != null ? 1 : 0
  backend     = vault_mount.pki_codesign.path
  certificate = var.pki_codesign_cert
}

resource "vault_pki_secret_backend_config_cluster" "code_sign_ca" {
  # FIXME: Deploy this resource to PR clusters as well as the primary cluster
  backend  = vault_mount.pki_codesign.path
  path     = local.pki_codesign_path
  aia_path = local.pki_codesign_path
}

resource "vault_pki_secret_backend_config_urls" "code_sign_ca" {
  backend                 = vault_mount.pki_codesign.path
  issuing_certificates    = ["{{cluster_aia_path}}/issuer/{{issuer_id}}/der"]
  crl_distribution_points = ["{{cluster_aia_path}}/issuer/{{issuer_id}}/crl/der"]
  ocsp_servers            = ["{{cluster_aia_path}}/issuer/{{issuer_id}}/ocsp"]
  enable_templating       = true
}

resource "vault_pki_secret_backend_role" "code_sign_gh_actions" {
  backend                   = vault_mount.pki_codesign.path
  name                      = "github-actions"
  key_type                  = "ec"
  key_bits                  = 256
  ttl                       = var.code_sign_cert_ttl
  max_ttl                   = var.code_sign_cert_ttl
  key_usage                 = ["DigitalSignature"]
  code_signing_flag         = true
  server_flag               = false
  client_flag               = false
  country                   = var.pki_country != null ? [var.pki_country] : null
  organization              = var.pki_organization != null ? [var.pki_organization] : null
  enforce_hostnames         = false
  allowed_domains_template  = true
  allowed_domains           = [local.spiffe_id_template]
  allow_bare_domains        = true
  allowed_uri_sans_template = true
  allowed_uri_sans          = [local.spiffe_id_template]
  allow_ip_sans             = false
}

# Authentication Backend -------------------------------------------------------
resource "vault_jwt_auth_backend" "github_actions" {
  path               = var.gh_actions_auth_mount_path
  description        = "GitHub Actions OIDC Authentication"
  oidc_discovery_url = var.gh_actions_oidc_discovery_url
  bound_issuer       = var.gh_actions_oidc_discovery_url
}

resource "vault_jwt_auth_backend_role" "github_actions" {
  backend         = vault_jwt_auth_backend.github_actions.path
  role_name       = "repository"
  role_type       = "jwt"
  bound_audiences = [var.vault_addr]
  bound_claims    = { repository_owner = join(",", var.repository_owners) }
  user_claim      = "sub"
  claim_mappings = {
    repository       = "repository"
    repository_owner = "repository_owner"
    repository_id    = "repository_id"
    environment      = "environment"
  }

  token_type     = "batch"
  token_ttl      = 600
  token_max_ttl  = 600
  token_policies = [vault_policy.github_actions_code_sign_cert.name]
}

# ACL Policy -------------------------------------------------------------------
resource "vault_policy" "github_actions_code_sign_cert" {
  name   = "gh-actions-codesign-cert"
  policy = data.vault_policy_document.github_actions_code_sign_cert.hcl
}

data "vault_policy_document" "github_actions_code_sign_cert" {
  dynamic "rule" {
    for_each = toset(["issue", "sign"])
    content {
      description  = "${title(rule.key)} short-lived code signing certificates"
      path         = join("/", [vault_mount.pki_codesign.path, rule.key, vault_pki_secret_backend_role.code_sign_gh_actions.name])
      capabilities = ["create", "update"]

      allowed_parameter {
        key   = "issuer_ref"
        value = ["default"]
      }

      allowed_parameter {
        key   = "csr"
        value = []
      }

      allowed_parameter {
        key   = "common_name"
        value = []
      }

      allowed_parameter {
        key   = "uri_sans"
        value = []
      }
    }
  }
}
