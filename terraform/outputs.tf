output "code_sign_ca_csr" {
  description = "Certificate signing request for the Code Sign Issuing CA"
  value       = vault_pki_secret_backend_intermediate_cert_request.code_sign_ca.csr
}
