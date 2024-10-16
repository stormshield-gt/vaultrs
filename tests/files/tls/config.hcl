storage "inmem" {}

listener "tcp" {
  address     = "0.0.0.0:8200"
  # Specifies the path to the root CA that sign the vault certificate
  tls_cert_file = "/vault/config/vault_server.crt"
  # Specifies the path to the Vault server private key.
  tls_key_file = "/vault/config/vault_server.key"
  tls_client_ca_file = "/vault/config/ca_cert.crt"
  tls_min_version = "tls13"
}

default_lease_ttl = "168h"
max_lease_ttl     = "720h"
ui                = true

disable_mlock     = true
