# Vault Key Management for Cosign Signing

This guide outlines how to securely generate, store, and retrieve Cosign signing keys using HashiCorp Vault. It is intended for platform teams managing CI/CD signing workflows, with keys fully controlled by the platform and never exposed to developers.

---

## 1. Install Vault CLI (v1.16.2) on macOS

```bash
# Download Vault 1.16.2 for macOS (Intel)
curl -LO https://releases.hashicorp.com/vault/1.16.2/vault_1.16.2_darwin_amd64.zip

# Unzip and move to PATH
unzip vault_1.16.2_darwin_amd64.zip
chmod +x vault
sudo mv vault /usr/local/bin/

# Confirm installation
vault version
```

You should see:

```
Vault v1.16.2
```

---

## 2. Authenticate to Vault Server

```bash
export VAULT_ADDR=https://phobos.butterflycluster.com:8200
export VAULT_SKIP_VERIFY=true   # Only for dev/self-signed Vault
export VAULT_TOKEN="s.your-token-here"
```

Check connection:

```bash
vault status
```

---

## 3. Generate and Store a Cosign Key Pair

Generate a keypair using Cosign:

```bash
cosign generate-key-pair
```

Store in Vault:

```bash
vault kv put secret/cosign/key private_key=@cosign.key
vault kv put secret/cosign/pub key=@cosign.pub
```

---

## 4. Retrieve the Keys from Vault

To fetch the private key (for use by CI/CD only):

```bash
vault kv get -field=private_key secret/cosign/key > cosign.key
```

To fetch the public key (readable by devs or verification tools):

```bash
vault kv get -field=key secret/cosign/pub > cosign.pub
```

---

## 5. Access Control

- The `secret/cosign/key` path should be restricted to CI/CD runner identities only.
- The `secret/cosign/pub` path can be made read-only and auditable for developers and systems that need to verify signatures.
- Rotate keys periodically and update policies accordingly.