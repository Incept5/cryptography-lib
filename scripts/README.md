# Key Rotation Script

This directory contains utility scripts for the Incept5 Cryptography Library.

## Key Rotation

The `key_rotation.py` script allows you to rotate encryption keys in the vault. This is useful when you need to change encryption keys for security reasons or compliance requirements.

### Prerequisites

- Python 3.6+
- Required Python packages:
  - psycopg2
  - cryptography

You can install the required packages using pip:

```bash
pip install psycopg2-binary cryptography
```

### Usage

```bash
python key_rotation.py --db-url <jdbc_url> --db-user <username> --db-password <password> \
                      --old-key-id <old_key_id> --old-key-aes <old_key_aes_base64> --old-key-hmac <old_key_hmac_base64> \
                      --new-key-id <new_key_id> --new-key-aes <new_key_aes_base64> --new-key-hmac <new_key_hmac_base64> \
                      [--schema <schema_name>] [--dry-run]
```

### Parameters

- **Database Connection**:
  - `--db-url`: JDBC URL for the database (e.g., `jdbc:postgresql://localhost:5432/cryptography_test`)
  - `--db-user`: Database username
  - `--db-password`: Database password

- **Old Key**:
  - `--old-key-id`: ID of the old encryption key
  - `--old-key-aes`: Base64-encoded AES key (old)
  - `--old-key-hmac`: Base64-encoded HMAC key (old)

- **New Key**:
  - `--new-key-id`: ID of the new encryption key
  - `--new-key-aes`: Base64-encoded AES key (new)
  - `--new-key-hmac`: Base64-encoded HMAC key (new)

- **Optional Parameters**:
  - `--schema`: Database schema (default: public)
  - `--dry-run`: Perform a dry run without making changes

### Example

```bash
python key_rotation.py --db-url jdbc:postgresql://localhost:5432/cryptography_test \
                      --db-user postgres --db-password postgres \
                      --old-key-id 81b4f837-c134-4e7f-bb5e-802d5dcc5d4c \
                      --old-key-aes 8hV/a1MfXxjS54JS+35TMQx7K2TH/8eX6BtrwRKXARg= \
                      --old-key-hmac sHjLLmW3wA6KWu3cBDJwi9bsVD7bqoTVEzJHacgSfns= \
                      --new-key-id 92c5f948-d245-5f8g-cc6f-913e6edd6e5d \
                      --new-key-aes 9iW/b2NgYyKjT65KT+46UNRy8L3UI/9fY7CusXSLBSh= \
                      --new-key-hmac tIkMMnX4xB7LXv4dCEKxj0ctWE8crlUWFzKIbdgTgot= \
                      --schema example
```

### Generating New Keys

You can generate new encryption keys using the following commands:

```bash
# Generate a new AES key
openssl rand -base64 32

# Generate a new HMAC key
openssl rand -base64 32

# Generate a new key ID
python -c "import uuid; print(uuid.uuid4())"
```

### Dry Run Mode

Use the `--dry-run` flag to test the key rotation process without making any changes to the database. This is useful for verifying that the script can successfully decrypt all data with the old key before actually performing the rotation.

```bash
python key_rotation.py --db-url ... --dry-run
```

### After Key Rotation

After successfully rotating the keys, you should update your application configuration to use the new encryption key. For example, in your `application.yaml`:

```yaml
incept5:
  cryptography:
    encryption:
      key:
        id: <new-key-id>
        aes: <new-key-aes>
        hmac: <new-key-hmac>
      decryption-keys:
        - id: ${incept5.cryptography.encryption.key.id}
          aes: ${incept5.cryptography.encryption.key.aes}
          hmac: ${incept5.cryptography.encryption.key.hmac}
        # Keep the old key for backward compatibility if needed
        - id: <old-key-id>
          aes: <old-key-aes>
          hmac: <old-key-hmac>
```

### Security Considerations

- Store encryption keys securely and never commit them to version control
- Consider using a secrets management solution like HashiCorp Vault or AWS KMS
- Perform key rotation during maintenance windows to minimize impact
- Always back up your database before performing key rotation