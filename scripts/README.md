# Key Rotation Script

This directory contains utility scripts for the Incept5 Cryptography Library.

## Key Rotation

The `key_rotation.py` script allows you to rotate encryption keys in the vault. This is useful when you need to change encryption keys for security reasons or compliance requirements.

### Prerequisites

- Python 3.6+
- Required Python packages:
  - psycopg2
  - cryptography
  - pyyaml

You can install the required packages using pip:

```bash
pip install psycopg2-binary cryptography pyyaml
```

### Usage

```bash
python key_rotation.py --config <config_file_path> [--dry-run]
```

### Parameters

- `--config`: Path to the YAML configuration file
- `--dry-run`: Perform a dry run without making changes (optional)

### Configuration File

The script uses a YAML configuration file to specify database connection details and encryption keys. An example configuration file is provided at `key_rotation_config.yaml.example`. Make a copy of this file and update it with your actual values.

```yaml
# Database connection settings
database:
  url: jdbc:postgresql://localhost:5432/cryptography_test
  username: postgres
  password: postgres
  schema: example  # Optional, defaults to public if not specified

# Old encryption key (current key)
old_key:
  id: 81b4f837-c134-4e7f-bb5e-802d5dcc5d4c
  aes: 8hV/a1MfXxjS54JS+35TMQx7K2TH/8eX6BtrwRKXARg=
  hmac: sHjLLmW3wA6KWu3cBDJwi9bsVD7bqoTVEzJHacgSfns=

# New encryption key (to rotate to)
new_key:
  id: 92c5f948-d245-5f8g-cc6f-913e6edd6e5d
  aes: 9iW/b2NgYyKjT65KT+46UNRy8L3UI/9fY7CusXSLBSh=
  hmac: tIkMMnX4xB7LXv4dCEKxj0ctWE8crlUWFzKIbdgTgot=
```

### Example

```bash
# Create your configuration file
cp key_rotation_config.yaml.example key_rotation_config.yaml
# Edit the file with your actual values
nano key_rotation_config.yaml

# Run the script with your configuration
python key_rotation.py --config key_rotation_config.yaml

# Or perform a dry run first
python key_rotation.py --config key_rotation_config.yaml --dry-run
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
python key_rotation.py --config key_rotation_config.yaml --dry-run
```

### Configuration Security

The configuration file contains sensitive information such as database credentials and encryption keys. To keep this information secure:

1. Never commit the actual configuration file to version control
2. Use restrictive file permissions for the configuration file
3. Consider using environment variables or a secrets management solution for production environments

```bash
# Set restrictive permissions on the configuration file
chmod 600 key_rotation_config.yaml
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
- Use environment variables or a secure parameter store for sensitive configuration in production