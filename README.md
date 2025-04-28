# Incept5 Cryptography Library

A robust, easy-to-use cryptography library for securing sensitive data in your applications. This library provides encryption, decryption, and secure storage capabilities with a focus on simplicity and security.

## Features

- **Strong Encryption**: AES encryption with HMAC validation for data integrity
- **Vault Storage**: Secure storage of encrypted data with UUID-based retrieval
- **JPA Integration**: Automatic encryption/decryption of entity fields
- **Quarkus Support**: Seamless integration with Quarkus applications
- **Flyway Migration**: Database schema setup for vault storage

## Modules

### cryptography-core

The core module provides the fundamental cryptography functionality:

- `EncryptionService`: Interface for encrypting and decrypting data
- `Vault`: Interface for storing and retrieving encrypted data
- Encryption providers and utilities

### cryptography-quarkus

The Quarkus integration module provides:

- Automatic configuration via application.yaml
- CDI integration for dependency injection
- JPA attribute converters for entity field encryption
- Flyway migration scripts for vault setup

### cryptography-sample-app

A sample Quarkus application demonstrating the library's usage:

- Entity field encryption examples
- Vault storage examples
- Complete configuration setup

## Installation

### Maven

Add the following dependencies to your `pom.xml`:

```xml
<!-- Core library -->
<dependency>
    <groupId>com.github.incept5</groupId>
    <artifactId>cryptography-core</artifactId>
    <version>${version}</version>
</dependency>

<!-- Quarkus integration (if using Quarkus) -->
<dependency>
    <groupId>com.github.incept5</groupId>
    <artifactId>cryptography-quarkus</artifactId>
    <version>${version}</version>
</dependency>
```

### Gradle (Kotlin DSL)

Add the following dependencies to your `build.gradle.kts`:

```kotlin
// Core library
implementation("com.github.incept5:cryptography-core:${version}")

// Quarkus integration (if using Quarkus)
implementation("com.github.incept5:cryptography-quarkus:${version}")
```

### Gradle (Groovy DSL)

Add the following dependencies to your `build.gradle`:

```groovy
// Core library
implementation 'com.github.incept5:cryptography-core:${version}'

// Quarkus integration (if using Quarkus)
implementation 'com.github.incept5:cryptography-quarkus:${version}'
```

## Configuration

### Quarkus Configuration

Add the following to your `application.yaml` or `application.properties`:

```yaml
# Flyway configuration for vault schema
quarkus:
  flyway:
    locations: db/migration,incept5/cryptography

# Encryption key configuration
incept5:
  cryptography:
    encryption:
      key:
        id: your-key-id-uuid
        aes: your-base64-encoded-aes-key
        hmac: your-base64-encoded-hmac-key
      decryption-keys:
        - id: ${incept5.cryptography.encryption.key.id}
          aes: ${incept5.cryptography.encryption.key.aes}
          hmac: ${incept5.cryptography.encryption.key.hmac}
```

### Generating Secure Keys

You can generate secure keys using the following commands:

```bash
# Generate AES key (256 bits)
openssl rand -base64 32

# Generate HMAC key (256 bits)
openssl rand -base64 32

# Generate UUID for key ID
uuidgen
```

## Usage Examples

### Using the Vault

The Vault provides a way to store encrypted data and retrieve it using a UUID token:

```kotlin
// Inject the Vault
@Inject
lateinit var vault: Vault

// Store sensitive data and get a token
val token: UUID = vault.store("Sensitive information")

// Retrieve the data using the token
val retrievedData: String? = vault.retrieve(token)

// Delete the data when no longer needed
vault.delete(token)
```

### Encrypting Entity Fields

You can automatically encrypt entity fields using the `EncryptedValueConverter`:

```kotlin
@Entity
@Table(name = "Person")
data class Person(
    @Id
    var id: UUID = UUID.randomUUID(),
    
    var name: String,
    
    // This field will be automatically encrypted in the database
    @Column(nullable = true)
    @Convert(converter = EncryptedValueConverter::class)
    var socialSecurityNumber: String? = null,
    
    // This field will be automatically encrypted in the database
    @Column(nullable = true)
    @Convert(converter = EncryptedValueConverter::class)
    var creditCardNumber: String? = null
)
```

### Direct Encryption/Decryption

For more control, you can use the `EncryptionService` directly:

```kotlin
@Inject
lateinit var encryptionService: EncryptionService

// Encrypt data
val encryptedData: String = encryptionService.encrypt("Sensitive data")

// Decrypt data
val decryptedData: String? = encryptionService.decrypt(encryptedData)
```

## Security Considerations

- Store encryption keys securely, preferably in a secure vault like HashiCorp Vault or AWS KMS
- Rotate encryption keys periodically (see [Key Rotation Documentation](scripts/README.md) for details)
- Use environment variables or secure configuration providers for key storage in production
- Consider implementing key rotation strategies for long-term data storage

## Database Schema

The library creates a `vault` table with the following structure:

- `id`: UUID primary key
- `encrypted_value`: The encrypted data
- `created_at`: Timestamp of creation
- `updated_at`: Timestamp of last update

## Advanced Usage

### Multiple Decryption Keys

You can configure multiple decryption keys to support key rotation:

```yaml
incept5:
  cryptography:
    encryption:
      key:
        id: current-key-id
        aes: current-aes-key
        hmac: current-hmac-key
      decryption-keys:
        - id: current-key-id
          aes: current-aes-key
          hmac: current-hmac-key
        - id: old-key-id
          aes: old-aes-key
          hmac: old-hmac-key
```

### Key Rotation

For secure key rotation, a Python utility script is provided in the `scripts` directory. This script helps you safely rotate encryption keys in the vault database.

See the [Key Rotation Documentation](scripts/README.md) for detailed instructions on how to use this utility.

### Custom Encryption Providers

You can implement custom encryption providers by implementing the `CryptographyProvider` interface.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.