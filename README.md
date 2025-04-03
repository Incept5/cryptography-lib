# Velostone Cryptography Lib

Welcome to the Cryptography-Lib, a library designed to streamline cryptography in your projects.


## Usage

## Add flyway location

Include the velostone/cryptography location as an extra flyway location in your application.yaml:

    quarkus:
      flyway:
        locations: db/migration,velostone/cryptography


### Vault

Inject vault and you can use it to encrypt a string and get back a token (UUID)
 which can be used to decrypt the string later to get the original contents.

```java
class ExampleService(vault:Vault) {
    public void example() {
        val token = vault.encrypt("Hello World");
        val value = vault.decrypt(token);
        assert value.equals("Hello World");
    }
}
```

### EncryptedValueConverter on Entities
Or you can use the `EncryptedValueConverter` to encrypt a field on an entity.

    @Entity
    @Table(name = "Person")
    data class Person(

        @Column(nullable = true)
        @Convert(converter = EncryptedValueConverter::class)
        var ssn: String? = null
    
    )

## Modules

### Cryptography-Quarkus
The `cryptography-quarkus` module is a specialized cryptography library tailored for Quarkus applications. It extends the functionality of the VeloPayments core library `org.incept5:cryptography-core` to provide a seamless and efficient cryptography experience within Quarkus projects.

### Cryptography-Sample-App
The `cryptography-sample-app` module is a sample application specifically created for testing the cryptography capabilities of the Quarkus library. It serves as a practical demonstration of how to implement and leverage the features provided by the `cryptography-quarkus` module in a Quarkus environment.

## Getting Started
To incorporate Cryptography-Lib into your project, follow the instructions provided in each module's respective documentation. If you are in a Quarkus project, to incorporate `cryptography-quarkus` into your project, just add the following dependency to your `build.gradle` file:

```groovy
implementation 'org.incept5.libs:cryptography-quarkus:${version}'
```
To get the latest version, check all [releases] in the repository:

https://ci.velointra.net/nexus/content/repositories/releases/org.incept5/libs/cryptography-quarkus/