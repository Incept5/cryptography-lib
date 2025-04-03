package org.incept5.cryptography.quarkus.service

import org.incept5.cryptography.core.EncryptionService
import org.incept5.cryptography.vault.Vault
import org.incept5.cryptography.vault.db.SqlVault
import jakarta.enterprise.inject.Produces
import jakarta.inject.Singleton
import org.eclipse.microprofile.config.inject.ConfigProperty
import javax.sql.DataSource

/**
 * Create Quarkus managed bean for Vault
 * Use the simple SQL implementation
 */
class VaultFactory {

    @Produces
    @Singleton
    fun createVault(dataSource: DataSource, encryptionService: EncryptionService, @ConfigProperty(name = "quarkus.flyway.default-schema", defaultValue = "" ) schema: String = ""): Vault {
        return SqlVault(dataSource, encryptionService, schema)
    }

}