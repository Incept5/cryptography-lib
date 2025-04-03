package org.incept5.cryptography.vault.db

import org.incept5.cryptography.core.EncryptionService
import org.incept5.cryptography.vault.Vault
import java.time.Instant
import java.util.*
import javax.sql.DataSource

/**
 * Simple standard SQL Vault implementation.
 *
 * Allows up to 20MB of data per item by default
 *
 */
class SqlVault(private val dataSource: DataSource, private val encryptionService: EncryptionService, scheme: String = "", private val   maxBytes : Long = MAX_BYTES) : Vault {

    companion object {
        const val MAX_BYTES : Long = 1024 * 1024 * 20 // 20MB
    }

    private val tableName = if (scheme.isEmpty()) "vault" else "$scheme.vault"

    override fun store(plainBytes: ByteArray?): UUID {
        if ( plainBytes != null && plainBytes.size > maxBytes ) {
            throw IllegalArgumentException("Vault item too large for storing: ${plainBytes.size} bytes")
        }
        val encryptedText = encryptionService.encrypt(plainBytes)
        val id = UUID.randomUUID()
        dataSource.connection.use { conn ->
            conn.prepareStatement("INSERT INTO $tableName (id, encrypted_contents, created_at) VALUES (?, ?, ?)").use { stmt ->
                stmt.setObject(1, id)
                stmt.setString(2, encryptedText)
                stmt.setTimestamp(3, java.sql.Timestamp.from(Instant.now()))
                stmt.executeUpdate()
            }
        }
        return id
    }

    override fun retrieveAsBytes(id: UUID): ByteArray? {
        return dataSource.connection.use { conn ->
            conn.prepareStatement("SELECT encrypted_contents FROM $tableName WHERE id = ?").use { stmt ->
                stmt.setObject(1, id)
                stmt.executeQuery().use { rs ->
                    if (rs.next()) {
                        val encryptedText = rs.getString("encrypted_contents")
                        encryptionService.decryptAsBytes(encryptedText)
                    }
                    else {
                        throw IllegalArgumentException("Vault item not found for ID: $id")
                    }
                }
            }
        }
    }

    override fun delete(id: UUID) {
        dataSource.connection.use { conn ->
            conn.prepareStatement("DELETE FROM $tableName WHERE id = ?").use { stmt ->
                stmt.setObject(1, id)
                stmt.executeUpdate()
            }
        }
    }
}