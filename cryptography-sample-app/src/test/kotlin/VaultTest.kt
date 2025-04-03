package org.incept5.cryptography.sampleApp

import org.incept5.cryptography.vault.Vault
import io.quarkus.test.junit.QuarkusTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Test

@QuarkusTest
class VaultTest {

    @Inject
    lateinit var vault: Vault

    @Test
    fun `test vault`() {
        val someString = "some string"
        val token = vault.store(someString)
        val retrievedString = vault.retrieve(token)
        assert(someString == retrievedString)
    }

    @Test
    fun `test vault handles null`() {
        val someString = null as String?
        val token = vault.store(someString)
        val retrievedString = vault.retrieve(token)
        assert(someString == retrievedString)
    }

    /**
     * Should throw IllegalArgumentException
     */
    @Test
    fun `test vault delete`() {
        val someString = "some string"
        val token = vault.store(someString)
        val retrievedString = vault.retrieve(token)
        assert(someString == retrievedString)

        vault.delete(token)
        try{
            vault.retrieve(token)
            assert(false)
        } catch (e: IllegalArgumentException) {
            assert(true)
        }
    }
}
