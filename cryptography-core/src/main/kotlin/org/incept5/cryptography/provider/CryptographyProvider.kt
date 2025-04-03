package org.incept5.cryptography.provider

import org.incept5.cryptography.EncryptionException
import org.incept5.cryptography.core.EncryptedValue

interface EncryptionProvider {
    /**
     * Encrypt a value
     *
     * @param value
     * @return an encrypted representation of the value
     * @throws EncryptionException
     */
    @Throws(EncryptionException::class)
    fun encrypt(value: String?): EncryptedValue?

    /**
     * Encrypt arbitrary bytes (support binary files)
     * @param value
     * @return
     * @throws EncryptionException
     */
    @Throws(EncryptionException::class)
    fun encrypt(value: ByteArray?): EncryptedValue

    /**
     * Decrypt a value
     *
     * @param encryptedValue - the encrypted representation of the value
     * @return the decrypted value
     * @throws EncryptionException
     */
    @Throws(EncryptionException::class)
    fun decrypt(encryptedValue: EncryptedValue?): String?


    /**
     * Decrypt a value as bytes (support binary files)
     *
     * @param encryptedValue - the encrypted representation of the value
     * @return the decrypted value
     * @throws EncryptionException
     */
    @Throws(EncryptionException::class)
    fun decryptAsBytes(encryptedValue: EncryptedValue?): ByteArray?

    /**
     * Has the value changed?
     *
     * @param initialValue - can be plain value or EncryptedValueWrapper Json
     * @param proposedValue - can be plain value or EncryptedValueWrapper Json
     *
     * @return boolean
     */
    fun hasChanged(initialValue: EncryptedValue, proposedValue: String): Boolean
}