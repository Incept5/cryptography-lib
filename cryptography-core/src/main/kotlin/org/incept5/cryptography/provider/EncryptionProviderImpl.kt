package org.incept5.cryptography.provider

import org.incept5.cryptography.EncryptionException
import org.incept5.cryptography.core.EncryptedValue
import org.incept5.cryptography.core.EncryptionKey
import java.nio.charset.StandardCharsets
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class EncryptionProviderImpl(encryptionKey: EncryptionKey, decryptionKeys: Iterable<EncryptionKey?>) : EncryptionProvider {
    private val encryptionKey: EncryptionKey = encryptionKey
    private val decryptionKeys: Map<String, EncryptionKey>

    init {
        val keys: HashMap<String, EncryptionKey> = HashMap<String, EncryptionKey>()
        for (key in decryptionKeys) {
            keys[key!!.keyId] = key
        }
        this.decryptionKeys = keys
    }

    @Throws(EncryptionException::class)
    override fun encrypt(unencryptedValue: String?): EncryptedValue {
        return encrypt(unencryptedValue?.toByteArray(StandardCharsets.UTF_8))
    }

    @Throws(EncryptionException::class)
    override fun encrypt(value: ByteArray?): EncryptedValue {
        var unencryptedValue = value
        try {
            if (unencryptedValue == null) { //we can't encrypt null, so we give it a magic value to substitute for null
                unencryptedValue = MAGIC_NULL_VALUE.toByteArray(StandardCharsets.UTF_8)
            }

            val cipher = Cipher.getInstance(ENC_ALGORITHM) //Ciphers are not thread-safe
            val ivSpec = makeIV()
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey.aesKey, ivSpec)

            val ciphertext = cipher.doFinal(unencryptedValue)
            val base64OfEncryptedValue = Base64.getEncoder().encodeToString(ciphertext)
            val base64OfIV = Base64.getEncoder().encodeToString(ivSpec.iv)
            val hashBytes = hash(ciphertext, ivSpec.iv, encryptionKey.hmacKey)
            val base64OfHashOfEncryptedValueAndIV = Base64.getEncoder().encodeToString(hashBytes)

            return EncryptedValue(
                ID,
                encryptionKey.keyId,
                base64OfHashOfEncryptedValueAndIV,
                base64OfEncryptedValue,
                base64OfIV
            )
        } catch (e: RuntimeException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: NoSuchAlgorithmException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: InvalidKeyException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: NoSuchPaddingException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: BadPaddingException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: IllegalBlockSizeException) {
            throw EncryptionException("Error performing encryption", e)
        }
    }

    @Throws(EncryptionException::class)
    private fun hash(encryptedValue: ByteArray, initialisationVector: ByteArray, hmacKey: SecretKeySpec): ByteArray {
        try {
            val sha256_HMAC = Mac.getInstance("HmacSHA256")
            sha256_HMAC.init(hmacKey)

            val data: ByteArray = org.apache.commons.lang3.ArrayUtils.addAll(encryptedValue, *initialisationVector)
            return sha256_HMAC.doFinal(data)
        } catch (e: RuntimeException) {
            throw EncryptionException("Error performing HMAC", e)
        } catch (e: NoSuchAlgorithmException) {
            throw EncryptionException("Error performing HMAC", e)
        } catch (e: InvalidKeyException) {
            throw EncryptionException("Error performing HMAC", e)
        }
    }

    @Throws(EncryptionException::class)
    override fun decrypt(encryptedValue: EncryptedValue?): String? {
        val bytes = decryptAsBytes(encryptedValue) ?: return null
        return String(bytes, StandardCharsets.UTF_8)
    }

    @Throws(EncryptionException::class)
    override fun decryptAsBytes(encryptedValue: EncryptedValue?): ByteArray? {
        if (encryptedValue == null) {
            return null
        }

        try {
            //verify the HMAC - only proceed to decrypt if the hash of the encrypted value + IV matches the stored hash
            //This protects us against some attacks and means that we don't bring the unencrypted value into memory unless absolutely necessary.
            val encBytes: ByteArray = Base64.getDecoder().decode(encryptedValue.encryptedValue)
            val encIv: ByteArray = Base64.getDecoder().decode(encryptedValue.initialisationVector)

            val decryptionKey: EncryptionKey = decryptionKeys[encryptedValue.keyId]
                ?: throw EncryptionException("No matching key is found for decryption. The data is encrypted with key id: " + encryptedValue.keyId)

            val hashBytes = hash(encBytes, encIv, decryptionKey.hmacKey)
            if (!CryptoUtil.areEqual(hashBytes, Base64.getDecoder().decode(encryptedValue.hmac))) {
                throw EncryptionException("HMAC of encrypted value/IV does not match computed HMAC.  This may be due to the wrong encryption.Incept5EncryptionProviderV1.key.<key-uuid>.hmac")
            }

            /* Decrypt the message, given derived key and initialization vector. */
            val cipher = Cipher.getInstance(ENC_ALGORITHM) //Ciphers are not thread-safe
            val ivSpec = IvParameterSpec(encIv)
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey.aesKey, ivSpec)

            var plaintext = cipher.doFinal(encBytes)
            if (MAGIC_NULL_VALUE.toByteArray(StandardCharsets.UTF_8).contentEquals(plaintext)) {
                plaintext = null //'decode' the null
            }
            return plaintext
        } catch (e: RuntimeException) {
            throw EncryptionException("Error performing decryption", e)
        } catch (e: NoSuchAlgorithmException) {
            throw EncryptionException("Error performing decryption", e)
        } catch (e: InvalidKeyException) {
            throw EncryptionException("Error performing decryption", e)
        } catch (e: NoSuchPaddingException) {
            throw EncryptionException("Error performing decryption", e)
        } catch (e: BadPaddingException) {
            throw EncryptionException("Error performing decryption", e)
        } catch (e: IllegalBlockSizeException) {
            throw EncryptionException("Error performing decryption", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw EncryptionException("Error performing decryption", e)
        }
    }

    override fun hasChanged(wrapper: EncryptedValue, proposedValue: String): Boolean {
        try {
            //encrypt the proposed value using the key and the IV from the initial value
            //this is to avoid unnecessarily decrypting existing values into memory
            val encIv: ByteArray = Base64.getDecoder().decode(wrapper.initialisationVector)

            val cipher = Cipher.getInstance(ENC_ALGORITHM) //Ciphers are not thread-safe
            val ivSpec = IvParameterSpec(encIv)
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey.aesKey, ivSpec)

            //encrypt this proposed value with this IV and see if we end up with the same encrypted value
            val ciphertext = cipher.doFinal(proposedValue.toByteArray(StandardCharsets.UTF_8))

            val base64OfEncryptedProposedValue = Base64.getEncoder().encodeToString(ciphertext)
            val base64OfEncryptedExistingValue: String = wrapper.encryptedValue

            return base64OfEncryptedExistingValue != base64OfEncryptedProposedValue
        } catch (e: RuntimeException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: NoSuchAlgorithmException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: InvalidKeyException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: NoSuchPaddingException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: BadPaddingException) {
            throw EncryptionException("Error performing encryption", e)
        } catch (e: IllegalBlockSizeException) {
            throw EncryptionException("Error performing encryption", e)
        }
    }

    companion object {
        private const val ID = "Incept5EncryptionProviderV1"
        const val ENC_ALGORITHM: String = "AES/CBC/PKCS5Padding"
        private val random: Random = SecureRandom()

        //if a null value is passed for encryption then encrypt this string.
        // Because we use a different initialisation vector each time (meaning that the same value
        // encrypted twice will result in different cipher text), this does not have to be kept secret
        //
        //We could have returned null as the 'encrypted' version of a null string.
        // But by doing it this way, it avoids being able to look at an encrypted value and tell whether it is null
        private const val MAGIC_NULL_VALUE = "0e27b9e4-258a-40f2-8135-5cd44a3f56ef"

        private fun makeIV(): IvParameterSpec {
            val iv = ByteArray(16)
            random.nextBytes(iv)
            return IvParameterSpec(iv)
        }
    }
}