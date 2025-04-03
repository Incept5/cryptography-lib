package org.incept5.cryptography.provider

import org.incept5.cryptography.core.EncryptedValue
import org.incept5.cryptography.utils.CryptoMarshallingUtil

object CryptoUtil {
    /**
     * Are the two byte arrays the same?
     *
     * Note that if they are both null then we deliberately return false
     *
     * @param left
     * @param right
     * @return boolean
     */
    fun areEqual(left: ByteArray?, right: ByteArray?): Boolean {
        if (left == null || right == null) {
            return false
        }
        if (left.size != right.size) {
            return false
        }
        var cksum = 0
        for (i in left.indices) {
            cksum = cksum or (left[i].toInt() xor right[i].toInt())
        }
        return cksum == 0
    }

    fun isEncryptedValueWrapper(value: String?): Boolean {
        try {
            val wrapper: EncryptedValue? = CryptoMarshallingUtil.unmarshal(value)
            return wrapper?.provider != null
        } catch (e: Exception) {
            return false
        }
    }
}