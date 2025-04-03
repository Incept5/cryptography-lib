package org.incept5.cryptography.core

import org.incept5.cryptography.utils.CryptoMarshallingUtil

data class EncryptedValue(
    val provider: String, //id of the encryption system
    val keyId: String, //id of the key used to encrypt this value
    val hmac: String, //base64 of the HMAC
    val encryptedValue: String, //base64 of the encrypted value
    val initialisationVector: String
)//base64 of the initialisation vector of the encrypted value
{
    fun asString(): String {
        return CryptoMarshallingUtil.marshal(this)
    }

    companion object {
        fun fromString(json: String): EncryptedValue? {
            return CryptoMarshallingUtil.unmarshal(json)
        }
    }
}
