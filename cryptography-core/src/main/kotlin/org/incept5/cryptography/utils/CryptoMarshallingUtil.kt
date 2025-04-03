package org.incept5.cryptography.utils

import org.incept5.cryptography.EncryptionException
import org.incept5.cryptography.core.EncryptedValue
import java.io.IOException

object CryptoMarshallingUtil {
    private val objectMapper: com.fasterxml.jackson.databind.ObjectMapper = com.fasterxml.jackson.databind.ObjectMapper()

    init {
        objectMapper.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
        objectMapper.configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        objectMapper.registerModule(com.fasterxml.jackson.datatype.jsr310.JSR310Module())
        objectMapper.registerModule(com.fasterxml.jackson.datatype.jdk8.Jdk8Module())
        //objectMapper.registerModule(new JavaTimeModule());
    }

    @Throws(EncryptionException::class)
    fun marshal(wrapper: EncryptedValue?): String {
        try {
            if (wrapper == null) {
                throw EncryptionException("Cannot marshal a null object")
            }
            return objectMapper.writeValueAsString(wrapper)
        } catch (e: com.fasterxml.jackson.core.JsonProcessingException) {
            throw EncryptionException("Error marshalling object", e) //don't include problematic object in the stack trace
        } catch (e: RuntimeException) {
            throw EncryptionException("Error marshalling object", e)
        }
    }

    @Throws(EncryptionException::class)
    fun unmarshal(json: String?): EncryptedValue? {
        try {
            if (json == null) {
                return null
            }
            return objectMapper.readValue<EncryptedValue>(json, EncryptedValue::class.java)
        } catch (e: IOException) {
            throw EncryptionException("Error unmarshalling JSON: $json", e) //won't be a security problem because the JSON is always encrypted
        } catch (e: RuntimeException) {
            throw EncryptionException("Error unmarshalling JSON: $json", e)
        }
    }
}