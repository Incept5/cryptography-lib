package org.incept5.cryptography.utils

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.incept5.cryptography.EncryptionException
import org.incept5.cryptography.core.EncryptedValue
import java.io.IOException

object CryptoMarshallingUtil {
    private val objectMapper: ObjectMapper = ObjectMapper()

    init {
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        // Register Kotlin module for proper data class serialization/deserialization
        objectMapper.registerKotlinModule()
        // Use JavaTimeModule instead of deprecated JSR310Module
        objectMapper.registerModule(JavaTimeModule())
        objectMapper.registerModule(Jdk8Module())
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
            return objectMapper.readValue(json, EncryptedValue::class.java)
        } catch (e: IOException) {
            throw EncryptionException("Error unmarshalling JSON: $json", e) //won't be a security problem because the JSON is always encrypted
        } catch (e: RuntimeException) {
            throw EncryptionException("Error unmarshalling JSON: $json", e)
        }
    }
}