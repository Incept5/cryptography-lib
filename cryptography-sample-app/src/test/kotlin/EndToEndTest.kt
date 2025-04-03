package org.incept5.cryptography.sampleApp

import io.quarkus.test.junit.QuarkusTest
import io.restassured.RestAssured
import io.restassured.common.mapper.TypeRef
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test

@QuarkusTest
class EndToEndTest {

    @Test
    fun `test end to end`() {
        // Direct approach using TypeRef for type safety
        val response = RestAssured.given().get("/v1/people")
        val responseBody = response.then().extract().body()
        
        val responsePii = RestAssured.given().get("/v1/people/pii")
        val responseBodyPii = responsePii.then().extract().body()
        
        // Try to parse as a list first
        val peopleNoPii = try {
            responseBody.`as`(object : TypeRef<List<Map<String, Any>>>() {})
        } catch (e: Exception) {
            // If it fails, try to parse as a single object and wrap in a list
            listOf(responseBody.`as`(object : TypeRef<Map<String, Any>>() {}))
        }
        
        val peopleWithPii = try {
            responseBodyPii.`as`(object : TypeRef<List<Map<String, Any>>>() {})
        } catch (e: Exception) {
            // If it fails, try to parse as a single object and wrap in a list
            listOf(responseBodyPii.`as`(object : TypeRef<Map<String, Any>>() {}))
        }
        
        // Verify we have results
        assert(peopleNoPii.isNotEmpty()) { "No people returned from /v1/people endpoint" }
        assert(peopleWithPii.isNotEmpty()) { "No people returned from /v1/people/pii endpoint" }

        val person = peopleNoPii[0]
        assertFalse(person.containsKey("ssn"))     // demonstrate that the entity loaded via the noEncRepo has no encrypted field

        assertNotNull(peopleWithPii[0]["ssn"])    // check we did get back SSNs
    }
}
