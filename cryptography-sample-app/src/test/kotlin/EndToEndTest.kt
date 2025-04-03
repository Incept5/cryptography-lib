package org.incept5.cryptography.sampleApp

import io.quarkus.test.junit.QuarkusTest
import io.restassured.RestAssured
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test

@QuarkusTest
class EndToEndTest {

    @Test
    fun `test end to end`() {
        val peopleNoPii = RestAssured.given().get("/v1/people").then().extract().body().jsonPath().getList(".", Map::class.java)
        val peopleWithPii = RestAssured.given().get("/v1/people/pii").then().extract().body().jsonPath().getList(".", Map::class.java)

        val person = peopleNoPii[0]
        assertFalse(person.containsKey("ssn"))     // demonstrate that the entity loaded via the noEncRepo has no encrypted field

        assertNotNull(peopleWithPii[0]["ssn"])    // check we did get back SSNs
    }
}
