package org.incept5.cryptography.sampleApp.controller

import org.incept5.cryptography.sampleApp.domain.Person
import org.incept5.cryptography.sampleApp.domain.PersonWithPIIFields
import org.incept5.cryptography.sampleApp.repository.PersonRepository
import org.incept5.cryptography.sampleApp.repository.PersonRepositoryWithPIIFields
import jakarta.inject.Inject
import jakarta.persistence.EntityManager
import jakarta.ws.rs.*
import jakarta.ws.rs.core.MediaType

@Path("/v1/people")
class PersonController {

    @Inject
    lateinit var repo: PersonRepository

    @Inject
    lateinit var repoWithPii: PersonRepositoryWithPIIFields

    @Inject
    lateinit var entityManager: EntityManager

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    fun list(): List<Person> {
        return repo.listAll()
    }

    @GET
    @Path("pii")
    @Produces(MediaType.APPLICATION_JSON)
    fun listWithPii(): List<PersonWithPIIFields> {
        return repoWithPii.listAll()
    }

    @GET
    @Path("viewdb")
    @Produces(MediaType.APPLICATION_JSON)
    fun viewDatabaseContents(): List<Map<String, Any>> {
        val query = entityManager.createNativeQuery("SELECT * FROM Person", Any::class.java)
        @Suppress("UNCHECKED_CAST")
        return query.resultList as List<Map<String, Any>>
    }
}
