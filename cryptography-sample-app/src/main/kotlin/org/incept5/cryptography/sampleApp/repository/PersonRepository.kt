package org.incept5.cryptography.sampleApp.repository

import org.incept5.cryptography.sampleApp.domain.Person
import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepository
import jakarta.enterprise.context.ApplicationScoped

@ApplicationScoped
class PersonRepository : PanacheRepository<Person>
