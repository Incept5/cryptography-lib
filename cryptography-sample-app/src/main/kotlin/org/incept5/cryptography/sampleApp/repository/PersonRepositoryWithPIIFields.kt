package org.incept5.cryptography.sampleApp.repository

import org.incept5.cryptography.sampleApp.domain.PersonWithPIIFields
import io.quarkus.hibernate.orm.panache.kotlin.PanacheRepository
import jakarta.enterprise.context.ApplicationScoped

@ApplicationScoped
class PersonRepositoryWithPIIFields : PanacheRepository<PersonWithPIIFields>
