package org.incept5.cryptography.sampleApp.service

import org.incept5.cryptography.sampleApp.domain.PersonWithPIIFields
import io.quarkus.logging.Log
import io.quarkus.runtime.Startup
import io.quarkus.runtime.StartupEvent
import jakarta.enterprise.event.Observes
import jakarta.inject.Inject
import jakarta.inject.Singleton
import jakarta.persistence.EntityManager
import jakarta.transaction.Transactional
import kotlin.random.Random

@Startup
@Singleton
class StartupService {

    @Inject
    lateinit var entityManager: EntityManager

    private val random = Random(System.currentTimeMillis())

    @Transactional
    fun onStart(@Observes ev: StartupEvent) {
        Log.info("StartupService.onStart() called")
        (0 until 3).forEach {
            Log.info("Creating person $it")
            entityManager.persist(
                PersonWithPIIFields(
                    name = "Mr $it",
                    ssn = createRandomSSN()
                )
            )
        }
    }

    private fun createRandomSSN(): String {
        return buildString {
            (0 until 10).forEach {
                append(random.nextInt(10))
            }
        }
    }
}