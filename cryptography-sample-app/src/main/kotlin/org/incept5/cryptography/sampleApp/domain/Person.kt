package org.incept5.cryptography.sampleApp.domain

import jakarta.persistence.Entity
import jakarta.persistence.Table
import java.util.*

@Entity
@Table(name = "Person")
data class Person(
    override var id: UUID? = null,
    override var name: String? = null,
) : PersonBase(id, name) {
    // Additional entity-specific logic can be added here
}
