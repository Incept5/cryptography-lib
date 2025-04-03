package org.incept5.cryptography.sampleApp.domain

import io.quarkus.hibernate.orm.panache.kotlin.PanacheEntityBase
import jakarta.persistence.Column
import jakarta.persistence.GeneratedValue
import jakarta.persistence.Id
import jakarta.persistence.MappedSuperclass
import org.hibernate.annotations.GenericGenerator
import java.util.*

@MappedSuperclass
open class PersonBase(

    @Id
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    open var id: UUID? = null,

    @Column
    open var name: String? = null
) : PanacheEntityBase {
    // Additional entity-specific logic can be added here
}
