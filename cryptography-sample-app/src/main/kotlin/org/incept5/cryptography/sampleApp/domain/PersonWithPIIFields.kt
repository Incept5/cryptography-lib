package org.incept5.cryptography.sampleApp.domain

import org.incept5.cryptography.quarkus.service.EncryptedValueConverter
import jakarta.persistence.*
import java.util.*

@Entity
@Table(name = "Person")
data class PersonWithPIIFields(
    override var id: UUID? = null,
    override var name: String? = null,

    @Column(nullable = true)
    @Convert(converter = EncryptedValueConverter::class)
    var ssn: String? = null

) : PersonBase(id, name)
