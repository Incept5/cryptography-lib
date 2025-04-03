package org.incept5.cryptography

class EncryptionException : RuntimeException {
    constructor(message: String?) : super(message)

    constructor(message: String?, cause: Throwable?) : super(message, cause)
}