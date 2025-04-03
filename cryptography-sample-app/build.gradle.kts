plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.allopen)
    alias(libs.plugins.quarkus)
}

dependencies {

    implementation(project(":cryptography-quarkus"))

    implementation(enforcedPlatform(libs.quarkus.bom))

    api("jakarta.ws.rs:jakarta.ws.rs-api")
    api("io.quarkus:quarkus-hibernate-orm-panache-kotlin")
    api("io.quarkus:quarkus-core")
    api("io.quarkus:quarkus-panache-common")
    api("jakarta.enterprise:jakarta.enterprise.cdi-api")
    api("jakarta.inject:jakarta.inject-api")
    api("jakarta.persistence:jakarta.persistence-api")
    api("jakarta.transaction:jakarta.transaction-api")
    api("com.fasterxml.jackson.core:jackson-annotations")

    implementation("io.quarkus:quarkus-kotlin")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.hibernate.orm:hibernate-core")

    runtimeOnly("io.quarkus:quarkus-arc")
    runtimeOnly("io.quarkus:quarkus-resteasy-reactive")
    runtimeOnly("io.quarkus:quarkus-resteasy-reactive-jackson")
    runtimeOnly("io.quarkus:quarkus-jdbc-postgresql")
    runtimeOnly("io.quarkus:quarkus-config-yaml")
    runtimeOnly("io.quarkus:quarkus-flyway")

    testImplementation("io.quarkus:quarkus-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("io.rest-assured:rest-assured")
    testImplementation("io.rest-assured:json-path")
    testImplementation(project(":cryptography-core"))

}

tasks.withType<Test> {
    systemProperty("java.util.logging.manager", "org.jboss.logmanager.LogManager")
}
allOpen {
    annotation("jakarta.ws.rs.Path")
    annotation("jakarta.enterprise.context.ApplicationScoped")
    annotation("jakarta.persistence.Entity")
    annotation("io.quarkus.test.junit.QuarkusTest")
}

//dependencyAnalysis {
//    issues {
//        onUnusedAnnotationProcessors {
//            exclude("io.quarkus:quarkus-panache-common")
//        }
//    }
//}