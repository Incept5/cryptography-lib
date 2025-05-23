plugins {
    `java-library`
    `maven-publish`

    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.allopen)
    // include quarkus metadata in the jar
    alias(libs.plugins.jandex)
}

dependencies {

    api(project(":cryptography-core"))
    implementation(platform(libs.quarkus.bom))
    api("jakarta.persistence:jakarta.persistence-api")
    api("io.smallrye.config:smallrye-config-core")
    api("jakarta.enterprise:jakarta.enterprise.cdi-api")
    api("jakarta.inject:jakarta.inject-api")
    api("org.eclipse.microprofile.config:microprofile-config-api")

    implementation("commons-codec:commons-codec:1.16.1")
    implementation("io.quarkus:quarkus-kotlin")

    // test dependencies
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("org.mockito:mockito-core:5.2.0")
    testImplementation("org.apache.commons:commons-lang3:3.14.0")
    testImplementation("org.mockito:mockito-inline:5.2.0")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.2.1")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            // For JitPack compatibility, we need to use the correct group ID format
            // JitPack expects: com.github.{username}.{repository}
            val publishGroupId = rootProject.properties["publishGroupId"]?.toString() 
                ?: if (System.getenv("JITPACK") != null) {
                    // When building on JitPack
                    "com.github.incept5.cryptography-lib"
                } else {
                    // For local development
                    "com.github.incept5"
                }
            
            // Explicitly set the coordinates
            groupId = publishGroupId
            artifactId = "cryptography-quarkus"
            version = project.version.toString()
            
            // This will include all dependencies marked as 'api' as transitive dependencies
            // The 'api' configuration automatically makes dependencies transitive
            from(components["java"])
            
            // POM information
            pom {
                name.set("Cryptography Quarkus")
                description.set("Quarkus integration for cryptography Handling in Rest Services")
                url.set("https://github.com/incept5/cryptography-lib")
                
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                
                developers {
                    developer {
                        id.set("incept5")
                        name.set("Incept5")
                        email.set("info@incept5.com")
                    }
                }
                
                // Important for JitPack to resolve dependencies correctly
                scm {
                    connection.set("scm:git:github.com/incept5/cryptography-lib.git")
                    developerConnection.set("scm:git:ssh://github.com/incept5/cryptography-lib.git")
                    url.set("https://github.com/incept5/cryptography-lib/tree/main")
                }
            }
        }
    }
}

tasks.test {
    dependsOn(tasks.jandex)
    useJUnitPlatform()
}

// For JitPack compatibility
tasks.register("install") {
    dependsOn(tasks.named("publishToMavenLocal"))
}

// Always publish to local Maven repository after build for local development
tasks.named("build") {
    finalizedBy(tasks.named("publishToMavenLocal"))
}
