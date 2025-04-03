rootProject.name = "cryptography-lib"

include("cryptography-core")
include("cryptography-quarkus")
include("cryptography-sample-app")

pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

