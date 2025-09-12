
plugins {
    kotlin("jvm") version "2.0.20"
    id("io.ktor.plugin") version "3.2.3"
}

application {
    mainClass.set("io.ktor.server.netty.EngineMain")
}

tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    manifest {
        attributes["Main-Class"] = application.mainClass.get()
    }
}
repositories {
    mavenCentral()
}

dependencies {
    // Align all Ktor modules to the same version
    implementation(platform("io.ktor:ktor-bom:3.2.3"))

    implementation("io.ktor:ktor-server-core-jvm")
    implementation("io.ktor:ktor-server-netty-jvm")
    implementation("io.ktor:ktor-server-auth-jvm")
    implementation("io.ktor:ktor-server-auth-jwt-jvm")
    implementation("io.ktor:ktor-server-content-negotiation-jvm")
    implementation("io.ktor:ktor-serialization-jackson-jvm")

    // JWT & JSON libs
    implementation("com.nimbusds:nimbus-jose-jwt:10.5")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.20.0")

    // JSON-LD (for VC/LD work)
    implementation("com.apicatalog:titanium-json-ld:1.6.0")
}
