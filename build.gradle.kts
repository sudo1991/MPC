plugins {
    kotlin("jvm") version "2.0.10"
}

group = "io.opusm"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.web3j:core:${property("web3jVersion")}")

    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}