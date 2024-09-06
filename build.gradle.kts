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
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}