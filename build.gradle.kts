plugins {
    kotlin("jvm") version "2.0.20"
}

group = "io.opusm"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven {
        url = uri("https://nexus.ledgermaster.kr/repository/maven-releases/")
        credentials {
            username = "$System.env.OPUSM_NEXUS_USERNAME"
            password = "$System.env.OPUSM_NEXUS_PASSWORD"
        }
    }
}

dependencies {
    implementation("org.web3j:core:${property("web3jVersion")}")
    implementation("org.bouncycastle:bcprov-jdk18on:${property("bouncycastleVersion")}")

    testImplementation("io.opusm:abc-ethereum:${property("abcVersion")}")
    testImplementation("io.opusm:abc-api:${property("abcVersion")}")
    testImplementation("com.esaulpaugh:headlong:${property("headlongVersion")}")

    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}