// :andp — ANDP version v1 (spec/andp.md): formats, signatures, placement and HTTP client.
//
//   ./gradlew :andp:jvmTest :andp:jsTest              # vectors and unit tests
//   ./gradlew :andp:testAndroidHostTest              # Android unit tests (needs the Android SDK)
//   ./gradlew :andp:compileKotlinIosSimulatorArm64   # iOS (needs Xcode)

import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.kotlinSerialization)
}

// The shared test vectors in the repository root; tests read them, never write them.
val vectorsFile = rootProject.layout.projectDirectory.file("../vectors/andp-v1.json")
// The Go test relay for the JVM integration test lives in the private repository ANDP-Peer, next to this one
// (ANDP_PEER_DIR overrides it). Without it the integration test is skipped, unless ANDP_REQUIRE_GO=1.
val goDir = providers.environmentVariable("ANDP_PEER_DIR").map { file(it) }
    .getOrElse(rootProject.layout.projectDirectory.dir("../../ANDP-Peer").asFile)

kotlin {
    jvmToolchain(21)

    jvm()

    android {
        namespace = "app.anynear.andp"
        compileSdk = libs.versions.androidCompileSdk.get().toInt()
        minSdk = libs.versions.androidMinSdk.get().toInt()
        withHostTest {}
    }

    iosArm64()
    iosSimulatorArm64()
    iosX64()

    js(IR) {
        outputModuleName = "andp"
        browser {
            testTask { enabled = false } // no browser in CI; the same code runs under Node
        }
        nodejs {
            testTask { useMocha { timeout = "60s" } }
        }
        binaries.library()
        generateTypeScriptDefinitions()
    }

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common {
            // Pinned TLS (§12): apps on Android, JVM and iOS. JS has only Web PKI.
            group("pinned") {
                group("jdk") {
                    withJvm()
                    // The Android KMP library target is not matched by withAndroidTarget().
                    withCompilations { it.target.platformType == KotlinPlatformType.androidJvm }
                }
                group("ios") { withIos() }
            }
        }
    }

    targets.configureEach {
        compilations.configureEach {
            compileTaskProvider.configure {
                compilerOptions {
                    freeCompilerArgs.add("-opt-in=kotlin.js.ExperimentalJsExport")
                    freeCompilerArgs.add("-opt-in=kotlin.time.ExperimentalTime")
                    freeCompilerArgs.add("-Xexpect-actual-classes")
                }
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            api(libs.coroutines.core)
            api(libs.ktor.client.core)
            implementation(libs.serialization.json)
            implementation(libs.serialization.cbor)
            api(libs.cryptography.core)
        }
        // JVM and Android: OkHttp, JDK crypto with BouncyCastle (Ed25519 before Android API 33).
        getByName("jdkMain").dependencies {
            implementation(libs.ktor.client.okhttp)
            implementation(libs.cryptography.provider.jdk)
            implementation(libs.bouncycastle)
        }
        iosMain.dependencies {
            implementation(libs.ktor.client.darwin)
            implementation(libs.cryptography.provider.optimal)
        }
        jsMain.dependencies {
            implementation(libs.ktor.client.js)
            implementation(libs.cryptography.provider.optimal)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.coroutines.test)
            implementation(libs.ktor.client.mock)
        }
    }
}

// Tests find the vectors through an environment variable (JVM, Android host, Node).
tasks.withType<Test>().configureEach {
    environment("ANDP_VECTORS", vectorsFile.asFile.absolutePath)
    inputs.file(vectorsFile)
}
tasks.named<Test>("jvmTest") {
    environment("ANDP_GO_DIR", goDir.absolutePath)
    inputs.files(fileTree(goDir) { include("**/*.go", "go.mod", "go.sum") })
}
tasks.withType<org.jetbrains.kotlin.gradle.targets.js.testing.KotlinJsTest>().configureEach {
    environment("ANDP_VECTORS", vectorsFile.asFile.absolutePath)
    inputs.file(vectorsFile)
}
// iOS simulator tests: simctl passes SIMCTL_CHILD_* to the test process; the simulator reads host paths.
tasks.withType<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest>().configureEach {
    environment("SIMCTL_CHILD_ANDP_VECTORS", vectorsFile.asFile.absolutePath)
    inputs.file(vectorsFile)
}
