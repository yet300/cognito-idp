import com.android.build.gradle.LibraryExtension
import com.liftric.vault.GetVaultSecretTask
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    kotlin("multiplatform") version libs.versions.kotlin
    alias(libs.plugins.kotlin.serialization)
    id("com.android.library") version libs.versions.android.tools.gradle
    alias(libs.plugins.definitions)
    alias(libs.plugins.npm.publishing)
    alias(libs.plugins.versioning)
    alias(libs.plugins.vault.client)
    id("maven-publish")
    id("signing")
}

repositories {
    mavenCentral()
    google()
    gradlePluginPortal()
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

kotlin {
    ios {
        binaries.framework()
    }

    iosSimulatorArm64()

    androidTarget() {
        publishAllLibraryVariants()
    }
    jvm()
    js(IR) {
        generateTypeScriptDefinitions()
        browser {
            testTask {
                useMocha {
                    timeout = "10s"
                }
            }
        }
        binaries.library()
        compilations.all {
            compileTaskProvider.configure {
                compilerOptions.freeCompilerArgs.add("-Xir-minimized-member-names=false")
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(libs.ktor.client.core)
                api(libs.kotlinx.coroutines)
                api(libs.kotlinx.serialization)
            }
        }
        val commonTest by getting {
            kotlin.srcDir("${layout.buildDirectory}/gen")
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
            }
        }
        val androidMain by getting {
            dependencies {
                api(libs.ktor.client.android)
            }
        }
        val jvmMain by getting {
            dependencies {
                api(libs.ktor.client.jvm)
            }
        }
        val androidUnitTest by getting {
            dependencies {
                implementation(libs.roboelectric)
                implementation(kotlin("test"))
                implementation(kotlin("test-junit"))
                implementation(libs.androidx.test.core)
                implementation(libs.opt.java)
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlin("test-junit"))
                implementation(libs.opt.java)
            }
        }
        val iosMain by getting {
            dependencies {
                api(libs.ktor.client.darwin)
            }
        }
        val iosTest by getting
        val iosSimulatorArm64Main by getting {
            dependsOn(iosMain)
        }
        val iosSimulatorArm64Test by getting {
            dependsOn(iosTest)
        }
        val jsMain by getting {
            dependencies {
                api(libs.ktor.client.js)
            }
        }
        val jsTest by getting {
            dependencies {
                implementation(kotlin("test-js"))
            }
        }
        all {
            languageSettings {
                optIn("kotlinx.serialization.ExperimentalSerializationApi")
                optIn("kotlin.js.ExperimentalJsExport")
                optIn("kotlin.RequiresOptIn")
            }
        }
    }
}

configure<LibraryExtension> {
    defaultConfig.apply {
        compileSdk = 30
        minSdkVersion(21)
        targetSdkVersion(30)
        testInstrumentationRunner = "org.robolectric.RobolectricTestRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    testOptions {
        unitTests.apply {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }

    namespace = "com.liftric.cognito.idp"

    publishing {
        multipleVariants {
            allVariants()
            withJavadocJar()
        }
    }
}

group = "com.liftric"
version = with(versioning.info) {
    if (branch == "HEAD" && dirty.not()) tag else full
}

afterEvaluate {
    project.publishing.publications.withType(MavenPublication::class.java).forEach {
        it.groupId = group.toString()
    }
}

tasks {
    withType(KotlinNativeSimulatorTest::class) {
        filter.excludeTestsMatching("com.liftric.cognito.idp.IdentityProviderClientTests")
    }

    val testSecrets by creating(GetVaultSecretTask::class) {
        secretPath.set("secret/apps/smartest/shared/cognito")
    }

    val createJsEnvHack by creating {
        outputs.dir("${layout.buildDirectory}/gen")

        if (System.getenv("region") == null || System.getenv("clientId") == null) {
            // github ci provides region and clientId envs, locally we'll use vault directly
            dependsOn(testSecrets)
        }

        doFirst {
            val (clientId, region) = with(testSecrets.secret.get()) {
                ((System.getenv("clientId") ?: this["client_id_dev"].toString()) to
                        (System.getenv("region") ?: this["client_region_dev"].toString()))
            }

            mkdir("${layout.buildDirectory}/gen")
            with(File("${layout.buildDirectory}/gen/env.kt")) {
                createNewFile()
                writeText(
                    """
                    val env = mapOf(
                        "region" to "$region",
                        "clientId" to "$clientId",
                    )
                    """.trimIndent()
                )
            }
        }
    }

    withType<KotlinCompileCommon> {
        dependsOn(createJsEnvHack)
    }

    withType<KotlinCompile> {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
            freeCompilerArgs.set(
                listOf("-Xinline-classes")
            )
        }
    }

    /**
     * Ugly atomicfu export hack: Coroutines core needs atomicfu-js, which generates broken d.ts entries. Excluding
     * atomicfu-js breaks the ktor client and filtering d.ts types in the IR compile is currently not possible... so let's
     * just rip it out after the fact
     *
     * The build/js/packages/cognito-idp/kotlin/cognito-idp.d.ts file should now be without errors and usable from typescript
     */
    val cleanTypescriptTypes by creating {
        fun MutableList<String>.removeFromTill(from: String, till: String) {
            val fromIndex = indexOfFirst { it == from }
            val tillIndex = indexOfFirst { it == till }
            if (fromIndex == -1 || tillIndex == -1) {
                println("looks like from='$from' till='$till' already scraped")
                return
            }
            println("removeFromTill from='$from' till='$till' fromIndex=$fromIndex")
            println("removeFromTill from='$from' till='$till' tillIndex=$tillIndex")
            (fromIndex..tillIndex).forEach {
                removeAt(fromIndex)
            }
        }

        val dTsFile = file("${layout.buildDirectory}/js/packages/cognito-idp/kotlin/cognito-idp.d.ts")
        inputs.file(dTsFile)
        outputs.file(dTsFile)

        doLast {
            val dTs = dTsFile.readLines().toMutableList()
            dTs.removeFromTill("export namespace kotlinx.atomicfu {", "}")
            dTs.removeFromTill("export namespace io.ktor.util {", "}")
            dTsFile.writeText(dTs.joinToString("\n"))
        }
    }
    val jsBrowserProductionLibraryDistribution by existing {
        finalizedBy(cleanTypescriptTypes)
    }
    val jsProductionLibraryCompileSync by existing {
        finalizedBy(cleanTypescriptTypes)
    }
}

val ossrhUsername: String? by project
val ossrhPassword: String? by project

val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
}

publishing {
    repositories {
        maven {
            name = "sonatype"
            setUrl("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = ossrhUsername
                password = ossrhPassword
            }
        }
    }

    publications.withType<MavenPublication> {
        artifact(javadocJar.get())

        pom {
            name.set(project.name)
            description.set("Lightweight AWS Cognito Identity Provider client for Kotlin Multiplatform projects.")
            url.set("https://github.com/liftric/cognito-idp")

            licenses {
                license {
                    name.set("MIT")
                    url.set("https://github.com/liftric/cognito-idp/blob/master/LICENSE")
                }
            }
            developers {
                developer {
                    id.set("benjohnde")
                    name.set("Ben John")
                    email.set("john@liftric.com")
                }
                developer {
                    id.set("ingwersaft")
                    name.set("Marcel Kesselring")
                    email.set("kesselring@liftric.com")
                }
            }
            scm {
                url.set("https://github.com/liftric/cognito-idp")
            }
        }
    }
}

val npmAccessKey: String? by project

npmPublish {
    organization.set("liftric")
    access.set(PUBLIC)
    readme.set(rootProject.file("README.md"))

    packages {
        named("js") {
            packageName.set(project.name)
            packageJson {
                keywords.set(
                    listOf(
                        "kotlin",
                        "cognito",
                        "identity-provider",
                        "liftric",
                        "aws"
                    )
                )
                license.set("MIT")
                description.set("Lightweight AWS Cognito Identity Provider client.")
                homepage.set("https://github.com/liftric/cognito-idp")
            }
        }
    }

    registries {
        npmjs {
            uri.set(uri("https://registry.npmjs.org"))
            authToken.set(npmAccessKey)
        }
    }
}

signing {
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications)
}

vault {
    vaultAddress.set("https://dark-lord.liftric.io")
    if (System.getenv("CI") == null) {
        vaultTokenFilePath.set("${System.getProperty("user.home")}/.vault-token")
    } else {
        vaultToken.set(System.getenv("VAULT_TOKEN"))
    }
}
tasks {
    afterEvaluate {
        val signingTasks = filter { it.name.startsWith("sign") }
        all {
            // lets bruteforce this until the plugins play along nicely again

            if (name.contains("compile", true) && name.contains("kotlin", true)) {
                dependsOn("createJsEnvHack")
            }
            if (name.startsWith("publish")) {
                signingTasks.forEach { signTask ->
                    dependsOn(signTask)
                }
            }
        }
    }
}
