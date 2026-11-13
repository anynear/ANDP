package app.anynear.andp

import java.io.File

actual fun readVectorsText(): String =
    File(System.getenv("ANDP_VECTORS") ?: error("ANDP_VECTORS not set (run the tests through Gradle)")).readText()

actual val signaturesAreDeterministic: Boolean = true
