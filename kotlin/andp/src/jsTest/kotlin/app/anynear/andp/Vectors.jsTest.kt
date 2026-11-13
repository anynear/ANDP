package app.anynear.andp

private external fun require(module: String): dynamic

private val process: dynamic = js("process")

actual fun readVectorsText(): String {
    val path = process.env.ANDP_VECTORS as String? ?: error("ANDP_VECTORS not set (run the tests through Gradle)")
    return require("fs").readFileSync(path, "utf8") as String
}

actual val signaturesAreDeterministic: Boolean = true
