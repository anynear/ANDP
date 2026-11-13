package app.anynear.andp

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.stringWithContentsOfFile

@OptIn(ExperimentalForeignApi::class)
actual fun readVectorsText(): String {
    val path = NSProcessInfo.processInfo.environment["ANDP_VECTORS"] as String? ?: error("ANDP_VECTORS not set")
    return NSString.stringWithContentsOfFile(path, NSUTF8StringEncoding, null) ?: error("cannot read $path")
}

actual val signaturesAreDeterministic: Boolean = false
