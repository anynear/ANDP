package app.anynear.andp

import app.anynear.andp.AndpClient.Companion.andpDefaults
import dev.whyoleg.cryptography.CryptographyProvider
import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import platform.CoreFoundation.CFArrayGetCount
import platform.CoreFoundation.CFArrayGetValueAtIndex
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFRelease
import platform.Foundation.NSURLAuthenticationMethodServerTrust
import platform.Foundation.NSURLCredential
import platform.Foundation.NSURLSessionAuthChallengeCancelAuthenticationChallenge
import platform.Foundation.NSURLSessionAuthChallengePerformDefaultHandling
import platform.Foundation.NSURLSessionAuthChallengeUseCredential
import platform.Foundation.credentialForTrust
import platform.Foundation.serverTrust
import platform.Security.SecCertificateCopyData
import platform.Security.SecCertificateRef
import platform.Security.SecTrustCopyCertificateChain
import platform.Security.SecTrustRef

// CryptoKit and CommonCrypto.
internal actual val cryptoProvider: CryptographyProvider = CryptographyProvider.Default

@OptIn(ExperimentalForeignApi::class)
internal actual fun pinnedHttpClient(pin: Hash): HttpClient = HttpClient(Darwin) {
    engine {
        handleChallenge { _, _, challenge, completionHandler ->
            val space = challenge.protectionSpace
            if (space.authenticationMethod != NSURLAuthenticationMethodServerTrust) {
                completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, null)
                return@handleChallenge
            }
            // No system check of the chain (self-signed, IP address): only the pinned key counts.
            val trust = space.serverTrust
            val leaf = trust?.let { leafCertificateDer(it) }
            if (trust != null && leaf != null && matchesPin(leaf, pin)) {
                completionHandler(NSURLSessionAuthChallengeUseCredential, NSURLCredential.credentialForTrust(trust))
            } else {
                completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, null)
            }
        }
    }
    andpDefaults()
}

/** The server certificate (first of the chain) as DER. */
@OptIn(ExperimentalForeignApi::class)
private fun leafCertificateDer(trust: SecTrustRef): ByteArray? {
    val chain = SecTrustCopyCertificateChain(trust) ?: return null
    try {
        if (CFArrayGetCount(chain) < 1) return null
        val leaf: SecCertificateRef = CFArrayGetValueAtIndex(chain, 0)?.reinterpret() ?: return null
        val data = SecCertificateCopyData(leaf) ?: return null
        try {
            val bytes = CFDataGetBytePtr(data) ?: return null
            return bytes.readBytes(CFDataGetLength(data).toInt())
        } finally {
            CFRelease(data)
        }
    } finally {
        CFRelease(chain)
    }
}
