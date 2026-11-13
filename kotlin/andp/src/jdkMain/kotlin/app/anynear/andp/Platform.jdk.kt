package app.anynear.andp

import app.anynear.andp.AndpClient.Companion.andpDefaults
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.providers.jdk.JDK
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import org.bouncycastle.jce.provider.BouncyCastleProvider

// JDK crypto with an own BouncyCastle instance, as in the App: Ed25519 exists in the Android JDK only
// from API 33, and the plain JDK cannot derive the public key from a seed.
internal actual val cryptoProvider: CryptographyProvider = CryptographyProvider.JDK(BouncyCastleProvider())

internal actual fun pinnedHttpClient(pin: Hash): HttpClient = HttpClient(OkHttp) {
    engine {
        config {
            val trust = PinnedTrustManager(pin)
            val tls = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trust), null) }
            sslSocketFactory(tls.socketFactory, trust)
            // The address is an IP literal; the pinned key replaces the name check (and no SNI is sent).
            hostnameVerifier { _, _ -> true }
            // OkHttp allows 5 calls per host by default; a relay holds the stream (§18) and many long polls at once.
            dispatcher(okhttp3.Dispatcher().apply { maxRequests = 128; maxRequestsPerHost = 64 })
        }
    }
    andpDefaults()
}

/** Accepts exactly one server key: the pinned one. No CA, no system store. */
private class PinnedTrustManager(private val pin: Hash) : X509TrustManager {
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        val leaf = chain?.firstOrNull() ?: throw CertificateException("relay sent no certificate")
        if (!matchesPin(leaf.encoded, pin)) throw CertificateException("relay TLS key does not match the pinned key")
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?): Unit =
        throw CertificateException("no client certificates")

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}
