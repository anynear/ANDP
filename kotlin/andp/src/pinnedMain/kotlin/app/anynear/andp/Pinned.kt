package app.anynear.andp

import io.ktor.client.HttpClient

/**
 * A client that connects to [Relay.addr] and accepts only the TLS key [Relay.key] (SHA-256 of the
 * SubjectPublicKeyInfo, §12). The certificate is otherwise not checked and no SNI name is sent: the
 * address is an IP literal. The check runs on every connection.
 */
fun AndpClient.Companion.pinned(relay: Relay): AndpClient {
    if (relay.addr.isEmpty()) throw AndpException("client: relay has no addr")
    return AndpClient("https://" + relay.addr, pinnedHttpClient(relay.key), relay, ownsHttp = true)
}

/** An HTTP client that completes TLS only with a server whose leaf key has SPKI hash [pin]. */
internal expect fun pinnedHttpClient(pin: Hash): HttpClient

/** SHA-256 of the certificate's SubjectPublicKeyInfo, the pinned key of §5.8. */
fun spkiHash(certificateDer: ByteArray): Hash = Hash.of(Spki.subjectPublicKeyInfo(certificateDer))

/** Whether the certificate (DER) has the pinned key; broken input does not match. */
internal fun matchesPin(certificateDer: ByteArray, pin: Hash): Boolean =
    try {
        spkiHash(certificateDer) == pin
    } catch (e: IllegalArgumentException) {
        false
    }

/**
 * Cuts SubjectPublicKeyInfo with its DER header out of an X.509 certificate:
 * Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL, serialNumber,
 * signature, issuer, validity, subject, subjectPublicKeyInfo, … }, … }
 */
internal object Spki {
    fun subjectPublicKeyInfo(der: ByteArray): ByteArray {
        val cert = der.tlv(0, der.size)
        require(cert.tag == SEQUENCE)
        val tbs = der.tlv(cert.content, cert.end)
        require(tbs.tag == SEQUENCE)
        var field = der.tlv(tbs.content, tbs.end)
        if (field.tag == VERSION) field = der.tlv(field.end, tbs.end)
        // field is serialNumber; subjectPublicKeyInfo is five fields further.
        repeat(5) { field = der.tlv(field.end, tbs.end) }
        require(field.tag == SEQUENCE)
        return der.copyOfRange(field.start, field.end)
    }

    private class Tlv(val tag: Int, val start: Int, val content: Int, val end: Int)

    private fun ByteArray.tlv(pos: Int, limit: Int): Tlv {
        require(pos >= 0 && pos + 2 <= limit)
        val tag = this[pos].toInt() and 0xff
        var length = this[pos + 1].toInt() and 0xff
        var p = pos + 2
        if (length and 0x80 != 0) {
            val count = length and 0x7f
            require(count in 1..3 && p + count <= limit)
            length = 0
            repeat(count) { length = (length shl 8) or (this[p++].toInt() and 0xff) }
        }
        require(length <= limit - p)
        return Tlv(tag, pos, p, p + length)
    }

    private const val SEQUENCE = 0x30
    private const val VERSION = 0xA0
}
