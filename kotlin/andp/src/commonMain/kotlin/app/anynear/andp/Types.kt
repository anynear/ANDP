package app.anynear.andp

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** Fixed-length binary value written as strict b64u. Instances are immutable. */
sealed class FixedBytes(bytes: ByteArray, size: Int, what: String) {
    private val raw: ByteArray

    init {
        if (bytes.size != size) throw AndpException("andp: invalid $what")
        raw = bytes.copyOf()
    }

    /** A copy of the raw bytes. */
    val bytes: ByteArray get() = raw.copyOf()

    internal val unsafeBytes: ByteArray get() = raw

    val isZero: Boolean get() = raw.all { it == 0.toByte() }

    final override fun equals(other: Any?): Boolean =
        other != null && other::class == this::class && (other as FixedBytes).raw.contentEquals(raw)

    final override fun hashCode(): Int = raw.contentHashCode()

    /** The b64u form. */
    final override fun toString(): String = B64.encode(raw)
}

internal fun decodeFixed(s: String, size: Int, what: String): ByteArray {
    val raw = try {
        B64.decode(s)
    } catch (e: AndpException) {
        throw AndpException("andp: invalid $what", e)
    }
    if (raw.size != size) throw AndpException("andp: invalid $what")
    return raw
}

/** A 32-byte Ed25519 public key: space, node, writer, grantee or network key (§2). */
@Serializable(with = KeySerializer::class)
class Key(bytes: ByteArray) : FixedBytes(bytes, SIZE, "key") {
    /** Checks an Ed25519 signature by this key over [message]. */
    suspend fun verify(message: ByteArray, sig: Sig): Boolean = Ed25519.verify(this, message, sig)

    companion object {
        const val SIZE = 32
        fun parse(s: String): Key = Key(decodeFixed(s, SIZE, "key"))
    }
}

/** An object id: SHA-256 of the object bytes (§2). */
@Serializable(with = IDSerializer::class)
class ID(bytes: ByteArray) : FixedBytes(bytes, SIZE, "id") {
    companion object {
        const val SIZE = 32
        fun parse(s: String): ID = ID(decodeFixed(s, SIZE, "id"))

        /** The id of [data]. */
        fun of(data: ByteArray): ID = ID(Sha256.digest(data))
    }
}

/** Any other SHA-256 value: grant hash (§4.2), network ID (§2) or TLS key fingerprint (§5.8). */
@Serializable(with = HashSerializer::class)
class Hash(bytes: ByteArray) : FixedBytes(bytes, SIZE, "hash") {
    companion object {
        const val SIZE = 32
        fun parse(s: String): Hash = Hash(decodeFixed(s, SIZE, "hash"))

        /** SHA-256 of [data]. */
        fun of(data: ByteArray): Hash = Hash(Sha256.digest(data))
    }
}

/** An Ed25519 signature. */
@Serializable(with = SigSerializer::class)
class Sig(bytes: ByteArray) : FixedBytes(bytes, SIZE, "signature") {
    companion object {
        const val SIZE = 64
        fun parse(s: String): Sig = Sig(decodeFixed(s, SIZE, "signature"))
    }
}

/** The network ID: SHA-256 of the raw first network key (§2). It stays the same on key rotation. */
fun networkId(firstKey: Key): Hash = Hash.of(firstKey.unsafeBytes)

/** The watch ID: b64u of the first 16 bytes of SHA-256 over the raw push token bytes (§2, §10). */
fun watchId(token: ByteArray): String = B64.encode(Sha256.digest(token).copyOf(16))

/** The watch ID of an APNs token given as hex (§10). */
fun watchIdForHexToken(hexToken: String): String = watchId(hexToBytes(hexToken))

/** Lower-case hex of [b], e.g. the token of a `relay` watch target (§10.2). */
fun bytesToHex(b: ByteArray): String = b.joinToString("") { ((it.toInt() and 0xff) or 0x100).toString(16).substring(1) }

internal fun hexToBytes(s: String): ByteArray {
    if (s.length % 2 != 0) throw AndpException("andp: invalid hex")
    return ByteArray(s.length / 2) { i ->
        val hi = s[2 * i].digitToIntOrNull(16) ?: throw AndpException("andp: invalid hex")
        val lo = s[2 * i + 1].digitToIntOrNull(16) ?: throw AndpException("andp: invalid hex")
        (hi * 16 + lo).toByte()
    }
}

internal open class B64Serializer<T : Any>(
    name: String,
    private val parse: (String) -> T,
    private val format: (T) -> String = { it.toString() },
) : KSerializer<T> {
    override val descriptor = PrimitiveSerialDescriptor("app.anynear.andp.$name", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: T) = encoder.encodeString(format(value))
    override fun deserialize(decoder: Decoder): T = try {
        parse(decoder.decodeString())
    } catch (e: AndpException) {
        throw SerializationException(e.message, e)
    }
}

internal object KeySerializer : B64Serializer<Key>("Key", { Key.parse(it) })
internal object IDSerializer : B64Serializer<ID>("ID", { ID.parse(it) })
internal object HashSerializer : B64Serializer<Hash>("Hash", { Hash.parse(it) })
internal object SigSerializer : B64Serializer<Sig>("Sig", { Sig.parse(it) })

/** Binary data that JSON carries as b64u (§1). */
internal object B64BytesSerializer : B64Serializer<ByteArray>("Bytes", { B64.decode(it) }, { B64.encode(it) })
