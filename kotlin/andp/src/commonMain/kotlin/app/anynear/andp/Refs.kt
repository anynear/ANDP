package app.anynear.andp

import kotlinx.serialization.Serializable

/** A content an entry refers to (§3). */
@Serializable
data class Ref(val id: ID, val size: Long)

/** The refs CBOR (§3): array of `[id-bytes, size]` pairs in the given order. */
object Refs {
    /** The CBOR of [refs], or `null` when empty. */
    fun encode(refs: List<Ref>): ByteArray? {
        if (refs.isEmpty()) return null
        if (refs.any { it.size < 0 }) throw AndpException("andp: ref size must not be negative")
        return AndpCbor.encode(AndpCbor.refsSerializer, refs.map { AndpCbor.RefWire(it.id.unsafeBytes, it.size) })
    }

    /** Parses a deterministic, non-empty refs array. */
    fun decode(data: ByteArray): List<Ref> {
        val w = AndpCbor.decodeCanonical(AndpCbor.refsSerializer, data, "refs")
        if (w.isEmpty()) throw AndpException("andp: refs: empty array (omit instead)")
        return w.map {
            if (it.id.size != ID.SIZE || it.size < 0) throw AndpException("andp: refs: invalid pair")
            Ref(ID(it.id), it.size)
        }
    }

    /** b64u(SHA-256(refs CBOR)), or "" when [refs] is empty (§3). */
    fun digest(refs: List<Ref>): String = encode(refs)?.let { B64.encode(Sha256.digest(it)) } ?: ""
}
