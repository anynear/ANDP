package app.anynear.andp

import kotlinx.serialization.Serializable

/** The content of a grant (§4.2). [grantee] `null` means anyone, [scope] `null` the whole space. */
data class GrantBody(
    val space: Key,
    val rights: Rights,
    val grantee: Key? = null,
    val scope: ID? = null,
    val until: Long,
    val issued: Long,
) {
    private fun check() {
        if (!rights.isValid) throw AndpException("andp: grant rights are zero or unknown")
        if (until < 0 || issued < 0) throw AndpException("andp: grant times must not be negative")
    }

    /** The deterministic CBOR of the body. */
    fun encode(): ByteArray {
        check()
        return AndpCbor.encode(
            AndpCbor.GrantBodyWire.serializer(),
            AndpCbor.GrantBodyWire(space.unsafeBytes, rights.bits, grantee?.unsafeBytes, scope?.unsafeBytes, until, issued),
        )
    }

    companion object {
        /** Parses deterministic CBOR and rejects unknown keys, unknown rights and wrong lengths. */
        fun decode(data: ByteArray): GrantBody {
            val w = AndpCbor.decodeCanonical(AndpCbor.GrantBodyWire.serializer(), data, "grant body")
            fun <T> field(name: String, f: () -> T): T = try {
                f()
            } catch (e: AndpException) {
                throw AndpException("andp: grant $name must be 32 bytes", e)
            }
            if (w.until < 0 || w.issued < 0 || w.rights < 0) throw AndpException("andp: grant value out of range")
            val b = GrantBody(
                space = field("space") { Key(w.space) },
                rights = Rights(w.rights),
                grantee = w.grantee?.let { field("grantee") { Key(it) } },
                scope = w.scope?.let { field("scope") { ID(it) } },
                until = w.until,
                issued = w.issued,
            )
            b.check()
            return b
        }
    }
}

/**
 * A signed grant body (§4.2). [raw] holds the body bytes as signed; [body] is decoded from them.
 * On the wire (JSON, headers) a grant is b64u of the CBOR array `[body, sig]`.
 */
@Serializable(with = GrantSerializer::class)
class Grant private constructor(val body: GrantBody, raw: ByteArray, val sig: Sig) {
    private val rawBytes = raw.copyOf()

    /** The body bytes as signed. */
    val raw: ByteArray get() = rawBytes.copyOf()

    /** CBOR `[body, sig]`. */
    fun encode(): ByteArray = AndpCbor.encode(AndpCbor.GrantWire.serializer(), AndpCbor.GrantWire(rawBytes, sig.unsafeBytes))

    /** The wire form. */
    override fun toString(): String = B64.encode(encode())

    override fun equals(other: Any?): Boolean = other is Grant && other.rawBytes.contentEquals(rawBytes) && other.sig == sig
    override fun hashCode(): Int = rawBytes.contentHashCode() * 31 + sig.hashCode()

    /** SHA-256 of the body bytes (§2). */
    val hash: Hash by lazy { Hash.of(rawBytes) }

    /** Throws [BadSignatureException] unless the owner (body.space) signed the body. */
    suspend fun verifySig() {
        if (!body.space.verify(SigningBytes.grant(rawBytes), sig)) throw BadSignatureException("grant")
    }

    /** Checks the signature and issued ≤ [t] ≤ until (§4.2). Revocation is checked by [authorize]. */
    suspend fun validAt(t: Long) {
        verifySig()
        if (t < body.issued || t > body.until) throw NotAuthorizedException("grant not valid at $t")
    }

    companion object {
        /** Signs [body] with the owner key, which must be the key of body.space. */
        suspend fun issue(owner: SigningKey, body: GrantBody): Grant {
            if (owner.key != body.space) throw AndpException("andp: only the space owner issues grants")
            val raw = body.encode()
            return Grant(body, raw, owner.sign(SigningBytes.grant(raw)))
        }

        /** Decodes the wire form and checks the structure, not the signature. */
        fun parse(s: String): Grant {
            val data = try {
                B64.decode(s)
            } catch (e: AndpException) {
                throw AndpException("andp: grant: invalid base64url", e)
            }
            return decode(data)
        }

        /** Decodes CBOR `[body, sig]`. */
        fun decode(data: ByteArray): Grant {
            val w = AndpCbor.decodeCanonical(AndpCbor.GrantWire.serializer(), data, "grant")
            if (w.sig.size != Sig.SIZE) throw AndpException("andp: grant signature must be 64 bytes")
            return Grant(GrantBody.decode(w.body), w.body, Sig(w.sig))
        }
    }
}

internal object GrantSerializer : B64Serializer<Grant>("Grant", { Grant.parse(it) })

/** Tells whether a grant hash is revoked in a space (§4.3). Content holders and clients pass `null`. */
fun interface Revoked {
    fun isRevoked(space: Key, grant: Hash): Boolean
}

/**
 * What a caller wants to do: [key] is the caller (request), writer (object) or deleter (tombstone),
 * [need] the rights, [obj] the object of the operation (`null` for list, status and watch) and [at]
 * the time the grant must be valid at.
 */
data class Access(val space: Key, val key: Key, val need: Rights, val obj: ID?, val at: Long)

/**
 * Applies §4.4: the owner may do everything; otherwise [grant] must be valid at [Access.at], be for
 * the space, contain the rights, name the key as grantee (or nobody) and, when scoped, be scoped to
 * the object. A scoped grant never authorizes an operation without an object.
 */
suspend fun authorize(a: Access, grant: Grant?, revoked: Revoked? = null) {
    if (a.key == a.space) return
    if (grant == null) throw NotAuthorizedException("no grant")
    val b = grant.body
    if (b.space != a.space) throw NotAuthorizedException("grant is for another space")
    grant.validAt(a.at)
    if (!b.rights.has(a.need)) throw NotAuthorizedException("grant lacks the right")
    if (b.grantee != null && b.grantee != a.key) throw NotAuthorizedException("grant is for another grantee")
    if (b.scope != null && (a.obj == null || b.scope != a.obj)) throw NotAuthorizedException("grant is scoped to another object")
    if (revoked != null && revoked.isRevoked(a.space, grant.hash)) throw RevokedException()
}
