package app.anynear.andp

import kotlinx.serialization.Serializable

/** A parsed or built Authorization header (§4.4). */
data class Auth(val key: Key, val ts: Long, val sig: Sig, val grant: Grant? = null) {
    /** The header value: `ANDP key=…, ts=…, sig=…[, grant=…]`. */
    override fun toString(): String = buildString {
        append(Andp.AUTH_SCHEME).append(" key=").append(key).append(", ts=").append(AndpInt.format(ts)).append(", sig=").append(sig)
        if (grant != null) append(", grant=").append(grant)
    }

    /** Checks the signature over METHOD, path and ts and the time window around [now] (Unix seconds). */
    suspend fun verify(method: String, path: String, now: Long) {
        checkSkew(ts, now)
        if (!key.verify(SigningBytes.request(method, path, ts), sig)) throw BadSignatureException("Authorization")
    }

    /** Checks that the caller holds [need] in [space] at [now]; [obj] is the object of the path, `null` for list, status and watch. */
    suspend fun authorize(space: Key, need: Rights, obj: ID?, now: Long, revoked: Revoked? = null) =
        authorize(Access(space, key, need, obj, now), grant, revoked)

    /** Whether the caller is a relay of [list], in any state (§4.4). */
    fun isPeer(list: NetworkList): Boolean = list.relay(key) != null

    companion object {
        /** Signs METHOD, path and ts. [path] is the request path without query string. */
        suspend fun sign(signer: SigningKey, method: String, path: String, ts: Long, grant: Grant? = null): Auth =
            Auth(signer.key, ts, signer.sign(SigningBytes.request(method, path, ts)), grant)

        /** Parses the header value. Parameters may come in any order; unknown ones are ignored, known ones must appear once. */
        fun parse(h: String): Auth {
            val space = h.indexOf(' ')
            if (space < 0 || !h.substring(0, space).equals(Andp.AUTH_SCHEME, ignoreCase = true)) {
                throw AndpException("andp: Authorization: not the ANDP scheme")
            }
            var key: Key? = null
            var ts: Long? = null
            var sig: Sig? = null
            var grant: Grant? = null
            val seen = mutableSetOf<String>()
            for (p in h.substring(space + 1).split(", ")) {
                val eq = p.indexOf('=')
                if (eq <= 0) throw AndpException("andp: Authorization: malformed parameter \"$p\"")
                val name = p.substring(0, eq)
                val value = p.substring(eq + 1)
                try {
                    when (name) {
                        "key" -> key = Key.parse(value)
                        "ts" -> ts = AndpInt.parse(value)
                        "sig" -> sig = Sig.parse(value)
                        "grant" -> grant = Grant.parse(value)
                        else -> continue
                    }
                } catch (e: AndpException) {
                    throw AndpException("andp: Authorization $name: ${e.message}", e)
                }
                if (!seen.add(name)) throw AndpException("andp: Authorization: $name given twice")
            }
            return Auth(
                key ?: throw AndpException("andp: Authorization: key missing"),
                ts ?: throw AndpException("andp: Authorization: ts missing"),
                sig ?: throw AndpException("andp: Authorization: sig missing"),
                grant,
            )
        }
    }
}

/** A delete record (§5.5). [key] signed it; [grant] is the deleter's grant, `null` for the owner. */
@Serializable
data class Tombstone(
    val space: Key,
    val id: ID,
    val ts: Long,
    val key: Key,
    val grant: Grant? = null,
    val sig: Sig,
) {
    /** Checks the delete signature and the delete right at ts (§5.5, §8 step 7). */
    suspend fun verify(revoked: Revoked? = null) {
        if (ts < 0) throw AndpException("andp: tombstone: negative ts")
        if (!key.verify(SigningBytes.delete(space, id, ts), sig)) throw BadSignatureException("tombstone")
        authorize(Access(space, key, Rights.DELETE, id, ts), grant, revoked)
    }

    companion object {
        /** The ANDP-Del-Sig value for (space, id, ts). */
        suspend fun signDelete(signer: SigningKey, space: Key, id: ID, ts: Long): Sig =
            signer.sign(SigningBytes.delete(space, id, ts))

        /** The tombstone of a DELETE from its verified Authorization and the ANDP-Del-Sig header. Call [verify] afterwards. */
        fun fromRequest(auth: Auth, space: Key, id: ID, h: HeaderSource): Tombstone =
            Tombstone(space, id, auth.ts, auth.key, auth.grant, Sig.parse(h.required(AndpHeaders.DEL_SIG)))
    }
}
