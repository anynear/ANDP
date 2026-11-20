package app.anynear.andp

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Read access to HTTP headers: all values of a header, matched case-insensitively; empty when absent. */
fun interface HeaderSource {
    fun values(name: String): List<String>

    companion object {
        /** Headers from a map with one value per name; names match case-insensitively. */
        fun of(map: Map<String, String>): HeaderSource = HeaderSource { name ->
            map.entries.filter { it.key.equals(name, ignoreCase = true) }.map { it.value }
        }
    }
}

internal fun HeaderSource.single(name: String): String? {
    val v = values(name)
    return when (v.size) {
        0 -> null
        1 -> v[0]
        else -> throw AndpException("andp: header $name given more than once")
    }
}

internal fun HeaderSource.required(name: String): String = single(name) ?: throw AndpException("andp: header $name missing")

/**
 * The signed metadata of an object (§3). [until] `0` means no expiry; [refs] only for entries;
 * [revokes] only for revocation entries; [grant] `null` when the writer is the owner.
 */
data class Meta(
    val space: Key,
    val id: ID,
    val size: Long,
    val ts: Long,
    val until: Long,
    val placement: Placement,
    val refs: List<Ref> = emptyList(),
    val revokes: Hash? = null,
    val writer: Key,
    val grant: Grant? = null,
    val sig: Sig,
) {
    /** Placement space. */
    val isEntry: Boolean get() = placement == Placement.SPACE

    /** The key of §6: the space for entries, the id for contents. */
    val placementKey: String get() = if (isEntry) space.toString() else id.toString()

    /** The andp/v1/obj bytes. */
    fun signingBytes(): ByteArray = signingBytes(space, id, size, ts, until, placement, refs, revokes)

    /** Checks the rules of §3 and §4.3 that need no policy, keys or bytes. */
    fun validate() = validate(space, id, size, ts, until, placement, refs, revokes, writer, grant)

    /** Applies max_until (policy, §3 rule 4). */
    fun checkUntil(maxUntil: Long) {
        if (until != 0L && until - ts > maxUntil) throw AndpException("andp: until exceeds max_until")
    }

    /**
     * Applies §19 rule 2 to a write of this metadata with ANDP-Not-Before [notBefore]; `0` (an ordinary write) is
     * always valid. [maxUntil] is the relay's policy value.
     */
    fun checkNotBefore(notBefore: Long, maxUntil: Long) {
        if (notBefore == 0L) return
        val ok = notBefore > 0 && isEntry && revokes == null && notBefore > ts && notBefore - ts <= maxUntil &&
            (until == 0L || notBefore < until)
        if (!ok) throw AndpException("andp: invalid not_before")
    }

    /** Whether the object must no longer be delivered at [now] (Unix seconds, §3 rule 4). */
    fun isExpired(now: Long): Boolean = until != 0L && now > until

    /** Checks hash and size of the bytes (§3 rule 1). */
    fun checkData(data: ByteArray) {
        if (data.size.toLong() != size || ID.of(data) != id) throw AndpException("andp: bytes do not match id or size")
    }

    /** Throws [BadSignatureException] unless the writer signed the metadata. */
    suspend fun verifySig() {
        if (!writer.verify(signingBytes(), sig)) throw BadSignatureException("object")
    }

    /** Checks that the writer holds write at ts (§5.3). Content holders and clients pass `null`. */
    suspend fun authorize(revoked: Revoked? = null) =
        authorize(Access(space, writer, Rights.WRITE, id, ts), grant, revoked)

    /** Runs [validate], [verifySig] and [authorize]. It does not check bytes, policy or clock. */
    suspend fun verify(revoked: Revoked? = null) {
        validate()
        verifySig()
        authorize(revoked)
    }

    /** The rules for a client PUT (§3 rule 5, §5.3): the Authorization key is the writer, ts is near [now]. */
    fun checkClientWrite(auth: Auth, now: Long) {
        if (auth.key != writer) throw NotAuthorizedException("Authorization key is not the writer")
        checkSkew(ts, now)
    }

    /** The metadata headers (§5.3, §5.4) in the order of [AndpHeaders.META]; empty optional values are omitted. */
    fun headers(): List<Pair<String, String>> = buildList {
        add(AndpHeaders.WRITER to writer.toString())
        add(AndpHeaders.TS to AndpInt.format(ts))
        add(AndpHeaders.UNTIL to AndpInt.format(until))
        add(AndpHeaders.PLACEMENT to placement.wire)
        Refs.encode(refs)?.let { add(AndpHeaders.REFS to B64.encode(it)) }
        revokes?.let { add(AndpHeaders.REVOKES to it.toString()) }
        grant?.let { add(AndpHeaders.GRANT to it.toString()) }
        add(AndpHeaders.SIG to sig.toString())
    }

    /** The list item of this metadata (§5.6); [data] `null` when the entry is not inlined. */
    fun listed(seq: Long, data: ByteArray?): ListedObject =
        ListedObject(seq, id, size, ts, until, placement, refs, revokes, writer, grant, sig, data)

    companion object {
        /**
         * Validates and signs metadata; the writer is the key of [signer]. For a grantee pass its
         * [grant]; the owner writes without grant.
         */
        suspend fun sign(
            signer: SigningKey,
            space: Key,
            id: ID,
            size: Long,
            ts: Long,
            until: Long = 0,
            placement: Placement,
            refs: List<Ref> = emptyList(),
            revokes: Hash? = null,
            grant: Grant? = null,
        ): Meta {
            validate(space, id, size, ts, until, placement, refs, revokes, signer.key, grant)
            val sig = signer.sign(signingBytes(space, id, size, ts, until, placement, refs, revokes))
            return Meta(space, id, size, ts, until, placement, refs, revokes, signer.key, grant, sig)
        }

        /** [sign] for the bytes [data]: id and size are taken from them. */
        suspend fun signData(
            signer: SigningKey,
            space: Key,
            data: ByteArray,
            ts: Long,
            until: Long = 0,
            placement: Placement,
            refs: List<Ref> = emptyList(),
            revokes: Hash? = null,
            grant: Grant? = null,
        ): Meta = sign(signer, space, ID.of(data), data.size.toLong(), ts, until, placement, refs, revokes, grant)

        /**
         * Reads the metadata headers; [space] and [id] come from the path, [size] from the body. It runs
         * [validate] but does not verify the signature.
         */
        fun fromHeaders(space: Key, id: ID, size: Long, h: HeaderSource): Meta {
            val refs = h.single(AndpHeaders.REFS)?.let { Refs.decode(B64.decode(it)) } ?: emptyList()
            val m = Meta(
                space = space,
                id = id,
                size = size,
                writer = Key.parse(h.required(AndpHeaders.WRITER)),
                ts = AndpInt.parse(h.required(AndpHeaders.TS)),
                until = AndpInt.parse(h.required(AndpHeaders.UNTIL)),
                placement = Placement.parse(h.required(AndpHeaders.PLACEMENT)),
                sig = Sig.parse(h.required(AndpHeaders.SIG)),
                refs = refs,
                revokes = h.single(AndpHeaders.REVOKES)?.let { Hash.parse(it) },
                grant = h.single(AndpHeaders.GRANT)?.let { Grant.parse(it) },
            )
            m.validate()
            return m
        }

        private fun signingBytes(
            space: Key, id: ID, size: Long, ts: Long, until: Long, placement: Placement, refs: List<Ref>, revokes: Hash?,
        ): ByteArray = SigningBytes.obj(space, id, size, ts, until, placement, Refs.digest(refs), revokes?.toString() ?: "")

        private fun validate(
            space: Key, id: ID, size: Long, ts: Long, until: Long, placement: Placement, refs: List<Ref>, revokes: Hash?,
            writer: Key, grant: Grant?,
        ) {
            if (size < 0 || ts < 0 || until < 0) throw AndpException("andp: negative size or time")
            if (until != 0L && until <= ts) throw AndpException("andp: until must be 0 or greater than ts")
            if (placement != Placement.SPACE && (refs.isNotEmpty() || revokes != null)) {
                throw AndpException("andp: a content must not have refs or revokes")
            }
            if (refs.any { it.size < 0 }) throw AndpException("andp: negative ref size")
            if (writer == space && grant != null) throw AndpException("andp: the owner writes without grant")
            if (revokes != null) {
                if (writer != space) throw AndpException("andp: only the owner writes revocations")
                if (size != Hash.SIZE.toLong() || id != ID.of(revokes.unsafeBytes)) {
                    throw AndpException("andp: revocation bytes must be the raw grant hash")
                }
            }
        }

        /** The bytes of a revocation entry for grant hash [grant] (§4.3). */
        fun revocationData(grant: Hash): ByteArray = grant.bytes
    }
}

/** One item of a list response (§5.6). [data] holds the inlined bytes, `null` when not inlined. */
@Serializable
class ListedObject(
    val seq: Long,
    val id: ID,
    val size: Long,
    val ts: Long,
    val until: Long,
    val placement: Placement,
    val refs: List<Ref> = emptyList(),
    val revokes: Hash? = null,
    val writer: Key,
    val grant: Grant? = null,
    val sig: Sig,
    @Serializable(with = B64BytesSerializer::class) val data: ByteArray? = null,
    /** The time the entry was held until (§19); `0` for an ordinary entry. Not signed, for information only. */
    @SerialName("not_before") val notBefore: Long = 0,
) {
    /** The metadata of the item in [space]. */
    fun meta(space: Key): Meta = Meta(space, id, size, ts, until, placement, refs, revokes, writer, grant, sig)

    /** The inlined bytes, or `null` when the client has to GET the entry. An empty entry is always inline. */
    fun inline(): ByteArray? = when {
        data != null && data.isNotEmpty() -> data
        size == 0L -> ByteArray(0)
        else -> null
    }
}
