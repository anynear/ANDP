package app.anynear.andp

/** Signing bytes of every domain (§1, §14): the domain, then each field preceded by "\n", no trailing newline. */
object SigningBytes {
    fun of(domain: String, vararg fields: String): ByteArray = buildString {
        append(domain)
        for (f in fields) append('\n').append(f)
    }.encodeToByteArray()

    /** andp/v1/obj (§3). [refsDigest] and [revokes] are "" when empty. */
    fun obj(space: Key, id: ID, size: Long, ts: Long, until: Long, placement: Placement, refsDigest: String, revokes: String): ByteArray =
        of(Andp.DOMAIN_OBJ, space.toString(), id.toString(), AndpInt.format(size), AndpInt.format(ts), AndpInt.format(until),
            placement.wire, refsDigest, revokes)

    /** andp/v1/del (§5.5). */
    fun delete(space: Key, id: ID, ts: Long): ByteArray = of(Andp.DOMAIN_DEL, space.toString(), id.toString(), AndpInt.format(ts))

    /** andp/v1/req (§4.4). [method] is upper case, [path] has no query string. */
    fun request(method: String, path: String, ts: Long): ByteArray = of(Andp.DOMAIN_REQ, method, path, AndpInt.format(ts))

    /** andp/v1/grant over b64u of the grant body (§4.2). */
    fun grant(body: ByteArray): ByteArray = of(Andp.DOMAIN_GRANT, B64.encode(body))

    /** andp/v1/receipt (§5.3). */
    fun receipt(space: Key, id: ID, until: Long): ByteArray = of(Andp.DOMAIN_RECEIPT, space.toString(), id.toString(), AndpInt.format(until))

    /** andp/v1/net over the exact list text (§5.8). */
    fun net(list: String): ByteArray = of(Andp.DOMAIN_NET, list)

    /** andp/v1/radio over the exact radio list text (§5.9). */
    fun radio(list: String): ByteArray = of(Andp.DOMAIN_RADIO, list)

    /** andp/v1/card over the exact card text (§17.1). */
    fun card(card: String): ByteArray = of(Andp.DOMAIN_CARD, card)

    /** Input of the placement rank (§6); it is hashed, not signed. */
    fun place(key: String, node: Key): ByteArray = of(Andp.DOMAIN_PLACE, key, node.toString())
}

/** A relay's confirmation of durable storage (§5.3). */
@kotlinx.serialization.Serializable
data class Receipt(val node: Key, val receipt: Sig) {
    /** Throws [BadSignatureException] unless the receipt signs (space, id, until). */
    suspend fun verify(space: Key, id: ID, until: Long) {
        if (!node.verify(SigningBytes.receipt(space, id, until), receipt)) throw BadSignatureException("receipt")
    }

    companion object {
        /** Creates a receipt with the node key (relays and tests). */
        suspend fun sign(node: SigningKey, space: Key, id: ID, until: Long): Receipt =
            Receipt(node.key, node.sign(SigningBytes.receipt(space, id, until)))
    }
}
