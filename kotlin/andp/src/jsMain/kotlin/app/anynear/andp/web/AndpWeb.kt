// JavaScript facade for TypeScript callers (browsers, Node.js). Kotlin callers use the app.anynear.andp
// API directly. Binary values are Int8Array, integers are numbers (Unix seconds and milliseconds stay
// below 2^53), structured values are the JSON of spec/andp.md, and every asynchronous call returns a
// Promise. Browsers reach relays only through their host with Web PKI (§12); there is no pinned mode.
@file:OptIn(DelicateCoroutinesApi::class)

package app.anynear.andp.web

import app.anynear.andp.B64
import app.anynear.andp.Credentials
import app.anynear.andp.GetOptions
import app.anynear.andp.Grant
import app.anynear.andp.GrantBody
import app.anynear.andp.Hash
import app.anynear.andp.ID
import app.anynear.andp.Key
import app.anynear.andp.ListOptions
import app.anynear.andp.ListPage
import app.anynear.andp.Meta
import app.anynear.andp.NetworkList
import app.anynear.andp.AndpClient
import app.anynear.andp.AndpException
import app.anynear.andp.AndpHttpException
import app.anynear.andp.AndpJson
import app.anynear.andp.Placement
import app.anynear.andp.Placements
import app.anynear.andp.PutOptions
import app.anynear.andp.Ref
import app.anynear.andp.Relay
import app.anynear.andp.Rights
import app.anynear.andp.SignedList
import app.anynear.andp.SigningKey
import app.anynear.andp.WatchRequest
import app.anynear.andp.networkId
import app.anynear.andp.watchIdForHexToken
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.promise
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.js.Promise

/** A rejected Promise of this facade. [status] is the HTTP status (0 for protocol errors); [holdersJson] the holders of a 404. */
@JsExport
class AndpWebError(message: String, val status: Int, val code: String, val holdersJson: String?) : Throwable(message)

private fun <T> call(block: suspend () -> T): Promise<T> = GlobalScope.promise {
    try {
        block()
    } catch (e: AndpHttpException) {
        throw AndpWebError(e.message ?: "", e.status, e.code, e.holders?.let { AndpJson.encodeToString(ListSerializer(Relay.serializer()), it) })
    } catch (e: AndpException) {
        throw AndpWebError(e.message ?: "", 0, "", null)
    }
}

private fun sync(block: () -> String): String = try {
    block()
} catch (e: AndpException) {
    throw AndpWebError(e.message ?: "", 0, "", null)
}

/** An Ed25519 key pair. [key] is the public key (b64u). */
@JsExport
class AndpWebSigner internal constructor(internal val signing: SigningKey) {
    val key: String get() = signing.key.toString()

    /** The 32-byte seed. */
    fun seed(): ByteArray = signing.seed

    /** Signs [message]; resolves to the b64u signature. */
    fun sign(message: ByteArray): Promise<String> = call { signing.sign(message).toString() }

    companion object {
        fun fromSeed(seed: ByteArray): Promise<AndpWebSigner> = call { AndpWebSigner(SigningKey.fromSeed(seed)) }
        fun generate(): Promise<AndpWebSigner> = call { AndpWebSigner(SigningKey.generate()) }
    }
}

/** Formats without network access. */
@JsExport
object AndpWeb {
    /** The object id (b64u SHA-256) of [data]. */
    fun idOf(data: ByteArray): String = ID.of(data).toString()

    /** The watch ID of an APNs token given as hex (§10). */
    fun watchId(hexToken: String): String = sync { watchIdForHexToken(hexToken) }

    /** The network ID of the first network key (§2). */
    fun networkId(firstKey: String): String = sync { networkId(Key.parse(firstKey)).toString() }

    /**
     * Issues a grant (§4.2); [owner] must hold the space key. [rights] is the bit set of §4.1, [grantee]
     * and [scope] empty for anyone and the whole space. Resolves to the grant's wire form.
     */
    fun issueGrant(owner: AndpWebSigner, rights: Int, grantee: String, scope: String, until: Double, issued: Double): Promise<String> = call {
        Grant.issue(
            owner.signing,
            GrantBody(
                owner.signing.key, Rights(rights.toLong()), grantee.takeIf { it.isNotEmpty() }?.let { Key.parse(it) },
                scope.takeIf { it.isNotEmpty() }?.let { ID.parse(it) }, until.toLong(), issued.toLong(),
            ),
        ).toString()
    }

    /** The hash (b64u) of a grant in wire form (§2), for revocations. */
    fun grantHash(grant: String): String = sync { Grant.parse(grant).hash.toString() }

    /** Opens a signed list (JSON `{list, sig}`) on first contact; resolves to the list JSON. */
    fun verifyNetworkList(signedJson: String, networkId: String, key: String): Promise<String> = call {
        val l = NetworkList.verify(AndpJson.decodeFromString(SignedList.serializer(), signedJson), Hash.parse(networkId), Key.parse(key))
        AndpJson.encodeToString(NetworkList.serializer(), l)
    }

    /** Accepts a newer signed list after the current list JSON (§5.8); resolves to the new list JSON. */
    fun acceptNetworkList(currentJson: String, signedJson: String): Promise<String> = call {
        val cur = AndpJson.decodeFromString(NetworkList.serializer(), currentJson)
        val l = cur.accept(AndpJson.decodeFromString(SignedList.serializer(), signedJson))
        AndpJson.encodeToString(NetworkList.serializer(), l)
    }

    /**
     * The relays (JSON array) that hold [key] (a space for entries, an id for contents) in the list
     * JSON, with substitutes for the nodes in [down] (§6).
     */
    fun targets(key: String, listJson: String, down: Array<String>): String = sync {
        val l = AndpJson.decodeFromString(NetworkList.serializer(), listJson)
        val t = Placements.place(key, l.relays).targets { it.toString() !in down }
        AndpJson.encodeToString(ListSerializer(Relay.serializer()), t)
    }
}

/** A verified object of [AndpWebClient.get]: bytes and metadata headers (JSON object). */
@JsExport
class AndpWebObject internal constructor(val data: ByteArray, val metaJson: String)

/**
 * Client for one relay over Web PKI (§12). Create it with [forRelay] from a relay entry of the
 * verified network list (uses `host`), or with a base URL. [grant] arguments are the caller's grant in
 * wire form, empty for the owner. Every answer is verified like in the Kotlin client.
 */
@JsExport
class AndpWebClient(baseUrl: String) {
    internal var client: AndpClient = AndpClient.forUrl(baseUrl)

    private fun cred(signer: AndpWebSigner, grant: String) = Credentials(signer.signing, grant.takeIf { it.isNotEmpty() }?.let { Grant.parse(it) })

    /** GET /andp/v1/info; resolves to its JSON. */
    fun info(): Promise<String> = call { AndpJson.encodeToString(app.anynear.andp.Info.serializer(), client.info()) }

    /** GET /andp/v1/net; resolves to `{list, sig}` (unverified). */
    fun net(): Promise<String> = call { AndpJson.encodeToString(SignedList.serializer(), client.net()) }

    /** GET /andp/v1/s/{space}; resolves to the verified page JSON `{objects, next}`. */
    fun list(signer: AndpWebSigner, grant: String, space: String, after: String, waitSeconds: Int, limit: Int): Promise<String> = call {
        AndpJson.encodeToString(ListPage.serializer(), client.list(cred(signer, grant), Key.parse(space), ListOptions(after, waitSeconds, limit)))
    }

    /**
     * Signs metadata for [data] at the current time and writes it (§5.3). [placement] is `space` or
     * `object`, [until] 0 for no expiry, [refsJson] a JSON array of `{id, size}` or empty. Resolves to
     * the object id; the receipt is verified.
     */
    fun put(
        signer: AndpWebSigner, grant: String, space: String, data: ByteArray, until: Double, placement: String, refsJson: String,
        noNotify: Boolean, watchSkip: String,
    ): Promise<String> = call {
        val c = cred(signer, grant)
        val spaceKey = Key.parse(space)
        val refs = if (refsJson.isEmpty()) emptyList() else AndpJson.decodeFromString(ListSerializer(Ref.serializer()), refsJson)
        val meta = Meta.signData(
            c.key, spaceKey, data, client.now(), until.toLong(), Placement.parse(placement), refs,
            grant = if (c.key.key == spaceKey) null else c.grant,
        )
        client.put(c, meta, data, PutOptions(noNotify, watchSkip))
        meta.id.toString()
    }

    /** GET /andp/v1/s/{space}/{id}; [signer] `null` for contents. Resolves to the verified object. */
    fun get(signer: AndpWebSigner?, grant: String, space: String, id: String, proxy: Boolean): Promise<AndpWebObject> = call {
        val f = client.get(signer?.let { cred(it, grant) }, Key.parse(space), ID.parse(id), GetOptions(proxy))
        AndpWebObject(f.data, JsonObject(f.meta.headers().associate { (k, v) -> k to JsonPrimitive(v) }).toString())
    }

    /** DELETE /andp/v1/s/{space}/{id}. */
    fun delete(signer: AndpWebSigner, grant: String, space: String, id: String): Promise<Unit> = call {
        client.delete(cred(signer, grant), Key.parse(space), ID.parse(id))
    }

    /** POST /andp/v1/s/{space}/status; resolves to JSON `{"<id>": "here" | "gone" | "missing"}`. */
    fun status(signer: AndpWebSigner, grant: String, space: String, ids: Array<String>): Promise<String> = call {
        val out = client.status(cred(signer, grant), Key.parse(space), ids.map { ID.parse(it) })
        JsonObject(out.entries.associate { (k, v) -> k.toString() to JsonPrimitive(v.wire) }).toString()
    }

    /** POST /andp/v1/watch with the request JSON of §10. */
    fun watch(signer: AndpWebSigner, grant: String, requestJson: String): Promise<Unit> = call {
        client.watch(cred(signer, grant), AndpJson.decodeFromString(WatchRequest.serializer(), requestJson))
    }

    fun close() = client.close()

    companion object {
        /** A client for a relay entry (JSON) of the verified network list; it connects to its `host`. */
        fun forRelay(relayJson: String): AndpWebClient {
            val r = try {
                AndpJson.decodeFromString(Relay.serializer(), relayJson)
            } catch (e: Exception) {
                throw AndpWebError("andp: invalid relay: ${e.message}", 0, "", null)
            }
            return AndpWebClient("https://" + r.host).also {
                it.client.close()
                it.client = sync0 { AndpClient.webPki(r) }
            }
        }

        private fun <T> sync0(block: () -> T): T = try {
            block()
        } catch (e: AndpException) {
            throw AndpWebError(e.message ?: "", 0, "", null)
        }
    }
}
