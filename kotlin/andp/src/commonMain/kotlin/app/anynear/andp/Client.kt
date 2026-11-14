package app.anynear.andp

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.HttpTimeoutConfig
import io.ktor.client.plugins.pluginOrNull
import io.ktor.client.plugins.timeout
import io.ktor.client.request.header
import io.ktor.client.request.prepareRequest
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.ByteArrayContent
import io.ktor.http.isSuccess
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.readUTF8Line
import kotlinx.io.readByteArray
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlin.time.Clock

/** Signs requests: a client key with an optional grant. */
class Credentials(val key: SigningKey, val grant: Grant? = null)

/** Query parameters of GET /andp/v1/s/{space} (§5.6). */
data class ListOptions(
    /** Cursor of the previous page at the same relay; "" = from the start. */
    val after: String = "",
    /** Long poll in seconds, capped at [Andp.MAX_LIST_WAIT]; 0 = answer at once. */
    val waitSeconds: Int = 0,
    /** Page size 1–200, capped at [Andp.MAX_LIST_LIMIT]; 0 = relay default. */
    val limit: Int = 0,
)

/** Optional headers of PUT (§5.3). */
data class PutOptions(
    /** ANDP-Notify: none, suppresses watch notifications. */
    val noNotify: Boolean = false,
    /** ANDP-Watch-Skip, a watch ID that is not notified (the writer's own). */
    val watchSkip: String = "",
    /** ANDP-Notify: alarm, wakes with alarm priority (§10); [noNotify] wins. */
    val alarm: Boolean = false,
)

/** Options of GET of an object. */
data class GetOptions(
    /** ANDP-Fetch: proxy (contents only, §9): the relay fetches from a holder and delivers without storing. */
    val proxy: Boolean = false,
)

/** A verified object: metadata and bytes. */
class Fetched(val meta: Meta, val data: ByteArray)

/**
 * HTTP client for one relay and all client endpoints of ANDP version v1 (§5). Apps create it with
 * `AndpClient.pinned` (connects to [Relay.addr] and accepts only the TLS key [Relay.key]; not in JS),
 * browsers with [webPki] (connects to [Relay.host] with normal certificate checks). It is safe for
 * concurrent use. Every answer is verified; a failed verification throws [AndpException], an error
 * answer [AndpHttpException].
 */
class AndpClient internal constructor(
    baseUrl: String,
    private val http: HttpClient,
    /** The relay this client was created for; `null` for [forUrl]. Info and receipts must come from its node. */
    val relay: Relay? = null,
    private val ownsHttp: Boolean = false,
) : AutoCloseable {
    private val base = baseUrl.trimEnd('/')

    /** Clock for Authorization timestamps, Unix seconds. */
    var now: () -> Long = { Clock.System.now().epochSeconds }

    /** Limit for GET bodies; 0 means [DEFAULT_MAX_BODY]. Set it from the relay's max_object_bytes. */
    var maxObjectBytes: Long = 0

    override fun close() {
        if (ownsHttp) http.close()
    }

    /** GET /andp/v1/info. With a relay, the answer must come from its node. */
    suspend fun info(): Info {
        val info = json(HttpMethod.Get, AndpPaths.INFO, Info.serializer())
        if (relay != null && info.node != relay.node) throw AndpException("client: relay answers with another node key")
        return info
    }

    /** GET /andp/v1/net. The caller verifies the list ([NetworkList.verify] or [NetworkList.accept]). */
    suspend fun net(): SignedList = json(HttpMethod.Get, AndpPaths.NET, SignedList.serializer())

    /** POST /andp/v1/net. A 409 (not newer) or 403 (bad signature) comes back as [AndpHttpException]. */
    suspend fun offerNet(signed: SignedList) {
        send(Req(HttpMethod.Post, AndpPaths.NET, body = encode(SignedList.serializer(), signed), json = true)).discard()
    }

    /** GET /andp/v1/radio (§5.9). A relay without a radio list answers 404 ([AndpHttpException]). */
    suspend fun radio(): SignedList = json(HttpMethod.Get, AndpPaths.RADIO, SignedList.serializer())

    /** POST /andp/v1/radio. A 409 (not newer) or 403 (bad signature) comes back as [AndpHttpException]. */
    suspend fun offerRadio(signed: SignedList) {
        send(Req(HttpMethod.Post, AndpPaths.RADIO, body = encode(SignedList.serializer(), signed), json = true)).discard()
    }

    /**
     * GET /andp/v1/s/{space}. Every item is verified (entry, signature, grant at ts, inline bytes); an
     * invalid item fails the call, since the relay is then not trustworthy.
     */
    suspend fun list(cred: Credentials, space: Key, options: ListOptions = ListOptions()): ListPage {
        val query = buildList {
            if (options.after.isNotEmpty()) add("after" to options.after)
            if (options.waitSeconds > 0) add("wait" to minOf(options.waitSeconds, Andp.MAX_LIST_WAIT).toString())
            if (options.limit > 0) add("limit" to minOf(options.limit, Andp.MAX_LIST_LIMIT).toString())
        }
        val wait = minOf(maxOf(options.waitSeconds, 0), Andp.MAX_LIST_WAIT)
        val page = decode(
            send(Req(HttpMethod.Get, AndpPaths.space(space), query = query, cred = cred, withGrant = true, waitSeconds = wait)),
            ListPage.serializer(), "GET " + AndpPaths.space(space),
        )
        page.objects.forEachIndexed { i, o ->
            val m = o.meta(space)
            try {
                if (!m.isEntry) throw AndpException("andp: not an entry")
                m.verify()
                o.inline()?.let { m.checkData(it) }
            } catch (e: AndpException) {
                throw AndpException("client: list item $i: ${e.message}", e)
            }
        }
        return page
    }

    /**
     * PUT /andp/v1/s/{space}/{id} with signed metadata [meta] and its bytes. [cred] is the writer; the
     * writer's right travels in ANDP-Grant, so the Authorization header carries no grant. The receipt
     * is verified.
     */
    suspend fun put(cred: Credentials, meta: Meta, data: ByteArray, options: PutOptions = PutOptions()): Receipt {
        meta.checkData(data)
        val headers = meta.headers().toMutableList()
        when {
            options.noNotify -> headers += AndpHeaders.NOTIFY to AndpHeaders.NOTIFY_NONE
            options.alarm -> headers += AndpHeaders.NOTIFY to AndpHeaders.NOTIFY_ALARM
        }
        if (options.watchSkip.isNotEmpty()) headers += AndpHeaders.WATCH_SKIP to options.watchSkip
        val path = AndpPaths.obj(meta.space, meta.id)
        val rc = decode(send(Req(HttpMethod.Put, path, body = data, cred = cred, headers = headers)), Receipt.serializer(), "PUT $path")
        if (relay != null && rc.node != relay.node) throw AndpException("client: receipt from another node")
        try {
            rc.verify(meta.space, meta.id, meta.until)
        } catch (e: AndpException) {
            throw AndpException("client: ${e.message}", e)
        }
        return rc
    }

    /**
     * GET /andp/v1/s/{space}/{id}. [cred] may be `null` for contents. Metadata and bytes are verified
     * (hash, size, signature, grant at ts; revocations are not known here). A 404 throws
     * [AndpHttpException] with [AndpHttpException.holders].
     */
    suspend fun get(cred: Credentials?, space: Key, id: ID, options: GetOptions = GetOptions()): Fetched {
        val headers = if (options.proxy) listOf(AndpHeaders.FETCH to AndpHeaders.FETCH_PROXY) else emptyList()
        val resp = send(Req(HttpMethod.Get, AndpPaths.obj(space, id), cred = cred, withGrant = true, headers = headers))
        val limit = if (maxObjectBytes > 0) maxObjectBytes else DEFAULT_MAX_BODY
        val data = resp.readLimited(limit) ?: throw AndpException("client: object larger than allowed")
        val meta = Meta.fromHeaders(space, id, data.size.toLong()) { resp.headers.getAll(it).orEmpty() }
        meta.checkData(data)
        meta.verify()
        return Fetched(meta, data)
    }

    /** DELETE /andp/v1/s/{space}/{id} with ANDP-Del-Sig over the Authorization ts (§5.5). */
    suspend fun delete(cred: Credentials, space: Key, id: ID) {
        val path = AndpPaths.obj(space, id)
        val ts = now()
        val auth = Auth.sign(cred.key, "DELETE", path, ts, cred.grant)
        val delSig = Tombstone.signDelete(cred.key, space, id, ts)
        send(Req(HttpMethod.Delete, path, auth = auth, headers = listOf(AndpHeaders.DEL_SIG to delSig.toString()))).discard()
    }

    /** POST /andp/v1/s/{space}/status for at most [Andp.MAX_STATUS_IDS] ids. */
    suspend fun status(cred: Credentials, space: Key, ids: List<ID>): Map<ID, ObjectState> {
        if (ids.size > Andp.MAX_STATUS_IDS) throw AndpException("client: too many ids")
        val path = AndpPaths.status(space)
        val out = decode(
            send(Req(HttpMethod.Post, path, body = encode(StatusRequest.serializer(), StatusRequest(ids)), json = true, cred = cred, withGrant = true)),
            StatusResponse.serializer(), "POST $path",
        )
        return out.objects.entries.associate { (k, v) ->
            val id = try {
                ID.parse(k)
            } catch (e: AndpException) {
                throw AndpException("client: POST $path: ${e.message}", e)
            }
            id to v
        }
    }

    /** POST /andp/v1/watch (extension, §10). Set [WatchRequest.remove] to remove the watch. */
    suspend fun watch(cred: Credentials, request: WatchRequest) {
        send(Req(HttpMethod.Post, AndpPaths.WATCH, body = encode(WatchRequest.serializer(), request), json = true, cred = cred, withGrant = true))
            .discard()
    }

    /**
     * GET /andp/v1/stream (extension, §18.1), signed with the stream key in [cred]: calls [onEvent] for every event
     * until the relay closes the stream, the call is cancelled or no data arrives for [idleTimeoutMillis] (then it
     * throws). Returns normally when the relay ends the stream. Unknown event types are passed on.
     */
    suspend fun stream(cred: Credentials, idleTimeoutMillis: Long, onEvent: suspend (StreamEvent) -> Unit) {
        val auth = Auth.sign(cred.key, HttpMethod.Get.value, AndpPaths.STREAM, now(), null)
        http.prepareRequest(base + AndpPaths.STREAM) {
            method = HttpMethod.Get
            header(AndpHeaders.AUTHORIZATION, auth.toString())
            header("Accept", "text/event-stream")
            if (http.pluginOrNull(HttpTimeout) != null) {
                timeout {
                    socketTimeoutMillis = idleTimeoutMillis
                    requestTimeoutMillis = HttpTimeoutConfig.INFINITE_TIMEOUT_MS
                }
            }
        }.execute { resp ->
            if (!resp.status.isSuccess()) throw readError(resp)
            readEvents(resp.bodyAsChannel(), onEvent)
        }
    }

    /**
     * POST /stats/v1, a daily usage report of the app (ADR 0045); not part of ANDP, but sent over the same pinned
     * connection. The relay checks the report itself; an error answer comes back as [AndpHttpException].
     */
    suspend fun postStats(report: ByteArray) {
        send(Req(HttpMethod.Post, STATS_PATH, body = report)).discard()
    }

    private class Req(
        val method: HttpMethod,
        val path: String,
        val query: List<Pair<String, String>> = emptyList(),
        val body: ByteArray? = null,
        val json: Boolean = false,
        val cred: Credentials? = null,
        /** Put cred.grant into Authorization. */
        val withGrant: Boolean = false,
        val auth: Auth? = null,
        val headers: List<Pair<String, String>> = emptyList(),
        val waitSeconds: Int = 0,
    )

    private suspend fun send(r: Req): HttpResponse {
        val auth = r.auth ?: r.cred?.let { Auth.sign(it.key, r.method.value, r.path, now(), if (r.withGrant) it.grant else null) }
        val url = base + r.path + if (r.query.isEmpty()) "" else r.query.joinToString("&", "?") { (k, v) -> "$k=${urlEncode(v)}" }
        val resp = http.request(url) {
            method = r.method
            for ((k, v) in r.headers) header(k, v)
            if (auth != null) header(AndpHeaders.AUTHORIZATION, auth.toString())
            if (r.body != null) {
                setBody(ByteArrayContent(r.body, if (r.json) ContentType.Application.Json else ContentType.Application.OctetStream))
            }
            if (r.waitSeconds > 0 && http.pluginOrNull(HttpTimeout) != null) {
                timeout { socketTimeoutMillis = (r.waitSeconds + SOCKET_TIMEOUT_SECONDS) * 1000L }
            }
        }
        if (!resp.status.isSuccess()) throw readError(resp)
        return resp
    }

    private suspend fun <T> json(method: HttpMethod, path: String, serializer: KSerializer<T>): T =
        decode(send(Req(method, path)), serializer, "${method.value} $path")

    private suspend fun <T> decode(resp: HttpResponse, serializer: KSerializer<T>, what: String): T {
        val data = resp.readLimited(MAX_JSON_BYTES) ?: throw AndpException("client: response too large")
        return try {
            decodeAndpJson(serializer, data.decodeToString())
        } catch (e: SerializationException) {
            throw AndpException("client: $what: ${e.message}", e)
        } catch (e: IllegalArgumentException) {
            throw AndpException("client: $what: ${e.message}", e)
        }
    }

    private fun <T> encode(serializer: KSerializer<T>, value: T): ByteArray = AndpJson.encodeToString(serializer, value).encodeToByteArray()

    private suspend fun HttpResponse.discard() {
        readLimited(MAX_ERROR_BYTES)
    }

    companion object {
        /** Path of the daily usage report (ADR 0045), outside of `/andp/v1`. */
        const val STATS_PATH = "/stats/v1"

        /** Limit for JSON answers. */
        const val MAX_JSON_BYTES = 64L shl 20

        /** Limit for error answers. */
        const val MAX_ERROR_BYTES = 64L shl 10

        /** Default limit for object bodies. */
        const val DEFAULT_MAX_BODY = 64L shl 20

        /** Socket timeout of the HTTP clients this class creates; a long poll adds its wait. */
        const val SOCKET_TIMEOUT_SECONDS = 60

        /** A client that connects to [Relay.host] with Web PKI (§12). [http] `null` creates a default client. */
        fun webPki(relay: Relay, http: HttpClient? = null): AndpClient {
            if (relay.host.isEmpty()) throw AndpException("client: relay has no host")
            return AndpClient("https://" + relay.host, http ?: defaultHttpClient(), relay, ownsHttp = http == null)
        }

        /**
         * A client for a base URL such as `https://anynear.net`, for a starting point without a network list
         * or for tests. [http] `null` creates a default client.
         */
        fun forUrl(baseUrl: String, http: HttpClient? = null): AndpClient =
            AndpClient(baseUrl, http ?: defaultHttpClient(), null, ownsHttp = http == null)

        /** Settings of every HTTP client this class creates. */
        internal fun HttpClientConfig<*>.andpDefaults() {
            followRedirects = false
            expectSuccess = false
            install(HttpTimeout) {
                connectTimeoutMillis = 15_000
                socketTimeoutMillis = SOCKET_TIMEOUT_SECONDS * 1000L
            }
        }

        private fun defaultHttpClient(): HttpClient = HttpClient { andpDefaults() }
    }
}

/** Reads the body up to [limit] bytes; `null` if it is longer. */
private suspend fun HttpResponse.readLimited(limit: Long): ByteArray? {
    val data = bodyAsChannel().readRemaining(limit + 1).readByteArray()
    return if (data.size > limit) null else data
}

private suspend fun readError(resp: HttpResponse): AndpHttpException {
    val status = resp.status.value
    val data = resp.readLimited(AndpClient.MAX_ERROR_BYTES) ?: ByteArray(0)
    val body = try {
        decodeAndpJson(ErrorBody.serializer(), data.decodeToString())
    } catch (e: Exception) {
        null
    }
    return if (body != null) {
        AndpHttpException(status, body.error, body.message, body.holders)
    } else {
        AndpHttpException(status, "", HttpStatusCode.fromValue(status).description, null)
    }
}

private fun urlEncode(s: String): String = buildString {
    for (b in s.encodeToByteArray()) {
        val c = b.toInt().toChar()
        if (c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '_' || c == '.' || c == '~') {
            append(c)
        } else {
            append('%').append(((b.toInt() and 0xff) or 0x100).toString(16).substring(1).uppercase())
        }
    }
}

/**
 * Reads Server-Sent Events (only the fields `event` and `data`, §18.1) from [ch] and calls [onEvent] for each, until the
 * channel ends.
 */
internal suspend fun readEvents(ch: ByteReadChannel, onEvent: suspend (StreamEvent) -> Unit) {
    var type = ""
    val data = StringBuilder()
    var hasData = false
    while (true) {
        val line = ch.readUTF8Line(MAX_EVENT_LINE) ?: return
        when {
            line.isEmpty() -> {
                if (type.isNotEmpty() || hasData) onEvent(StreamEvent(type.ifEmpty { "message" }, data.toString()))
                type = ""
                data.clear()
                hasData = false
            }
            line.startsWith(":") -> Unit
            line.startsWith("event:") -> type = line.removePrefix("event:").trim()
            line.startsWith("data:") -> {
                if (hasData) data.append('\n')
                data.append(line.removePrefix("data:").removePrefix(" "))
                hasData = true
            }
        }
    }
}

/** Longest line of an event the client reads (§18.1). */
private const val MAX_EVENT_LINE = 1 shl 20
