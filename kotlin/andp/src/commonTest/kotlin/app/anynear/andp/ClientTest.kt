package app.anynear.andp

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

internal const val NOW = 1761200000L

/**
 * A minimal relay built from this library's relay-side helpers (Auth, Meta.fromHeaders, Tombstone), as
 * the fake relay of go/andp/client/client_test.go. [tamper] changes answers to test the client's checks.
 */
internal class FakeRelay(val node: SigningKey, var signed: SignedList, var net: NetworkList) {
    class Stored(val meta: Meta, val data: ByteArray, val seq: Long)

    val objects = mutableMapOf<String, Stored>()
    val tombstones = mutableMapOf<String, Tombstone>()
    val requests = mutableListOf<HttpRequestData>()
    val watches = mutableListOf<WatchRequest>()
    var seq = 0L
    var tamper: (String) -> Unit = {}
    var mode = ""

    private val json = Json { ignoreUnknownKeys = true; explicitNulls = false; encodeDefaults = false }

    private fun MockRequestHandleScope.json(text: String, status: HttpStatusCode = HttpStatusCode.OK): HttpResponseData =
        respond(text, status, headersOf(HttpHeaders.ContentType, "application/json"))

    private fun MockRequestHandleScope.fail(status: Int, code: String): HttpResponseData =
        json("{\"error\":\"$code\",\"message\":\"$code\"}", HttpStatusCode.fromValue(status))

    private suspend fun auth(r: HttpRequestData): Auth? = try {
        val values = r.headers.getAll(AndpHeaders.AUTHORIZATION).orEmpty()
        if (values.size != 1) null else Auth.parse(values[0]).also { it.verify(r.method.value, r.url.encodedPath, NOW) }
    } catch (e: AndpException) {
        null
    }

    suspend fun handle(scope: MockRequestHandleScope, r: HttpRequestData): HttpResponseData = with(scope) {
        requests += r
        val path = r.url.encodedPath
        val body = r.body.toByteArray()
        when {
            path == AndpPaths.INFO -> json(
                json.encodeToString(Info.serializer(), Info(if (mode == "other-node") net.relays[1].node else node.key, net.network, Policy.DEFAULT, listOf("watch"))),
            )
            path == AndpPaths.NET && r.method.value == "GET" -> json(json.encodeToString(SignedList.serializer(), signed))
            path == AndpPaths.NET -> {
                val s = json.decodeFromString(SignedList.serializer(), body.decodeToString())
                try {
                    net = net.accept(s)
                    signed = s
                    json("{}")
                } catch (e: ListNotNewerException) {
                    fail(409, "not_newer")
                } catch (e: AndpException) {
                    fail(403, "bad_list")
                }
            }
            path == AndpPaths.WATCH -> {
                val a = auth(r) ?: return fail(401, "unauthorized")
                val req = json.decodeFromString(WatchRequest.serializer(), body.decodeToString())
                try {
                    a.authorize(req.space, Rights.LIST, null, NOW)
                } catch (e: AndpException) {
                    return fail(403, "forbidden")
                }
                watches += req
                respond("", HttpStatusCode.NoContent)
            }
            path.startsWith(Andp.PATH_PREFIX + "/s/") -> space(r, path.removePrefix(Andp.PATH_PREFIX + "/s/").split("/"), body)
            else -> fail(404, "no_route")
        }
    }

    private suspend fun MockRequestHandleScope.space(r: HttpRequestData, parts: List<String>, body: ByteArray): HttpResponseData {
        val space = Key.parse(parts[0])
        if (parts.size == 1) {
            val a = auth(r) ?: return fail(401, "unauthorized")
            try {
                a.authorize(space, Rights.LIST, null, NOW)
            } catch (e: AndpException) {
                return fail(403, "forbidden")
            }
            val after = r.url.parameters["after"]?.toLong() ?: 0
            val items = objects.values.filter { it.meta.space == space && it.meta.isEntry && it.seq > after }.sortedBy { it.seq }
            var page = ListPage(items.map { it.meta.listed(it.seq, it.data) }, (items.maxOfOrNull { it.seq } ?: after).toString())
            if (mode == "tamper-list") page = page.copy(objects = page.objects.map { it.meta(space).copy(ts = it.ts + 1).listed(it.seq, it.data) })
            if (mode == "content-in-list") {
                val c = objects.values.first { !it.meta.isEntry }
                page = page.copy(objects = listOf(c.meta.listed(c.seq, c.data)))
            }
            return json(json.encodeToString(ListPage.serializer(), page))
        }
        if (parts[1] == "status") {
            val a = auth(r) ?: return fail(401, "unauthorized")
            try {
                a.authorize(space, Rights.READ, null, NOW)
            } catch (e: AndpException) {
                return fail(403, "forbidden")
            }
            val ids = json.decodeFromString(StatusRequest.serializer(), body.decodeToString()).ids
            val out = ids.associate { it.toString() to if (objects.containsKey("$space/$it")) ObjectState.HERE else ObjectState.MISSING }
            return json(json.encodeToString(StatusResponse.serializer(), StatusResponse(out)))
        }
        val id = ID.parse(parts[1])
        val k = "$space/$id"
        when (r.method.value) {
            "PUT" -> {
                val a = auth(r) ?: return fail(401, "unauthorized")
                val m = try {
                    Meta.fromHeaders(space, id, body.size.toLong()) { r.headers.getAll(it).orEmpty() }.also { it.checkData(body) }
                } catch (e: AndpException) {
                    return fail(400, "bad_request")
                }
                try {
                    if (!a.isPeer(net)) m.checkClientWrite(a, NOW)
                    m.verify()
                } catch (e: AndpException) {
                    return fail(403, "forbidden")
                }
                if (tombstones.containsKey(k)) return fail(410, "gone")
                objects[k] = Stored(m, body, ++seq)
                val signer = if (mode == "receipt-other-node") testKey("node-x") else node
                var rc = Receipt.sign(signer, space, id, m.until)
                if (mode == "bad-receipt") rc = Receipt.sign(node, space, id, m.until + 1)
                return json(json.encodeToString(Receipt.serializer(), rc))
            }
            "GET" -> {
                val o = objects[k]
                if (o == null) {
                    if (tombstones.containsKey(k)) return fail(410, "gone")
                    val holders = json.encodeToString(Relay.serializer(), net.relays[1])
                    return json("{\"error\":\"not_found\",\"holders\":[$holders]}", HttpStatusCode.NotFound)
                }
                if (o.meta.isEntry) {
                    val a = auth(r) ?: return fail(401, "unauthorized")
                    try {
                        a.authorize(space, Rights.READ, id, NOW)
                    } catch (e: AndpException) {
                        return fail(403, "forbidden")
                    }
                }
                val data = if (mode == "tamper-get") o.data + byteArrayOf(1) else o.data
                val meta = if (mode == "tamper-sig") o.meta.copy(until = o.meta.until + 1) else o.meta
                return respond(ByteReadChannel(data), HttpStatusCode.OK, headersOf(*meta.headers().map { it.first to listOf(it.second) }.toTypedArray()))
            }
            "DELETE" -> {
                val a = auth(r) ?: return fail(401, "unauthorized")
                val t = try {
                    Tombstone.fromRequest(a, space, id) { r.headers.getAll(it).orEmpty() }.also { it.verify() }
                } catch (e: AndpException) {
                    return fail(403, "forbidden")
                }
                tombstones[k] = t
                objects.remove(k)
                return respond("", HttpStatusCode.NoContent)
            }
        }
        return fail(405, "method")
    }
}

internal class Env(
    val relay: FakeRelay,
    val client: AndpClient,
    val list: NetworkList,
    val netKey: SigningKey,
    val owner: Credentials,
    val grantee: Credentials,
    val space: Key,
)

internal suspend fun setup(): Env {
    val node = testKey("node-0")
    val netKey = testKey("network")
    val relays = listOf(
        Relay("a-0", "192.0.2.10:443", Hash.of(byteArrayOf(0)), "a-0.example.net", node.key, "a", RelayState.ACTIVE),
        Relay("b-1", "192.0.2.11:443", Hash.of(byteArrayOf(1)), "b-1.example.net", testKey("node-1").key, "b", RelayState.ACTIVE),
    )
    val list = NetworkList(1, networkId(netKey.key), netKey.key, 1000, relays = relays)
    val fake = FakeRelay(node, list.sign(netKey), list)
    val http = HttpClient(MockEngine { fake.handle(this, it) })
    val client = AndpClient.webPki(relays[0], http).apply { now = { NOW } }
    val owner = testKey("owner")
    val grantee = testKey("grantee")
    val g = Grant.issue(owner, GrantBody(owner.key, Rights.WRITE + Rights.READ + Rights.LIST, grantee.key, until = NOW + 3600, issued = NOW - 60))
    return Env(fake, client, list, netKey, Credentials(owner), Credentials(grantee, g), owner.key)
}

private suspend fun Env.meta(cred: Credentials, data: ByteArray, placement: Placement, refs: List<Ref> = emptyList()): Meta =
    Meta.signData(cred.key, space, data, NOW, NOW + 3600, placement, refs, grant = if (cred.key.key == space) null else cred.grant)

private suspend inline fun httpError(status: Int, noinline block: suspend () -> Unit): AndpHttpException {
    val e = assertFailsWith<AndpHttpException> { block() }
    assertEquals(status, e.status, e.message)
    return e
}

class ClientTest {
    @Test
    fun infoAndNet() = runTest {
        val e = setup()
        val info = e.client.info()
        assertTrue(info.hasExtension(Andp.EXTENSION_WATCH))
        assertEquals(60, info.policy.repairInterval)
        e.relay.mode = "other-node"
        assertFailsWith<AndpException> { e.client.info() }
        e.relay.mode = ""
        assertFailsWith<AndpException> { AndpClient.webPki(e.list.relays[0].copy(host = "")) }

        val s = e.client.net()
        val l = NetworkList.verify(s, networkId(e.netKey.key), e.netKey.key)
        httpError(409) { e.client.offerNet(s) }
        val s2 = l.copy(issued = l.issued + 1).sign(e.netKey)
        e.client.offerNet(s2)
        httpError(403) { e.client.offerNet(s2.copy(sig = Sig(ByteArray(64)))) }
    }

    @Test
    fun alarmNotify() = runTest {
        val e = setup()
        val entry = "alarm".encodeToByteArray()
        val em = e.meta(e.grantee, entry, Placement.SPACE)
        e.client.put(e.grantee, em, entry, PutOptions(alarm = true))
        assertEquals(AndpHeaders.NOTIFY_ALARM, e.relay.requests.last().headers[AndpHeaders.NOTIFY])
        val other = "none wins".encodeToByteArray()
        e.client.put(e.grantee, e.meta(e.grantee, other, Placement.SPACE), other, PutOptions(noNotify = true, alarm = true))
        assertEquals(AndpHeaders.NOTIFY_NONE, e.relay.requests.last().headers[AndpHeaders.NOTIFY])
        val quiet = "quiet wins over alarm".encodeToByteArray()
        e.client.put(e.grantee, e.meta(e.grantee, quiet, Placement.SPACE), quiet, PutOptions(quiet = true, alarm = true))
        assertEquals(AndpHeaders.NOTIFY_QUIET, e.relay.requests.last().headers[AndpHeaders.NOTIFY])
    }

    @Test
    fun notBeforeHeader() = runTest {
        val e = setup()
        val entry = "held".encodeToByteArray()
        val em = e.meta(e.grantee, entry, Placement.SPACE)
        e.client.put(e.grantee, em, entry, PutOptions(alarm = true, notBefore = em.ts + 600))
        assertEquals((em.ts + 600).toString(), e.relay.requests.last().headers[AndpHeaders.NOT_BEFORE])
        assertEquals(AndpHeaders.NOTIFY_ALARM, e.relay.requests.last().headers[AndpHeaders.NOTIFY])
        val plain = "ordinary".encodeToByteArray()
        e.client.put(e.grantee, e.meta(e.grantee, plain, Placement.SPACE), plain)
        assertNull(e.relay.requests.last().headers[AndpHeaders.NOT_BEFORE])
    }

    @Test
    fun objects() = runTest {
        val e = setup()
        val content = "ciphertext".encodeToByteArray()
        val cm = e.meta(e.grantee, content, Placement.OBJECT)
        val rc = e.client.put(e.grantee, cm, content, PutOptions(noNotify = true))
        assertEquals(e.list.relays[0].node, rc.node)
        val put = e.relay.requests.last()
        assertEquals(AndpHeaders.NOTIFY_NONE, put.headers[AndpHeaders.NOTIFY])
        assertNull(Auth.parse(put.headers[AndpHeaders.AUTHORIZATION]!!).grant, "the right travels in ANDP-Grant")
        assertEquals(cm.grant.toString(), put.headers[AndpHeaders.GRANT])

        val entry = "entry".encodeToByteArray()
        val em = e.meta(e.grantee, entry, Placement.SPACE, listOf(Ref(cm.id, cm.size)))
        e.client.put(e.grantee, em, entry, PutOptions(watchSkip = watchId(byteArrayOf(1))))
        assertEquals(watchId(byteArrayOf(1)), e.relay.requests.last().headers[AndpHeaders.WATCH_SKIP])
        assertNull(e.relay.requests.last().headers[AndpHeaders.NOTIFY])

        // Content without credentials, entry with.
        val got = e.client.get(null, e.space, cm.id)
        assertContentEquals(content, got.data)
        assertEquals(cm, got.meta)
        assertNull(e.relay.requests.last().headers[AndpHeaders.AUTHORIZATION])
        httpError(401) { e.client.get(null, e.space, em.id) }
        val ge = e.client.get(e.grantee, e.space, em.id, GetOptions(proxy = true))
        assertEquals(1, ge.meta.refs.size)
        assertEquals(AndpHeaders.FETCH_PROXY, e.relay.requests.last().headers[AndpHeaders.FETCH])
        assertNotNull(Auth.parse(e.relay.requests.last().headers[AndpHeaders.AUTHORIZATION]!!).grant)

        // 404 with holders.
        val nf = httpError(404) { e.client.get(null, e.space, ID.of("nope".encodeToByteArray())) }
        assertTrue(nf.isNotFound)
        assertEquals(Andp.ERROR_NOT_FOUND, nf.code)
        assertEquals(1, nf.knownHolders(e.list).size)
        assertEquals(0, nf.knownHolders(e.list.copy(relays = e.list.relays.take(1))).size)

        // Status.
        val st = e.client.status(e.grantee, e.space, listOf(cm.id, ID.of("nope".encodeToByteArray())))
        assertEquals(ObjectState.HERE, st[cm.id])
        assertEquals(ObjectState.MISSING, st[ID.of("nope".encodeToByteArray())])
        assertFailsWith<AndpException> { e.client.status(e.grantee, e.space, List(1001) { cm.id }) }

        // List with long poll; wait and limit are capped.
        val page = e.client.list(e.grantee, e.space, ListOptions(waitSeconds = 30, limit = 500))
        assertEquals(1, page.objects.size)
        assertEquals("2", page.next)
        val q = e.relay.requests.last().url.parameters
        assertEquals("25", q["wait"])
        assertEquals("200", q["limit"])
        assertEquals("entry", page.objects[0].inline()!!.decodeToString())
        assertEquals(0, e.client.list(e.grantee, e.space, ListOptions(after = page.next)).objects.size)
        assertEquals("2", e.relay.requests.last().url.parameters["after"])

        // Writer mismatch, stranger, bytes not matching.
        httpError(403) { e.client.put(e.owner, cm, content) }
        val stranger = Credentials(testKey("stranger"), e.grantee.grant)
        val sm = e.meta(stranger, "x".encodeToByteArray(), Placement.OBJECT)
        httpError(403) { e.client.put(stranger, sm, "x".encodeToByteArray()) }
        assertFailsWith<AndpException> { e.client.put(e.grantee, cm, "other".encodeToByteArray()) }

        // Delete by owner, then 410 on write and read.
        e.client.delete(e.owner, e.space, cm.id)
        assertTrue(httpError(410) { e.client.put(e.grantee, cm, content) }.isGone)
        httpError(410) { e.client.get(null, e.space, cm.id) }
        httpError(403) { e.client.delete(e.grantee, e.space, em.id) }
    }

    @Test
    fun answersAreVerified() = runTest {
        val e = setup()
        val content = "ciphertext".encodeToByteArray()
        val cm = e.meta(e.grantee, content, Placement.OBJECT)
        e.relay.mode = "receipt-other-node"
        assertFailsWith<AndpException> { e.client.put(e.grantee, cm, content) }
        e.relay.mode = "bad-receipt"
        assertFailsWith<AndpException> { e.client.put(e.grantee, cm, content) }
        e.relay.mode = ""
        e.client.put(e.grantee, cm, content)
        val entry = "entry".encodeToByteArray()
        val em = e.meta(e.grantee, entry, Placement.SPACE)
        e.client.put(e.grantee, em, entry)

        e.relay.mode = "tamper-get"
        assertFailsWith<AndpException> { e.client.get(null, e.space, cm.id) }
        e.relay.mode = "tamper-sig"
        assertFailsWith<BadSignatureException> { e.client.get(null, e.space, cm.id) }
        e.relay.mode = "tamper-list"
        assertFailsWith<AndpException> { e.client.list(e.grantee, e.space) }
        e.relay.mode = "content-in-list"
        assertFailsWith<AndpException> { e.client.list(e.grantee, e.space) }
        e.relay.mode = ""
        e.client.maxObjectBytes = 4
        assertFailsWith<AndpException> { e.client.get(null, e.space, cm.id) }
    }

    @Test
    fun watch() = runTest {
        val e = setup()
        val req = WatchRequest(e.space, WatchTarget("apns", "00ff", "app", "production"))
        e.client.watch(e.grantee, req)
        e.client.watch(e.owner, req.copy(remove = true))
        assertEquals(listOf(false, true), e.relay.watches.map { it.remove })
        httpError(403) { e.client.watch(Credentials(testKey("stranger")), req) }
    }

    @Test
    fun errorDecoding() = runTest {
        val http = HttpClient(MockEngine { r ->
            when (r.url.encodedPath) {
                AndpPaths.INFO -> respond("<html>bad gateway</html>", HttpStatusCode.BadGateway)
                AndpPaths.NET -> respond("{\"error\":\"rate_limit\",\"message\":\"slow down\",\"extra\":1}", HttpStatusCode.TooManyRequests)
                else -> respond("{\"objects\":[{\"seq\":1}]}", HttpStatusCode.OK)
            }
        })
        val c = AndpClient.forUrl("https://relay.example.net/", http)
        val e1 = httpError(502) { c.info() }
        assertEquals("Bad Gateway", e1.detail)
        val e2 = httpError(429) { c.net() }
        assertEquals("rate_limit", e2.code)
        assertEquals("slow down", e2.detail)
        assertNull(e2.holders)
        // A malformed success answer is a AndpException, not a serialization error.
        assertFailsWith<AndpException> { c.list(Credentials(testKey("x")), testKey("x").key) }
    }
}
