package app.anynear.andp

import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.Serializable
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Pinned client against the Go test relay (internal/cmd/testrelay in the private repository ANDP-Peer) over real TLS: SPKI pinning, no
 * SNI, and every endpoint. Runs only where `go` is installed (set ANDP_REQUIRE_GO=1 to fail instead).
 */
class GoRelayIntegrationTest {
    @Serializable
    private class Started(val relay: Relay, val list: SignedList)

    private fun goAvailable(): Boolean = try {
        ProcessBuilder("go", "version").redirectErrorStream(true).start().waitFor(30, TimeUnit.SECONDS)
    } catch (e: Exception) {
        false
    }

    private suspend fun clientKey(label: String) = SigningKey.fromSeed(Sha256.digest("ANDP client test: $label".encodeToByteArray()))

    @Test
    fun pinnedClientAgainstGoRelay() {
        val goDir = File(System.getenv("ANDP_GO_DIR") ?: return)
        if (!goAvailable()) {
            if (System.getenv("ANDP_REQUIRE_GO") == "1") error("go is required for the integration test")
            println("GoRelayIntegrationTest: go not found, skipped")
            return
        }
        val proc = ProcessBuilder("go", "run", "./internal/cmd/testrelay").directory(goDir).redirectError(ProcessBuilder.Redirect.INHERIT).start()
        try {
            val line = proc.inputStream.bufferedReader().readLine() ?: error("test relay did not start")
            val started = AndpJson.decodeFromString(Started.serializer(), line)
            runBlocking { exercise(started) }
        } finally {
            proc.outputStream.close()
            proc.descendants().forEach { it.destroy() }
            proc.destroy()
            proc.waitFor(10, TimeUnit.SECONDS)
        }
    }

    private suspend fun exercise(s: Started) {
        val netKey = clientKey("network").key
        val list = NetworkList.verify(s.list, networkId(netKey), netKey)
        assertEquals(s.relay, list.relays[0])

        AndpClient.pinned(s.relay).use { c ->
            val info = c.info()
            assertTrue(info.hasExtension(Andp.EXTENSION_WATCH))
            assertEquals(s.list, c.net())

            val owner = clientKey("owner")
            val grantee = clientKey("grantee")
            val space = owner.key
            val now = c.now()
            val g = Grant.issue(owner, GrantBody(space, Rights.WRITE + Rights.READ + Rights.LIST, grantee.key, until = now + 3600, issued = now - 60))
            val gc = Credentials(grantee, g)

            val content = "ciphertext from kotlin".encodeToByteArray()
            val cm = Meta.signData(grantee, space, content, now, now + 3600, Placement.OBJECT, grant = g)
            val rc = c.put(gc, cm, content, PutOptions(noNotify = true))
            assertEquals(s.relay.node, rc.node)
            val entry = "entry from kotlin".encodeToByteArray()
            val em = Meta.signData(grantee, space, entry, now, placement = Placement.SPACE, refs = listOf(Ref(cm.id, cm.size)), grant = g)
            c.put(gc, em, entry)

            assertContentEquals(content, c.get(null, space, cm.id).data)
            assertEquals(em, c.get(gc, space, em.id, GetOptions(proxy = true)).meta)
            assertEquals(401, assertFailsWith<AndpHttpException> { c.get(null, space, em.id) }.status)
            val nf = assertFailsWith<AndpHttpException> { c.get(null, space, ID.of(ByteArray(3))) }
            assertEquals(1, nf.knownHolders(list).size)

            val page = c.list(gc, space, ListOptions(waitSeconds = 1))
            assertEquals(listOf(em.id), page.objects.map { it.id })
            assertContentEquals(entry, page.objects[0].inline())
            assertEquals(ObjectState.HERE, c.status(gc, space, listOf(cm.id))[cm.id])

            c.watch(gc, WatchRequest(space, WatchTarget("apns", "00ff", "app", "production")))

            // Stream (§18): ping at once, then a new event for an entry in a space with a relay watch.
            assertTrue(info.hasExtension(Andp.EXTENSION_STREAM))
            assertEquals(Andp.DEFAULT_STREAM_PING, info.stream?.ping)
            val streamKey = clientKey("stream")
            val tag = B64.encode(ByteArray(Andp.STREAM_TAG_BYTES) { 7 })
            val events = kotlinx.coroutines.channels.Channel<StreamEvent>(8)
            kotlinx.coroutines.coroutineScope {
                val job = launch { c.stream(Credentials(streamKey), 30_000) { events.send(it) } }
                assertEquals(Andp.STREAM_EVENT_PING, withTimeout(10_000) { events.receive() }.type)
                c.watch(gc, WatchRequest(space, WatchTarget(Andp.WATCH_TYPE_RELAY, bytesToHex(streamKey.key.bytes), node = s.relay.node.toString(), tag = tag)))
                val e2 = "second entry".encodeToByteArray()
                c.put(gc, Meta.signData(grantee, space, e2, now, placement = Placement.SPACE, grant = g), e2, PutOptions(alarm = true))
                val ev = withTimeout(10_000) { events.receive() }
                assertEquals(Andp.STREAM_EVENT_NEW, ev.type)
                assertEquals(StreamNew(listOf(tag), alarm = true), AndpJson.decodeFromString(StreamNew.serializer(), ev.data))
                job.cancel()
            }
            c.delete(Credentials(owner), space, cm.id)
            assertTrue(assertFailsWith<AndpHttpException> { c.put(gc, cm, content) }.isGone)
            assertEquals(403, assertFailsWith<AndpHttpException> { c.delete(gc, space, em.id) }.status)
        }

        // A wrong pin fails the TLS handshake.
        AndpClient.pinned(s.relay.copy(key = Hash.of(ByteArray(0)))).use { c ->
            assertFailsWith<Exception> { c.info() }
        }
        // Web PKI does not accept the self-signed certificate (the relay also refuses SNI).
        AndpClient.forUrl("https://" + s.relay.addr).use { c ->
            assertFailsWith<Exception> { c.info() }
        }
    }
}
