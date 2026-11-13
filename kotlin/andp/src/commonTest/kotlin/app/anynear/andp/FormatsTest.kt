package app.anynear.andp

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal suspend fun testKey(label: String): SigningKey = SigningKey.fromSeed(Sha256.digest("ANDP kotlin test: $label".encodeToByteArray()))

/** Error cases of the formats that the vectors do not cover. */
class FormatsTest {
    private val t0 = 1761200000L

    @Test
    fun sha256() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Sha256.digest(ByteArray(0)).hex())
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Sha256.digest("abc".encodeToByteArray()).hex())
        assertEquals(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            Sha256.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".encodeToByteArray()).hex(),
        )
        assertEquals("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", Sha256.digest(ByteArray(1_000_000) { 'a'.code.toByte() }).hex())
    }

    @Test
    fun integers() {
        assertEquals(0, AndpInt.parse("0"))
        assertEquals(Long.MAX_VALUE, AndpInt.parse("9223372036854775807"))
        for (s in listOf("", "01", "-1", "+1", " 1", "1 ", "9223372036854775808", "99999999999999999999", "1e3", "١")) {
            assertFailsWith<AndpException>(s) { AndpInt.parse(s) }
        }
        assertFailsWith<IllegalArgumentException> { AndpInt.format(-1) }
    }

    @Test
    fun fixedBytes() = runTest {
        val k = testKey("a").key
        assertEquals(k, Key.parse(k.toString()))
        assertFailsWith<AndpException> { Key.parse("AAAA") }
        assertFailsWith<AndpException> { Key.parse(k.toString() + "=") }
        assertFailsWith<AndpException> { Sig.parse(k.toString()) }
        assertFailsWith<AndpException> { Key(ByteArray(31)) }
        // Different types with the same bytes are not equal.
        assertFalse(ID(k.bytes) == Hash(k.bytes) as Any)
        val raw = k.bytes
        raw[0] = (raw[0] + 1).toByte()
        assertEquals(k, Key.parse(k.toString()), "bytes returns a copy")
    }

    @Test
    fun rights() {
        assertTrue((Rights.READ + Rights.WRITE).has(Rights.WRITE))
        assertFalse(Rights.READ.has(Rights.READ + Rights.LIST))
        assertFalse(Rights(0).isValid)
        assertFalse(Rights(16).isValid)
        assertTrue(Rights.ALL.isValid)
        assertEquals("read|write|0x10", Rights(21).toString())
    }

    @Test
    fun grantsAndAuthorize() = runTest {
        val owner = testKey("owner")
        val grantee = testKey("grantee")
        val stranger = testKey("stranger")
        val space = owner.key
        val obj = ID.of("x".encodeToByteArray())
        assertFailsWith<AndpException> { Grant.issue(grantee, GrantBody(space, Rights.WRITE, until = t0, issued = t0)) }
        assertFailsWith<AndpException> { Grant.issue(owner, GrantBody(space, Rights(0), until = t0, issued = t0)) }
        assertFailsWith<AndpException> { Grant.issue(owner, GrantBody(space, Rights(32), until = t0, issued = t0)) }
        assertFailsWith<AndpException> { Grant.issue(owner, GrantBody(space, Rights.READ, until = -1, issued = t0)) }

        val g = Grant.issue(owner, GrantBody(space, Rights.WRITE + Rights.READ, grantee.key, until = t0 + 100, issued = t0 - 100))
        assertEquals(g, Grant.parse(g.toString()))
        assertEquals(g.body, GrantBody.decode(g.raw))
        fun access(key: Key = grantee.key, need: Rights = Rights.WRITE, o: ID? = obj, at: Long = t0) = Access(space, key, need, o, at)
        authorize(access(), g)
        authorize(access(key = space), null) // the owner needs no grant
        assertFailsWith<NotAuthorizedException> { authorize(access(), null) }
        assertFailsWith<NotAuthorizedException> { authorize(access(at = t0 + 101), g) }
        assertFailsWith<NotAuthorizedException> { authorize(access(at = t0 - 101), g) }
        authorize(access(at = t0 + 100), g)
        assertFailsWith<NotAuthorizedException> { authorize(access(need = Rights.DELETE), g) }
        assertFailsWith<NotAuthorizedException> { authorize(access(key = stranger.key), g) }
        assertFailsWith<NotAuthorizedException> { authorize(Access(stranger.key, grantee.key, Rights.WRITE, obj, t0), g) }
        assertFailsWith<RevokedException> { authorize(access(), g) { s, h -> s == space && h == g.hash } }
        authorize(access(), g) { _, _ -> false }

        val anyone = Grant.issue(owner, GrantBody(space, Rights.LIST, until = t0 + 100, issued = t0))
        authorize(access(key = stranger.key, need = Rights.LIST, o = null), anyone)

        val scoped = Grant.issue(owner, GrantBody(space, Rights.DELETE, scope = obj, until = t0 + 100, issued = t0))
        authorize(access(need = Rights.DELETE), scoped)
        assertFailsWith<NotAuthorizedException> { authorize(access(need = Rights.DELETE, o = ID.of(ByteArray(0))), scoped) }
        assertFailsWith<NotAuthorizedException> { authorize(access(need = Rights.DELETE, o = null), scoped) }

        // A grant whose signature was made by someone else.
        val forged = Grant.decode(
            AndpCbor.encode(AndpCbor.GrantWire.serializer(), AndpCbor.GrantWire(g.raw, stranger.sign(SigningBytes.grant(g.raw)).bytes)),
        )
        assertFailsWith<BadSignatureException> { authorize(access(), forged) }

        // Trailing bytes and a short signature.
        assertFailsWith<AndpException> { Grant.decode(g.encode() + byteArrayOf(0)) }
        assertFailsWith<AndpException> {
            Grant.decode(AndpCbor.encode(AndpCbor.GrantWire.serializer(), AndpCbor.GrantWire(g.raw, ByteArray(63))))
        }
    }

    @Test
    fun meta() = runTest {
        val owner = testKey("owner")
        val grantee = testKey("grantee")
        val space = owner.key
        val g = Grant.issue(owner, GrantBody(space, Rights.WRITE, grantee.key, until = t0 + 100, issued = t0 - 100))
        val data = "entry".encodeToByteArray()
        val content = "content".encodeToByteArray()
        val ref = Ref(ID.of(content), content.size.toLong())

        val m = Meta.signData(grantee, space, data, t0, t0 + 10, Placement.SPACE, listOf(ref), grant = g)
        m.verify()
        m.checkData(data)
        assertFailsWith<AndpException> { m.checkData(content) }
        assertFailsWith<BadSignatureException> { m.copy(ts = t0 + 1).verifySig() }
        assertFailsWith<NotAuthorizedException> { m.copy(grant = null).authorize() }
        assertFailsWith<AndpException> { m.copy(until = t0).validate() }
        assertFailsWith<AndpException> { m.checkUntil(5) }
        m.checkUntil(10)
        assertTrue(m.isExpired(t0 + 11))
        assertFalse(m.isExpired(t0 + 10))
        assertFalse(m.copy(until = 0).isExpired(Long.MAX_VALUE))
        assertEquals(space.toString(), m.placementKey)
        assertFailsWith<AndpException> { m.copy(placement = Placement.OBJECT).validate() }

        assertFailsWith<AndpException> { Meta.signData(owner, space, data, t0, placement = Placement.SPACE, grant = g) }
        assertFailsWith<AndpException> { Meta.signData(grantee, space, data, t0, placement = Placement.OBJECT, refs = listOf(ref), grant = g) }
        assertFailsWith<AndpException> { Meta.signData(grantee, space, data, t0, until = t0, placement = Placement.SPACE, grant = g) }

        // Revocations: owner only, bytes are the raw grant hash.
        val rev = Meta.signData(owner, space, Meta.revocationData(g.hash), t0, placement = Placement.SPACE, revokes = g.hash)
        rev.verify()
        assertFailsWith<AndpException> { Meta.signData(owner, space, data, t0, placement = Placement.SPACE, revokes = g.hash) }
        assertFailsWith<AndpException> {
            Meta.signData(grantee, space, Meta.revocationData(g.hash), t0, placement = Placement.SPACE, revokes = g.hash, grant = g)
        }

        // Headers.
        val h = m.headers().toMap()
        val back = Meta.fromHeaders(space, m.id, m.size, HeaderSource.of(h))
        assertEquals(m, back)
        assertFailsWith<AndpException> { Meta.fromHeaders(space, m.id, m.size, HeaderSource.of(h - AndpHeaders.SIG)) }
        assertFailsWith<AndpException> { Meta.fromHeaders(space, m.id, m.size, HeaderSource.of(h + (AndpHeaders.PLACEMENT to "file"))) }
        assertFailsWith<AndpException> { Meta.fromHeaders(space, m.id, m.size, HeaderSource.of(h + (AndpHeaders.TS to "01"))) }
        assertFailsWith<AndpException> {
            Meta.fromHeaders(space, m.id, m.size) { name -> if (name == AndpHeaders.TS) listOf("1", "1") else h[name]?.let(::listOf).orEmpty() }
        }
        // Lower-case header names are found.
        Meta.fromHeaders(space, m.id, m.size, HeaderSource.of(h.mapKeys { it.key.lowercase() }))
        // Empty refs array is rejected; refs must be omitted instead.
        assertFailsWith<AndpException> { Meta.fromHeaders(space, m.id, m.size, HeaderSource.of(h + (AndpHeaders.REFS to B64.encode(byteArrayOf(0x80.toByte()))))) }
        assertFailsWith<AndpException> { Refs.decode(byteArrayOf(0x81.toByte(), 0x82.toByte(), 0x41, 0, 1)) }

        // Client write rules.
        val auth = Auth.sign(grantee, "PUT", AndpPaths.obj(space, m.id), t0)
        m.checkClientWrite(auth, t0 + 300)
        assertFailsWith<SkewException> { m.checkClientWrite(auth, t0 + 301) }
        assertFailsWith<NotAuthorizedException> { m.checkClientWrite(auth.copy(key = owner.key), t0) }

        // The listed form carries the same metadata.
        val listed = m.listed(7, data)
        assertEquals(m, listed.meta(space))
        assertEquals("entry", listed.inline()!!.decodeToString())
        assertEquals(null, m.listed(7, null).inline())
    }

    @Test
    fun auth() = runTest {
        val k = testKey("caller")
        val path = "/andp/v1/s/x"
        val a = Auth.sign(k, "GET", path, t0)
        val s = a.toString()
        assertEquals(a, Auth.parse(s))
        assertEquals(a, Auth.parse("andp " + s.removePrefix("ANDP ")))
        assertEquals(a, Auth.parse("ANDP sig=${a.sig}, other=1, ts=$t0, key=${a.key}"))
        a.verify("GET", path, t0)
        assertFailsWith<BadSignatureException> { a.verify("GET", "$path/", t0) }
        assertFailsWith<BadSignatureException> { a.verify("PUT", path, t0) }
        assertFailsWith<SkewException> { a.verify("GET", path, t0 - 301) }
        for (bad in listOf(
            "Bearer x", "ANDP", "ANDP key=${a.key}, ts=$t0", "ANDP key=${a.key}, ts=$t0, sig=${a.sig}, ts=$t0",
            "ANDP key=${a.key},ts=$t0,sig=${a.sig}", "ANDP key=${a.key}, ts=0$t0, sig=${a.sig}", "ANDP =x, key=${a.key}, ts=$t0, sig=${a.sig}",
            "ANDP key=${a.key}, ts=$t0, sig=${a.sig}, grant=AAAA",
        )) {
            assertFailsWith<AndpException>(bad) { Auth.parse(bad) }
        }
    }

    @Test
    fun tombstone() = runTest {
        val owner = testKey("owner")
        val stranger = testKey("stranger")
        val id = ID.of(ByteArray(1))
        val sig = Tombstone.signDelete(owner, owner.key, id, t0)
        val t = Tombstone(owner.key, id, t0, owner.key, null, sig)
        t.verify()
        assertFailsWith<BadSignatureException> { t.copy(ts = t0 + 1).verify() }
        val ts = Tombstone(owner.key, id, t0, stranger.key, null, Tombstone.signDelete(stranger, owner.key, id, t0))
        assertFailsWith<NotAuthorizedException> { ts.verify() }
        assertFailsWith<AndpException> { Tombstone.fromRequest(Auth.sign(owner, "DELETE", "/", t0), owner.key, id, HeaderSource.of(emptyMap())) }
    }

    @Test
    fun addresses() {
        for (ok in listOf("1.2.3.4", "255.255.255.255", "0.0.0.0", "::", "::1", "2001:db8::1", "1:2:3:4:5:6:7:8", "::ffff:1.2.3.4", "fe80::1%eth0", "1::")) {
            assertTrue(IpAddress.isValid(ok), ok)
        }
        for (bad in listOf("", "1.2.3", "1.2.3.4.5", "01.2.3.4", "256.1.1.1", "1.2.3.-4", ":::", "1:2:3:4:5:6:7:8:9", "1::2::3", ":1::", "1:2:3:4:5:6:7::8", "fe80::1%", "g::1", "12345::", "1:")) {
            assertFalse(IpAddress.isValid(bad), bad)
        }
        assertEquals("1.2.3.4" to "443", splitHostPort("1.2.3.4:443"))
        assertEquals("::1" to "443", splitHostPort("[::1]:443"))
        assertEquals(null, splitHostPort("::1:443"))
        assertEquals(null, splitHostPort("1.2.3.4"))
        assertTrue(isDnsName("relay.anynear.net"))
        for (bad in listOf("relay.anynear.net.", "-a.net", "a..net", "1.2.3.4", "a_b.net", "ä.net")) assertFalse(isDnsName(bad), bad)
        assertTrue(isDnsName("01.2.3.4"), "not an IP address for netip, so a name")
    }

    private suspend fun relay(i: Int, op: String, state: RelayState = RelayState.ACTIVE, addr: String = "192.0.2.$i:443") =
        Relay("s$i", addr, Hash.of(byteArrayOf(i.toByte())), "r$i.example.net", testKey("node-$i").key, op, state)

    @Test
    fun networkList() = runTest {
        val net = testKey("network")
        val next = testKey("network-next")
        val other = testKey("other")
        val id = networkId(net.key)
        val relays = listOf(relay(1, "a"), relay(2, "b"))
        val l1 = NetworkList(1, id, net.key, 1000, next.key, relays)
        val s1 = l1.sign(net)
        assertEquals(l1, NetworkList.verify(s1, id, net.key))
        assertFailsWith<ListSignerException> { NetworkList.verify(s1, id, next.key) }
        assertFailsWith<ListNetworkException> { NetworkList.verify(s1, networkId(next.key), net.key) }
        assertFailsWith<BadSignatureException> { s1.copy(sig = next.sign(SigningBytes.net(s1.list))).open() }
        assertFailsWith<ListNotNewerException> { l1.accept(s1) }

        val s2 = l1.copy(network = next.key, next = null, issued = 1001).sign(next)
        val l2 = l1.accept(s2)
        assertFailsWith<ListSignerException> { l2.accept(l1.copy(issued = 1002).sign(net)) }
        assertFailsWith<ListSignerException> { l1.accept(l1.copy(network = other.key, issued = 1002).sign(other)) }
        assertFailsWith<ListNetworkException> { l1.accept(l1.copy(id = networkId(other.key), issued = 1002).sign(net)) }
        assertFailsWith<ListNotNewerException> { l2.accept(l2.copy(issued = 1001).sign(next)) }

        // Invalid lists are rejected as a whole.
        suspend fun rejects(l: NetworkList) = assertFailsWith<AndpException> { l.sign(net) }
        rejects(l1.copy(v = 2))
        rejects(l1.copy(issued = 0))
        rejects(l1.copy(relays = relays + relays[0]))
        rejects(l1.copy(relays = listOf(relay(1, "a", addr = "relay.example.net:443"))))
        rejects(l1.copy(relays = listOf(relay(1, "a", addr = "192.0.2.1"))))
        rejects(l1.copy(relays = listOf(relay(1, "a", addr = "192.0.2.1:0"))))
        rejects(l1.copy(relays = listOf(relay(1, "a", addr = "192.0.2.1:0443"))))
        rejects(l1.copy(relays = listOf(relay(1, "a", addr = "192.0.2.1:65536"))))
        rejects(l1.copy(relays = listOf(relay(1, ""))))
        rejects(l1.copy(relays = listOf(relay(1, "a").copy(host = "bad_host"))))
        rejects(l1.copy(relays = listOf(relay(1, "a").copy(key = Hash(ByteArray(32))))))
        l1.copy(relays = listOf(relay(1, "a", addr = "[2001:db8::1]:443"), relay(2, "b").copy(host = "", site = ""))).sign(net)

        // Unknown version rejects the list; an unknown state keeps the relay but not as active (§5.8, §13);
        // unknown fields are ignored.
        suspend fun signedText(text: String) = SignedList(text, net.sign(SigningBytes.net(text)))
        val text = s1.list
        val retired = signedText(text.replaceFirst("\"active\"", "\"retired\"")).open()
        assertEquals(RelayState("retired"), retired.relays[0].state)
        assertFalse(retired.active().any { it.node == relays[0].node })
        // An invalid relay entry is skipped, the rest counts.
        val skipped = signedText(text.replaceFirst(relays[0].addr, "relay.example.net:443")).open()
        assertEquals(relays.drop(1), skipped.relays)
        assertFailsWith<AndpException> { signedText(text.replace("\"v\":1", "\"v\":1.5")).open() }
        assertFailsWith<AndpException> { signedText(text.replace(",\"id\":\"$id\"", "")).open() }
        assertEquals(l1, signedText(text.replace("\"v\":1", "\"v\":1,\"future\":{\"x\":[1]}")).open())

        // Holders are followed only when node and TLS key are in the list.
        assertTrue(l1.knows(relays[0]))
        assertFalse(l1.knows(relays[0].copy(key = Hash.of(ByteArray(0)))))
        assertFalse(l1.knows(relay(3, "c")))
        assertEquals(relays, l1.active())
    }

    @Test
    fun placementWithFewOperators() = runTest {
        val relays = listOf(relay(1, "a"), relay(2, "a"), relay(3, "b"), relay(4, "b", RelayState.DRAINING), relay(5, "c", RelayState.CANDIDATE))
        val c = Placements.place("k", relays)
        assertEquals(2, c.chosen.size)
        assertEquals(setOf("a", "b"), c.chosen.map { it.op }.toSet())
        assertEquals(1, c.spare.size)
        // All chosen down and no spare left: fewer targets.
        assertEquals(listOf(c.spare[0]), c.targets { false || it == c.spare[0].node })
        assertEquals(emptyList(), c.targets { false })
    }
}
