package app.anynear.andp

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** Path of vectors/andp-v1.json (environment variable ANDP_VECTORS) and its text, per platform. */
expect fun readVectorsText(): String

/** False where Ed25519 signing adds randomness (Apple CryptoKit): fresh signatures verify but differ from the vectors. */
expect val signaturesAreDeterministic: Boolean

@Serializable
class VKey(val label: String, val seed: String, val public: String)

@Serializable
class VB64Valid(val text: String, val hex: String)

@Serializable
class VB64(val valid: List<VB64Valid>, val invalid: List<String>)

@Serializable
class VGrant(
    val name: String,
    val space: String,
    val rights: Long,
    val grantee: String = "",
    val scope: String = "",
    val until: Long,
    val issued: Long,
    @SerialName("body_cbor_hex") val bodyHex: String,
    @SerialName("signing_bytes") val signingBytes: String,
    val sig: String,
    @SerialName("grant_cbor_hex") val grantHex: String,
    val grant: String,
    val hash: String,
)

@Serializable
class VInvalidGrant(val name: String, val grant: String, val reason: String)

@Serializable
class VRefs(val name: String, val refs: List<Ref>, @SerialName("cbor_hex") val cborHex: String, val header: String, val digest: String)

@Serializable
class VObject(
    val name: String,
    @SerialName("data_hex") val dataHex: String,
    val space: String,
    val id: String,
    val size: Long,
    val writer: String,
    @SerialName("signing_bytes") val signingBytes: String,
    val sig: String,
    val path: String,
    val headers: Map<String, String>,
)

@Serializable
class VAuth(
    val name: String,
    val method: String,
    val path: String,
    val ts: Long,
    val key: String,
    @SerialName("signing_bytes") val signingBytes: String,
    val sig: String,
    val header: String,
)

@Serializable
class VDelete(
    val name: String,
    val authorization: String,
    @SerialName("signing_bytes") val signingBytes: String,
    @SerialName("del_sig") val delSig: String,
    val tombstone: Tombstone,
)

@Serializable
class VSigning(val name: String, val domain: String, val signer: String = "", @SerialName("signing_bytes") val signingBytes: String, val sig: String = "")

@Serializable
class VNetwork(val name: String, val signed: SignedList, @SerialName("network_id") val networkId: String)

@Serializable
class VLenient(val name: String, val signed: SignedList, val relays: List<String>, val active: List<String>)

@Serializable
class VRadio(val name: String, val signed: SignedList, val accept: Boolean, val issued: Long = 0)

@Serializable
class VRank(val node: String, @SerialName("rank_hex") val rank: String)

@Serializable
class VTargets(val down: List<String>, val targets: List<String>)

@Serializable
class VPlace(
    val key: String,
    @SerialName("rank_input_node_0") val input: String,
    @SerialName("order_active") val order: List<VRank>,
    val chosen: List<String>,
    val spare: List<String>,
    val targets: List<VTargets>,
)

@Serializable
class VPlacement(val relays: List<Relay>, val cases: List<VPlace>)

@Serializable
class VCard(val name: String, val signed: SignedCard, val open: Boolean, val accept: Boolean)

@Serializable
class VScore(val node: String, val score: String)

@Serializable
class VLog2(val x: String, @SerialName("log2_q32") val log: String)

@Serializable
class VWeighted(val key: String, val weights: Map<String, Int>, val order: List<VScore>, val chosen: List<String>, val spare: List<String>)

@Serializable
class VDamage(val name: String, val cards: List<SignedCard>, val node: String, val damaged: Boolean, val read: List<String>)

@Serializable
class VView(
    @SerialName("network_id") val networkId: String,
    val damage: List<VDamage>,
    val cards: List<VCard>,
    val weighted: List<VWeighted>,
    @SerialName("log2_q32") val log2: List<VLog2>,
)

@Serializable
class VWatch(@SerialName("token_hex") val tokenHex: String, @SerialName("watch_id") val watchId: String)

@Serializable
class VNotBeforeWrite(
    val name: String,
    val placement: String,
    val revocation: Boolean = false,
    val ts: Long,
    val until: Long,
    val header: String,
    val accept: Boolean,
)

@Serializable
class VHeld(@SerialName("data_hex") val dataHex: String, val path: String, val headers: Map<String, String>, val listed: ListedObject)

@Serializable
class VNotBefore(@SerialName("max_until") val maxUntil: Long, val writes: List<VNotBeforeWrite>, val held: VHeld)

@Serializable
class VectorFile(
    val ts: Long,
    val keys: List<VKey>,
    val b64u: VB64,
    val grants: List<VGrant>,
    @SerialName("invalid_grants") val invalidGrants: List<VInvalidGrant>,
    val refs: List<VRefs>,
    val objects: List<VObject>,
    val authorization: List<VAuth>,
    val delete: List<VDelete>,
    val signing: List<VSigning>,
    val network: List<VNetwork>,
    @SerialName("network_lenient") val lenient: List<VLenient>,
    val radio: List<VRadio>,
    val placement: VPlacement,
    val view: VView,
    @SerialName("watch_id") val watch: List<VWatch>,
    @SerialName("not_before") val notBefore: VNotBefore,
)

internal val vectorJson = Json { ignoreUnknownKeys = true }

/** The parsed vector file. */
internal fun vectors(): VectorFile = vectorJson.decodeFromString(VectorFile.serializer(), readVectorsText())

internal fun ByteArray.hex(): String = joinToString("") { ((it.toInt() and 0xff) or 0x100).toString(16).substring(1) }

/**
 * Checks every vector of vectors/andp-v1.json (spec §15) through the parsing and verifying API, as
 * go/andp/vectors_test.go does, and additionally that this implementation produces the same bytes and
 * signatures from the same seeds. The file is only read.
 */
class VectorsTest {
    private val v: VectorFile = vectors()
    private val now get() = v.ts

    private suspend fun keys(): Map<String, SigningKey> = v.keys.associate { k ->
        val seed = B64.decode(k.seed)
        assertEquals(Sha256.digest("ANDP vectors: ${k.label}".encodeToByteArray()).hex(), seed.hex(), "seed of ${k.label}")
        val sk = SigningKey.fromSeed(seed)
        assertEquals(k.public, sk.key.toString(), "public key of ${k.label}")
        k.label to sk
    }

    private fun pub(label: String): Key = Key.parse(v.keys.first { it.label == label }.public)

    @Test
    fun seedsAndPublicKeys() = runTest { assertEquals(11, keys().size) }

    @Test
    fun b64u() {
        for (b in v.b64u.valid) assertEquals(b.hex, B64.decode(b.text).hex(), "b64u ${b.text}")
        for (s in v.b64u.invalid) assertFailsWith<AndpException>("b64u \"$s\" accepted") { B64.decode(s) }
        for (b in v.b64u.valid) assertEquals(b.text, B64.encode(hexToBytes(b.hex)))
    }

    @Test
    fun grants() = runTest {
        val owner = keys().getValue("owner")
        for (vg in v.grants) {
            val g = Grant.parse(vg.grant)
            g.verifySig()
            assertEquals(vg.bodyHex, g.raw.hex(), vg.name)
            assertEquals(vg.grantHex, g.encode().hex(), vg.name)
            assertEquals(vg.hash, g.hash.toString(), vg.name)
            assertEquals(vg.signingBytes, SigningBytes.grant(g.raw).decodeToString(), vg.name)
            assertEquals(vg.sig, g.sig.toString(), vg.name)
            assertEquals(vg.rights, g.body.rights.bits, vg.name)
            assertEquals(vg.until, g.body.until, vg.name)
            assertEquals(vg.issued, g.body.issued, vg.name)
            assertEquals(vg.space, g.body.space.toString(), vg.name)
            assertEquals(vg.grantee, g.body.grantee?.toString() ?: "", vg.name)
            assertEquals(vg.scope, g.body.scope?.toString() ?: "", vg.name)
            assertEquals(vg.grant, g.toString(), vg.name)
            // Issuing the same body with the same key gives the same bytes (Ed25519 is deterministic).
            val again = Grant.issue(owner, g.body)
            if (signaturesAreDeterministic) assertEquals(vg.grant, again.toString(), vg.name) else again.verifySig()
            assertEquals(vg.bodyHex, g.body.encode().hex(), vg.name)
        }
    }

    @Test
    fun invalidGrants() = runTest {
        for (ig in v.invalidGrants) {
            when (ig.reason) {
                "decode" -> assertFailsWith<AndpException>("invalid grant \"${ig.name}\" decoded") { Grant.parse(ig.grant) }
                "signature" -> {
                    val g = Grant.parse(ig.grant)
                    assertFailsWith<BadSignatureException>(ig.name) { g.verifySig() }
                }
                else -> fail("unknown reason ${ig.reason}")
            }
        }
    }

    @Test
    fun refs() {
        for (r in v.refs) {
            assertEquals(r.digest, Refs.digest(r.refs), r.name)
            assertEquals(r.cborHex, Refs.encode(r.refs)?.hex() ?: "", r.name)
            if (r.header.isEmpty()) continue
            val raw = B64.decode(r.header)
            assertEquals(r.cborHex, raw.hex(), r.name)
            assertEquals(r.refs, Refs.decode(raw), r.name)
        }
    }

    @Test
    fun objects() = runTest {
        val keys = keys()
        val signers = keys.values.associateBy { it.key }
        for (o in v.objects) {
            val data = hexToBytes(o.dataHex)
            val space = Key.parse(o.space)
            val id = ID.of(data)
            assertEquals(o.id, id.toString(), o.name)
            assertEquals(o.path, AndpPaths.obj(space, id), o.name)
            val h = HeaderSource.of(o.headers)
            val m = Meta.fromHeaders(space, id, data.size.toLong(), h)
            assertEquals(o.signingBytes, m.signingBytes().decodeToString(), o.name)
            assertEquals(o.sig, m.sig.toString(), o.name)
            assertEquals(o.writer, m.writer.toString(), o.name)
            m.checkData(data)
            m.verify()
            // The headers this implementation writes are the same.
            assertEquals(o.headers - AndpHeaders.AUTHORIZATION, m.headers().toMap(), o.name)
            // Signing the same metadata again gives the same signature.
            val again = Meta.signData(signers.getValue(m.writer), space, data, m.ts, m.until, m.placement, m.refs, m.revokes, m.grant)
            if (signaturesAreDeterministic) assertEquals(m, again, o.name) else again.verify()
            o.headers[AndpHeaders.AUTHORIZATION]?.let {
                val a = Auth.parse(it)
                a.verify("PUT", o.path, now)
                m.checkClientWrite(a, now)
            }
        }
    }

    @Test
    fun authorization() = runTest {
        val signers = keys().values.associateBy { it.key }
        for (va in v.authorization) {
            val a = Auth.parse(va.header)
            assertEquals(va.key, a.key.toString(), va.name)
            assertEquals(va.ts, a.ts, va.name)
            assertEquals(va.sig, a.sig.toString(), va.name)
            assertEquals(va.signingBytes, SigningBytes.request(va.method, va.path, va.ts).decodeToString(), va.name)
            a.verify(va.method, va.path, now)
            assertFailsWith<SkewException>(va.name) { a.verify(va.method, va.path, now + Andp.MAX_SKEW_SECONDS + 1) }
            assertEquals(va.header, a.toString(), va.name)
            val fresh = Auth.sign(signers.getValue(a.key), va.method, va.path, va.ts, a.grant)
            if (signaturesAreDeterministic) assertEquals(va.header, fresh.toString(), va.name) else fresh.verify(va.method, va.path, now)
        }
        Auth.parse(v.authorization[0].header).authorize(pub("owner"), Rights.LIST, null, now)
    }

    @Test
    fun delete() = runTest {
        for (d in v.delete) {
            val a = Auth.parse(d.authorization)
            a.verify("DELETE", AndpPaths.obj(d.tombstone.space, d.tombstone.id), now)
            val ts = Tombstone.fromRequest(a, d.tombstone.space, d.tombstone.id, HeaderSource.of(mapOf(AndpHeaders.DEL_SIG to d.delSig)))
            ts.verify()
            assertEquals(d.signingBytes, SigningBytes.delete(ts.space, ts.id, ts.ts).decodeToString(), d.name)
            assertEquals(d.tombstone.grant.toString(), ts.grant.toString(), d.name)
            assertEquals(d.tombstone, ts, d.name)
            d.tombstone.verify()
        }
    }

    @Test
    fun network() = runTest {
        var list: NetworkList? = null
        for ((i, n) in v.network.withIndex()) {
            list = if (i == 0) {
                val id = Hash.parse(n.networkId)
                assertEquals(networkId(pub("network")), id, "network id is the hash of the first key")
                NetworkList.verify(n.signed, id, pub("network"))
            } else {
                list!!.accept(n.signed)
            }
            assertEquals(n.networkId, list.id.toString(), n.name)
        }
        assertNotNull(list)
    }

    @Test
    fun networkLenient() = runTest {
        val id = networkId(pub("network"))
        for (c in v.lenient) {
            val l = NetworkList.verify(c.signed, id, pub("network"))
            assertEquals(c.relays, l.relays.map { it.node.toString() }, c.name)
            assertEquals(c.active, l.active().map { it.node.toString() }, c.name)
        }
    }

    @Test
    fun radio() = runTest {
        val first = NetworkList.verify(v.network[0].signed, networkId(pub("network")), pub("network"))
        for (c in v.radio) {
            val h = runCatching { first.acceptRadio(null, c.signed) }
            assertEquals(c.accept, h.isSuccess, c.name)
            if (c.accept) assertEquals(c.issued, h.getOrThrow().issued, c.name)
        }
    }

    @Test
    fun signing() = runTest {
        for (s in v.signing) {
            assertTrue(pub(s.signer).verify(s.signingBytes.encodeToByteArray(), Sig.parse(s.sig)), s.name)
        }
        val receipt = v.signing.first { it.domain == Andp.DOMAIN_RECEIPT }
        val obj = v.objects[0]
        val rc = Receipt(pub("node-0"), Sig.parse(receipt.sig))
        val content = Meta.fromHeaders(Key.parse(obj.space), ID.parse(obj.id), obj.size, HeaderSource.of(obj.headers))
        assertEquals(receipt.signingBytes, SigningBytes.receipt(content.space, content.id, content.until).decodeToString())
        rc.verify(content.space, content.id, content.until)
        assertFailsWith<BadSignatureException> { rc.verify(content.space, content.id, content.until + 1) }
        val net = v.signing.first { it.domain == Andp.DOMAIN_NET }
        assertEquals(net.signingBytes, SigningBytes.net(v.network[0].signed.list).decodeToString())
    }

    @Test
    fun placement() {
        val rev = v.placement.relays.reversed()
        for (c in v.placement.cases) {
            // Reversed input must not change the result.
            val ch = Placements.place(c.key, rev)
            assertEquals(c.chosen, ch.chosen.map { it.node.toString() }, c.key)
            assertEquals(c.spare, ch.spare.map { it.node.toString() }, c.key)
            val order = Placements.order(c.key, NetworkList(1, Hash(ByteArray(32)), Key(ByteArray(32)), 1, relays = rev).active())
            assertEquals(c.order.size, order.size, c.key)
            for ((i, o) in c.order.withIndex()) {
                assertEquals(o.node, order[i].node.toString(), "${c.key} order $i")
                assertEquals(o.rank, Placements.rank(c.key, order[i].node).bytes.hex(), "${c.key} order $i")
            }
            assertEquals(c.input, SigningBytes.place(c.key, v.placement.relays[0].node).decodeToString())
            for (tg in c.targets) {
                val got = ch.targets { it.toString() !in tg.down }
                assertEquals(tg.targets, got.map { it.node.toString() }, "${c.key} targets with ${tg.down} down")
            }
            assertTrue(ch.isChosen(ch.chosen[0].node))
            assertFalse(ch.isChosen(ch.spare[0].node))
            assertEquals(2, ch.chosenRank(ch.chosen[2].node))
        }
    }

    @Test
    fun view() = runTest {
        val list = NetworkList(1, Hash.parse(v.view.networkId), Key(ByteArray(32)), 1, relays = v.placement.relays)
        for (c in v.view.cards) {
            val opened = try {
                c.signed.open()
                true
            } catch (e: AndpException) {
                false
            }
            assertEquals(c.open, opened, "card ${c.name}: open")
            assertEquals(c.accept, View().offer(c.signed, list) != null, "card ${c.name}: accept")
        }
        for (l in v.view.log2) {
            assertEquals(l.log, Placements.log2Q32(l.x.toULong()).toString(), "log2 of ${l.x}")
        }
        for (d in v.view.damage) {
            val view = View()
            for (sc in d.cards) assertNotNull(view.offer(sc, list), "damage ${d.name}")
            assertEquals(d.damaged, view.damaged(list, Key.parse(d.node)), "damage ${d.name}")
            assertEquals(d.read, view.members(list, Role.READ, false).map { it.relay.node.toString() }, "damage ${d.name} read")
        }
        for (w in v.view.weighted) {
            val members = v.placement.relays.reversed().mapNotNull { r -> w.weights[r.node.toString()]?.let { Member(r, it) } }
            val ch = Placements.placeWeighted(w.key, members)
            assertEquals(w.chosen, ch.chosen.map { it.node.toString() }, "${w.key} ${w.weights}")
            assertEquals(w.spare, ch.spare.map { it.node.toString() }, "${w.key} ${w.weights}")
            for (o in w.order) {
                assertEquals(o.score, Placements.weightedScore(w.key, Key.parse(o.node)).toString(), "${w.key} score of ${o.node}")
            }
        }
    }

    @Test
    fun watch() {
        for (w in v.watch) {
            assertEquals(w.watchId, watchId(hexToBytes(w.tokenHex)))
            assertEquals(w.watchId, watchIdForHexToken(w.tokenHex))
        }
    }

    @Test
    fun notBefore() = runTest {
        val nb = v.notBefore
        val space = Key.parse(v.objects[0].space)
        for (w in nb.writes) {
            val revokes = if (w.revocation) Hash.of(ByteArray(0)) else null
            val data = revokes?.bytes ?: ByteArray(0)
            val ok = try {
                val notBefore = AndpInt.parse(w.header)
                Meta(space, ID.of(data), data.size.toLong(), w.ts, w.until, Placement.parse(w.placement), revokes = revokes, writer = space,
                    sig = Sig.parse(v.objects[0].sig)).checkNotBefore(notBefore, nb.maxUntil)
                true
            } catch (e: AndpException) {
                false
            }
            assertEquals(w.accept, ok, "not_before ${w.name}")
        }
        val data = hexToBytes(nb.held.dataHex)
        val m = Meta.fromHeaders(space, ID.of(data), data.size.toLong(), HeaderSource.of(nb.held.headers))
        m.checkData(data)
        m.verify()
        assertEquals(nb.held.path, AndpPaths.obj(space, m.id))
        val notBefore = AndpInt.parse(nb.held.headers.getValue(AndpHeaders.NOT_BEFORE))
        m.checkNotBefore(notBefore, nb.maxUntil)
        // The list item verifies like any other: not_before is not signed (§19 rule 1).
        assertEquals(notBefore, nb.held.listed.notBefore)
        val lm = nb.held.listed.meta(space)
        lm.verify()
        assertEquals(m, lm)
        assertTrue(data.contentEquals(nb.held.listed.inline()))
    }

    @Test
    fun relaysValidate() {
        for (r in v.placement.relays) r.validate()
        assertNull(v.placement.relays.firstOrNull { it.host.isEmpty() })
    }
}
