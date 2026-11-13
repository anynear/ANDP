package app.anynear.andp.web

import app.anynear.andp.ID
import app.anynear.andp.Placement
import app.anynear.andp.setup
import app.anynear.andp.vectors
import kotlinx.coroutines.await
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AndpWebTest {
    private val v = vectors()

    @Test
    fun formats() = runTest {
        val owner = AndpWebSigner.fromSeed(app.anynear.andp.B64.decode(v.keys.first { it.label == "owner" }.seed)).await()
        assertEquals(v.keys.first { it.label == "owner" }.public, owner.key)
        val g = v.grants.first { it.name == "write-grantee" }
        assertEquals(g.grant, AndpWeb.issueGrant(owner, g.rights.toInt(), g.grantee, g.scope, g.until.toDouble(), g.issued.toDouble()).await())
        assertEquals(g.hash, AndpWeb.grantHash(g.grant))
        assertEquals(v.watch[0].watchId, AndpWeb.watchId(v.watch[0].tokenHex))
        assertEquals(ID.of(byteArrayOf(1)).toString(), AndpWeb.idOf(byteArrayOf(1)))

        val netKey = v.keys.first { it.label == "network" }.public
        val l1 = AndpWeb.verifyNetworkList(Json.encodeToString(app.anynear.andp.SignedList.serializer(), v.network[0].signed), AndpWeb.networkId(netKey), netKey).await()
        val l2 = AndpWeb.acceptNetworkList(l1, Json.encodeToString(app.anynear.andp.SignedList.serializer(), v.network[1].signed)).await()
        assertEquals(v.network[1].networkId, Json.parseToJsonElement(l2).jsonObject["id"]!!.jsonPrimitive.content)
        val e = assertFailsWith<AndpWebError> { AndpWeb.acceptNetworkList(l2, Json.encodeToString(app.anynear.andp.SignedList.serializer(), v.network[1].signed)).await() }
        assertEquals(0, e.status)

        val c = v.placement.cases[0]
        val t = Json.parseToJsonElement(AndpWeb.targets(c.key, l1, c.targets[0].down.toTypedArray())).jsonArray
        assertEquals(c.targets[0].targets, t.map { it.jsonObject["node"]!!.jsonPrimitive.content })
        assertFailsWith<AndpWebError> { AndpWeb.networkId("x") }
    }

    @Test
    fun client() = runTest {
        val env = setup()
        val web = AndpWebClient("https://unused.example.net").apply { client = env.client }
        val grantee = AndpWebSigner(env.grantee.key)
        val grant = env.grantee.grant.toString()
        val space = env.space.toString()
        assertTrue(web.info().await().contains("\"watch\""))
        val data = "web".encodeToByteArray()
        val id = web.put(grantee, grant, space, data, 0.0, Placement.SPACE.wire, "", false, "").await()
        val obj = web.get(grantee, grant, space, id, false).await()
        assertContentEquals(data, obj.data)
        assertEquals("space", Json.parseToJsonElement(obj.metaJson).jsonObject["ANDP-Placement"]!!.jsonPrimitive.content)
        val page = Json.parseToJsonElement(web.list(grantee, grant, space, "", 0, 0).await()).jsonObject
        assertEquals(id, page["objects"]!!.jsonArray[0].jsonObject["id"]!!.jsonPrimitive.content)
        assertEquals("{\"$id\":\"here\"}", web.status(grantee, grant, space, arrayOf(id)).await())
        val e = assertFailsWith<AndpWebError> { web.get(null, "", space, id, false).await() }
        assertEquals(401, e.status)
        val nf = assertFailsWith<AndpWebError> { web.get(null, "", space, ID.of(ByteArray(0)).toString(), false).await() }
        assertEquals(404, nf.status)
        assertEquals("not_found", nf.code)
        assertTrue(nf.holdersJson!!.contains("b-1"))
        assertFailsWith<AndpWebError> { AndpWebClient.forRelay("{}") }
    }
}
