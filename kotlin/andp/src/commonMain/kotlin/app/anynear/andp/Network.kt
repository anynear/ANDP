package app.anynear.andp

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** JSON of the API (§1): unknown fields are ignored, absent optional fields are omitted. */
internal val AndpJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    encodeDefaults = false
}

/**
 * One entry of the network list (§5.8). [addr] is `IP:port` for apps (pinned TLS), [key] the SHA-256
 * of its TLS SubjectPublicKeyInfo, [host] an optional DNS name for browsers (Web PKI), [op] the
 * operator (failure domain for placement).
 */
@Serializable
data class Relay(
    val site: String = "",
    val addr: String,
    val key: Hash,
    val host: String = "",
    val node: Key,
    val op: String,
    val state: RelayState,
) {
    /** Checks the fields of §5.8. */
    fun validate() {
        val (ip, port) = splitHostPort(addr) ?: throw AndpException("andp: relay addr \"$addr\" is not host:port")
        if (!IpAddress.isValid(ip)) throw AndpException("andp: relay addr \"$addr\" is not an IP address")
        val p = port.toIntOrNull()
        if (p == null || p < 1 || p > 65535 || p.toString() != port) throw AndpException("andp: relay addr \"$addr\" has an invalid port")
        if (host.isNotEmpty() && !isDnsName(host)) throw AndpException("andp: relay host \"$host\" is not a DNS name")
        if (key.isZero || node.isZero) throw AndpException("andp: relay key or node missing")
        if (op.isEmpty()) throw AndpException("andp: relay op missing")
    }
}

/** The content of the signed list text (§5.8). [issued] is Unix milliseconds. */
@Serializable
data class NetworkList(
    val v: Int,
    /** The network ID; it never changes. */
    val id: Hash,
    /** The key that signed this list (the current network key). */
    val network: Key,
    val issued: Long,
    /** The announced next network key. */
    val next: Key? = null,
    val relays: List<Relay> = emptyList(),
) {
    /**
     * Checks version, keys and relays strictly, as a signer must ([sign]); node keys must be unique. Receivers are
     * lenient instead ([SignedList.open]): invalid relay entries are skipped there.
     */
    fun validate() {
        validateHead()
        val seen = mutableSetOf<Key>()
        for (r in relays) {
            r.validate()
            if (!seen.add(r.node)) throw AndpException("andp: node ${r.node} listed twice")
        }
    }

    internal fun validateHead() {
        if (v != Andp.LIST_VERSION) throw AndpException("andp: unknown network list version $v")
        if (network.isZero) throw AndpException("andp: network list without network key")
        if (id.isZero) throw AndpException("andp: network list without id")
        if (issued <= 0) throw AndpException("andp: network list without issued")
    }

    /**
     * Checks a radio list (§5.9) against this network list and the receiver's current radio list [current] (null
     * if none): same network ID, signed by [network] or the announced [next], issued strictly greater.
     */
    suspend fun acceptRadio(current: RadioHead?, signed: SignedList): RadioHead {
        val h = RadioHead.parse(signed.list)
        if (h.id != id) throw ListNetworkException()
        if (h.network != network && (next == null || h.network != next)) throw ListSignerException()
        if (!h.network.verify(SigningBytes.radio(signed.list), signed.sig)) throw BadSignatureException("radio list")
        if (current != null && h.issued <= current.issued) throw RadioNotNewerException()
        return h
    }

    /** The relay with node key [node], in any state. */
    fun relay(node: Key): Relay? = relays.firstOrNull { it.node == node }

    /** The active relays in list order. */
    fun active(): List<Relay> = relays.filter { it.state == RelayState.ACTIVE }

    /** Whether [holder] has the node and TLS key of a relay of this list (§9). */
    fun knows(holder: Relay): Boolean = relay(holder.node)?.key == holder.key

    /**
     * Checks a list offered after this one: same id, signed by this list's network key or, if
     * announced, by [next], and issued strictly greater (§5.8). The result replaces this list.
     */
    suspend fun accept(signed: SignedList): NetworkList {
        val l = signed.open()
        if (l.id != id) throw ListNetworkException()
        if (l.network != network && (next == null || l.network != next)) throw ListSignerException()
        if (l.issued <= issued) throw ListNotNewerException()
        return l
    }

    /**
     * Encodes the list as JSON text and signs it with the network key, which must be [network]. For
     * the first list of a network use `id = networkId(network)`; later lists keep that id.
     */
    suspend fun sign(networkKey: SigningKey): SignedList {
        if (networkKey.key != network) throw AndpException("andp: network list must be signed by its network key")
        validate()
        val text = AndpJson.encodeToString(serializer(), this)
        return SignedList(text, networkKey.sign(SigningBytes.net(text)))
    }

    companion object {
        /** Opens a list on first contact: the network ID and the current key come from configuration. */
        suspend fun verify(signed: SignedList, id: Hash, key: Key): NetworkList {
            val l = signed.open()
            if (l.id != id) throw ListNetworkException()
            if (l.network != key) throw ListSignerException()
            return l
        }
    }
}

/** The body of GET and POST /andp/v1/net: the exact list text and the network key's signature over it. */
@Serializable
data class SignedList(val list: String, val sig: Sig) {
    /**
     * Parses and validates the list and checks the signature by the list's own network key. It does
     * not decide whether that key is trusted; use [NetworkList.verify] or [NetworkList.accept].
     */
    suspend fun open(): NetworkList {
        val l = parseList(list)
        if (!l.network.verify(SigningBytes.net(list), sig)) throw BadSignatureException("network list")
        return l
    }
}

/**
 * Reads a received list text (§5.8): the head must be valid, a repeated node key rejects the list, relay entries that
 * do not parse or validate are skipped.
 */
private fun parseList(text: String): NetworkList {
    fun bad(e: Exception): Nothing = throw AndpException("andp: network list: ${e.message}", e)
    val obj = try {
        AndpJson.parseToJsonElement(text).jsonObject
    } catch (e: SerializationException) {
        bad(e)
    } catch (e: IllegalArgumentException) {
        bad(e)
    }
    val head = try {
        AndpJson.decodeFromJsonElement(NetworkList.serializer(), JsonObject(obj - "relays"))
    } catch (e: SerializationException) {
        bad(e)
    } catch (e: IllegalArgumentException) {
        bad(e)
    }
    head.validateHead()
    val seen = mutableSetOf<String>()
    val relays = mutableListOf<Relay>()
    val entries = (obj["relays"] as? JsonArray) ?: JsonArray(emptyList())
    for (e in entries) {
        val node = ((e as? JsonObject)?.get("node") as? JsonPrimitive)?.takeIf { it.isString }?.content
        if (!node.isNullOrEmpty() && !seen.add(node)) throw AndpException("andp: node $node listed twice")
        val r = try {
            AndpJson.decodeFromJsonElement(Relay.serializer(), e).also { it.validate() }
        } catch (_: SerializationException) {
            continue
        } catch (_: IllegalArgumentException) {
            continue
        } catch (_: AndpException) {
            continue
        }
        relays += r
    }
    return head.copy(relays = relays)
}

/** The head of a radio list that ANDP checks (§5.9); all other fields belong to ANMP. [issued] is Unix milliseconds. */
@Serializable
data class RadioHead(val v: Int, val id: Hash, val network: Key, val issued: Long) {
    companion object {
        fun parse(text: String): RadioHead {
            val h = try {
                AndpJson.decodeFromString(serializer(), text)
            } catch (e: SerializationException) {
                throw AndpException("andp: radio list: ${e.message}", e)
            } catch (e: IllegalArgumentException) {
                throw AndpException("andp: radio list: ${e.message}", e)
            }
            if (h.v != Andp.RADIO_LIST_VERSION) throw AndpException("andp: unknown radio list version ${h.v}")
            if (h.id.isZero || h.network.isZero || h.issued <= 0) throw AndpException("andp: radio list without id, network or issued")
            return h
        }

        /** Signs [list] with the network key; its head must name that key as `network`. */
        suspend fun sign(networkKey: SigningKey, list: String): SignedList {
            val h = parse(list)
            if (networkKey.key != h.network) throw AndpException("andp: radio list must be signed by its network key")
            return SignedList(list, networkKey.sign(SigningBytes.radio(list)))
        }
    }
}

/** Like Go's net.SplitHostPort: `host:port` or `[host]:port`; `null` when malformed. */
internal fun splitHostPort(s: String): Pair<String, String>? {
    if (s.startsWith("[")) {
        val end = s.indexOf(']')
        if (end < 0 || end + 1 >= s.length || s[end + 1] != ':') return null
        val host = s.substring(1, end)
        val port = s.substring(end + 2)
        if (port.contains(':') || port.contains('[') || port.contains(']')) return null
        return host to port
    }
    val i = s.lastIndexOf(':')
    if (i < 0) return null
    val host = s.substring(0, i)
    if (host.contains(':') || host.contains('[') || host.contains(']')) return null
    val port = s.substring(i + 1)
    if (port.contains('[') || port.contains(']')) return null
    return host to port
}

internal fun isDnsName(h: String): Boolean {
    if (h.length > 253 || h.endsWith(".") || IpAddress.isValid(h)) return false
    return h.split('.').all { label ->
        label.isNotEmpty() && label.length <= 63 && label[0] != '-' && label.last() != '-' &&
            label.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }
    }
}

/** IP address syntax as accepted by Go's netip.ParseAddr (IPv4 without leading zeros, IPv6 with optional zone). */
internal object IpAddress {
    fun isValid(s: String): Boolean = if (s.contains(':')) isV6(s) else isV4(s)

    fun isV4(s: String): Boolean {
        val parts = s.split('.')
        return parts.size == 4 && parts.all { p ->
            p.isNotEmpty() && p.length <= 3 && p.all { it in '0'..'9' } && (p.length == 1 || p[0] != '0') && p.toInt() <= 255
        }
    }

    fun isV6(input: String): Boolean {
        var s = input
        val zone = s.indexOf('%')
        if (zone >= 0) {
            if (zone == s.length - 1) return false
            s = s.substring(0, zone)
        }
        var groups = 0
        var ellipsis = false
        var i = 0
        if (s.startsWith("::")) {
            ellipsis = true
            i = 2
            if (s.length == 2) return true
        } else if (s.startsWith(":")) {
            return false
        }
        while (i < s.length) {
            // An embedded IPv4 address ends the address and counts as two groups.
            val nextColon = s.indexOf(':', i).let { if (it < 0) s.length else it }
            val part = s.substring(i, nextColon)
            if (part.contains('.')) {
                if (nextColon != s.length || !isV4(part)) return false
                groups += 2
                break
            }
            if (part.isEmpty() || part.length > 4 || !part.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return false
            groups++
            i = nextColon
            if (i == s.length) break
            // At a colon.
            if (i + 1 < s.length && s[i + 1] == ':') {
                if (ellipsis) return false
                ellipsis = true
                i += 2
                if (i == s.length) break
            } else {
                i += 1
                if (i == s.length) return false
            }
            if (groups > 8) return false
        }
        return if (ellipsis) groups < 8 else groups == 8
    }
}
