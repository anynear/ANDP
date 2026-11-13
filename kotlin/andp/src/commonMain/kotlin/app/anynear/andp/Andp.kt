// ANDP (anynear Distributed Protocol) version v1 as specified in spec/andp.md: identifiers, signing bytes,
// grants, refs, object metadata, the Authorization header, tombstones, the network list, placement
// and an HTTP client. The formats hold no state; storage and revocation lists belong to the caller.
package app.anynear.andp

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.io.encoding.Base64
import kotlin.jvm.JvmInline

/** Protocol constants (§5, §6, §14). */
object Andp {
    const val DOMAIN_OBJ = "andp/v1/obj"
    const val DOMAIN_DEL = "andp/v1/del"
    const val DOMAIN_REQ = "andp/v1/req"
    const val DOMAIN_GRANT = "andp/v1/grant"
    const val DOMAIN_RECEIPT = "andp/v1/receipt"
    const val DOMAIN_NET = "andp/v1/net"
    const val DOMAIN_RADIO = "andp/v1/radio"
    const val DOMAIN_PLACE = "andp/v1/place"
    const val DOMAIN_CARD = "andp/v1/card"

    /** Prefix of every HTTP path (§5). */
    const val PATH_PREFIX = "/andp/v1"

    /** Number of holders per object, each at a different operator (§6). */
    const val COPIES = 3

    /** Accepted clock difference in seconds for requests and client writes (§3, §4.4). */
    const val MAX_SKEW_SECONDS = 300L

    /** Maximum number of ids in one status request (§5.7). */
    const val MAX_STATUS_IDS = 1000

    /** Maximum number of items in one peer/have or peer/ref request (§8). */
    const val MAX_PEER_ITEMS = 1000

    /** Longest long poll in seconds (§5.6). */
    const val MAX_LIST_WAIT = 25

    /** Largest page of a list request (§5.6). */
    const val MAX_LIST_LIMIT = 200

    /** The only network list version of ANDP 1 (§5.8). */
    const val LIST_VERSION = 1

    /** Name of the watch extension (§10). */
    const val EXTENSION_WATCH = "watch"

    /** The webpush target of watch (§10.1). */
    const val EXTENSION_WEBPUSH = "webpush"

    /** The radio list extension (§5.9). */
    /** Name of the view extension (§17). */
    const val EXTENSION_VIEW = "view"

    const val EXTENSION_RADIO = "radio"

    /** Extension stream (§18) with the watch target `relay` (§10.2). */
    const val EXTENSION_STREAM = "stream"

    /** Target types of watch (§10, §10.1, §10.2). */
    const val WATCH_TYPE_APNS = "apns"
    const val WATCH_TYPE_WEBPUSH = "webpush"
    const val WATCH_TYPE_RELAY = "relay"

    /** Length of the tag of a `relay` target (§10.2). */
    const val STREAM_TAG_BYTES = 16

    /** Default of `stream.ping` in seconds (§18). */
    const val DEFAULT_STREAM_PING = 180

    /** Event types of the stream (§18.1). */
    const val STREAM_EVENT_PING = "ping"
    const val STREAM_EVENT_NEW = "new"
    const val STREAM_EVENT_BYE = "bye"

    /** The only radio list version (§5.9). */
    const val RADIO_LIST_VERSION = 1

    /** Error code of a missing object (§5.4). */
    const val ERROR_NOT_FOUND = "not_found"

    /** Scheme of the Authorization header (§4.4). */
    const val AUTH_SCHEME = "ANDP"
}

/** Base64url without padding (§1). */
object B64 {
    private val codec = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

    fun encode(data: ByteArray): String = codec.encode(data)

    /** Strict decoding: no padding, only the url alphabet, canonical (re-encoding gives [s]). */
    fun decode(s: String): ByteArray {
        val raw = try {
            codec.decode(s)
        } catch (e: IllegalArgumentException) {
            throw AndpException("andp: invalid base64url", e)
        }
        if (codec.encode(raw) != s) throw AndpException("andp: invalid base64url")
        return raw
    }
}

/** Integers as in §1: ASCII digits, no sign, no leading zeros, at most 2^63−1. */
object AndpInt {
    fun format(v: Long): String {
        require(v >= 0) { "andp: negative values are not part of the protocol" }
        return v.toString()
    }

    fun parse(s: String): Long {
        if (s.isEmpty() || s.length > 19 || (s.length > 1 && s[0] == '0') || s.any { it !in '0'..'9' }) {
            throw AndpException("andp: invalid integer \"$s\"")
        }
        return s.toLongOrNull() ?: throw AndpException("andp: invalid integer \"$s\"")
    }
}

/** Throws [SkewException] if [ts] is more than [Andp.MAX_SKEW_SECONDS] away from [now] (§3 rule 5, §4.4). */
fun checkSkew(ts: Long, now: Long) {
    val d = now - ts
    if (d > Andp.MAX_SKEW_SECONDS || d < -Andp.MAX_SKEW_SECONDS) throw SkewException()
}

/** Where an object lives (§3, §6). */
@Serializable
enum class Placement(val wire: String) {
    /** Entry, placed by its space. */
    @SerialName("space")
    SPACE("space"),

    /** Content, placed by its id. */
    @SerialName("object")
    OBJECT("object");

    override fun toString(): String = wire

    companion object {
        /** Accepts only the values of version v1 (§13). */
        fun parse(s: String): Placement = entries.firstOrNull { it.wire == s } ?: throw AndpException("andp: unknown placement \"$s\"")
    }
}

/** State of an object in status and peer/have answers (§5.7, §8). */
@Serializable
enum class ObjectState(val wire: String) {
    @SerialName("here")
    HERE("here"),
    @SerialName("gone")
    GONE("gone"),
    @SerialName("missing")
    MISSING("missing");

    override fun toString(): String = wire

    companion object {
        fun parse(s: String): ObjectState = entries.firstOrNull { it.wire == s } ?: throw AndpException("andp: unknown object state \"$s\"")
    }
}

/**
 * State of a relay in the network list (§5.8). Other values than the known ones are allowed (§13): a relay with an
 * unknown state is kept but not active.
 */
@Serializable
@JvmInline
value class RelayState(val wire: String) {
    override fun toString(): String = wire

    companion object {
        val CANDIDATE = RelayState("candidate")
        val ACTIVE = RelayState("active")
        val DRAINING = RelayState("draining")

        fun parse(s: String): RelayState = RelayState(s)
    }
}

/** Bit set of rights (§4.1). */
class Rights(val bits: Long) {
    /** Not zero and no unknown bits (§4.2, §13). */
    val isValid: Boolean get() = bits != 0L && bits and ALL.bits.inv() == 0L

    /** Contains all bits of [need]. */
    fun has(need: Rights): Boolean = bits and need.bits == need.bits

    operator fun plus(other: Rights): Rights = Rights(bits or other.bits)

    override fun equals(other: Any?): Boolean = other is Rights && other.bits == bits
    override fun hashCode(): Int = bits.hashCode()

    override fun toString(): String {
        val names = listOf("read", "list", "write", "delete").filterIndexed { i, _ -> bits and (1L shl i) != 0L }
        val rest = bits and ALL.bits.inv()
        return (names + if (rest != 0L) listOf("0x" + rest.toString(16)) else emptyList()).joinToString("|")
    }

    companion object {
        val READ = Rights(1)
        val LIST = Rights(2)
        val WRITE = Rights(4)
        val DELETE = Rights(8)

        /** Every right of version v1. */
        val ALL = Rights(15)
    }
}

/** HTTP header names of §5.3–§5.5 and §9. */
object AndpHeaders {
    const val AUTHORIZATION = "Authorization"
    const val WRITER = "ANDP-Writer"
    const val TS = "ANDP-Ts"
    const val UNTIL = "ANDP-Until"
    const val PLACEMENT = "ANDP-Placement"
    const val REFS = "ANDP-Refs"
    const val REVOKES = "ANDP-Revokes"
    const val GRANT = "ANDP-Grant"
    const val SIG = "ANDP-Sig"
    const val NOTIFY = "ANDP-Notify"
    const val WATCH_SKIP = "ANDP-Watch-Skip"
    const val DEL_SIG = "ANDP-Del-Sig"
    const val FETCH = "ANDP-Fetch"

    /** Value of ANDP-Notify: no watch notification. */
    const val NOTIFY_NONE = "none"

    /** Value of ANDP-Notify: wake with alarm priority (§10). */
    const val NOTIFY_ALARM = "alarm"

    /** Value of ANDP-Fetch. */
    const val FETCH_PROXY = "proxy"

    /** Headers that carry object metadata (PUT request, GET response). */
    val META: List<String> = listOf(WRITER, TS, UNTIL, PLACEMENT, REFS, REVOKES, GRANT, SIG)
}

/** HTTP paths of §5.1. */
object AndpPaths {
    const val INFO = Andp.PATH_PREFIX + "/info"
    const val NET = Andp.PATH_PREFIX + "/net"
    const val RADIO = Andp.PATH_PREFIX + "/radio"
    const val PEER_HAVE = Andp.PATH_PREFIX + "/peer/have"
    const val PEER_TOMBSTONES = Andp.PATH_PREFIX + "/peer/tombstones"
    const val PEER_REF = Andp.PATH_PREFIX + "/peer/ref"
    const val WATCH = Andp.PATH_PREFIX + "/watch"
    const val STREAM = Andp.PATH_PREFIX + "/stream"
    const val PEER_NOTIFY = Andp.PATH_PREFIX + "/peer/notify"

    /** /andp/v1/s/{space} */
    fun space(space: Key): String = Andp.PATH_PREFIX + "/s/" + space

    /** /andp/v1/s/{space}/{id} */
    fun obj(space: Key, id: ID): String = space(space) + "/" + id

    /** /andp/v1/s/{space}/status */
    fun status(space: Key): String = space(space) + "/status"
}
