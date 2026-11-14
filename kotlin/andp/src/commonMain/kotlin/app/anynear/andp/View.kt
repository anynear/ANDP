package app.anynear.andp

import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * Phase of a relay in placement (§17.2): `probe` (admitted, no copies), `join` (gets copies, not asked by clients),
 * `active` (gets copies, asked by clients), `leave` (no new copies, hands its copies off).
 */
@Serializable
@JvmInline
value class Phase(val wire: String) {
    override fun toString(): String = wire

    /** Whether this is a phase of version v1. */
    val isValid: Boolean get() = this in KNOWN

    companion object {
        val PROBE = Phase("probe")
        val JOIN = Phase("join")
        val ACTIVE = Phase("active")
        val LEAVE = Phase("leave")
        private val KNOWN = setOf(PROBE, JOIN, ACTIVE, LEAVE)
    }
}

/** What a relay found about another relay in its last repair round (§17.1). [at] is Unix milliseconds. */
@Serializable
data class Seen(val ph: Phase, val miss: Long, val total: Long, val at: Long, val lost: Long = 0)

/** The content of a signed card text (§17.1). Times are Unix milliseconds, [cap] and [used] bytes. */
@Serializable
data class Card(
    val v: Int,
    val id: Hash,
    val node: Key,
    val ver: Long,
    val beat: Long,
    val phase: Phase,
    val since: Long,
    val weight: Int,
    val cap: Long,
    val used: Long,
    val full: Boolean = false,
    /** Weight mode this relay supports (§17.4): "", "contents" or "all". */
    val weights: String = "",
    /** Since when (Unix milliseconds) the relay has had at least COPIES − 1 healthy other relays; 0 if not. */
    val conn: Long = 0,
    val seen: Map<Key, Seen> = emptyMap(),
    val sw: String = "",
) {
    /** Checks the fields of §17.1. */
    fun validate() {
        if (v != CARD_VERSION) throw AndpException("andp: unknown card version $v")
        if (id.isZero || node.isZero) throw AndpException("andp: card without id or node")
        if (ver <= 0 || beat <= 0) throw AndpException("andp: card without ver or beat")
        if (!phase.isValid) throw AndpException("andp: unknown phase \"$phase\"")
        if (weight < 0 || weight > MAX_WEIGHT) throw AndpException("andp: card weight $weight out of range")
        if (cap < 0 || used < 0 || conn < 0) throw AndpException("andp: card with negative cap, used or conn")
    }

    companion object {
        const val CARD_VERSION = 1
        const val MAX_WEIGHT = 1024
    }
}

/** One card on the wire: `sig = sign("andp/v1/card", card)` by the card's node key (§17.1). */
@Serializable
data class SignedCard(val card: String, val sig: Sig) {
    /** Parses and validates the card and checks the signature by its node key. */
    suspend fun open(): Card {
        val c = try {
            decodeAndpJson(Card.serializer(), card)
        } catch (e: SerializationException) {
            throw AndpException("andp: card: ${e.message}", e)
        } catch (e: IllegalArgumentException) {
            throw AndpException("andp: card: ${e.message}", e)
        }
        c.validate()
        if (!c.node.verify(SigningBytes.card(card), sig)) throw BadSignatureException("card")
        return c
    }
}

/** For which objects placement uses weights (§17.4). */
enum class WeightMode(val wire: String) {
    OFF(""),
    CONTENTS("contents"),
    ALL("all");

    /** Whether placement uses weights for objects with placement [p] in this mode. */
    fun usesWeights(p: Placement): Boolean = this == ALL || (this == CONTENTS && p == Placement.OBJECT)

    companion object {
        fun of(s: String): WeightMode = entries.firstOrNull { it.wire == s && s.isNotEmpty() } ?: OFF
    }
}

/** A relay with its weight for weighted placement (§17.4). */
data class Member(val relay: Relay, val weight: Int)

/** Selects the relays of a placement (§17.2). */
enum class Role {
    /** join or active: where copies belong. */
    TARGET,

    /** active or leave: where clients ask. */
    READ;

    internal fun has(p: Phase?): Boolean = when (this) {
        TARGET -> p == Phase.JOIN || p == Phase.ACTIVE
        READ -> p == Phase.ACTIVE || p == Phase.LEAVE
    }
}

/**
 * The newest valid card of each relay (§17.3). Merging keeps the card with the highest `ver` per node, so the result
 * does not depend on the order cards arrive in. Not safe for concurrent use.
 */
class View {
    private val cards = mutableMapOf<Key, Pair<SignedCard, Card>>()

    /** Opens [s] and keeps it if its node is in [list], its id is the list's id and its ver is higher; null otherwise. */
    suspend fun offer(s: SignedCard, list: NetworkList): Card? {
        val c = try {
            s.open()
        } catch (e: AndpException) {
            return null
        }
        if (c.id != list.id || list.relays.none { it.node == c.node }) return null
        val cur = cards[c.node]
        if (cur != null && cur.second.ver >= c.ver) return null
        cards[c.node] = s to c
        return c
    }

    /** The newest card of [node]. */
    fun card(node: Key): Card? = cards[node]?.second

    /** The lowest weight mode announced by the relays of [list] in join or active; a relay without card announces none. */
    fun networkWeights(list: NetworkList): WeightMode {
        var mode = WeightMode.ALL
        var any = false
        for (r in list.relays) {
            val c = card(r.node)
            val p = phaseOf(r, c)
            if (p != Phase.JOIN && p != Phase.ACTIVE) continue
            any = true
            val m = c?.let { WeightMode.of(it.weights) } ?: WeightMode.OFF
            if (m.ordinal < mode.ordinal) mode = m
        }
        return if (any) mode else WeightMode.OFF
    }

    /** node → ver of every card held. */
    fun digest(): Map<Key, Long> = cards.mapValues { it.value.second.ver }

    /** Every card held, ordered by node. */
    fun signedCards(): List<SignedCard> = cards.entries.sortedBy { it.key.toString() }.map { it.value.first }

    /**
     * Whether relays of at least [DAMAGE_OPS] other operators report lost copies for [node], together at least
     * [DAMAGE_MIN] and more than one in [DAMAGE_SHARE] of what they expect it to hold (§17.6).
     */
    fun damaged(list: NetworkList, node: Key): Boolean {
        val ops = mutableSetOf<String>()
        var lost = 0L
        var total = 0L
        for (r in list.relays) {
            if (r.node == node) continue
            val s = card(r.node)?.seen?.get(node) ?: continue
            if (s.lost == 0L) continue
            ops += r.op
            lost += s.lost
            total += s.total
        }
        list.relays.firstOrNull { it.node == node }?.let { ops -= it.op }
        return ops.size >= DAMAGE_OPS && lost >= DAMAGE_MIN && lost * DAMAGE_SHARE > total
    }

    /**
     * The relays of [list] that take part in [role], with their weight. Without [weighted] every member has weight 1;
     * otherwise a relay without card has weight 1 and a card with weight 0 drops the relay from the target role. A
     * damaged relay ([damaged]) counts as join whatever its card says.
     */
    fun members(list: NetworkList, role: Role, weighted: Boolean, skip: (Key) -> Boolean = { false }): List<Member> =
        list.relays.mapNotNull { r ->
            val c = card(r.node)
            var ph = phaseOf(r, c)
            if (ph == Phase.ACTIVE && damaged(list, r.node)) ph = Phase.JOIN
            if (!role.has(ph) || skip(r.node)) return@mapNotNull null
            var w = if (weighted && c != null) c.weight else 1
            if (w == 0 && role == Role.READ) w = 1
            if (w > 0) Member(r, w) else null
        }

    companion object {
        const val DAMAGE_OPS = 2
        const val DAMAGE_MIN = 10L
        const val DAMAGE_SHARE = 100L

        /** The phase of [r]: from its card, else from its state (active → active, candidate → probe, draining → leave). */
        fun phaseOf(r: Relay, c: Card?): Phase? = c?.phase ?: when (r.state) {
            RelayState.ACTIVE -> Phase.ACTIVE
            RelayState.CANDIDATE -> Phase.PROBE
            RelayState.DRAINING -> Phase.LEAVE
            else -> null
        }
    }
}
