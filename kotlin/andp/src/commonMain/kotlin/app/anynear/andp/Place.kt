package app.anynear.andp

/** Placement of objects on relays (§6). */
object Placements {
    /** SHA-256 of the placement input, compared as unsigned big-endian (§6 step 1). */
    fun rank(key: String, node: Key): Hash = Hash.of(SigningBytes.place(key, node))

    /**
     * Sorts [relays] ascending by [rank], ties by node string (§6 steps 1–2). It does not filter by
     * state and does not depend on the input order.
     */
    fun order(key: String, relays: List<Relay>): List<Relay> =
        relays.map { Triple(it, rank(key, it.node).unsafeBytes, it.node.toString()) }
            .sortedWith { a, b -> compareUnsigned(a.second, b.second).takeIf { it != 0 } ?: a.third.compareTo(b.third) }
            .map { it.first }

    /**
     * The placement of [key] over the active relays: up to [Andp.COPIES] chosen at different operators,
     * the others spare. With fewer operators there are fewer chosen; there is no fallback.
     */
    fun place(key: String, relays: List<Relay>): Choice = choose(order(key, relays.filter { it.state == RelayState.ACTIVE }))

    /**
     * log2([x]) for x ≥ 1 in fixed point with 32 fractional bits (§17.4), with integer operations only: integer part
     * from the highest set bit, then 32 rounds of squaring the normalized value in Q62.
     */
    fun log2Q32(x: ULong): ULong {
        val n = 63 - x.countLeadingZeroBits()
        var y = if (n <= 62) x shl (62 - n) else x shr 1
        var result = n.toULong() shl 32
        for (i in 31 downTo 0) {
            val hi = mulHigh(y, y)
            val lo = y * y
            y = (hi shl 2) or (lo shr 62)
            if (y >= (1UL shl 63)) {
                y = y shr 1
                result = result or (1UL shl i)
            }
        }
        return result
    }

    /** −log2(1 − u) in Q32 from the placement rank of [node] (§17.4); a smaller rank gives a smaller score. */
    fun weightedScore(key: String, node: Key): ULong {
        val r = rank(key, node).unsafeBytes
        var top = 0UL
        for (k in 0 until 8) top = (top shl 8) or (r[k].toULong() and 0xffUL)
        val x = (1UL shl 63) - (top shr 1)
        return (63UL shl 32) - log2Q32(x)
    }

    /**
     * Weighted placement (§17.4): ascending by score divided by weight (compared as score_a · w_b < score_b · w_a), ties
     * by rank and then node, then as §6. Members with weight below 1 are not placed; weights above [Card.MAX_WEIGHT] count
     * as that. With the same weight for all it equals [place].
     */
    fun placeWeighted(key: String, members: List<Member>): Choice {
        class Ranked(val r: Relay, val score: ULong, val w: ULong, val rank: ByteArray, val node: String)
        val list = members.filter { it.weight >= 1 }.map {
            Ranked(it.relay, weightedScore(key, it.relay.node), minOf(it.weight, Card.MAX_WEIGHT).toULong(),
                rank(key, it.relay.node).unsafeBytes, it.relay.node.toString())
        }
        return choose(
            list.sortedWith { a, b ->
                val l = a.score * b.w
                val r = b.score * a.w
                when {
                    l != r -> l.compareTo(r)
                    else -> compareUnsigned(a.rank, b.rank).takeIf { it != 0 } ?: a.node.compareTo(b.node)
                }
            }.map { it.r },
        )
    }

    /** High 64 bits of the 128-bit product of [a] and [b], from 32-bit halves (no platform intrinsics). */
    private fun mulHigh(a: ULong, b: ULong): ULong {
        val mask = 0xffffffffUL
        val aLo = a and mask
        val aHi = a shr 32
        val bLo = b and mask
        val bHi = b shr 32
        val ll = aLo * bLo
        val lh = aLo * bHi
        val hl = aHi * bLo
        val hh = aHi * bHi
        val mid = (ll shr 32) + (lh and mask) + (hl and mask)
        return hh + (lh shr 32) + (hl shr 32) + (mid shr 32)
    }

    private fun choose(order: List<Relay>): Choice {
        val chosen = mutableListOf<Relay>()
        val spare = mutableListOf<Relay>()
        val ops = mutableSetOf<String>()
        for (r in order) {
            if (chosen.size < Andp.COPIES && ops.add(r.op)) chosen += r else spare += r
        }
        return Choice(chosen, spare)
    }
}

/** The placement of one key (§6 steps 3–4). */
data class Choice(val chosen: List<Relay>, val spare: List<Relay>) {
    /** Whether [node] is one of the chosen relays. */
    fun isChosen(node: Key): Boolean = chosenRank(node) >= 0

    /** The position of [node] among the chosen relays, or -1. */
    fun chosenRank(node: Key): Int = chosen.indexOfFirst { it.node == node }

    /**
     * The holders when some relays are down (§6 step 5): every healthy chosen relay in order, then for
     * each chosen relay that is down a substitute, the first healthy spare whose operator is not yet
     * taken, else the first healthy spare. A caller counts itself as healthy.
     */
    fun targets(healthy: (Key) -> Boolean): List<Relay> {
        val targets = mutableListOf<Relay>()
        val ops = mutableSetOf<String>()
        val taken = mutableSetOf<Key>()
        var down = 0
        for (r in chosen) {
            if (healthy(r.node)) {
                targets += r
                ops += r.op
                taken += r.node
            } else {
                down++
            }
        }
        while (down > 0) {
            val candidates = spare.filter { it.node !in taken && healthy(it.node) }
            val pick = candidates.firstOrNull { it.op !in ops } ?: candidates.firstOrNull() ?: break
            targets += pick
            ops += pick.op
            taken += pick.node
            down--
        }
        return targets
    }
}
