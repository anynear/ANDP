package app.anynear.andp

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Policy announced in /andp/v1/info (§5.2, §11). Sizes in bytes, durations in seconds. */
@Serializable
data class Policy(
    @SerialName("max_object_bytes") val maxObjectBytes: Long = 0,
    @SerialName("max_until") val maxUntil: Long = 0,
    @SerialName("inline_bytes") val inlineBytes: Long = 0,
    @SerialName("orphan_grace") val orphanGrace: Long = 0,
    @SerialName("quota_space_bytes") val quotaSpaceBytes: Long = 0,
    @SerialName("writer_daily_bytes") val writerDailyBytes: Long = 0,
    @SerialName("cors_origins") val corsOrigins: List<String> = emptyList(),
    @SerialName("repair_interval") val repairInterval: Long = 0,
) {
    companion object {
        /** The defaults of the anynear network (§11). Clients read the relay's values instead of assuming these. */
        val DEFAULT = Policy(
            maxObjectBytes = (50L shl 20) + (1L shl 10),
            maxUntil = 30L * 24 * 3600,
            inlineBytes = 64L shl 10,
            orphanGrace = 24L * 3600,
            quotaSpaceBytes = 1L shl 30,
            writerDailyBytes = 1L shl 30,
            corsOrigins = listOf("*"),
            repairInterval = 60,
        )
    }
}

/** The body of GET /andp/v1/info (§5.2). */
@Serializable
data class Info(
    val node: Key,
    val network: Key,
    val policy: Policy = Policy(),
    val extensions: List<String> = emptyList(),
    /** VAPID public key (b64u) when [Andp.EXTENSION_WEBPUSH] is offered (§10.1). */
    val webpush: String = "",
    /** The lowest client level the network still serves fully (§5.2). */
    val clients: Clients? = null,
    /** Settings of the stream extension (§18); `null` without it. */
    val stream: StreamInfo? = null,
) {
    fun hasExtension(name: String): Boolean = name in extensions

    /** `clients.min`, or 1 when absent (§5.2). A client below it keeps working and asks the person to update. */
    val minClientLevel: Int get() = clients?.min?.takeIf { it >= 1 } ?: 1
}

/** The clients field of /andp/v1/info (§5.2). */
@Serializable
data class Clients(val min: Int = 1)

/** The stream field of /andp/v1/info (§18): [ping] seconds between pings, [clients] whether apps shall use it now. */
@Serializable
data class StreamInfo(val ping: Int = Andp.DEFAULT_STREAM_PING, val clients: Boolean = false)

/** The data of a `new` event of the stream (§18.1). */
@Serializable
data class StreamNew(val tags: List<String> = emptyList(), val alarm: Boolean = false)

/** One event of GET /andp/v1/stream (§18.1): [type] such as `ping` or `new`, [data] the JSON of its data line. */
data class StreamEvent(val type: String, val data: String)

/** The body of GET /andp/v1/s/{space} (§5.6). [next] is the cursor for the following call at the same relay. */
@Serializable
data class ListPage(val objects: List<ListedObject> = emptyList(), val next: String = "")

@Serializable
internal class StatusRequest(val ids: List<ID>)

@Serializable
internal class StatusResponse(val objects: Map<String, ObjectState> = emptyMap())

/**
 * A push target (§10). [token] is hex: for `apns` the device token, for `webpush` the endpoint URL (§10.1), for `relay`
 * the stream key with the home relay [node] (b64u) and the [tag] (b64u, 16 bytes) of the space (§10.2).
 */
@Serializable
data class WatchTarget(
    val type: String,
    val token: String,
    val topic: String = "",
    val env: String = "",
    val node: String = "",
    val tag: String = "",
)

/** The body of POST /andp/v1/watch (§10). With [remove] the watch of that target for that space is removed. */
@Serializable
data class WatchRequest(val space: Key, val target: WatchTarget, val remove: Boolean = false)

/** The JSON of every error answer (§5); holders only on 404 for objects (§5.4). */
@Serializable
internal class ErrorBody(val error: String = "", val message: String = "", val holders: List<Relay>? = null)
