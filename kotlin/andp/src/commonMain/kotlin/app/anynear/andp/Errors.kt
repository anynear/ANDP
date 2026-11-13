package app.anynear.andp

/** Any protocol error: malformed input, failed verification, or an error answer of a relay. */
open class AndpException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** A timestamp is more than [Andp.MAX_SKEW_SECONDS] away from now. */
class SkewException : AndpException("andp: timestamp too far from now")

/** An Ed25519 signature does not verify. */
class BadSignatureException(what: String) : AndpException("andp: $what: invalid signature")

/** The key is not allowed to do what it asks for. */
class NotAuthorizedException(message: String) : AndpException("andp: $message: not authorized")

/** The grant is revoked in the space. */
class RevokedException : AndpException("andp: grant revoked")

/** Network list verification (§5.8); a relay answers POST /andp/v1/net with 409 or 403 for these. */
class ListNotNewerException : AndpException("andp: network list is not newer")
class ListSignerException : AndpException("andp: network list signed by an unexpected key")
class RadioNotNewerException : AndpException("andp: radio list is not newer")
class ListNetworkException : AndpException("andp: network list of another network")

/**
 * A non-success HTTP answer. [holders] is set on a 404 that carries a holders list (§5.4); an empty
 * list means nobody has the object, `null` means the answer had no such field.
 */
class AndpHttpException(
    val status: Int,
    val code: String,
    val detail: String,
    val holders: List<Relay>?,
) : AndpException(buildString {
    append("andp: HTTP ").append(status)
    if (code.isNotEmpty()) append(' ').append(code)
    if (detail.isNotEmpty()) append(": ").append(detail)
}) {
    val isNotFound: Boolean get() = status == 404

    /** 410: deleted, or a tombstone exists. */
    val isGone: Boolean get() = status == 410

    /** The holders whose node and TLS key are in [list] (§9: clients follow only those). */
    fun knownHolders(list: NetworkList): List<Relay> = holders.orEmpty().filter { list.knows(it) }
}
