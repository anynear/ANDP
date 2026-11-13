package app.anynear.andp

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.CborLabel

/** Deterministic CBOR (§1): definite lengths, shortest integers, integer map keys in ascending order. */
@OptIn(ExperimentalSerializationApi::class)
internal object AndpCbor {
    private val cbor = Cbor {
        preferCborLabelsOverNames = true
        alwaysUseByteString = true
        encodeDefaults = false
        useDefiniteLengthEncoding = true
        // Unknown map keys are rejected: an ignored key could widen a grant.
        ignoreUnknownKeys = false
    }

    fun <T> encode(serializer: KSerializer<T>, value: T): ByteArray = cbor.encodeToByteArray(serializer, value)

    /**
     * Decodes [data] and rejects anything that does not re-encode to the same bytes. This also rejects
     * trailing bytes, unsorted or duplicate keys, indefinite lengths, tags and long integer forms.
     */
    fun <T> decodeCanonical(serializer: KSerializer<T>, data: ByteArray, what: String): T {
        val value = try {
            cbor.decodeFromByteArray(serializer, data)
        } catch (e: Exception) {
            throw AndpException("andp: $what: invalid CBOR", e)
        }
        val again = try {
            cbor.encodeToByteArray(serializer, value)
        } catch (e: Exception) {
            throw AndpException("andp: $what: invalid CBOR", e)
        }
        if (!again.contentEquals(data)) throw AndpException("andp: $what: CBOR is not deterministically encoded")
        return value
    }

    /** Field order is the key order 1–6; absent optional fields are omitted. */
    @Serializable
    class GrantBodyWire(
        @CborLabel(1) @ByteString val space: ByteArray,
        @CborLabel(2) val rights: Long,
        @CborLabel(3) @ByteString val grantee: ByteArray? = null,
        @CborLabel(4) @ByteString val scope: ByteArray? = null,
        @CborLabel(5) val until: Long,
        @CborLabel(6) val issued: Long,
    )

    @Serializable
    @CborArray
    class GrantWire(@ByteString val body: ByteArray, @ByteString val sig: ByteArray)

    @Serializable
    @CborArray
    class RefWire(@ByteString val id: ByteArray, val size: Long)

    val refsSerializer: KSerializer<List<RefWire>> = ListSerializer(RefWire.serializer())
}
