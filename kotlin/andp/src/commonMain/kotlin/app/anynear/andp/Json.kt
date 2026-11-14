package app.anynear.andp

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonElement

/**
 * Reading ANDP JSON as §1 requires: field names match exactly, unknown fields are ignored, and a document with a
 * repeated key in any object, at any depth, is invalid. kotlinx.serialization keeps the last value of a repeated key,
 * so every ANDP document is checked here before it is decoded. Applications that read ANDP texts themselves (for
 * example the content of a radio list) use [parse] too, so that they see the same document ANDP checked.
 */
object StrictJson {
    /** Parses [text] after [requireUniqueKeys]. Throws [AndpException] on invalid JSON or a repeated key. */
    fun parse(text: String): JsonElement {
        requireUniqueKeys(text)
        return try {
            AndpJson.parseToJsonElement(text)
        } catch (e: SerializationException) {
            throw AndpException("andp: invalid JSON: ${e.message}", e)
        } catch (e: IllegalArgumentException) {
            throw AndpException("andp: invalid JSON: ${e.message}", e)
        }
    }

    /**
     * Throws [AndpException] if an object in [text] names a key twice. Keys are compared after resolving escapes, so
     * `"a"` and `"a"` are the same key. It checks only keys; the decoder checks the rest of the syntax.
     */
    fun requireUniqueKeys(text: String) {
        // One entry per open object or array: the keys seen so far in an object, null for an array.
        val stack = ArrayList<HashSet<String>?>()
        var expectKey = false
        var i = 0
        while (i < text.length) {
            when (text[i]) {
                '{' -> {
                    stack.add(HashSet())
                    expectKey = true
                }
                '[' -> {
                    stack.add(null)
                    expectKey = false
                }
                '}', ']' -> {
                    if (stack.isEmpty()) throw AndpException("andp: invalid JSON: unbalanced brackets")
                    stack.removeAt(stack.lastIndex)
                    expectKey = false
                }
                ',' -> expectKey = stack.lastOrNull() != null
                '"' -> {
                    val end = stringEnd(text, i)
                    if (expectKey) {
                        val keys = stack.last() ?: throw AndpException("andp: invalid JSON")
                        val key = unescape(text, i + 1, end)
                        if (!keys.add(key)) throw AndpException("andp: invalid JSON: key \"$key\" given twice")
                        expectKey = false
                    }
                    i = end
                }
            }
            i++
        }
    }

    /** Index of the closing quote of the string that opens at [start]. */
    private fun stringEnd(text: String, start: Int): Int {
        var i = start + 1
        while (i < text.length) {
            when (text[i]) {
                '\\' -> i += 2
                '"' -> return i
                else -> i++
            }
        }
        throw AndpException("andp: invalid JSON: unterminated string")
    }

    /** The value of the string between [from] and [to] (exclusive, without quotes). */
    private fun unescape(text: String, from: Int, to: Int): String {
        if (text.indexOf('\\', from).let { it < 0 || it >= to }) return text.substring(from, to)
        val sb = StringBuilder(to - from)
        var i = from
        while (i < to) {
            val c = text[i]
            if (c != '\\') {
                sb.append(c)
                i++
                continue
            }
            if (i + 1 >= to) throw AndpException("andp: invalid JSON: bad escape")
            when (text[i + 1]) {
                '"' -> sb.append('"')
                '\\' -> sb.append('\\')
                '/' -> sb.append('/')
                'b' -> sb.append('\b')
                'f' -> sb.append('\u000C')
                'n' -> sb.append('\n')
                'r' -> sb.append('\r')
                't' -> sb.append('\t')
                'u' -> {
                    if (i + 6 > to) throw AndpException("andp: invalid JSON: bad escape")
                    var code = 0
                    for (k in i + 2 until i + 6) {
                        code = code * 16 + (text[k].digitToIntOrNull(16) ?: throw AndpException("andp: invalid JSON: bad escape"))
                    }
                    sb.append(code.toChar())
                    i += 4
                }
                else -> throw AndpException("andp: invalid JSON: bad escape")
            }
            i += 2
        }
        return sb.toString()
    }
}

/** Decodes an ANDP JSON document with [AndpJson] after [StrictJson.requireUniqueKeys] (§1). */
internal fun <T> decodeAndpJson(serializer: KSerializer<T>, text: String): T {
    StrictJson.requireUniqueKeys(text)
    return AndpJson.decodeFromString(serializer, text)
}
