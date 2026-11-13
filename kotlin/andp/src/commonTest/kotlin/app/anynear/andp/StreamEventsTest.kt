package app.anynear.andp

import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class StreamEventsTest {
    @Test
    fun readsEventsAndSkipsComments() = runTest {
        val text = ": comment\nevent: ping\ndata: {}\n\nevent: new\ndata: {\"tags\":[\"a\"],\"alarm\":true}\n\nevent: future\ndata: x\ndata: y\n\n"
        val got = mutableListOf<StreamEvent>()
        readEvents(ByteReadChannel(text)) { got += it }
        assertEquals(
            listOf(StreamEvent("ping", "{}"), StreamEvent("new", "{\"tags\":[\"a\"],\"alarm\":true}"), StreamEvent("future", "x\ny")),
            got,
        )
        assertEquals(StreamNew(listOf("a"), alarm = true), AndpJson.decodeFromString(StreamNew.serializer(), got[1].data))
    }

    @Test
    fun hexOfBytes() {
        assertEquals("00ff10", bytesToHex(byteArrayOf(0, -1, 16)))
    }
}
