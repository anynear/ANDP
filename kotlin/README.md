# ANDP for Kotlin Multiplatform

Gradle module `:andp` (package `app.anynear.andp`) implementing `spec/andp.md` (version v1) for Android, JVM, iOS
(arm64, simulatorArm64, x64) and JS (IR, browser and Node.js). It has the same semantics as the Go implementation
the relays use; the versions of Kotlin, Ktor, kotlinx-serialization and cryptography-kotlin follow the anynear app.

| Part | Content |
|---|---|
| formats | `Key`, `ID`, `Hash`, `Sig` (strict b64u), `Rights`, `Placement`, states, paths, headers, signing bytes of all domains |
| grants | `GrantBody`, `Grant` (deterministic CBOR, issue, parse, `validAt`), `authorize`, `Revoked` |
| objects | `Meta` (sign, verify, headers), `Refs`, `ListedObject`, `Receipt`, `Tombstone`, `Auth` (Authorization header) |
| network | `NetworkList` (`verify`, `accept` with `next` rotation, `sign`), `SignedList`, `Relay`, `networkId`, `watchId` |
| placement | `Placements.order`/`place`, `Choice.targets` |
| client | `AndpClient` (Ktor): `pinned` (Android, JVM, iOS) and `webPki`; info, net, list, put, get, delete, status, watch |
| JS facade | `app.anynear.andp.web` (`@JsExport`): `AndpWeb`, `AndpWebSigner`, `AndpWebClient` with Promises and JSON |

SHA-256 is plain Kotlin, so ids and hashes are synchronous everywhere; Ed25519 uses cryptography-kotlin (JDK with
BouncyCastle on Android and JVM, CryptoKit on iOS, WebCrypto in JS), so signing and verifying are `suspend`.

## Use

```kotlin
val owner = SigningKey.fromSeed(seed)
val space = owner.key
val grant = Grant.issue(owner, GrantBody(space, Rights.WRITE, grantee = contact, until = now + 86400, issued = now))

// The contact writes an entry.
val meta = Meta.signData(contactKey, space, data, ts = now, placement = Placement.SPACE, grant = grant)
val list = NetworkList.verify(signedList, networkId, networkKey)
val holders = Placements.place(meta.placementKey, list.relays).targets { healthy(it) }
AndpClient.pinned(holders[0]).use { c ->
    val receipt = c.put(Credentials(contactKey), meta, data)
}
```

## Build and test

```sh
cd kotlin
./gradlew :andp:jvmTest :andp:jsTest             # vectors, unit tests, client against a mock relay
./gradlew :andp:testAndroidHostTest             # the same on the Android host (needs the Android SDK)
./gradlew :andp:compileKotlinIosSimulatorArm64  # iOS (needs Xcode)
```

Tests read `../vectors/andp-v1.json` (never write it). `jvmTest` also runs the pinned client against the Go test
relay (`go run ./internal/cmd/testrelay` in the private repository ANDP-Peer, `../../ANDP-Peer` or `ANDP_PEER_DIR`)
when `go` and that repository are present, and skips this test otherwise; `ANDP_REQUIRE_GO=1` makes a missing Go an
error. The Android SDK is found through `ANDROID_HOME` or `local.properties` (not checked in).
