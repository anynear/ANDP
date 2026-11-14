# ANDP – anynear Distributed Protocol

ANDP is a content-blind, replicated object store. Clients write immutable, encrypted objects into spaces; a space
is an Ed25519 public key whose owner hands out rights (grants). The relays of a network keep three copies of every
object at three different operators and repair each other without consensus. A relay never sees plaintext.

ANDP is the storage and delivery layer of [anynear](https://anynear.app), an app that keeps a circle of people
connected: messages, shared files and passwords, end-to-end encrypted, over the internet and optionally by radio. What
the bytes mean is defined one layer up, in ANMP (anynear Message Protocol, repository `anynear/ANMP`).

**Status:** version v1, in use on the anynear network since November 2026. Security considerations: §16 of the
specification.

| Path | Content |
|---|---|
| `spec/andp.md` | protocol specification, version v1 (normative) |
| `vectors/` | test vectors shared by all implementations |
| `kotlin/` | Kotlin Multiplatform client (Android, iOS, JVM, JS) |

The relay server, its Go implementation and the protocol between relays are not part of this repository.

## Build and test

```bash
cd kotlin && ./gradlew :andp:jvmTest :andp:jsTest          # needs JDK 21
cd kotlin && ./gradlew :andp:iosSimulatorArm64Test         # macOS with Xcode only
```

Every implementation checks the same vectors in `vectors/andp-v1.json`. The reference implementation of the anynear
relays generates them; the Kotlin client only reads them.

## Contributing and security

See `CONTRIBUTING.md`. Please report vulnerabilities as described in `SECURITY.md`, not in a public issue.

## License

GPL-3.0-or-later, see `LICENSE` and `NOTICE`. A commercial licence is available, see `COMMERCIAL.md`. The name
“anynear” and its logos are not covered by the licence.
