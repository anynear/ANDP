package app.anynear.andp

import dev.whyoleg.cryptography.CryptographyProvider

// WebCrypto: Ed25519 in current browsers and Node.js.
internal actual val cryptoProvider: CryptographyProvider = CryptographyProvider.Default
