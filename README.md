# SerbianEIDSigner

A native macOS reimplementation of the **SmartBox** signing middleware used by the Serbian
tax portal **ePorezi** (`eporezi.purs.gov.rs`). It is a small, local WebSocket daemon that lets
the portal's web page authenticate and sign with a Serbian **MUP eID** smart card, with no Java
runtime and no vendor PKCS#11 stack.

The official SmartBox is a Java 21 application distributed by `itsinbox` / PURS. This project speaks
the same WebSocket JSON protocol so the ePorezi page talks to it unchanged, but it is written in
Swift on top of Apple **CryptoTokenKit** (the card is reached through the "Serbian eID Token"
CryptoTokenKit extension) and Apple's system **libxml2** for XML canonicalization.

> Independent, unofficial software. Not affiliated with PURS or itsinbox. Use with your own card.

## Status

- Card login and document signing against the live ePorezi backend: working.
- Origin-restricted (only `https://eporezi.purs.gov.rs`), loopback-only.
- 68 unit tests (`swift test`).

---

## Requirements

- macOS 13 or later.
- A PC/SC smart-card reader and a Serbian **MUP eID** card.
- The **"Serbian eID Token"** CryptoTokenKit extension installed and enabled
  (so the card appears as a `TKSmartCard` slot). Check with `security list-smartcards`.
- Swift 5.9+ toolchain (Xcode or the Command Line Tools) to build.

---

## Build and run (developer)

```sh
swift build -c release
```

The daemon reaches the card through CryptoTokenKit, which requires the
`com.apple.security.smartcard` entitlement. An unsigned `swift build` binary does not have it,
so sign it ad hoc with that entitlement before running:

```sh
cat > /tmp/signer.entitlements <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.smartcard</key><true/>
  <key>com.apple.security.network.server</key><true/>
</dict>
</plist>
EOF

codesign --force --sign - --entitlements /tmp/signer.entitlements .build/release/SignerApp
.build/release/SignerApp
```

`SignerApp` is a menu-bar (accessory) app: it starts the WebSocket server, shows an "eID" status
item with the bound port, and offers "Launch at Login". It keeps nothing on disk; the card PIN is
entered when the card is used and is never persisted.

To verify it is listening:

```sh
lsof -nP -iTCP -sTCP:LISTEN | grep -i SignerApp     # expect 127.0.0.1:17165
```

## Build a distributable app

A ready-to-package app target lives in `TokenApp/` (XcodeGen project with the sandboxed
`App.entitlements`: `app-sandbox`, `network.server`, `smartcard`).

```sh
brew install xcodegen
cd TokenApp && xcodegen generate         # produces the Xcode project
# build/archive in Xcode, then:
scripts/make-dmg.sh <path/to/App.app> <version> <out.dmg>   # needs: pip install dmgbuild==1.6.7
```

## Use

1. Start `SignerApp` with the reader connected and the card inserted.
2. Open `https://eporezi.purs.gov.rs/user/login.html` and choose certificate/card login (MUP).
3. The page connects to the local daemon, lists your certificate, and macOS prompts for the PIN
   to sign the authentication challenge.

---

## Protocol

The ePorezi page connects over **WebSocket** to `ws://127.0.0.1:<port>`. The daemon tries ports
**17165, 20806, 65097** in order and binds the first free one (loopback only, both `127.0.0.1`
and `::1`). These are the same fixed ports the official SmartBox uses, so the page finds the daemon.

### Connection security

- **Loopback only.** The socket is bound to `127.0.0.1` / `::1`, never to a routable address.
- **Origin allowlist.** At the WebSocket handshake the `Origin` header must be
  `https://eporezi.purs.gov.rs`; any other origin is rejected with **HTTP 403** before the
  connection is upgraded. (The official SmartBox performs no Origin check — see Security notes.)

### Message envelopes

Every message is a JSON object. The **request** sent by the page:

```json
{ "operation": "GET_CERTIFICATES", "input": { ... } }
```

Every **response** from the daemon:

```json
{ "operation": "GET_CERTIFICATES", "status": 0, "payload": { ... } }
```

`status` is a bare JSON number; **0 means success**. On error the daemon returns a non-zero status
and an empty payload (`{}`). Error statuses never carry card data, document contents or the PIN.

### Operations

| Operation          | Direction        | Input                                   | Success payload |
|--------------------|------------------|-----------------------------------------|-----------------|
| `ON_OPEN_EVENT`    | server → client  | —                                       | `{ "appName", "appVersion", "appBuild", "osName" }` sent once on connect |
| `GET_INFO`         | client → server  | `{ "sbSession", "host", "language" }`   | `{}` |
| `GET_PROVIDERS`    | client → server  | —                                       | `{ "providers": [ { "id", "name" } ] }` |
| `GET_TERMINALS`    | client → server  | `{ "providerId" }`                      | `{ "terminals": [ { "id", "name" } ] }` |
| `GET_CERTIFICATES` | client → server  | `{ "pin", "terminalId" }`               | `{ "certificates": [ { "alias", "name" } ] }` |
| `GET_SIGNED_XML`   | client → server  | `{ "certificate": {"alias","name"}, "pin", "xml" }` | `{ "xml": "<base64 of the signed XML>" }` |

Notes:

- **`GET_PROVIDERS`** returns the card issuer. Only **MUP** (id `0`) is implemented; a provider is
  reported only when an inserted card's ATR matches the MUP eID family.
- **`GET_TERMINALS`** lists the occupied reader slots for the provider.
- **`GET_CERTIFICATES`** requires the PIN (a PKCS#15 `VERIFY`). `alias` is the hex of the card's
  certificate id; **`name` is the card holder's display name** parsed from the certificate subject
  (GIVENNAME + SURNAME, else the leading part of CN), exactly as SmartBox's `extractName`. The
  portal reads the user identity from this field.
- **`GET_SIGNED_XML`**: `xml` in and `xml` out are **Base64**. The input is the document to sign;
  the output payload is `{ "xml": base64(signedDocument) }`.

### Error statuses

| Code | Meaning |
|------|---------|
| `1300` | GET_TERMINALS generic failure |
| `1350` | middleware / wrong provider |
| `1400` | GET_CERTIFICATES generic failure |
| `1440` | PIN incorrect |
| `1441` | PIN locked (PKCS#11 lockout) |
| `1500` | GET_SIGNED_XML generic failure |

> A wrong PIN repeated ~3 times locks the card. The daemon sends a single `VERIFY` per request and
> never retries after a failed one.

### Signature format

`GET_SIGNED_XML` produces an **enveloped XMLDSig** signature appended to the document root, matching
the official SmartBox profile byte-for-byte in structure:

- `SignatureMethod` `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` (RSASSA-PKCS1-v1_5)
- `DigestMethod` `http://www.w3.org/2001/04/xmlenc#sha256`
- `CanonicalizationMethod` `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` (**C14N 1.0 inclusive**)
- one `Reference` with `URI=""` and the `enveloped-signature` transform
- `KeyInfo` → `X509Data`, in this exact order:
  1. `X509Certificate` (the signing certificate, DER base64)
  2. `X509IssuerSerial` (`X509IssuerName` + `X509SerialNumber`)
  3. **`X509SubjectName`** (the certificate subject DN)

The relying party reads the holder identity from **`X509SubjectName`**; omitting it makes ePorezi
reject the login with "missing user data" (`Недостају подаци о кориснику`).

The RSA operation runs **on the card**: VERIFY (once), then `MANAGE SECURITY ENVIRONMENT` and
`PERFORM SECURITY OPERATION: COMPUTE DIGITAL SIGNATURE` over the SHA-256 DigestInfo of the canonical
`SignedInfo`. Only the card's **nonRepudiation** (signing) certificate key is used. The private key
never leaves the card.

---

## Architecture

| Area | File(s) |
|------|---------|
| WebSocket server, handshake, Origin check, loopback bind | `Sources/SignerCore/Server/WebSocketServer.swift` |
| Protocol messages and envelopes | `Sources/SignerCore/Protocol/Messages.swift` |
| Operation dispatch | `Sources/SignerCore/Dispatch/Dispatcher.swift` |
| CryptoTokenKit card access | `Sources/SignerCore/Card/TKCardService.swift` |
| PKCS#15 enumeration + on-card signing (APDUs) | `Sources/SignerCore/Card/PKCS15.swift` |
| XMLDSig builder + C14N (libxml2) | `Sources/SignerCore/Sign/XMLDSig.swift` |
| Certificate subject/issuer parsing, holder name | `Sources/SignerCore/Sign/CertificateInfo.swift` |
| Menu-bar app shell, login item | `Sources/SignerApp/main.swift` |

Card I/O (PIN prompt, APDUs) runs off the NIO event loop on a single serial queue, so one card is
never accessed concurrently. The PIN is held in a `Secret` type that is redacted when printed and
zeroized on deinit.

Built on `swift-nio` (WebSocket) and the system `libxml2` (canonicalization/serialization).

---

## Security notes

This project was built from a reverse-engineering study of the official SmartBox, which surfaced
weaknesses that are **fixed here**:

- **Origin validation.** SmartBox accepts WebSocket connections from any web origin; any site the
  user visits can reach the signer. This daemon validates `Origin` against an allowlist.
- **Loopback binding.** Both bind to loopback only (good); kept.

The PIN is only ever sent to the card (PKCS#15 `VERIFY`); it is not passed on a command line, not
logged, and not written to disk.

## License

MIT. © Nenad VULIC.
