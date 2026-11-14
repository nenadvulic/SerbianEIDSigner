# SerbianEIDSigner — Implementation Plan (MVP: MUP signing for e-porezi on macOS)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A macOS app that acts as a drop-in local signing service for the e-porezi portal, signing documents with the MUP eID card, replacing SmartBox (which has no macOS MUP support).

**Architecture:** A SwiftNIO WebSocket server on loopback speaks SmartBox's JSON protocol to the e-porezi page. Card access is direct via CryptoTokenKit/PC-SC (no vendor PKCS#11), reusing SerbianEIDToken's card layer, extended to use the card's qualified **signing** key. An XMLDSig builder canonicalizes `SignedInfo`, hashes it, and has the card produce the RSA-SHA256 signature, emitting the exact W3C XMLDSig shape SmartBox produces so the PURS backend accepts it.

**Tech Stack:** Swift 5.9+, macOS 13+; swift-nio (`NIOCore`, `NIOPosix`, `NIOHTTP1`, `NIOWebSocket`); CryptoTokenKit (`TKSmartCard`); libxml2 (C14N) via a system module; Security.framework (SHA-256, X.509). No vendor PKCS#11.

**Spec:** `docs/superpowers/specs/2026-11-14-eporezi-signer-design.md`

## Global Constraints

- macOS 13+, universal binary. Swift tools only (no vendor PKCS#11 for MUP).
- Wire protocol MUST match SmartBox exactly: request `{operation, input}`, response `{operation, status, payload}`; `status` is a **number**, `0` = success.
- Operation names (verbatim): `ON_OPEN_EVENT`, `GET_INFO`, `GET_PROVIDERS`, `GET_TERMINALS`, `GET_CERTIFICATES`, `GET_SIGNED_XML`.
- Ports, tried first-free in order: `17165, 20806, 65097`. Bind `127.0.0.1` only.
- Signature profile (verbatim URIs): enveloped (`http://www.w3.org/2000/09/xmldsig#enveloped-signature`), DigestMethod `http://www.w3.org/2001/04/xmlenc#sha256`, SignatureMethod `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`, CanonicalizationMethod `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`, Reference `URI=""`, KeyInfo = `X509Data`(cert + `X509IssuerSerial`).
- PIN: held only in memory, passed only to the card verify/sign, zeroized after use. **Never** in process args, logs, or on disk.
- Allowed WS Origin (MVP): `https://eporezi.purs.gov.rs` (allowlist, configurable).

## Review Focus

- **Non-allowlisted `Origin`** (malicious local page): handshake MUST be rejected, no upgrade. → Task 4.
- **Wrong or locked PIN**: must return a non-zero error status (incorrect / locked), never crash or retry into lockout. → Task 7.
- **No reader / no card inserted**: `GET_TERMINALS`/`GET_CERTIFICATES` return empty/error gracefully, no hang. → Task 6/7.
- **XML with namespaces / UTF-8 / existing whitespace**: inclusive C14N must produce a byte-stable canonical form the digest covers. → Task 8.
- **Multiple concurrent WS connections** (portal opens >1): server isolates per-connection state. → Task 3.

---

### Task 1: Project scaffold

**Files:**
- Create: `Package.swift`, `Sources/SignerCore/`, `Sources/SignerApp/`, `Tests/SignerCoreTests/`
- Create: `Sources/CLibXML2/module.modulemap` (system lib for libxml2)

**Interfaces:**
- Produces: a buildable SwiftPM package with a `SignerCore` library target (testable) and a `SignerApp` executable target.

- [ ] **Step 1:** Create `Package.swift` declaring targets `SignerCore` (deps: swift-nio products, `CLibXML2`), `SignerApp` (dep: `SignerCore`), test target `SignerCoreTests`. Pin swift-nio to an exact version ≥ 2.65.0.
- [ ] **Step 2:** Add `Sources/CLibXML2/module.modulemap` exposing `libxml/c14n.h`, `libxml/tree.h`.
- [ ] **Step 3:** Add a trivial `SignerCore` symbol + a placeholder test; run `swift build && swift test`. Expected: builds, 1 test passes.
- [ ] **Step 4:** Commit.

---

### Task 2: Protocol model (Codable) matching the wire format

**Files:**
- Create: `Sources/SignerCore/Protocol/Messages.swift`
- Test: `Tests/SignerCoreTests/MessagesTests.swift`

**Interfaces:**
- Produces: `enum Operation: String, Codable` (cases = the 6 verbatim names); `struct Status` carrying an `Int` (0 = OK) encoding as a bare number; `struct Envelope<Payload: Codable>` encoding `{operation,status,payload}`; `struct Request` decoding `{operation, input: JSONValue?}`; request-input structs `GetInfoInput{sbSession,host,language}`, `GetTerminalsInput{providerId:Int}`, `GetCertificatesInput{pin:Secret,terminalId:Int}`, `GetSignedXmlInput{certificate:Alias,pin:Secret,xml}`; `struct Alias{alias:String,name:String}`; `struct Secret` (wraps PIN bytes; `description`/`debugDescription` = `"<redacted>"`; **not** `Encodable`; `deinit` zeroizes). Decoding a `pin` field constructs a `Secret` directly (it never lands in a loggable/Encodable value).

- [ ] **Step 1: Write failing tests** `MessagesTests`:
  - decode `{"operation":"GET_INFO","input":{"sbSession":"s","host":"eporezi.purs.gov.rs","language":"sr-Cyrl-RS"}}` → `Operation.getInfo`, input fields equal.
  - encode a `GET_PROVIDERS` success with payload `{"providers":[]}` → JSON equals `{"operation":"GET_PROVIDERS","status":0,"payload":{"providers":[]}}` (status is a number, key order normalized by comparing parsed JSON).
  - decode `GET_SIGNED_XML` input with `certificate:{alias,name}`, `pin`, `xml`.
- [ ] **Step 2:** Run tests → FAIL (types undefined).
- [ ] **Step 3:** Implement the types in `Messages.swift`. `Status` encodes as `Int`. Use a small `JSONValue` for the dynamic `input` when needed, or per-operation typed decoding.
- [ ] **Step 4:** Run tests → PASS.
- [ ] **Step 5:** Commit.

---

### Task 3: WebSocket server on loopback with port selection

**Files:**
- Create: `Sources/SignerCore/Server/WebSocketServer.swift`
- Test: `Tests/SignerCoreTests/WebSocketServerTests.swift`

**Interfaces:**
- Consumes: Task 2 types.
- Produces: `final class WebSocketServer` with `init(ports:[Int], originAllowlist:[String], handler: MessageHandler)`, `func start() throws -> Int` (returns bound port), `func stop()`. `protocol MessageHandler { func handle(_ request: Request, send: @escaping (Data) -> Void, onOpen: ...) }` (text frames carry JSON).

- [ ] **Step 1: Write failing test:** start server with ports `[0]`-style injectable list; assert `start()` binds the **first free** port of the configured list (inject a pre-bound socket on the first port, assert it falls through to the second).
- [ ] **Step 2:** Also test: a second concurrent client connection is accepted and handled independently (two clients each get their own `ON_OPEN_EVENT`).
- [ ] **Step 3:** Run → FAIL.
- [ ] **Step 4:** Implement with NIO: `ServerBootstrap` bound to `127.0.0.1`, HTTP upgrade to WebSocket, per-channel handler. Bind loop over ports, catch "address in use", try next.
- [ ] **Step 5:** Run → PASS. Commit.

---

### Task 4: Origin validation at the WebSocket handshake (Finding #1 fix)

**Files:**
- Modify: `Sources/SignerCore/Server/WebSocketServer.swift`
- Test: `Tests/SignerCoreTests/OriginValidationTests.swift`

**Interfaces:**
- Produces: upgrade is rejected (HTTP 403, no upgrade) when the request `Origin` header is not in `originAllowlist`.

- [ ] **Step 1: Write failing tests:**
  - upgrade request with `Origin: https://eporezi.purs.gov.rs` → `101` switching protocols.
  - upgrade request with `Origin: https://evil.example` → `403`, connection not upgraded.
  - upgrade request with **no** `Origin` → rejected (`403`).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `shouldUpgrade` in the NIO HTTP upgrade config: read `Origin`, return upgrade headers only if allowlisted, else respond 403.
- [ ] **Step 4:** Run → PASS. Commit.

---

### Task 5: Dispatcher — ON_OPEN_EVENT, GET_INFO, GET_PROVIDERS

**Files:**
- Create: `Sources/SignerCore/Dispatch/Dispatcher.swift`
- Create: `Sources/SignerCore/Card/CardService.swift` (protocol only)
- Test: `Tests/SignerCoreTests/DispatcherTests.swift`

**Interfaces:**
- Consumes: Task 2 types.
- Produces: `protocol CardService { func providers() -> [Provider]; func terminals(providerId:Int) -> [Terminal]; func certificates(providerId:Int, terminalId:Int, pin:Secret) throws -> [Alias]; func sign(providerId:Int, terminalId:Int, alias:Alias, pin:Secret, canonicalSignedInfoSHA256: Data) throws -> Data }` ; `struct Provider{id:Int,name:String}`; `final class Dispatcher: MessageHandler` built with a `CardService`. `appInfo` constants for ON_OPEN_EVENT.
- Note: a `StubCardService` lives in the test target and returns a MUP provider.

- [ ] **Step 1: Write failing tests** (Dispatcher + StubCardService):
  - on connect, dispatcher emits `ON_OPEN_EVENT` with `status:0` and payload containing `appName`, `appVersion`, `osName`.
  - `GET_INFO` (any input) → `{operation:"GET_INFO",status:0,payload:{}}`.
  - `GET_PROVIDERS` → `{...,status:0,payload:{providers:[{...MUP...}]}}` (stub returns one MUP provider).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `Dispatcher.handle` switching on `Operation`; wire ON_OPEN on channel-active. `CardService` is a protocol (impl in later tasks).
- [ ] **Step 4:** Run → PASS. Commit.

---

### Task 6: GET_TERMINALS and GET_CERTIFICATES dispatch (stubbed card)

**Files:**
- Modify: `Sources/SignerCore/Dispatch/Dispatcher.swift`
- Test: `Tests/SignerCoreTests/DispatcherCertsTests.swift`

**Interfaces:**
- Produces: `GET_TERMINALS` → `payload:{terminals:[...]}`; `GET_CERTIFICATES` → `payload:{certificates:[{alias,name}]}`; error path returns non-zero `status` with no crash.

- [ ] **Step 1: Write failing tests:**
  - `GET_TERMINALS {providerId}` → terminals from stub.
  - `GET_CERTIFICATES {pin,terminalId}` (stub returns 1 alias) → `payload.certificates == [{alias,name}]`.
  - stub throws `CardError.pinIncorrect` → response `status` is the non-zero incorrect-PIN code, no throw escapes.
  - no card (stub returns empty terminals) → `GET_TERMINALS` returns `{terminals:[]}`, no hang.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement the two cases + map `CardError` → numeric status codes (mirror SmartBox: incorrect-PIN, locked, generic).
- [ ] **Step 4:** Run → PASS. Commit.

---

### Task 7: Card layer — reader/card enumeration + PKCS#15 signing cert discovery (MUP)

**Files:**
- Create: `Sources/SignerCore/Card/TKCardService.swift`
- Create: `Sources/SignerCore/Card/PKCS15.swift`
- Test: `Tests/SignerCoreTests/PKCS15Tests.swift` (parsing only; hardware path manual)

**Interfaces:**
- Consumes: SerbianEIDToken's card-reading approach (APDU/PKCS#15) — reuse its SELECT/READ logic.
- Produces: `final class TKCardService: CardService`. `providers()` returns MUP when a MUP ATR reader is present. `certificates(...)` logs into the card (PIN) and returns aliases for certs whose key usage is **nonRepudiation** (the signing cert), plus the auth cert if present. PKCS#15 parser `func signingCertificate(from: CardReader) throws -> (cert: Data, alias: Alias)`.

- [ ] **Step 1: Write failing test** (PKCS15, pure): given a captured DER cert fixture with `keyUsage` nonRepudiation, `isSigningCert(der)` → true; an auth-only cert → false.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `PKCS15.isSigningCert` (parse keyUsage via Security/ASN.1). Implement `TKCardService` card/reader enumeration via `TKSmartCard` (hardware; guarded behind the protocol, not unit-tested).
- [ ] **Step 4:** Run PKCS15 test → PASS.
- [ ] **Step 5:** **Manual hardware check** (document in task): with MUP card inserted, `GET_PROVIDERS` lists MUP, `GET_CERTIFICATES` with correct PIN lists the signing alias. Record result.
- [ ] **Step 6:** Commit.

---

### Task 8: XMLDSig builder (C14N + SHA-256 + external signer)

**Files:**
- Create: `Sources/SignerCore/Sign/XMLDSig.swift`
- Test: `Tests/SignerCoreTests/XMLDSigTests.swift`

**Interfaces:**
- Consumes: `CLibXML2` (c14n).
- Produces: `struct XMLDSigBuilder { func build(documentXML: String, certDER: Data, issuer: String, serial: Data, sign: (Data) throws -> Data) throws -> String }` — builds the enveloped `<Signature>` with the Global-Constraints profile; `sign` receives the SHA-256 digest of the canonical `SignedInfo` and returns the raw RSA-SHA256 signature; the builder assembles `SignatureValue` + `KeyInfo/X509Data`(cert + IssuerSerial) and returns the document with the signature appended.

- [ ] **Step 1: Write failing tests:**
  - canonicalization: given a document with a namespace + mixed whitespace, `canonicalizeC14N(node)` output equals a known-good fixture (inclusive C14N).
  - end-to-end with a **stub signer** returning fixed bytes: `build(...)` output parses, contains the 4 verbatim profile URIs, `Reference URI=""`, `X509IssuerSerial` with the given issuer/serial, and `SignatureValue` = base64 of the stub bytes.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement with libxml2 `xmlC14NDocDumpMemory` for canonicalization, Security.framework SHA-256, and DOM assembly of the Signature element. The RSA is delegated to the `sign` closure.
- [ ] **Step 4:** Run → PASS. Commit.

---

### Task 9: Card signing operation (APDU RSA-SHA256) + GET_SIGNED_XML wiring

**Files:**
- Modify: `Sources/SignerCore/Card/TKCardService.swift`
- Modify: `Sources/SignerCore/Dispatch/Dispatcher.swift`
- Test: `Tests/SignerCoreTests/SignedXmlFlowTests.swift`

**Interfaces:**
- Produces: `CardService.sign(...)` performs PIN verify + on-card RSA PKCS#1(SHA-256) over the provided digest, returning raw signature bytes. `GET_SIGNED_XML` handler: discover signing cert → `XMLDSigBuilder.build` with `sign` bound to the card → return `{status:0, payload: <signed xml string>}`.

- [ ] **Step 1: Write failing test** (Dispatcher + StubCardService whose `sign` returns deterministic bytes): `GET_SIGNED_XML {certificate,pin,xml}` → payload is signed XML whose `SignatureValue` matches the stub and whose structure matches the SmartBox profile (reuse Task 8 assertions).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement the handler wiring (Dispatcher → XMLDSigBuilder → CardService.sign). Implement the real `TKCardService.sign` APDU path (hardware, behind protocol).
- [ ] **Step 4:** Run flow test → PASS.
- [ ] **Step 5:** **Manual hardware check:** sign a benign test XML with the MUP card; verify the signature validates (e.g., `xmlsec1 --verify` offline) against the card cert. Record result.
- [ ] **Step 6:** Commit.

---

### Task 10: PIN non-leakage — redaction and zeroization checks

**Files:**
- Modify: `Sources/SignerCore/Protocol/Messages.swift` (the `Secret` from Task 2)
- Test: `Tests/SignerCoreTests/SecretTests.swift`

**Interfaces:**
- Consumes: `Secret` (Task 2).
- Produces: verified guarantees — `Secret` redacts in string interpolation/reflection, is not `Encodable`, zeroizes on `deinit`; the serialized `ON_OPEN_EVENT`/`GET_*` responses never contain a PIN value.

- [ ] **Step 1: Write failing tests:** `"\(secret)"` and `String(reflecting: secret)` both equal `"<redacted>"`; encoding any response `Envelope` that passed through a `GET_SIGNED_XML` request never contains the PIN substring; add a compile-time note that `Secret: Encodable` must not exist.
- [ ] **Step 2:** Run → FAIL (if any guarantee missing from the Task-2 `Secret`).
- [ ] **Step 3:** Harden `Secret` as needed (redaction, zeroizing `deinit`); confirm no code path puts the PIN into a logged/encoded value.
- [ ] **Step 4:** Run → PASS. Commit.

---

### Task 11: App shell — SignerApp wiring, launch-at-login, packaging

**Files:**
- Create: `Sources/SignerApp/main.swift`, menu-bar item
- Create: `TokenApp/` app target config (reuse SerbianEIDToken shell, trust-chain install, `make-dmg`), `Local.xcconfig`
- Test: `Tests/SignerCoreTests/ConfigTests.swift` (config only)

**Interfaces:**
- Consumes: all of SignerCore.
- Produces: an `.app` that starts the server (ports + origin allowlist from a config), shows a menu-bar status item, installs as a login item. Packaging + notarization reused from SerbianEIDToken.

- [ ] **Step 1: Write failing test:** default config = ports `[17165,20806,65097]`, allowlist `["https://eporezi.purs.gov.rs"]`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `AppConfig` + `main.swift` (start `WebSocketServer` with `Dispatcher(TKCardService())`), menu-bar item, login-item registration. Reuse SerbianEIDToken packaging scripts.
- [ ] **Step 4:** Run config test → PASS.
- [ ] **Step 5:** **Manual check:** launch app, open the Task-1-era local capture tool pointed at this server, run `GET_INFO`/`GET_PROVIDERS` with a MUP card → responses match the SmartBox shape. Record result.
- [ ] **Step 6:** Commit.

---

## Phase 2 (out of MVP scope — needs live portal, documented, not built here)

- Confirm against the real portal: exact `GET_PIN`/`GET_TERMINAL_ID_FROM_SESSION` sub-flow, whether the backend validates `appName/appVersion` from `ON_OPEN_EVENT`, and final PURS acceptance of the produced signature.
- Browser transport hardening (PNA/WSS) if browsers tighten.
- Additional tokens (Pošta/eToken) via vendor PKCS#11 — with library signature/hash verification (Finding #5).
