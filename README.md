# SerbianEIDSigner

Log in and sign on [ePorezi](https://eporezi.purs.gov.rs) with a Serbian MUP eID card on macOS,
without SmartBox, Java or a vendor PKCS#11 module.

ePorezi talks to a local program called SmartBox over a WebSocket. This is a small native
replacement: a menu-bar app that speaks the same protocol, so the portal works with it as is.
The card is reached through CryptoTokenKit and the RSA signature is computed on the card.

Unofficial, not affiliated with PURS. Use it with your own card.

## Install

Download the DMG from [Releases](../../releases), drag the app to Applications and launch it.
An "eID" item appears in the menu bar. It starts at login; you can turn that off from its menu.

You need a PC/SC reader and a MUP eID card. macOS 13 or later.

## Use

1. Insert the card.
2. On ePorezi, choose login with a certificate (MUP).
3. Enter your PIN when the page asks for it.

The PIN goes to the card and nowhere else: it is not logged, not stored and not passed on a
command line.

## Build

```sh
swift test
swift build -c release
```

Card access needs the `com.apple.security.smartcard` entitlement, so sign the binary ad hoc
before running it:

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

The sandboxed app bundle is generated with XcodeGen from `TokenApp/project.yml`. Releases are
built by `.github/workflows/release.yml` when a `vX.Y.Z` tag is pushed (Developer ID signing,
notarization, DMG).

## How ePorezi talks to SmartBox

What follows was worked out from SmartBox 2.0.0 and checked against the live portal.

The page opens `ws://127.0.0.1:<port>` and tries **17165, 20806, 65097**. This app binds the
first free one on `127.0.0.1` and `::1`, and refuses the handshake (HTTP 403) unless `Origin` is
`https://eporezi.purs.gov.rs`.

Requests are `{"operation": ..., "input": {...}}`. Responses are
`{"operation": ..., "status": <int>, "payload": {...}}`, where `status` 0 means success.

| Operation          | Input                                 | Payload |
|--------------------|---------------------------------------|---------|
| `ON_OPEN_EVENT`    | sent by the server on connect         | `appName`, `appVersion`, `appBuild`, `osName` |
| `GET_INFO`         | `sbSession`, `host`, `language`       | `{}` |
| `GET_PROVIDERS`    |                                       | `providers: [{id, name}]` |
| `GET_TERMINALS`    | `providerId`                          | `terminals: [{id, name}]` |
| `GET_CERTIFICATES` | `pin`, `terminalId`                   | `certificates: [{alias, name}]` |
| `GET_SIGNED_XML`   | `certificate: {alias, name}`, `pin`, `xml` | `xml` |

Things that are not obvious:

- `ON_OPEN_EVENT` must announce `SmartBox` / `2.0.0`.
- `GET_CERTIFICATES` already needs the PIN. The portal shows `name` as the logged-in user, so it
  has to be the holder's name (GIVENNAME + SURNAME, or the name part of the CN).
- `GET_SIGNED_XML` has no terminal id: it uses the one from the last `GET_CERTIFICATES` on the
  same connection. Its `xml` is Base64 both ways.
- Error statuses: 1300 terminals, 1350 wrong provider, 1400 certificates, 1440 wrong PIN,
  1441 PIN blocked, 1500 signing.

### Signature

An enveloped XMLDSig over the whole document (`URI=""`), RSA-SHA256, SHA-256 digest,
inclusive C14N 1.0. Not XAdES. `KeyInfo/X509Data` holds, in this order, `X509Certificate`,
`X509IssuerSerial` and `X509SubjectName`.

Without `X509SubjectName` the login fails with "Недостају подаци о кориснику" (missing user
data): that is where the portal reads the user from.

## The card

The MUP eID card exposes a PKCS#15 applet (AID `A0 00 00 00 63 50 4B 43 53 2D 31 35`).

- File `8FFF` indexes the objects. Each record gives a class (1 = certificate, 2 = public key),
  the data file, a label and a 20-byte id shared by a certificate and its key.
- Certificate files are zlib-compressed behind a 6-byte header.
- The PIN is ASCII, padded with zeros to 8 bytes, `VERIFY` reference `80`. Only one `VERIFY` is
  sent per request: three wrong PINs block the card.
- Of the two certificates, the signing one is the one with nonRepudiation in keyUsage.
- Signing is `MSE SET` (`80 01 02`, `84` + private key FID) and then
  `PSO COMPUTE DIGITAL SIGNATURE` over the SHA-256 DigestInfo.

Card code is in `Sources/SignerCore/Card`, the XMLDSig builder (libxml2 C14N) in
`Sources/SignerCore/Sign`, and the WebSocket server (SwiftNIO) in `Sources/SignerCore/Server`.

## License

MIT. © Nenad VULIC.
