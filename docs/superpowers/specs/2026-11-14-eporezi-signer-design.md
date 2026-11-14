# Design — SerbianEIDSigner (remplaçant macOS de SmartBox pour e-porezi)

> Nom de travail : **SerbianEIDSigner** (changeable). Projet frère de SerbianEIDToken.
> Statut : brouillon de conception, en attente d'approbation.

## Intention & pourquoi

Fournir une application **macOS, open-source et communautaire** qui remplace **SmartBox**
(le middleware de signature officiel de la Poreska uprava) sur Mac, en :
- corrigeant les failles de sécurité identifiées par rétro-ingénierie de SmartBox v2.0.0 ;
- restant **compatible drop-in** avec le portail e-porezi existant (aucun changement côté PURS requis).

Même esprit et mêmes fondations que **SerbianEIDToken** (qui a comblé le manque eUprava sur Mac) :
libre, indépendant, natif, sans télémétrie.

## Objectifs

- Serveur de signature local que le portail e-porezi (`purs.gov.rs`) utilise **à la place de SmartBox**.
- **Compatibilité protocole & format** : mêmes ports, mêmes opérations, même format de signature que SmartBox,
  pour que le backend PURS accepte les signatures sans modification.
- Corriger les défauts de SmartBox :
  1. **Validation d'`Origin`** à la poignée de main WebSocket (allowlist PURS) — *fix Finding #1*.
  2. **Signature in-process** : le PIN n'est jamais passé en argument de process — *fix Finding #4*.
  3. Pas de `-Djava.security.debug=sunpkcs11` / pas de log de données sensibles.
- Réutiliser au maximum SerbianEIDToken (coquille app, installation chaîne de confiance, packaging, i18n, update check).

## Non-objectifs

- Windows / Linux (choix assumé : macOS only ; c'est un remplaçant de SmartBox **sur Mac**).
- Changer le format de signature sur le fil (XAdES) dans le MVP — voir « plus tard ».
- Signature de documents hors du flux e-porezi (PDF, etc.).

## Anti-objectifs (échec même si « ça marche »)

- Une app qui oblige PURS à modifier le portail → ce n'est plus un drop-in.
- Réintroduire une des failles de SmartBox (origine non vérifiée, PIN exposé).
- Produire des signatures que le backend PURS refuse.

## Contraintes

- **Drop-in** : le portail e-porezi parle déjà le protocole SmartBox ; on doit le reproduire fidèlement
  (ports, noms d'opérations, formes JSON, format de signature).
- **macOS 13+**, Swift, binaire universel (comme SerbianEIDToken).
- Les tokens de signature qualifiée (eToken, IDPrime, Pošta, Halcom, PKS, MUP) s'utilisent via **PKCS#11**
  (libs `.dylib` des vendeurs), pas via CryptoTokenKit.

## Approches considérées

Décision de plateforme déjà prise avec le partenaire (voir historique) :
- **A. macOS natif Swift (CHOISI)** — réutilise SerbianEIDToken ; rapide ; très propre ; limite = macOS only.
- B. Cross-platform Rust/Go — écarté : nouvelle stack, plus d'effort ; non retenu malgré la couverture OS.
- C. Cross-platform Java (comme SmartBox) — écarté : embarque une JRE, moins aligné avec l'ADN natif du partenaire.

Décision d'interface carte déjà prise : **PKCS#11 via FFI C** (CTK ne couvre pas ces tokens).

## Architecture (le « comment » décidé)

1. **Serveur WebSocket local** — SwiftNIO (`NIOWebSocketServer`), bindé `127.0.0.1`,
   port = premier libre parmi `[17165, 20806, 65097]` (= `Constants.PORTS` de SmartBox, pour le drop-in).
2. **Validation d'`Origin`** — à `upgrade`/handshake, rejeter toute connexion dont l'`Origin` n'est pas dans
   l'allowlist PURS (à confirmer dynamiquement, cf. builder). *Fix #1.*
3. **Protocole JSON** — requête `{ operation, input }`, réponse `{ operation, status, payload }`.
   Opérations reproduites à l'identique :
   | Opération | input | PIN | payload |
   |---|---|---|---|
   | `GET_INFO` | — | non | infos app (à confirmer : le portail vérifie-t-il nom/version ?) |
   | `GET_PROVIDERS` | — | non | middlewares installés |
   | `GET_TERMINALS` | `{providerId:int}` | non | lecteurs |
   | `GET_CERTIFICATES` | `{pin, terminalId:int}` | oui | `[{alias, name}]` |
   | `GET_SIGNED_XML` | `{certificate:{alias,name}, pin, xml}` | oui | XML signé |

   Valeurs `Status` connues (extraites du jar) : succès + erreurs dont
   `GET_CERTIFICATES_ERROR_1440_PIN_INCORRECT_ERROR`, `..._1441_CKR_PIN_LOCKED_ERROR`,
   `GET_TERMINALS_ERROR_1350_MIDDLEWARE_ERROR`, `GET_*_GENERIC_ERROR`, `GENERIC_UNAVAILABLE_*_ID`.
   Payload `GET_CERTIFICATES = { certificates: [ {alias, name} ] }`.
   **17 annotations `@SerializedName`** présentes → les noms sur le fil peuvent différer des champs Java :
   mapper exactement (à confirmer au spike). Transport : **`ws://` loopback en clair** pour le MVP
   (empiriquement OK — SmartBox en production l'utilise) ; WSS + cert loopback de confiance = repli si les
   navigateurs durcissent (Chrome Private Network Access, mixed-content) — à vérifier au spike.
4. **Couche PKCS#11 (FFI C)** — charger la `.dylib` du vendeur selon `CardVendor`, appeler
   `C_Initialize / C_GetSlotList / C_OpenSession / C_Login / C_FindObjects / C_Sign / C_Logout / C_Finalize`.
   **PIN gardé en mémoire, transmis uniquement à `C_Login`, effacé après usage. Jamais en argv.** *Fix #4.*
5. **Signeur XMLDSig** — produire **exactement** le profil SmartBox :
   enveloppé, `Reference URI=""` + transform `enveloped-signature`, digest **SHA-256**,
   signature **RSA-SHA256** (PKCS#1 v1.5), canonicalisation **C14N 1.0 inclusive**,
   `KeyInfo/X509Data` = certificat + `X509IssuerSerial`.
   Recommandation builder : évaluer **libxmlsec1** (xmlsec, via FFI) qui gère C14N + digest + signature et
   s'intègre à PKCS#11 ; repli = libxml2 (C14N) + Security.framework (RSA) avec `<Signature>` construit à la main.
6. **PIN & UX** — réutiliser l'approche sécurisée de SerbianEIDToken (dialogue système).
   Décision ouverte (voir plus bas) : PIN fourni par le portail sur le WS (drop-in strict) vs dialogue natif.
7. **Réutilisé de SerbianEIDToken** — **seulement le périphérique** : coquille app, installation chaîne de
   confiance (MUP CA), packaging (`make-dmg`), localisation (en/sr/sr-Latn), vérification de mise à jour.
   ⚠️ **Le cœur est net-new** : serveur WS SwiftNIO + couche PKCS#11 FFI + signeur XMLDSig n'existent pas dans
   SerbianEIDToken (qui est CTK, sans serveur). Dimensionner en conséquence. Base de réemploi =
   dépôt public `github.com/nenadvulic/SerbianEIDToken`.

## Développement & test (sans token physique)

- **Soft-token PKCS#11 (SoftHSM2)** : clé + certificat de **test**, protégés par PIN, exposés via la même FFI
  PKCS#11 → permet de développer/tester serveur WS + signeur **sans le token qualifié physique**.
  Signatures de test uniquement (non acceptées par PURS).
- **Production = QSCD obligatoire** : les tokens qualifiés (eToken, IDPrime, Pošta, Halcom, PKS) ont une clé
  privée **non-exportable, liée au matériel**. On **ne peut pas** émuler/cloner le vrai token ; le token
  physique est requis au moment de signer pour de vrai. L'app ne contourne pas cette protection.

## Faits confirmés en live (capture Chrome ↔ SmartBox, 2026-11-14)

Protocole réel observé sur le portail e-porezi (handshake + frames WS) :
- Handshake : `GET ws://localhost:17165/` → `101`, `Server: TooTallNate Java-WebSocket`, `permessage-deflate`.
- **`Origin: https://eporezi.purs.gov.rs`** → valeur exacte pour l'allowlist (SmartBox l'accepte sans la vérifier = Finding #1).
- `status` sur le fil = **numérique**, `0` = succès.
- Séquence :
  - `↓ ON_OPEN_EVENT {status:0, payload:{appName:"SmartBox", appVersion:"2.0.0", appBuild:1, osName:"Mac OS X", ...}}`
  - `↑ GET_INFO {input:{sbSession:"<uuid>", host:"eporezi.purs.gov.rs", language:"sr-Cyrl-RS"}}`
  - `↓ GET_INFO {status:0, payload:{}}`
  - `↑ GET_PROVIDERS` → `↓ {status:0, payload:{providers:[]}}`
- Le portail **relaie** chaque réponse vers son backend : `POST /startWebSocket` avec
  `{requestTypeFromUser, message}`. Le serveur PURS orchestre via `sbSession`.
- Ports essayés par le portail, dans l'ordre : `17165 → 20806 → 65097` (confirme la RE).
- Erreur affichée si les 3 ports échouent : « Конекција са читачем картице није успостављена ».

**Détection middleware (macOS) — notre spec `GET_PROVIDERS`.** SmartBox vérifie l'existence de 3 `.dylib` :
- `/Applications/tokenadmin.app/Contents/Frameworks/libaetpkss.dylib` (Pošta / A-Trust-Athena)
- `/Library/Frameworks/eToken.framework/Versions/A/libIDPrimePKCS11.dylib` (eToken / IDPrime)
- `/Applications/Personal.app/Contents/Frameworks/libtokenapi.dylib` (Gemalto Classic Client → MUP/Halcom/PKS)
Il génère un `pkcs11.cfg` (`name = … / library = … / slot = …`) pour configurer SunPKCS11.

## ⚠️ Découverte majeure — MUP non supporté sur macOS par SmartBox (pivot de conception)

`MUPSmartCard` ne définit **qu'un chemin Windows** (`C:\Program Files\TrustEdgeID\netsetpkcs11_x64.dll`) ;
son **chemin macOS est vide** → `isMiddlewareInstalled()` renvoie toujours faux sur Mac → `GET_PROVIDERS`
n'inclut jamais MUP. **SmartBox ne supporte donc pas le token MUP sur macOS.** C'est le trou que ce projet comble.

**Conséquence sur l'architecture (change une décision antérieure) :**
- Pour **MUP sur macOS il n'existe pas de PKCS#11 vendeur** → l'approche « PKCS#11 via FFI vers `.dylib` vendeur »
  **ne s'applique pas à MUP**. Il faut **accéder à la carte directement** (CryptoTokenKit / PC/SC / APDU),
  c.-à-d. **réutiliser le cœur de SerbianEIDToken** (qui lit déjà la carte MUP sur Mac).
- Le réemploi de SerbianEIDToken passe donc de « périphérique seulement » à **central** pour la cible MUP.
- PKCS#11 FFI reste pertinent **uniquement** si on veut supporter d'autres tokens (Pošta/eToken) qui, eux,
  ont un `.dylib` macOS. Décision de périmètre MVP = probablement **MUP d'abord** (la vraie valeur).
- ✅ **RÉSOLU (confirmé par le propriétaire)** : la carte MUP expose **auth + signature qualifiée**
  (clé nonRepudiation + certificat qualifié). Le MVP est donc faisable : on lit la **clé de signature**
  de la carte en direct (CTK/PC-SC/APDU) et on signe le XML. Reste à implémenter l'opération de signature
  (SerbianEIDToken ne faisait que l'auth — le signing est net-new, mais sur une base carte déjà maîtrisée).

## Plus tard (hors MVP)

- Profil **XAdES-B/-T** (SigningTime, SigningCertificateV2, politique, horodatage) si/quand PURS l'accepte.
- Canonicalisation exclusive.
- Éventuel durcissement : jeton d'appairage par session en plus de l'`Origin`.

## Première étape recommandée (spike, jetable)

Capturer le trafic réel **e-porezi ↔ SmartBox** (WebSocket loopback) lors d'une signature légitime, pour
**confirmer** : le format exact de `GET_INFO`, si le portail vérifie l'identité de l'app, si le PIN est
réellement envoyé par le portail, l'allowlist d'`Origin`, **le schéma de transport** (`ws://` en clair vs
exigences navigateur PNA/mixed-content), et **les noms sur le fil** (valeurs `status`, mapping `@SerializedName`,
sensibilité à la casse) des 4 opérations. De-risque tout le reste.
Rappel : toute la spec protocole/signature vient de **décompilation statique** (pas d'exécution) → le spike est
**load-bearing**, à faire avant d'implémenter.

## Laissé au builder

- Choix précis de la lib de signature (xmlsec1 vs libxml2+Security) après évaluation.
- Détails d'implémentation SwiftNIO / module map FFI PKCS#11.
- Gestion d'erreurs/timeouts, cycle de vie du serveur, intégration menu/tray.

## Décisions qui restent au partenaire (à trancher)

**Ressources / faisabilité — RÉSOLU (R1) :**
- Le partenaire dispose de **token qualifié + PIN + SmartBox installé** (pas de compte e-porezi actif requis
  à ce stade).
- **Le spike peut être piloté en local** : se connecter directement au WS de SmartBox et déclencher
  `GET_PROVIDERS/TERMINALS/CERTIFICATES/SIGNED_XML` (XML de test bénin, PIN saisi en local par le partenaire).
  → capture du protocole exact (formes, `status`, `@SerializedName`, `GET_INFO`) **et** production d'une
  **signature SmartBox connue-bonne**.
- **R2 (acceptation) — repli validé** : la signature connue-bonne ci-dessus sert de référence pour
  **comparaison octet-à-octet** du format produit par notre app, sans dépôt réel. Acceptation backend PURS
  confirmée en **phase 2** (accès portail).
- **Portal-gated → phase 2** (nécessite accès e-porezi réel) : `Origin` réelle du portail, application d'une
  identité via `GET_INFO`, source réelle du PIN (portail vs natif), acceptation backend finale.

**Conception :**
1. **Source du PIN** : depuis le portail via le WS (drop-in strict, comme SmartBox) **ou** dialogue natif
   (plus sûr, écart UX possible). Change le modèle de sécurité.
2. **Périmètre des tokens au MVP** : tous les `CardVendor` ou un sous-ensemble pour démarrer ?
3. **Compat `GET_INFO`** : à vérifier au spike — si le portail rejette une app inconnue, il faudra peut-être
   refléter l'identité/version de SmartBox dans la réponse.
