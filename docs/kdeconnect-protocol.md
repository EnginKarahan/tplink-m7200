# KDE Connect protocol: a virtual "phone" device talking to a local kdeconnectd 26.08.1

Source of truth: `kdeconnect-kde` at tag **v26.08.1** (commit `2b5cd7f7c306a25d9a8c3be78870944fc4582e06`).
The installed package on this host is `kdeconnectd-26.08.1-1.fc44`. It ships the same plugin set as the source tree (`/usr/lib64/qt6/plugins/kdeconnect/*.so`).
All `file:line` references are relative to the root of that source tree.

Cross-check of the phone side: `kdeconnect-android` master (commit `501aee79…`, 2026-11-12), cited as `android:<path>:<line>`.
That source only shows what a real phone sends. Wherever it disagrees with the desktop C++ source, the C++ source wins.

Scope: LAN backend, protocol version 8, and the plugins `sms`, `notifications`, `battery`, `connectivity_report` (plus `telephony`, only to explain why it does not apply).

---

## 0. TL;DR: the recommended connection strategy for a localhost bridge

1. **The bridge opens the TCP connection itself, to `127.0.0.1:<kdeconnectd tcpPort>`.** That port is the first free one in 1716..1764; it is 1716 on this host today.
   * The TCP server has no loopback filter (`core/backends/lan/server.cpp:22-32`, `lanlinkprovider.cpp:479-502`).
   * The UDP path does have one: UDP identity packets from 127.0.0.0/8 or ::1 are dropped (`lanlinkprovider.cpp:284-285`).
2. Send the plaintext identity line. Then act as **TLS server**, because kdeconnectd calls `startClientEncryption()` (`lanlinkprovider.cpp:573`).
3. After the handshake, kdeconnectd sends its identity over TLS. You send your identity over TLS (protocol v8, `lanlinkprovider.cpp:411-449`).
4. The deadline is **1 s** from TCP accept to TLS `encrypted` (`lanlinkprovider.cpp:492-500`).
5. Then either:
   * send `kdeconnect.pair {"pair":true,"timestamp":<unix s>}`, and the user clicks *Accept* in the Plasma notification; or
   * if already paired, just start sending packets.
6. Keep the socket open. kdeconnectd never connects to you on its own, so on disconnect you reconnect yourself (§8).

---

## 1. Wire format

### 1.1 Packet framing and JSON structure

* **Serialization** (`core/networkpacket.cpp:43-63`):
  * one compact JSON object per packet (`QJsonDocument::Compact`, `:55`), followed by a single `\n` (`:59`);
  * fields: `id`, `type`, `body`, plus `payloadSize` and `payloadTransferInfo`, but only when the packet has a payload (`:50-53`, `hasPayload()` means `payloadSize != 0`, `core/networkpacket.h:78-81`).
* **`id`** is `QDateTime::currentMSecsSinceEpoch()` (`networkpacket.cpp:46`). On receive it is **ignored**: `unserialize` only reads `type`, `body`, `payloadSize` and `payloadTransferInfo` (`:75-79`). Send any integer; ms-epoch is conventional.
* **`body`** is a JSON object and becomes a `QVariantMap` (`:76`).
  * JSON integers arrive as `qlonglong`, floats as `double`, and booleans as `bool`.
  * Getters convert as needed: `QVariant::toInt()` on `true` gives 1, and `toInt()` on `"2"` gives 2.
* **`payloadSize`** is read with `toInteger()` and defaults to 0 (`:77`). The value `-1` means an endless stream (`networkpacket.h:85`).
* **`payloadTransferInfo`**, if present, is `{"port": N}`. The receiver then opens a second TLS connection to the sender's IP and that port to pull the payload (`core/backends/lan/landevicelink.cpp:134-150`). **Not needed for SMS, battery, connectivity or notifications without icons; never send it.**
* **deviceId sanitising on every received packet.** If `body` contains `deviceId`, every character outside `[A-Za-z0-9_]` is replaced by `_` (`networkpacket.cpp:81-86`, `core/dbushelper.cpp:31-35`).
* **Receive loop** of an established link (`landevicelink.cpp:117-154`):
  * reads `while canReadLine()`, so lines must not contain raw newlines (compact JSON escapes them);
  * the maximum line is **32 MiB** (`:21`, `:119-122`).
* **Identity packets on the handshake path** are limited to **8192 bytes** (`lanlinkprovider.cpp:45`, `:416-420`, `:508-513`).
* **Protocol packets**: only `kdeconnect.identity` and `kdeconnect.pair` are "protocol packets" (`networkpacket.h:102-105`, `core/networkpackettypes.h:10-11`).

### 1.2 Protocol version

`NetworkPacket::s_protocolVersion = 8` (`core/networkpacket.cpp:33`).

There is no minimum-version check. Protocol 7 is still accepted (`lanlinkprovider.cpp:411`, `:450-453`; `pairinghandler.cpp:51`, `:188`), but `Device` logs a warning when the version differs from 8 (`core/device.cpp:70-73`).

**Downgrade protection:** if a *trusted* device connects with a protocolVersion lower than the stored one, the connection is refused (`lanlinkprovider.cpp:322-327`, `:549-554`, `:576-580`; the stored value is written by `kdeconnectconfig.cpp:177`). **Always send 8.**

### 1.3 Identity packet

Built by `DeviceInfo::toIdentityPacket()` (`core/deviceinfo.h:123-133`) and parsed by `FromIdentityPacketAndCert()` (`deviceinfo.h:135-147`).

| field | type | rules |
|---|---|---|
| `deviceId` | string | Must match `^[a-zA-Z0-9_-]{32,38}$` (`deviceinfo.h:162-166`). This is checked **after** the sanitising in §1.1, so a `-` silently becomes `_`. **Use only `[a-z0-9_]`, 32–38 characters.** Real devices use 32 lowercase hex characters: the desktop uses `QUuid::Id128` lowercased (`kdeconnectconfig.cpp:379-380`), Android a UUID without dashes (`android:helpers/DeviceHelper.kt:134`). It must equal the certificate CN (§3). |
| `deviceName` | string | `filterName()` removes the characters `"',;:.!?()[]<>` and truncates to **32** characters (`deviceinfo.h:149-154`). It must be non-empty after filtering, otherwise the identity is invalid (`deviceinfo.h:156-160`). |
| `deviceType` | string | `"desktop"`, `"laptop"`, `"phone"` (or `"smartphone"`), `"tablet"` or `"tv"`; anything else becomes Unknown (`deviceinfo.h:26-39`). Use **`"phone"`**. |
| `protocolVersion` | int | `8`. A missing value is read as -1 or 0, depending on the call site (`deviceinfo.h:144`, `lanlinkprovider.cpp:323`, `:410`). |
| `incomingCapabilities` | string[] | Packet types **you accept**. The desktop only sends packet types that appear in this list (`core/device.cpp:360-363`). |
| `outgoingCapabilities` | string[] | Packet types **you send**. |
| `tcpPort` | int | Only meaningful in **UDP** identity packets: it must be in 1716..1764, otherwise the packet is ignored (`lanlinkprovider.cpp:316-320`). It is not checked on the TCP path. |
| `targetDeviceId`, `targetProtocolVersion` | string / int | Optional, TCP path only. If present they must equal kdeconnectd's own id and `8` (`lanlinkprovider.cpp:536-545`). kdeconnectd itself sends them when it is the TCP client (`:370-372`). |

Validation that rejects an identity: `isValidIdentityPacket` requires all of the following (`deviceinfo.h:156-160`):

* `type == "kdeconnect.identity"`;
* a non-empty filtered `deviceName`;
* a valid `deviceId`.

Further rejections:

* UDP only: your deviceId equals kdeconnectd's own id (`lanlinkprovider.cpp:304-307`);
* the size exceeds 8192 bytes;
* the v8 TLS identity differs from the plaintext one in `deviceId` or `protocolVersion` (`:434-445`);
* the certificate CN differs from `deviceId` (`:639-645`).

**Capabilities matter twice:**

1. **Which desktop plugins get loaded** (`core/pluginloader.cpp:89-120`). A plugin is loaded if either intersection is non-empty:
   * your `outgoingCapabilities` ∩ the plugin's `X-KdeConnect-SupportedPacketType`, or
   * your `incomingCapabilities` ∩ the plugin's `X-KdeConnect-OutgoingPacketType`.

   If **both** of your lists are empty, *all* plugins are assumed (`:91-95`).
2. **Capability updates on reconnect.** When a known device reconnects, its capabilities are only updated if **both** lists are non-empty (`core/device.cpp:319-328`).

Desktop plugin metadata relevant here (from the plugin JSON files):

| plugin (`KPlugin.Id`) | desktop *receives* (`SupportedPacketType`) | desktop *sends* (`OutgoingPacketType`) | file |
|---|---|---|---|
| kdeconnect_sms | `kdeconnect.sms.messages`, `kdeconnect.sms.attachment_file` | `kdeconnect.sms.request`, `kdeconnect.sms.request_conversations`, `kdeconnect.sms.request_conversation`, `kdeconnect.sms.request_attachment` | `plugins/sms/kdeconnect_sms.json:141-151` |
| kdeconnect_notifications | `kdeconnect.notification` | `kdeconnect.notification.request`, `kdeconnect.notification.reply`, `kdeconnect.notification.action` | `plugins/notifications/kdeconnect_notifications.json:162-170` |
| kdeconnect_battery | `kdeconnect.battery` | `kdeconnect.battery` | `plugins/battery/kdeconnect_battery.json:144-149` |
| kdeconnect_connectivity_report | `kdeconnect.connectivity_report` | *(none)* | `plugins/connectivity-report/kdeconnect_connectivity_report.json:155-158` |
| kdeconnect_telephony | `kdeconnect.telephony` | `kdeconnect.telephony.request_mute` | `plugins/telephony/kdeconnect_telephony.json:158-163` |

All of these plugins are `EnabledByDefault: true`.

**Recommended identity for the M7200 bridge:**

```json
{"id":1762946400000,"type":"kdeconnect.identity","body":{
  "deviceId":"3f9c2a7e5b1d4c8e9a0b6f2d4e8c1a7b",
  "deviceName":"TP-Link M7200",
  "deviceType":"phone",
  "protocolVersion":8,
  "incomingCapabilities":["kdeconnect.sms.request","kdeconnect.sms.request_conversations",
                          "kdeconnect.sms.request_conversation","kdeconnect.notification.request",
                          "kdeconnect.notification.reply","kdeconnect.notification.action"],
  "outgoingCapabilities":["kdeconnect.sms.messages","kdeconnect.notification",
                          "kdeconnect.battery","kdeconnect.connectivity_report"]}}
```

With exactly these lists, the desktop loads `sms`, `notifications`, `battery`, `connectivity_report` and `screensaver_inhibit`. The last one has empty capabilities, so it always loads, but it is disabled by default. Computed against all 31 plugin JSONs.

Notes on the list:

* `kdeconnect.notification.action` is only needed if you send `actions`.
* Do **not** put `kdeconnect.notification` into incoming. That would load `sendnotifications` (it is disabled by default anyway).
* Optionally add `kdeconnect.battery` to incoming if you want the laptop's own battery state (`plugins/battery/batteryplugin.cpp:80-84`).
* Optionally add `kdeconnect.ping` to both lists for a "send ping" debug button (`plugins/ping/pingplugin.cpp:22-45`, body `{"message":"…"}` optional).

What kdeconnectd sends as **its** identity:

* deviceId = CN of `~/.config/kdeconnect/certificate.pem` (`kdeconnectconfig.cpp:111-114`); on this host that is a 32-hex-character CN;
* name from config `name=` or the hostname (`:64-71`);
* type `desktop` unless `PLASMA_PLATFORM` says otherwise (`:94-109`);
* protocolVersion 8;
* capabilities = the union of all installed plugin JSONs (`kdeconnectconfig.cpp:136-147`, `pluginloader.cpp:69-87`).

---

## 2. Discovery and connection

### 2.1 Ports and sockets of kdeconnectd

* **UDP 1716** (`lanlinkprovider.h:67`), bound to `QHostAddress::Any` (dual-stack `*:1716`) with `ShareAddress`, i.e. `SO_REUSEADDR` (`lanlinkprovider.cpp:128-137`).
* **TCP server** on the first free port in **1716..1764** (`lanlinkprovider.h:68-69`, `lanlinkprovider.cpp:139-147`), also dual-stack Any. `ss -ltnup` on this host shows `kdeconnectd` on `*:1716` for both TCP and UDP.
* The test-mode loopback binding (`:128`) is not used by the real daemon (`core/daemon.cpp:85`: `LanLinkProvider(false, …)`).

### 2.2 The two handshake directions (and the TLS role inversion)

**Rule: whoever *opened* the TCP connection sends its identity in plaintext and is the TLS *server*.**

**Path A: kdeconnectd is the TCP client.** It received your UDP identity (`lanlinkprovider.cpp:275-341`, `358-401`).

1. You send a UDP identity (with `tcpPort`) to port 1716.
2. kdeconnectd `connectToHost(sender, tcpPort)` (`:331-339`).
3. kdeconnectd writes **its** identity in plaintext, plus `targetDeviceId` = your id and `targetProtocolVersion` = your version (`:370-373`).
4. kdeconnectd calls `startServerEncryption()`: **kdeconnectd is the TLS server, you are the TLS client** (`:381-391`).
5. If the TCP connection fails, kdeconnectd falls back to sending its own UDP identity back to `sender:1716` (`:343-354`, `:395-396`).

**Path B: you are the TCP client.** You connect to kdeconnectd's TCP port (`lanlinkprovider.cpp:479-574`).

1. On accept, a **1000 ms single-shot timer** starts. If the TLS `encrypted` signal has not fired when it expires, the socket is aborted (`:492-500`).
2. You write **your** identity in plaintext, one line. kdeconnectd reads exactly **one** line (`:515-520`) and validates it (`:531-554`).
3. kdeconnectd then disconnects its plaintext reader and calls `startClientEncryption()`: **kdeconnectd is the TLS client, you are the TLS server** (`:559-573`).
4. kdeconnectd sends **nothing** in plaintext on this path.

**Protocol v8 second identity exchange (both paths)** (`lanlinkprovider.cpp:403-454`):

1. Right after `encrypted`, kdeconnectd writes its own identity over TLS (`:411-414`). It contains no `tcpPort` and no `target*` fields.
2. It waits for one line from you over TLS (`:415-433`). That line must be a valid identity, with the same `protocolVersion` (`:434-439`) and the same `deviceId` (`:440-445`) as the plaintext one.
3. **The name, type and capabilities that kdeconnectd actually keeps come from this TLS identity** (`:446`).
4. `addLink()` then requires `peerCertificate().subjectDisplayName()` (after sanitising) to equal `deviceId` (`:639-645`).

The protocol version that decides whether this exchange happens comes from the *plaintext/UDP* identity (`:410`).

**What travels in plaintext:**

* Path A: your UDP identity, then kdeconnectd's TCP identity line.
* Path B: your identity line only.

Everything after that is TLS.

### 2.3 UDP from 127.0.0.1 or from the host itself

* `if (sender.isLoopback() && !m_testMode) continue;` (`lanlinkprovider.cpp:284-285`). Datagrams whose **source** is 127/8 or ::1 are **silently dropped**.
* The **only** other self-filter is the deviceId (`:304-307`). There is no IP-based filter, so a datagram sent **from one of the host's non-loopback addresses** (e.g. bound to the WLAN IP) is accepted. kdeconnectd then TCP-connects back to that IP and `tcpPort`.
* Nothing in the code blocks a second device on the same host or IP:
  * links are keyed by deviceId (`:652`);
  * the UDP rate limit is per deviceId, 500 ms (`:49`, `:309-314`);
  * the only cap is 42 simultaneous unpaired links (`:47`, `:662-668`).
* Downsides of Path A for a bridge:
  * it needs an up, non-loopback IPv4 address (none exists when offline);
  * your TCP server must listen on a reachable address with a port in 1716..1764, which exposes it on the LAN.

  **Path B (connect to 127.0.0.1) has neither problem and is recommended.**

### 2.4 "Custom devices" / add-by-IP

* **Storage:** key `customDevices` (a QStringList) in `~/.config/kdeconnect/config` (QSettings INI, group `[General]`) (`kdeconnectconfig.cpp:58`, `:267-276`). For example `customDevices=127.0.0.1`; several entries are comma-separated.
* **D-Bus:** property `customDevices` (read/write) on `org.kde.kdeconnect` `/modules/kdeconnect` `org.kde.kdeconnect.daemon` (`core/daemon.h:28`; setter at `daemon.cpp:286-298`). The setter triggers a re-broadcast.
* **GUI:** the 26.08.1 source contains no GUI that sets it (`grep customDevices` hits only core/ and dbusinterfaces/).
* **Behaviour:** the entries are **IP addresses only, with no port** (`QHostAddress(customDevice)`, `lanlinkprovider.cpp:218-225`). kdeconnectd only **sends its UDP identity** to `<ip>:1716` (`:250-271`; destination port is always `UDP_PORT`, `:258`).
* kdeconnectd **does not open TCP to custom devices**. The custom device must react to the datagram by TCP-connecting to kdeconnectd's `tcpPort`, i.e. Path A with roles reversed, which is the same as Path B.
* Sending happens only:
  * at start (`:149`);
  * on network changes (`:88-98`, `:167-194`);
  * on `setCustomDevices`, `setAnnouncedName` or `forceOnNetworkChange` over D-Bus (`daemon.cpp:136-143`, `:277-298`).
* The datagram is sent once **per up, non-loopback IPv4 interface address**, with that address as source (`lanlinkprovider.cpp:230-248`). So when only `lo` is up, **nothing is sent at all**.
* To receive it on 127.0.0.1 you would have to bind UDP `127.0.0.1:1716` next to kdeconnectd's `*:1716` socket, using `SO_REUSEADDR`. Which socket gets the unicast datagram is then Linux kernel behaviour (see §9).
* **Conclusion:** custom devices only *announce* kdeconnectd. They are not an alternative to the bridge connecting itself; at most they are a "kdeconnectd (re)started" hint.
* (mDNS is similar: kdeconnectd announces `_kdeconnect._udp` with TXT `id`, `name`, `type`, `protocol` and SRV port = tcpPort (`avahidiscovery.cpp:135-149`). On discovering a peer it only sends a UDP identity to it (`avahidiscovery.cpp:238`).)

### 2.5 Sequence for Path B (recommended)

```
bridge (TCP client, TLS server)                  kdeconnectd (TCP server, TLS client)
  connect 127.0.0.1:1716 ------------------------> accept, start 1000 ms timer
  {"type":"kdeconnect.identity",...}\n ----------> readLine, validate
  <================= TLS handshake (kdeconnectd sends ClientHello) =================>
                                                   encrypted -> timer deleted
  <---------- {"type":"kdeconnect.identity",...}\n  (its identity, over TLS)
  {"type":"kdeconnect.identity",...}\n ----------> same deviceId + protocolVersion, CN check
                                                   -> LanDeviceLink, Device (paired / not paired)
  ... wait a little (see §9 "stuck line") ...
  {"type":"kdeconnect.pair","body":{"pair":true,"timestamp":...}}\n   (if not yet paired)
```

---

## 3. TLS and certificates

**What kdeconnectd generates for itself** (use the same shape) (`core/sslhelper.cpp:29-81`, `:139-257`; `kdeconnectconfig.cpp:345-404`):

* EC key on **prime256v1 / P-256** (`sslhelper.cpp:45`). RSA-2048 generation also exists (`:87-136`); old configs use `keyAlgorithm=RSA` (`kdeconnectconfig.cpp:149-157`).
* X.509 **v3** (`sslhelper.cpp:148-152`), random 160-bit serial (`:161`), **no extensions**.
* Subject = issuer = `CN=<deviceId>, O=KDE, OU=KDE Connect` (`:178-195`, self-signed).
* notBefore = now − 1 year, notAfter = now + 10 years (`:208-210`).
* Signed with SHA-512 (`:233`).
* The local cert on this host matches: `CN=…, O=KDE, OU=KDE Connect`, `prime256v1`, `ecdsa-with-SHA512`.

**What it expects from the peer:**

* **CN must equal deviceId.** `addLink` compares `peerCertificate().subjectDisplayName()`, i.e. the CN if present (else O, else OU), after `[^A-Za-z0-9_]`→`_` sanitising, with the identity's deviceId and aborts on mismatch (`lanlinkprovider.cpp:639-645`). O and OU are not checked.
* **Self-signed is fine.**
  * Untrusted peers: `QueryPeer`, no verification (`lanlinkprovider.cpp:600-602`). On Path B the `sslErrors` handler is not even connected for untrusted peers (`:569-571`).
  * Trusted peers: `VerifyPeer` with the CA list = **only the pinned certificate** (`:596-599`), plus `setPeerVerifyName(deviceId)` (`:604`). In the `sslErrors` handler (`:456-475`) a `SelfSignedCertificate` error is not flagged fatal. The handler never calls `ignoreSslErrors()`, so per Qt semantics any reported error still ends the handshake.
  * In practice, for a trusted peer your cert must chain to itself as the pinned trust anchor, and (Qt client mode, i.e. Path B) the CN must match the peer verify name. Verification is done by Qt and OpenSSL, not by kdeconnect code (§9).
* **Validity dates matter.**
  * For trusted devices, OpenSSL's VerifyPeer checks the dates.
  * At daemon start, trusted devices whose stored cert is not yet valid or already expired are **deleted** (`daemon.cpp:100-111`, `device.cpp:332-336`). The check is `effectiveDate() >= now`, so **notBefore must be in the past**.
* **Key type.** No code restriction exists; the verification key uses `publicKey().toDer()` (§4). Use **EC P-256** (like the desktop) or RSA ≥ 2048 (Fedora crypto-policies). Avoid Ed25519 (§9).
* **TLS version and ciphers.** The code sets none: `grep setProtocol|setCiphers` finds nothing. `configureSslSocket` builds a fresh `QSslConfiguration` with only the local cert, key, CA and verify mode (`lanlinkprovider.cpp:589-613`). Qt 6 defaults therefore apply (TLS 1.2+), plus Fedora's system OpenSSL policy. TLS 1.3 with Python's defaults works.
* **Client certificate.** kdeconnectd always presents its own cert (`setLocalCertificate`, `:593-594`). In Qt server mode (Path A) with Query/VerifyPeer it requests yours; in VerifyPeer mode you must send one.

**Pinning and storage** (`~/.config/kdeconnect/`, QSettings INI; `kdeconnectconfig.cpp:55-62`, `:116-124`):

* `privateKey.pem`, `certificate.pem`: kdeconnectd's own identity. Its CN is kdeconnectd's deviceId, also available as D-Bus `selfId()` (`daemon.h:52`).
* `config`: `[General] name=`, `keyAlgorithm=EC`, optional `customDevices=`, `disabled_providers_v2=` (`:91`).
* `trusted_devices`: one INI group per deviceId with `certificate="<PEM, \n-escaped>"`, `name=`, `type=`, `protocolVersion=` (`:172-184`, `:186-199`). The cert is pinned from the TLS peer cert at pairing time (`device.cpp:249-255`, `deviceinfo.h:135-147`).
* `<deviceId>/config`: per-device plugin enable flags, `[Plugins] kdeconnect_smsEnabled=true|false` (`device.cpp:213-216`, `:448-469`). Plugin subdirectories follow the pattern `<deviceId>/<plugin>/` (`kdeconnectconfig.cpp:284-289`).
* **If you change your key or cert after pairing, the link fails** (VerifyPeer against the old pin). Persist the bridge's key and cert.

**Getting kdeconnectd's certificate on the bridge side** (needed for the verification key and optional pinning):

* Path A (you are the TLS client): from the handshake, even with `CERT_NONE`, as binary DER.
* Path B (you are the TLS server): the stdlib `ssl` module cannot "request a client cert but not verify it" (§9). Either:
  * read `~/.config/kdeconnect/certificate.pem` (same user); or
  * request the client cert with that file loaded as the only trust anchor.

---

## 4. Pairing

`core/backends/pairinghandler.cpp`, `core/device.cpp`, `daemon/desktop_daemon.cpp`.

**Packet bodies** (type `kdeconnect.pair`):

| meaning | body | source |
|---|---|---|
| request | `{"pair":true,"timestamp":<unix seconds, int>}` | desktop builds it at `pairinghandler.cpp:113-118` |
| accept | `{"pair":true}` (no timestamp) | `:132` |
| reject / cancel / unpair / timeout | `{"pair":false}` | `:148`, `:156`, `:163` |

**Receiving logic on the desktop** (`pairinghandler.cpp:28-88`):

* Any pair packet stops the timeout (`:30`).
* `pair:true` while the desktop state is `Requested` (the desktop asked) completes pairing (`:34-35`). No timestamp is checked in this case.
* `pair:true` while `RequestedByPeer` is ignored as a duplicate (`:37-39`).
* `pair:true` while **`Paired`**:
  * the desktop **unpairs first** (emits unpaired, removes trust) and treats the packet as a new request (`:40-49`);
  * **never send `pair:true` for an already-paired link.**
* `pair:true` while `NotPaired`, with v ≥ 8:
  * `timestamp` must be present, otherwise the desktop unpairs (`:51-57`);
  * it must be within **±1800 s** of the desktop clock, otherwise it fails with "Device clocks are out of sync" (`:16`, `:58-63`).
  * After that the state becomes `RequestedByPeer`, a 30 s timer starts, and `incomingPairRequest` is emitted (`:66-68`).
* `pair:false`: `Requested`/`RequestedByPeer` become failed ("Canceled by other peer"); `Paired` becomes unpaired, which removes the device from `trusted_devices` (config dir kept) (`:71-86`, `device.cpp:265-272`, `kdeconnectconfig.cpp:232-237`).

**Device-initiated pairing (what the bridge should do):**

1. Once the link is up and the device is not trusted, send the request with the current timestamp.
2. kdeconnectd shows a persistent KNotification: "Pairing request from <name>\nKey: <VERIFICATION KEY>", with actions **Open / Accept / Reject**. It auto-closes after 30 s (`daemon/desktop_daemon.cpp:30-55`, wired at `daemon.cpp:335-339`). The request also appears in the app and applet (`Daemon::pairingRequests`, `daemon.cpp:346-354`).
3. Accept sends `{"pair":true}`, and the device is stored as trusted (`device.cpp:249-255`).
4. Reject sends `{"pair":false}` (`device.cpp:237-241`, `pairinghandler.cpp:144-151`).
5. Timeout (**30 s**, `pairinghandler.h:20`) sends `{"pair":false}` (`pairinghandler.cpp:161-167`).

**Desktop-initiated pairing:** the desktop sends `{"pair":true,"timestamp":T}`. The bridge may auto-accept by replying `{"pair":true}`. The desktop accepts that in state `Requested` without checking further fields (`:34-35`). Desktop timeout: 30 s.

**Before pairing completes, send nothing but `kdeconnect.pair`.** Any other packet from an unpaired device makes the desktop call `unpair()`. That sends `{"pair":false}` and kills a pending request (`device.cpp:391-394`). Plugins are only instantiated for paired and reachable devices (`device.cpp:160`).

**Verification key** (`pairinghandler.cpp:176-195`; identical in `android:PairingHandler.kt:247-266`):

```
A = DER SubjectPublicKeyInfo of kdeconnectd's cert public key   (QSslKey::toDer of a public key)
B = DER SubjectPublicKeyInfo of the bridge's cert public key
(hi, lo) = (A, B) if A >= B else (B, A)          # bytewise unsigned lexicographic compare
key = SHA256(hi || lo || ascii_decimal(timestamp)).hexdigest()[:8].upper()
```

* The timestamp is the one carried in the **request** packet (yours, if you initiated) (`pairinghandler.cpp:52`, `:113`). It is appended as the decimal string, e.g. `b"1762946400"` (`:189-191`).
* For protocol < 8 the timestamp is omitted (`:188`).
* In Python: `cert.public_key().public_bytes(DER, SubjectPublicKeyInfo)`; `bytes` comparison already matches.

**Unpair from the bridge:** send `{"pair":false}`. The desktop then removes the trust.

**Unpair from the desktop:** you receive `{"pair":false}`. Delete your stored pairing state. Plugins are unloaded, but the link stays open while unpaired.

---

## 5. SMS (desktop `plugins/sms`, `models/conversationmessage.*`, `smsapp/`)

### 5.1 Capability requirements

* The SMS app lists devices that are **paired, reachable and have `kdeconnect_sms` loaded** (`smsapp/qml/Main.qml:49-53`, `models/devicespluginfilterproxymodel.cpp:9-13`).
* The plugin loads given the capability rule in §1.3. In practice:
  * outgoing must contain `kdeconnect.sms.messages`;
  * incoming must contain `kdeconnect.sms.request`, `kdeconnect.sms.request_conversations` and `kdeconnect.sms.request_conversation`. Otherwise `Device::sendPacket` drops those requests (`device.cpp:360-363`).
* `kdeconnect.sms.request_attachment` and `kdeconnect.sms.attachment_file` are only needed for MMS attachments.

### 5.2 Desktop → phone

| type | body | source |
|---|---|---|
| `kdeconnect.sms.request_conversations` | `{}` (empty) | `smsplugin.cpp:88-93`; triggered when the SMS app opens or refreshes (`smsapp/conversationlistmodel.cpp:95-104`) |
| `kdeconnect.sms.request_conversation` | `{"threadID":<int64>,"rangeStartTimestamp":<int64 ms>,"numberToRequest":<int64>}` (always all three keys) | `smsplugin.cpp:95-103` |
| `kdeconnect.sms.request` | `{"version":2,"addresses":[{"address":"<str>"},…]}` plus optional `"messageBody":"<str>"` (omitted when the text is empty, `:61-63`), optional `"subID":<int64>` (only if not -1, `:65-67`), optional `"attachments":[{"fileName","base64EncodedFile","mimeType"}]` (`:69-81`) | `smsplugin.cpp:50-86`, `SMS_REQUEST_PACKET_VERSION 2` (`smsplugin.h:95`) |
| `kdeconnect.sms.request_attachment` | `{"part_id":<int64>,"unique_identifier":"<str>"}` | `smsplugin.cpp:105-112` (only for messages that carry `attachments`) |

Notes on these requests:

* **`rangeStartTimestamp` and `numberToRequest` semantics** as the desktop uses them (`plugins/sms/conversationsdbusinterface.cpp:174-187`):
  * nothing cached for the thread: `-1` ("newest") and `25` (`MIN_NUMBER_TO_REQUEST`, `conversationsdbusinterface.h:29`);
  * otherwise: the **date of the oldest cached message**, and the number of cached messages (minimum 25).
  * The desktop therefore wants messages **older than or equal to** that timestamp, newest first. That is what Android does: `date <= ?`, `ORDER BY date DESC`, limit n (`android:plugins/sms/SMSPlugin.kt:229-247`, `android:helpers/SMSHelper.kt:106-147`).
  * The C++ header doc says ">= this value" (`smsplugin.h:161`); follow the Android behaviour instead.
  * Via D-Bus `SmsPlugin.requestConversation` the defaults are `-1/-1` (`smsplugin.h:164`), so also handle `numberToRequest < 0`, meaning "all".
* **`subID` vs `sub_id`:** the code sends **`subID`** (`smsplugin.cpp:66`). The header doc still says `sub_id` (`smsplugin.h:83`). Its value is the `sub_id` of the reference message, which is the oldest cached message of the thread (`conversationsdbusinterface.cpp:195-211`). If messages carry no `sub_id`, it is -1 and the key is omitted (`conversationmessage.cpp:28-29`).
* **Who gets the message:** reply-to-thread sends to the `addresses` of the oldest cached message (`conversationsdbusinterface.cpp:204-211`). A "new conversation" sends to the addresses the user typed (`:242-245`, `smsapp/conversationmodel.cpp:112-127`). Multiple addresses are possible (group).

Examples:

```json
{"id":1762946500000,"type":"kdeconnect.sms.request_conversations","body":{}}
{"id":1762946501000,"type":"kdeconnect.sms.request_conversation","body":{"threadID":17,"rangeStartTimestamp":-1,"numberToRequest":25}}
{"id":1762946502000,"type":"kdeconnect.sms.request_conversation","body":{"threadID":17,"rangeStartTimestamp":1762800000000,"numberToRequest":25}}
{"id":1762946503000,"type":"kdeconnect.sms.request","body":{"version":2,"addresses":[{"address":"+4917612345678"}],"messageBody":"Bin gleich da","subID":1}}
```

### 5.3 Phone → desktop: `kdeconnect.sms.messages`

Body: `{"version":2,"messages":[<Message>,…]}`. The desktop ignores `version`, but Android sends 2 (`android:SMSPlugin.kt:401-408`, `smsplugin.h:24`). Only `messages` is read (`smsplugin.cpp:114-128`).

The `Message` fields as parsed by `ConversationMessage(QVariantMap)` (`models/conversationmessage.cpp:14-46`):

| key | parsed as | meaning / rules |
|---|---|---|
| `event` | `toInt()` | Bit flags (`conversationmessage.h:79-81`): `0x1` = text body present, **required for the body to be shown** (`smsapp/conversationlistmodel.cpp:209-210`, `conversationmessage.h:146-149`); `0x2` = multi-target (group). Plain SMS: `1`. |
| `body` | `toString()` | message text |
| `addresses` | list of `{"address":str}` | Non-empty, **otherwise the conversation row is dropped** (`conversationlistmodel.cpp:178-182`). Excludes the user's own number. Incoming group: the first entry is the sender (`smsplugin.h:32-39`). |
| `date` | `toLongLong()` | epoch **milliseconds** |
| `type` | `toInt()` | Android `MESSAGE_TYPE_*` (`conversationmessage.h:64-71`): 1 = inbox (incoming), 2 = sent, 3 = draft, 4 = outbox, 5 = failed, 6 = queued. 2–6 count as outgoing (`conversationmessage.cpp:84-87`). `-1` rows are skipped by the list (`conversationlistmodel.cpp:171-175`). |
| `read` | `toInt()` | 0/1 (a bool is fine) |
| `thread_id` | `toLongLong()`, but **truncated to `qint32`** in the cache (`conversationsdbusinterface.cpp:88`) | stable conversation id; keep it in 1..2^31-1 |
| `_id` | `toInt()` (**qint32**) | unique message id; **dedup key per thread** (`conversationsdbusinterface.cpp:97-100`, `smsapp/conversationmodel.cpp:182-185`) |
| `sub_id` | `toLongLong()`, default -1 | SIM id; echoed back as `subID` |
| `attachments` | list of `{"part_id":int64,"mime_type":str,"encoded_thumbnail":base64 str,"unique_identifier":str}` | optional, MMS only (`conversationmessage.cpp:31-45`) |

Android serialises all of these as JSON numbers (`android:helpers/SMSHelper.kt:881-894`).

**How the desktop merges messages** (`ConversationsDbusInterface::addMessages`, `conversationsdbusinterface.cpp:83-130`). There is **no notion of "listing complete" vs. "single conversation reply"**: every `kdeconnect.sms.messages` packet is merged the same way. For each message:

1. Its `thread_id` is marked "updated" (`:95`).
2. If `_id` is already known for the thread, the message is skipped (`:97-100`).
3. Otherwise it is stored in a `QMap<date, message>` per thread (`:104`, `conversationsdbusinterface.h:156`). **Two messages with the same `date` in a thread overwrite each other.**
4. A new thread emits `conversationCreated`. A message that is now the newest in its thread emits `conversationUpdated` (`:108-115`). Older messages emit neither; they only enter the cache.
5. For every thread in the packet, `conversationLoaded(threadId, count)` is emitted, and **any requester waiting for that thread is woken** (`:120-129`).

**Consequences for the reply strategy:**

* **`request_conversations`:** reply with the newest message of every thread. Android sends **one `kdeconnect.sms.messages` packet per thread**, each with a single message (`android:SMSPlugin.kt:215-226`). One big packet also works; it is the same merge. There is no end marker.
* **`request_conversation`:** the desktop worker thread **blocks without timeout** until some `kdeconnect.sms.messages` contains at least one message with that `thread_id` (`conversationsdbusinterface.cpp:143-193`, called from `requestconversationworker.cpp:48-66`).
  * **Always answer with ≥ 1 message of that thread.** The boundary message itself (`date <= rangeStartTimestamp`) satisfies this even when nothing older exists.
  * An empty `messages` array leaves that thread's history permanently stuck: later requests "join the existing wait" (`:147-155`).
* **New incoming SMS (live update):** push a `kdeconnect.sms.messages` with that message. Android pushes all messages newer than the last seen timestamp, but only after the desktop has requested messages once (`android:SMSPlugin.kt:106-133`).
  * Its `date` must be **greater than** every cached date in that thread, otherwise no `conversationUpdated` fires and the open conversation view does not update (`:108-115`).
  * Unknown `thread_id` → `conversationCreated`, so a new row appears in the list.
* **Sent SMS:** after `kdeconnect.sms.request` the desktop adds **nothing** locally (`smsapp/conversationmodel.cpp:101-127`). **You must echo the sent message** as `kdeconnect.sms.messages` with `type:2`, the thread's `thread_id`, a new `_id` and the current date.
  * For a new conversation, use a new `thread_id`. The SMS app adopts it if the first address matches what the user typed (`conversationmodel.cpp:260-269`).
  * On failure, push `type:5`.

Examples:

```json
{"id":1762946600000,"type":"kdeconnect.sms.messages","body":{"version":2,"messages":[
  {"event":1,"body":"Hallo, bist du schon da?","addresses":[{"address":"+4917612345678"}],
   "date":1762946590123,"type":1,"read":0,"thread_id":17,"_id":4711,"sub_id":1}]}}

{"id":1762946610000,"type":"kdeconnect.sms.messages","body":{"version":2,"messages":[
  {"event":1,"body":"Bin gleich da","addresses":[{"address":"+4917612345678"}],
   "date":1762946609000,"type":2,"read":1,"thread_id":17,"_id":4712,"sub_id":1}]}}
```

### 5.4 Not needed but present

* `kdeconnect.sms.attachment_file` (phone → desktop, with a payload; `smsplugin.cpp:130-160`): only for MMS.
* Contact names in the SMS app come from KPeople/vCards, synced by the separate `contacts` plugin (`kdeconnect.contacts.*`). Without it, numbers are shown (`conversationlistmodel.cpp:243-247`).

---

## 6. New-SMS popup with inline reply: notifications, not telephony

* `kdeconnect.telephony` with `event:"sms"` is **ignored** ("old style sms packet", `plugins/telephony/telephonyplugin.cpp:81-84`). Telephony only handles `ringing`, `missedCall` and `talking`, plus `isCancel` (`:20-79`).
* A real Android phone produces an SMS popup **via the notifications plugin**: it mirrors the SMS app's Android notification and attaches a `requestReplyId` when the notification has a RemoteInput (`android:plugins/notifications/NotificationsPlugin.kt:230-304`; `requestReplyId` = random UUID, `RepliableNotification.kt:13`).

### 6.1 Phone → desktop: `kdeconnect.notification`

Parsed in `plugins/notifications/notification.cpp:225-246`:

| key | type | effect |
|---|---|---|
| `id` | string | Notification key; a repeated `id` **updates** the existing popup (`notificationsplugin.cpp:48-64`). |
| `appName` | string | shown as the app name (`x-kde-display-appname`, `notification.cpp:92-95`) |
| `title`, `text` | string | popup title and body |
| `ticker` | string | fallback text, also the quoted text in the reply dialog (`notificationsplugin.cpp:157`) |
| `isClearable` | bool | If true, a dismiss on the desktop sends a cancel request back (`notification.cpp:51-56`). |
| `silent` | bool | If true, no popup; listed only (`notification.cpp:58-65`). |
| `requestReplyId` | string | **Non-empty adds an inline "Reply" action** (`KNotificationReplyAction`, `notification.cpp:116-131`). |
| `actions` | string[] | optional buttons (`notification.cpp:133-140`, `:242-245`) |
| `conversation` | `[{"sender":str,"content":str},…]` | optional messaging style; title becomes `groupName` or the first sender (`notification.cpp:82-85`, `:188-213`, `notification.h:134-142`) |
| `groupName` | string | optional (group chats) |
| `payloadHash` | string | **Omit it.** If set, the desktop expects an icon payload and tries to download it (`notification.cpp:142-148`, `:239`). |
| `isCancel` | bool | `{"id":…, "isCancel":true}` removes the notification (`notificationsplugin.cpp:39-46`) |

Android also sends `time` (a string, ms), which the desktop does not read.

### 6.2 Desktop → phone

| type | body | when |
|---|---|---|
| `kdeconnect.notification.request` | `{"request":true}` | every time the plugin is (re)loaded, i.e. on (re)connect of a paired device (`notificationsplugin.cpp:27-31`). The phone should (re)send its active notifications. |
| `kdeconnect.notification.request` | `{"cancel":"<id>"}` | the user dismissed a clearable notification (`notificationsplugin.cpp:140-151`) |
| `kdeconnect.notification.reply` | `{"requestReplyId":"<id>","message":"<text>"}` | inline reply, or reply via the fallback dialog (`notificationsplugin.cpp:98-105`, `:153-176`) |
| `kdeconnect.notification.action` | `{"key":"<notification id>","action":"<action label>"}` | an action button was clicked (`notificationsplugin.cpp:178-186`) |

**Bridge flow for an incoming SMS:**

1. Push `kdeconnect.sms.messages` (§5.3).
2. Push `kdeconnect.notification` with a `requestReplyId` mapped to the sender or thread.
3. On `kdeconnect.notification.reply`:
   * send the SMS;
   * echo it as `kdeconnect.sms.messages` with `type:2`;
   * optionally send `{"id":…,"isCancel":true}` to close the popup.

```json
{"id":1762946600500,"type":"kdeconnect.notification","body":{
  "id":"sms-thread-17","appName":"SMS (M7200)","title":"+49 176 12345678",
  "text":"Hallo, bist du schon da?","ticker":"+49 176 12345678: Hallo, bist du schon da?",
  "isClearable":true,"silent":false,"time":"1762946590123",
  "requestReplyId":"5b0f3c1e-7a51-4c3b-9a43-0f7c2b1d9e10"}}

{"id":1762946620000,"type":"kdeconnect.notification.reply","body":{"requestReplyId":"5b0f3c1e-7a51-4c3b-9a43-0f7c2b1d9e10","message":"Bin gleich da"}}
{"id":1762946630000,"type":"kdeconnect.notification","body":{"id":"sms-thread-17","isCancel":true}}
{"id":1762946640000,"type":"kdeconnect.notification.request","body":{"request":true}}
{"id":1762946650000,"type":"kdeconnect.notification.request","body":{"cancel":"sms-thread-17"}}
```

---

## 7. Battery and connectivity report

### 7.1 `kdeconnect.battery` (phone → desktop)

Read at `plugins/battery/batteryplugin.cpp:134-154`:

* `isCharging` (bool, default false);
* `currentCharge` (int 0..100, default -1, which means no battery);
* `thresholdEvent` (int: 0 = none, 1 = battery low; `batteryplugin.h:47-50`).

A low-battery KDE Connect notification is shown only when `thresholdEvent==1 && !isCharging` and Plasma's Solid backend is not already handling it (`:142-153`).

**There is no request packet anymore.** The desktop's battery plugin never asks; its `connected()` only sends the *desktop's own* battery (`:80-132`). The README's `"request": true` is stale (`plugins/battery/README`). **Push on connect (after pairing) and on every change.** Android behaves the same way (`android:plugins/battery/BatteryPlugin.kt:69-78`).

```json
{"id":1762946700000,"type":"kdeconnect.battery","body":{"currentCharge":87,"isCharging":false,"thresholdEvent":0}}
```

Desktop → phone (only if you list `kdeconnect.battery` in incoming, and only from machines with a battery) (`batteryplugin.cpp:119-131`):

```json
{"id":…,"type":"kdeconnect.battery","body":{"isCharging":true,"currentCharge":64,"batteryQuantity":1,"thresholdEvent":0}}
```

### 7.2 `kdeconnect.connectivity_report` (phone → desktop)

Read at `plugins/connectivity-report/connectivity_reportplugin.cpp:49-65`:

* **`signalStrengths`** is an object keyed by subscription id (a string). The desktop only uses **the first entry in key order** (`QVariantMap` is sorted: `subscriptions.first()`, `:51-53`).
* Each entry is `{"networkType":str,"signalStrength":int}` (`:58-59`).
* **Signal strength scale 0..4**, mapped to icons `network-mobile-{0,20,60,80,100}`. `-1` (the default) means `network-mobile-off` (`:28-36`, `connectivity_reportplugin.h:64`).
* **networkType:** the icon suffix exists only for `"5G"`, `"LTE"`, `"HSPA"`, `"UMTS"`, `"EDGE"` and `"GPRS"` (`:38-44`). Android also sends `"CDMA"`, `"GSM"`, `"iDEN"` and `"Unknown"` (`android:plugins/connectivityreport/ASUUtils.kt:21-32`); the README adds `"CDMA2000"`.
* The `refreshed` signal fires only on change (`:61-63`).
* **There is no request packet.** The plugin has no outgoing types (`kdeconnect_connectivity_report.json:155`); the README's `.request` is stale. **Push on connect and on change.**

```json
{"id":1762946800000,"type":"kdeconnect.connectivity_report","body":{"signalStrengths":{"1":{"networkType":"LTE","signalStrength":3}}}}
```

---

## 8. Keepalive, idle and disconnect

* **No application-level keepalive and no idle timeout.** The only timers in core and the LAN backend are the 1 s handshake timer and the upload-job timeout (`grep QTimer core/*.cpp core/backends/lan/*.cpp`). Your device does **not** need to send anything periodically.
* kdeconnectd enables **TCP keepalive** on every LAN socket: idle 30 s, interval 10 s, 3 probes, so a dead peer is detected after about 60 s (`lanlinkprovider.cpp:615-635`). On loopback the kernel answers these probes as long as your process holds the socket.
* **When TCP closes:**
  1. `LanDeviceLink` deletes itself (`landevicelink.cpp:41-47`).
  2. `Device::removeLink` unloads all plugins and emits `reachableChanged(false)` (`device.cpp:342-354`). This discards the SMS cache, which lives in the plugin's `ConversationsDbusInterface`.
  3. Unpaired devices are removed entirely (`daemon.cpp:262-275`).
* **kdeconnectd never reconnects to a peer by itself.** It only re-announces over UDP at start or on network change (§2.4). **The bridge must reconnect on its own**; use a backoff of about 1 s → 30 s (also covers kdeconnectd restarts, where its TCP port may change).
* A new connection for a deviceId that still has a link **replaces the old socket in place**, provided the certificate is unchanged (`lanlinkprovider.cpp:652-660`, `landevicelink.cpp:31-49`). Aggressive reconnects are therefore harmless.
* **No periodic UDP re-broadcast is needed** in Path B. Android also only broadcasts at start or on network change (`android:backends/lan/LanLinkProvider.kt:597`, `:625`).
* **On every (re)connect of a paired device**, kdeconnectd reloads plugins (`device.cpp:289-298`) and calls `connected()`. You will receive:
  * `kdeconnect.notification.request {"request":true}`;
  * optionally the desktop's battery.

  Then push battery, connectivity and current notifications. The SMS app re-requests conversations when it is (re)opened.

---

## 9. Gotchas (ordered by how likely they are to break a minimal Python implementation)

1. **UDP from 127.0.0.1 is silently ignored** (`lanlinkprovider.cpp:284-285`). Use Path B: TCP to 127.0.0.1, plaintext identity, then **TLS server**.
2. **The 1 s deadline** from TCP accept to TLS completion, with no log beyond a warning (`lanlinkprovider.cpp:492-500`). Do not wait for anything between the plaintext identity and the handshake.
3. **TLS role inversion in Python asyncio.**
   * `StreamWriter.start_tls()` picks `server_side` from who *accepted* the TCP connection (`/usr/lib64/python3.14/asyncio/streams.py:406`). For KDE Connect that is the wrong role in both paths.
   * Use `loop.start_tls(..., server_side=…)` explicitly, or `loop.connect_accepted_socket(sock=…, ssl=server_ctx)` on a socket you connected yourself. Alternatively, do the handshake with a blocking `SSLContext.wrap_socket(server_side=True)`.
   * Also make sure no bytes of kdeconnectd's ClientHello are consumed by a plaintext `StreamReader` before TLS starts.
4. **Python `ssl` server mode** cannot "request a client cert without verifying it".
   * Either use `CERT_NONE` and read kdeconnectd's cert from `~/.config/kdeconnect/certificate.pem`, or use `CERT_OPTIONAL` with that file as the only CA.
   * Do not build contexts with `ssl.create_default_context()`. It sets `VERIFY_X509_STRICT | VERIFY_X509_PARTIAL_CHAIN` (`/usr/lib64/python3.14/ssl.py:727-728`). kdeconnect certs are v3 **without any extensions**, and strict mode may reject them (not verified). Construct `SSLContext(PROTOCOL_TLS_SERVER/CLIENT)` directly, with `check_hostname=False`.
5. **deviceId and certificate CN.**
   * The deviceId must be 32–38 characters of `[A-Za-z0-9_]` (a `-` is rewritten to `_` before the length/regex check and the CN check) (`deviceinfo.h:162-166`, `networkpacket.cpp:81-86`, `dbushelper.cpp:31-35`).
   * The CN must equal the deviceId (`lanlinkprovider.cpp:639-645`).
   * With a `-` in the CN, pairing may succeed, but after pairing the Qt client-mode host-name check against the stored, sanitised id would fail (Qt behaviour, inferred).
6. **Certificate shape.**
   * Self-signed, notBefore in the past (`device.cpp:332-336`, `daemon.cpp:104-107`), notAfter far in the future, persisted forever (it is pinned).
   * Use EC P-256 or RSA-2048. Ed25519 is risky: `QSslCertificate::publicKey()` most likely yields no usable key, which breaks the verification key (not verified).
   * The safest choice is to mirror `sslhelper.cpp:139-257` exactly: v3, no extensions, `CN=id, O=KDE, OU=KDE Connect`.
7. **Never send a non-pair packet while unpaired.** The desktop answers with `unpair()`, i.e. `{"pair":false}` (`device.cpp:391-394`). **Never send `pair:true` while paired**: the desktop unpairs first (`pairinghandler.cpp:40-49`). Persist the paired state; react to `{"pair":false}` by clearing it.
8. **The pair request needs `timestamp` in unix seconds** within ±30 min (`pairinghandler.cpp:51-63`). The verification key includes that timestamp as a decimal string.
9. **"Stuck line" after the v8 TLS identity (inferred from code).**
   * kdeconnectd reads exactly one line in a temporary `readyRead` handler, then hands the socket to `LanDeviceLink`, which only reacts to *future* `readyRead` signals (`lanlinkprovider.cpp:415-449`, `landevicelink.cpp:31-49`).
   * If your identity and your next packet (e.g. the pair request or battery) arrive in the same read, the second packet sits unprocessed until more data arrives.
   * Send the TLS identity alone and pause briefly (≈ 250–500 ms) before the next packet. For paired links, the arrival of `kdeconnect.notification.request` is a good "link is up" signal.
10. **SMS cache quirks** (`conversationsdbusinterface.cpp:83-130`, `conversationmessage.cpp:14-46`):
    * `_id` is a **qint32** and the dedup key per thread. Missing `_id` means everything is `0` and only one message survives.
    * `thread_id` is **truncated to qint32**; values above 2^31-1 break lookups.
    * Messages are stored in a `QMap` keyed by `date`. **Equal ms dates in one thread overwrite each other**, so make dates unique per thread (the M7200 likely has second resolution).
    * `event` must have bit `0x1`, otherwise the text is not shown.
    * `addresses` must be non-empty.
    * A known `_id` is never updated, e.g. for read-state changes.
11. **Always answer `request_conversation` with ≥ 1 message of that thread.** Otherwise a desktop thread blocks forever (`conversationsdbusinterface.cpp:143-193`).
12. **Live updates require monotonic dates.** Only a message newer than everything cached in its thread emits `conversationUpdated` (`:108-115`). An SMS whose SMSC timestamp is older than the last sent message will not appear live; consider using the receive time.
13. **Echo sent SMS yourself** as `type:2`. The SMS app does not insert them optimistically (`smsapp/conversationmodel.cpp:101-127`).
14. **`subID`, not `sub_id`, in `kdeconnect.sms.request`** (`smsplugin.cpp:66` vs. the stale doc at `smsplugin.h:83`). `messageBody` is absent for attachment-only sends.
15. **No `.request` packets for battery or connectivity.** Both READMEs are stale; push the data yourself.
16. **The desktop only sends packet types listed in your `incomingCapabilities`** (`device.cpp:360-363`). Both capability lists must be non-empty for updates (`device.cpp:319-328`).
17. **MMS and group threads.**
    * Plain SMS should always use `event:1` and a single address.
    * The user can still start a conversation with several recipients. `kdeconnect.sms.request` then carries several `addresses`, and the M7200 cannot do MMS: decide whether to fan out individual SMS or answer with `type:5` (failed).
    * If you fan out but echo the send as one "group" message, give it its own `thread_id`, `event:3` (`0x1|0x2`) and all recipients in `addresses`. The list merges non-multi-target messages of an unknown thread into an existing row by the first address (`conversationlistmodel.cpp:185-192`).
    * `kdeconnect.sms.request_attachment` only arrives if you send `attachments`, so do not.
18. **Do not set `payloadHash` in notifications** (there is no payload; `notification.cpp:142-148`, `:239`).
19. **protocolVersion: always 8.** A trusted device that later announces a lower version is refused (`lanlinkprovider.cpp:576-580`). Version 7 still works for new devices but skips the TLS identity exchange and the pairing timestamp.
20. **Recent code worth knowing.** These are present in 26.08.1, but the shallow clone has no history to date them:
    * TCP keepalive tuning (`lanlinkprovider.cpp:620-634`, BUG 476747);
    * reply-to-uncached-conversation fetch with 3 retries (`conversationsdbusinterface.cpp:207-240`, BUG 517659);
    * the guard against empty conversations (`requestconversationworker.cpp:34-43`);
    * Bluetooth and loopback providers disabled by default (`kdeconnectconfig.cpp:87-91`).

### Could not be confirmed from the kdeconnect source (depends on Qt, OpenSSL or Linux)

* Qt's client-mode host-name check (`HostNameMismatch`) for trusted peers: the CN must match `setPeerVerifyName(deviceId)`. This is Qt-internal; the real-world evidence is that Android ids with `_` work.
* That `QSslKey::toDer()` of a public key yields SubjectPublicKeyInfo DER for EC and RSA, and an empty result for Ed25519. Android's `publicKey.encoded` is SPKI and interoperates, which supports the first part.
* Linux unicast delivery between kdeconnectd's `*:1716` (dual-stack, `SO_REUSEADDR`) and a bridge socket bound to `127.0.0.1:1716`. This only matters for the custom-device "poke" idea, which is not recommended.
* Whether OpenSSL 3.5 `X509_STRICT` (Python's default context) rejects extension-less v3 self-signed certs.
* The `QVariantList` → `QJsonArray` conversion behind `np.get<QJsonArray>("conversation"/"actions")`. Android's `conversation`/`actions` fields work with the desktop in practice.
