# Midea Wi-Fi module: provisioning and LAN control without the cloud

This documents two things that, as far as I can find, weren't public before:

1. **Provisioning a current Midea Wi-Fi module onto your network without the app.** Newer modules
   ignore the old `0x0068` setup command and want a `0x0070` command with a locally derived "random
   code".
2. **Controlling a V3 module on the LAN without a cloud token.** A module that has never been bound
   to Midea's cloud accepts a handshake keyed on your Wi-Fi credentials and its own MAC, so no
   token/key ever has to come from Midea.

Everything else (packet framing, encryption, the V3 transport, the appliance frames) was already
known, mostly through [msmart-ng](https://github.com/mill1000/midea-msmart). It's repeated here so
this document stands on its own.

- [Status and sources](#status-and-sources)
- [Shared building blocks](#shared-building-blocks)
- [Discovery](#discovery)
- [Provisioning over the setup AP](#provisioning-over-the-setup-ap)
- [LAN control without a cloud token](#lan-control-without-a-cloud-token)
- [Quirks](#quirks)
- [Open questions](#open-questions)

## Status and sources

Verified end to end on **one unit**: a Midea MWFF28H window air conditioner (New Zealand, 2025),
whose Wi-Fi module also advertises over Bluetooth LE. Its discovery reply reports `udpVersion` 2,
flags `87 00`. It was provisioned with `provision.py`, has never reached the internet (blocked at
the router), and is controlled daily with `ac.ts`.

How it was worked out:

- Static analysis of **Midea Air 5.45.0** (`com.midea.aircondition`), which bundles the same IoT
  SDK as MSmartHome but isn't packed. MSmartHome itself is wrapped by a commercial packer in every
  published version. Class names below are jadx's names for that build (obfuscated), so you can
  check the claims yourself.
- Midea's own [2017 Android SDK](https://github.com/midea-sdk-org/android-sdk), which contains the
  legacy provisioning commands.
- msmart-ng's implementation of the framing and the V3 transport.

No app was installed or run, and nothing talked to Midea's servers at any point.

## Shared building blocks

### Keys

| Name       | Value                                                          |
|------------|----------------------------------------------------------------|
| `SIGN_KEY` | ASCII `xhdiwjnchekd4d512chdjx5d8e4c394D2D7S` (also in msmart-ng) |
| `ENC_KEY`  | `MD5(SIGN_KEY)`, used for AES-128-ECB with PKCS#7 padding      |
| signature  | `MD5(packet_without_signature ‖ SIGN_KEY)`                     |

### The 5A5A packet

Every message to or from the module is wrapped in this, both in AP mode and on the LAN. On the LAN,
a V3 module additionally wraps it in an encrypted `8370` frame (see below).

| Offset | Size | Field                                                 |
|--------|------|-------------------------------------------------------|
| 0      | 2    | `5A 5A`                                               |
| 2      | 2    | `01 11` (version 1; encrypted and signed)             |
| 4      | 2    | total length, little-endian                           |
| 6      | 2    | message type, little-endian (`0x0020` = appliance data) |
| 8      | 4    | message ID (zero is fine)                             |
| 12     | 8    | timestamp, cosmetic                                   |
| 20     | 6+2  | device ID, little-endian, padded to 8 bytes           |
| 28     | 12   | zero                                                  |
| 40     | n    | `AES-128-ECB(ENC_KEY, payload)`                       |
| 40+n   | 16   | signature                                             |

Replies use message type `0x8000 | request`.

## Discovery

Send this fixed 72-byte blob (msmart-ng's) to UDP port 6445 on the module:

```
5a5a011148009200 + 32 zero bytes + 7f75bd6b3e4f8b762e849c6e578d6590036e9d4342a50f1f569eb8ec918e92e5
```

The reply is a 5A5A packet. A module that speaks V3 on the LAN wraps it in an 8-byte header starting
`83 70` and adds a 16-byte trailer, so strip those first. Some modules ignore broadcast discovery
and only answer unicast.

Decrypt the payload. With `L` = the byte at offset 40 (the length of the module's own SSID), the
fields that matter are below (parser: `MSDeviceScanResult.parseDataBytes()`):

| Offset          | Field                                                      |
|-----------------|------------------------------------------------------------|
| 4–5             | TCP control port, little-endian (6444)                     |
| 8–39            | serial number, ASCII                                       |
| 41 … 40+L       | the module's AP SSID                                       |
| 43+L            | flags 1                                                    |
| 44+L            | flags 2                                                    |
| 45+L … 48+L     | **`udpVersion`**, 32-bit little-endian                     |
| 55+L            | appliance type (`0xAC` = air conditioner)                  |
| 63+L … 68+L     | **module MAC**                                             |

The device ID comes from the packet header (offset 20). It's 0 in AP mode on a fresh module. Once
my unit was on the LAN it reported a different, MAC-derived ID.

Flag bits (flags 1): bit 0 extra auth, bit 1 **extra channel**, bit 2 extra last-error-code, bit 3
re-enter config, bit 4 supports the `0x0071` status query, bit 5 region ID, bit 7 **enable extra**.
The "extra" features and region ID only count when bit 7 is set. Flags 2: bit 0 function-set (again
gated on flags 1 bit 7), bit 3 ADNS, bit 4 combination.

## Provisioning over the setup AP

Put the appliance in AP mode. On the window AC that means holding SWING for 3 s until the display
shows `AP`; other appliances use other buttons. The window lasts about 8 minutes. The module then
runs:

- SSID `net_XX_YYYY` or `midea_XX_YYYY` (`XX` = appliance type in hex), WPA2, passphrase `12345678`
- itself at `192.168.1.1`, handing out addresses by DHCP
- the control port on TCP 6444

That `192.168.1.0/24` collides with many home LANs and VPNs, so pin your sockets to the Wi-Fi
interface (`SO_BINDTODEVICE` on Linux), or traffic may go somewhere else entirely.

**`udpVersion` from discovery picks the command set** (`config/ap/ad.java` loads
`MSDeviceV<udpVersion>APConfigTask`):

| `udpVersion` | Commands                                         | Status here                    |
|--------------|--------------------------------------------------|--------------------------------|
| 0            | legacy `0x0043` + `0x0068` + `0x0081`            | from the 2017 SDK, untested    |
| 2, 3         | `0x0070`                                         | `2` verified                   |
| ≥ 4          | `0x0070` over TLS                                | not covered                    |

A `udpVersion` 2 module silently ignores the legacy commands.

### Legacy (udpVersion 0)

From the 2017 SDK (`MSDeviceV0APConfigTask` in the newer app), all on one TCP connection:

1. `0x0043`, write device ID, only if it's 0: 32-byte SN followed by a 6-byte ID. The app makes the
   ID locally: the little-endian bytes of Java's `String.hashCode()` of the SN, then the appliance
   type, then `FF`.
2. `0x0068`, write Wi-Fi: `[security (2 = WPA-PSK), ssidLen, pskLen, ssid…, psk…]`. Reply payload
   byte 0 is 0 on success.
3. `0x0081`, switch to station mode: `[02]`. The connection may drop instead of replying.

### Current: `0x0070` (udpVersion ≥ 2)

One message on the TCP connection, with no device-ID write and no switch command (`MSDeviceV2APConfigTask`,
payload built in `local/a/e.java`). The header uses the device ID from discovery. Plaintext payload:

```
[16]  random code
[1]   ssid length (UTF-8)       [n] ssid (UTF-8)
[1]   passphrase length         [n] passphrase
[1]   06                        [6] router BSSID
[1]   ssid length (GBK)         [n] ssid (GBK); same bytes as above for ASCII SSIDs
[1]   router channel            only if flags 1 bit 7 AND bit 1 are set
[3]   01 01 01                  TLV: "check password" = 1
```

The **random code** is 2 random bytes followed by the first 14 bytes of
`MD5(router_BSSID_6_bytes ‖ passphrase_UTF-8)` (`config/a.java`). It's computed entirely
locally; the module presumably recomputes it to check the passphrase. The channel is the router's
2.4 GHz channel number (1–13).

Further TLVs (country code, time zone, channel list, region ID, server domain/port, ADS servers)
only go in when the module's flags ask for them (function-set, region ID, or `udpVersion` 3). They
mostly point the module at Midea's cloud. A module that sets those flags isn't covered here.

Reply `0x8070`: payload byte 0 is `0` on success and `4` for a wrong passphrase. The module then
leaves AP mode and joins the router by itself.

Worked example: SSID `test`, passphrase `password123`, BSSID `aa:bb:cc:dd:ee:ff`, no channel byte,
with the two random bytes shown as `00 00`:

```
00007374f4e6211a073db73e42f9204e 04 74657374 0b 70617373776f7264313233 06 aabbccddeeff 04 74657374 010101
```

## LAN control without a cloud token

After joining the network, my module answered discovery in V3 form and **only** accepted V3
sessions. A plain 5A5A `0x0020` query got no reply. Every existing project gets the V3 token and key
from Midea's cloud (`iot/secure/getToken`, looked up by `udpid`).

The app only does that when it already holds a token for the device. Otherwise it logs
`isGotR3 = false, 通过默认秘钥协商` ("negotiate with the default key") and runs the **same handshake
with a key derived from the Wi-Fi credentials** (`com.midea.iot.sdk.i3`, key in `d3.a`, logged as
`getR3`):

```
R3 = SHA-256( UTF-8(router SSID) ‖ UTF-8(router passphrase) ‖ module MAC (6 bytes, natural order) )
```

The handshake runs on TCP 6444 before anything else (`d3`, `b3`, AES in `y2`, SHA-256 in `z2`):

1. Pick 32 random bytes `A`.
2. Send 72 bytes: `83 70 00 40 20 00 00 00` ‖ `AES-256-CBC(key = R3, IV = 0, no padding, A)` ‖ `SHA-256(A)`.
3. Read 72 bytes back. `B = AES-256-CBC-decrypt(key = A, IV = 0, reply[8..39])`, and check that
   `SHA-256(B) == reply[40..71]`. A wrong R3 gets an error packet (type `0xF`) instead.
4. Session key = `A XOR B`.

This is exactly msmart-ng's V3 handshake with `token = AES-256-CBC(R3, A) ‖ SHA-256(A)` and `key = A`.
Calling its `authenticate(token, key)` with those values works unchanged.

After the handshake, the usual V3 framing applies:

- header `83 70 <length BE16> 20 <pad << 4 | type>`, with types `0` handshake request, `1` handshake
  response, `3` encrypted response, `6` encrypted request, `F` error
- encrypted body: a 2-byte big-endian packet counter, the data, and random padding to a multiple of
  16, under `AES-256-CBC(session key, IV = 0)`
- a trailer of `SHA-256(header ‖ plaintext body)`

The data is a 5A5A packet (type `0x0020`) carrying the appliance's `0xAA` frame. The AC frames
(`0x41` state query, `0x40` set state, `0xC0` state report) are the ones msmart-ng documents in code,
and `ac.ts` ports them.

## Quirks

- With its internet blocked at the router, the module has kept working. Others have reported
  offline units boot-looping; that hasn't happened here so far.
- The module occasionally drops a request while the AC changes state (seen once on power-on right
  after power-off). Resending the full set-state frame fixes it, and the frame is idempotent.
- The module didn't answer broadcast discovery on the LAN, only unicast.
- An appliance set command always carries the complete state: query first, change, then send it all
  back.

## Open questions

- **Do cloud-bound modules also accept the default key?** If they do, nobody with the Wi-Fi
  passphrase needs Midea's cloud at all. I can't test it: my unit has never been bound.
- Does a factory reset turn a cloud-bound module back into an unbound one?
- `udpVersion` 3 and ≥ 4 (TLS), and the flag-dependent TLVs.
- Other appliance types (dehumidifiers and the like) use the same modules and probably behave the
  same, but that's untested.
