#!/usr/bin/env -S python3 -I
"""Put a Midea Wi-Fi module onto your Wi-Fi network over its setup AP, without the app or cloud.

Put the appliance in AP mode first (window AC: hold SWING for 3 s until the display shows AP; the
window lasts about 8 minutes). Linux + NetworkManager. Protocol: PROTOCOL.md.
"""
import argparse, getpass, os, re, socket, struct, subprocess, sys, time
from datetime import datetime, timezone
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util import Padding

IFACE     = "wlan0"
NM_CONN   = "midea-provision"   # temporary profile, deleted afterwards
AP_PSK    = "12345678"          # Midea's fixed setup-AP passphrase
AP_RE     = re.compile(r"^(net|midea)_[0-9a-fA-F]{2}_[0-9A-Fa-f]{4}$")
AC_IP     = "192.168.1.1"       # module address on its own AP
AC_PORT   = 6444
DISC_PORT = 6445

SIGN_KEY = b"xhdiwjnchekd4d512chdjx5d8e4c394D2D7S"
ENC_KEY  = md5(SIGN_KEY).digest()

MSG_WRITE_ID     = 0x0043   # udpVersion 0
MSG_WRITE_WIFI   = 0x0068   # udpVersion 0
MSG_SWITCH_STA   = 0x0081   # udpVersion 0
MSG_WRITE_WIFI_2 = 0x0070   # udpVersion 2

SEC_PSK = 2

DISCOVERY_MSG = bytes.fromhex("5a5a011148009200" + "00" * 32
                              + "7f75bd6b3e4f8b762e849c6e578d6590036e9d4342a50f1f569eb8ec918e92e5")

WRITE_WIFI_2_ERRORS = {4: "wrong password"}

_msg_id = 0


def encrypt(data: bytes) -> bytes:
    return AES.new(ENC_KEY, AES.MODE_ECB).encrypt(Padding.pad(data, 16))


def decrypt(data: bytes) -> bytes:
    return Padding.unpad(AES.new(ENC_KEY, AES.MODE_ECB).decrypt(data), 16)


def timestamp() -> bytes:
    n = datetime.now(timezone.utc)
    return bytes([n.microsecond // 10000, n.second, n.minute, n.hour, n.day, n.month, n.year % 100, n.year // 100])


def packet(msg_type: int, device_id: int, payload: bytes) -> bytes:
    global _msg_id
    _msg_id += 1
    enc    = encrypt(payload) if payload else b""
    header = (b"\x5a\x5a\x01\x11"
              + struct.pack("<HHI", 56 + len(enc), msg_type, _msg_id)
              + timestamp()
              + device_id.to_bytes(6, "little")
              + bytes(14))
    body = header + enc
    return body + md5(body + SIGN_KEY).digest()


def unpack(data: bytes) -> tuple[int, int, bytes]:
    if data[:2] != b"\x5a\x5a": raise ValueError(f"bad magic: {data[:8].hex()}")
    length, msg_type = struct.unpack_from("<HH", data, 4)
    pkt = data[:length]
    if md5(pkt[:-16] + SIGN_KEY).digest() != pkt[-16:]: raise ValueError("bad signature")
    enc = pkt[40:-16]
    return msg_type, int.from_bytes(pkt[20:26], "little"), decrypt(enc) if enc else b""


def java_hash(s: str) -> int:
    h = 0
    for c in s: h = (31 * h + ord(c)) & 0xFFFFFFFF
    return h


def make_device_id(sn: str, dev_type: int) -> bytes:
    """App-side ID: LE bytes of String.hashCode(sn) + type + 0xFF (2017 SDK class `ad`)."""
    return java_hash(sn).to_bytes(4, "little") + bytes([dev_type, 0xFF])


def random_code(bssid: bytes, psk: bytes) -> bytes:
    """2 random bytes + MD5(bssid || psk)[0..13] (Midea Air `config/a.java#a`)."""
    return os.urandom(2) + md5(bssid + psk).digest()[:14]


# Pinned to the Wi-Fi interface: the AP's 192.168.1.0/24 often collides with the home LAN or a VPN.
def bound_socket(kind: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, kind)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, IFACE.encode())
    return s


def discover() -> dict:
    """Parse per MSDeviceScanResult.parseDataBytes(); offsets relative to the SSID length L."""
    s = bound_socket(socket.SOCK_DGRAM)
    s.settimeout(2)
    for _ in range(5):
        s.sendto(DISCOVERY_MSG, (AC_IP, DISC_PORT))
        try:
            data, _ = s.recvfrom(4096)
        except socket.timeout:
            continue
        if data[:2] != b"\x5a\x5a": sys.exit(f"Not a 5a5a reply ({data[:2].hex()}).")
        p  = decrypt(data[40:-16])
        L  = p[40]
        f1 = p[43 + L]
        f2 = p[44 + L]
        enable_extra = bool(f1 & 0x80)
        return {"device_id":     int.from_bytes(data[20:26], "little"),
                "sn":            p[8:40].decode(),
                "mac":           p[63 + L:69 + L].hex(":"),
                "ssid":          p[41:41 + L].decode(),
                "udp_version":   int.from_bytes(p[45 + L:49 + L], "little"),
                "extra_channel": enable_extra and bool(f1 & 0x02),
                "region_id":     enable_extra and bool(f1 & 0x20),
                "function_set":  enable_extra and bool(f2 & 0x01),
                "flags":         f"{f1:02x} {f2:02x}"}
    sys.exit(f"No discovery reply from the module. Is {IFACE} on its AP?")


def scan() -> list[tuple[int, str, int, str]]:
    """(signal, BSSID, channel, SSID) for every network in a fresh NetworkManager scan, strongest first."""
    out = subprocess.run(["nmcli", "-t", "-f", "BSSID,CHAN,SIGNAL,SSID", "dev", "wifi", "list", "ifname", IFACE, "--rescan", "yes"],
                         capture_output=True, text=True, check=True).stdout
    nets = []
    for line in out.splitlines():
        m = re.match(r"^((?:[0-9A-F]{2}\\:){5}[0-9A-F]{2}):(\d+):(\d+):(.*)$", line)
        if m: nets.append((int(m.group(3)), m.group(1).replace("\\", ""), int(m.group(2)), m.group(4)))
    return sorted(nets, reverse=True)


def router_info(nets: list, ssid: str) -> tuple[str, int]:
    hits = [n for n in nets if n[3] == ssid]
    if not hits: sys.exit(f"{ssid} not found in a Wi-Fi scan; pass --bssid and --channel.")
    if len(hits) > 1: print(f"note: {len(hits)} BSSIDs for {ssid}, using the strongest")
    return hits[0][1], hits[0][2]


def find_ap(nets: list) -> str:
    aps = [n[3] for n in nets if AP_RE.match(n[3])]
    if not aps: sys.exit("No Midea setup AP (net_xx_XXXX / midea_xx_XXXX) in range. Is the appliance in AP mode?")
    if len(aps) > 1: print(f"note: several setup APs ({', '.join(aps)}), using the strongest; pick with --ap")
    return aps[0]


def nm_up(ap_ssid: str) -> None:
    subprocess.run(["nmcli", "connection", "delete", NM_CONN], capture_output=True)
    subprocess.run(["nmcli", "connection", "add", "type", "wifi", "ifname", IFACE, "con-name", NM_CONN, "ssid", ap_ssid,
                    "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", AP_PSK, "ipv4.never-default", "yes",
                    "ipv6.method", "disabled", "connection.autoconnect", "no"], check=True, capture_output=True)
    subprocess.run(["nmcli", "connection", "up", NM_CONN], check=True)


def nm_down() -> None:
    subprocess.run(["nmcli", "connection", "down", NM_CONN], capture_output=True)
    subprocess.run(["nmcli", "connection", "delete", NM_CONN], capture_output=True)


def recv_packet(s: socket.socket) -> bytes:
    head = b""
    while len(head) < 6:
        chunk = s.recv(6 - len(head))
        if not chunk: raise ConnectionError("closed")
        head += chunk
    length = struct.unpack_from("<H", head, 4)[0]
    data = head
    while len(data) < length:
        chunk = s.recv(length - len(data))
        if not chunk: raise ConnectionError("closed")
        data += chunk
    return data


def request(s: socket.socket, msg_type: int, device_id: int, payload: bytes, show: bool = True) -> bytes:
    print(f"-> 0x{msg_type:04x} " + (payload.hex() if show else f"<{len(payload)} bytes, redacted>"))
    s.sendall(packet(msg_type, device_id, payload))
    while True:
        rtype, _, rpayload = unpack(recv_packet(s))
        print(f"<- 0x{rtype:04x} {rpayload.hex()}")
        if rtype == (msg_type | 0x8000): return rpayload
        print("   (late/unrelated reply, skipped)")


def provision_v0(s: socket.socket, info: dict, ssid: bytes, psk: bytes) -> None:
    dev_id = info["device_id"]
    if dev_id == 0:
        new_id = make_device_id(info["sn"], 0xAC)
        reply  = request(s, MSG_WRITE_ID, 0, info["sn"].encode().ljust(32, b"\0")[:32] + new_id)
        if reply[:6] != new_id: print(f"warning: ID echo {reply.hex()} != {new_id.hex()}")
        dev_id = int.from_bytes(new_id, "little")
    reply = request(s, MSG_WRITE_WIFI, dev_id, bytes([SEC_PSK, len(ssid), len(psk)]) + ssid + psk, show=False)
    if not reply or reply[0] != 0: sys.exit(f"Module rejected the Wi-Fi config: {reply.hex()}")
    try:
        request(s, MSG_SWITCH_STA, dev_id, b"\x02")
    except (ConnectionError, socket.timeout, OSError) as e:
        print(f"switch-to-STA: connection dropped ({e}), expected as the AP goes down")


def provision_v2(s: socket.socket, info: dict, ssid_str: str, psk: bytes, bssid: str, channel: int) -> None:
    """0x70 payload per Midea Air `local/a/e.java#a()`; optional TLVs 2-10 omitted (flags off)."""
    ssid     = ssid_str.encode("utf-8")
    ssid_gbk = ssid_str.encode("gbk")
    bssid_b  = bytes.fromhex(bssid.replace(":", ""))
    payload  = (random_code(bssid_b, psk)
                + bytes([len(ssid)]) + ssid
                + bytes([len(psk)]) + psk
                + bytes([6]) + bssid_b
                + bytes([len(ssid_gbk)]) + ssid_gbk
                + (bytes([channel]) if info["extra_channel"] else b"")
                + b"\x01\x01\x01")   # TLV 1: needCheckPassword = 1
    reply = request(s, MSG_WRITE_WIFI_2, info["device_id"], payload, show=False)
    if not reply or reply[0] != 0:
        code = reply[0] if reply else None
        sys.exit(f"Module rejected the Wi-Fi config: code {code} ({WRITE_WIFI_2_ERRORS.get(code, 'unknown')})")


def main() -> None:
    global IFACE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ssid",    required=True, help="your Wi-Fi network (2.4 GHz, WPA2-PSK)")
    ap.add_argument("--bssid",   help="router BSSID (default: strongest in a scan)")
    ap.add_argument("--channel", type=int, help="router channel (default: from the scan)")
    ap.add_argument("--iface",   default="wlan0", help="Wi-Fi interface to use (default wlan0)")
    ap.add_argument("--ap",      help="module setup AP SSID (default: strongest net_xx_XXXX / midea_xx_XXXX)")
    ap.add_argument("--no-nm",   action="store_true", help="don't manage NetworkManager; --iface is already on the AP")
    args = ap.parse_args()
    IFACE = args.iface

    nets = [] if args.no_nm and args.bssid and args.channel else scan()
    if args.bssid and args.channel: bssid, channel = args.bssid.upper(), args.channel
    else:
        bssid, channel = router_info(nets, args.ssid)
        bssid, channel = (args.bssid or bssid).upper(), args.channel or channel
    print(f"router {args.ssid} bssid={bssid} channel={channel}")

    ssid = args.ssid.encode()
    psk  = getpass.getpass(f"Password for {args.ssid}: ").encode()
    if not (8 <= len(psk) <= 63): sys.exit("WPA2-PSK passphrase must be 8-63 bytes.")

    if not args.no_nm:
        ap_ssid = args.ap or find_ap(nets)
        print(f"joining setup AP {ap_ssid} on {IFACE}")
        nm_up(ap_ssid)
    try:
        time.sleep(2)
        info = discover()
        print(f"found {info['ssid']} sn={info['sn']} mac={info['mac']} id={info['device_id']} "
              f"udpVersion={info['udp_version']} flags={info['flags']}")
        v = info["udp_version"]
        if v >= 4:                                     sys.exit("udpVersion >= 4 needs TLS; not implemented.")
        if v == 3 or info["function_set"]:             sys.exit("Module wants country/server fields (udpVersion 3 or functionSet); not implemented.")
        if info["region_id"]:                          sys.exit("Module wants a region ID; not implemented.")

        s = bound_socket(socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((AC_IP, AC_PORT))
        if v == 0: provision_v0(s, info, ssid, psk)
        else:      provision_v2(s, info, args.ssid, psk, bssid, channel)
        print(f"Done. The module should now join {args.ssid}. Find its IP in your router's DHCP leases "
              f"(look for MAC {info['mac']}), then: ac.ts setup <ip> '{args.ssid}'")
    finally:
        if not args.no_nm: nm_down()


if __name__ == "__main__":
    main()
