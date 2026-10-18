#!/usr/bin/env bun
// Local control for Midea air conditioners with a V3 Wi-Fi module that was never cloud-bound:
// no app, no cloud. Protocol: PROTOCOL.md. Uses node: APIs only, so it also runs under Deno.
// The 0xAA frame layouts, state parsing and V3 framing follow msmart-ng (MIT, see LICENSE-msmart-ng.md).
import { Buffer }                                                    from "node:buffer";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { createSocket }                                              from "node:dgram";
import { chmodSync, mkdirSync, readFileSync, writeFileSync }         from "node:fs";
import { Socket }                                                    from "node:net";
import { homedir }                                                   from "node:os";
import { join }                                                      from "node:path";
import process                                                       from "node:process";

const CONFIG_DIR  = join(homedir(), ".config", "aircon");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");
const DISC_PORT   = 6445;
const TIMEOUT     = 5000;   // connect and handshake
const REPLY_MS    = 2500;   // per attempt; requests are resent on timeout
const ATTEMPTS    = 3;

const DISCOVERY_MSG = Buffer.from("5a5a011148009200" + "00".repeat(32)
                                  + "7f75bd6b3e4f8b762e849c6e578d6590036e9d4342a50f1f569eb8ec918e92e5", "hex");

const SIGN_KEY = Buffer.from("xhdiwjnchekd4d512chdjx5d8e4c394D2D7S");
const ENC_KEY  = md5(SIGN_KEY);

const MODES  = { auto: 1, cool: 2, dry: 3, heat: 4, fan: 5 } as const;
const FANS   = { auto: 102, high: 80, med: 60, low: 40 } as const;
const SWING  = { off: 0x0, on: 0x3 } as const;   // 0x3 = side-to-side louvers

type State = {
    power: boolean; mode: number; target: number; fan: number; swing: number;
    turbo: boolean; eco: boolean; sleep: boolean; fahrenheit: boolean; followMe: boolean;
    purifier: boolean; freeze: boolean; humidity: number;
    indoor: number | null; outdoor: number | null; display: boolean; filter: boolean; error: number;
};

type Config = { ip: string; port: number; deviceId: string; mac: string; key: string };   // ids and keys as hex

class AcError extends Error {}
class AcTimeout extends AcError {}

// ---- crypto ----------------------------------------------------------------

function md5(b: Uint8Array): Buffer    { return createHash("md5").update(b).digest(); }
function sha256(b: Uint8Array): Buffer { return createHash("sha256").update(b).digest(); }

function aes128Ecb(encrypt: boolean, data: Uint8Array): Buffer {
    const c = encrypt ? createCipheriv("aes-128-ecb", ENC_KEY, null) : createDecipheriv("aes-128-ecb", ENC_KEY, null);
    return Buffer.concat([c.update(data), c.final()]);
}

function aes256Cbc(encrypt: boolean, key: Uint8Array, data: Uint8Array): Buffer {
    const iv = Buffer.alloc(16);
    const c  = encrypt ? createCipheriv("aes-256-cbc", key, iv) : createDecipheriv("aes-256-cbc", key, iv);
    c.setAutoPadding(false);
    return Buffer.concat([c.update(data), c.final()]);
}

function xor(a: Uint8Array, b: Uint8Array): Buffer { return Buffer.from(a.map((v, i) => v ^ b[i])); }

// R3: the module's default handshake key when it has never had a cloud token.
export function deriveKey(ssid: string, psk: string, mac: Uint8Array): Buffer {
    return sha256(Buffer.concat([Buffer.from(ssid + psk, "utf8"), mac]));
}

// ---- AC frames (0xAA) -------------------------------------------------------

let frameMsgId = 0;

export function crc8(data: number[]): number {
    let crc = 0;
    for(const b of data){
        crc ^= b;
        for(let i = 0; i < 8; i++) crc = crc & 1 ? (crc >> 1) ^ 0x8C : crc >> 1;
    }
    return crc;
}

export function checksum(data: number[]): number { return (~data.reduce((s, b) => s + b, 0) + 1) & 0xFF; }

export function acFrame(frameType: number, body: number[]): Buffer {
    const payload = [...body, (++frameMsgId) & 0xFF];
    const data    = [...payload, crc8(payload)];
    const frame   = [0xAA, data.length + 10, 0xAC, 0, 0, 0, 0, 0, 0, frameType, ...data];
    return Buffer.from([...frame, checksum(frame.slice(1))]);
}

export function queryFrame(): Buffer {
    return acFrame(0x03, [0x41, 0x81, 0x00, 0xFF, 0x03, 0xFF, 0x00, 0x02, ...Array(12).fill(0), 0x03]);
}

export function setFrame(s: State): Buffer {
    const whole = Math.trunc(s.target);
    const half  = s.target - whole > 0 ? 0x10 : 0;
    const temp  = whole >= 17 && whole <= 30 ? ((whole - 16) & 0xF) | half : half;
    const alt   = whole >= 17 && whole <= 30 ? 0 : (whole - 12) & 0x1F;
    return acFrame(0x02, [
        0x40,
        0x02 | (s.power ? 0x01 : 0),
        temp | ((s.mode & 0x7) << 5),
        s.fan,
        0x7F, 0x7F, 0x00,
        0x30 | (s.swing & 0x3F),
        (s.followMe ? 0x80 : 0) | (s.turbo ? 0x20 : 0),
        (s.eco ? 0x80 : 0) | (s.purifier ? 0x20 : 0),
        (s.sleep ? 0x01 : 0) | (s.turbo ? 0x02 : 0) | (s.fahrenheit ? 0x04 : 0),
        0, 0, 0, 0, 0, 0, 0,
        alt,
        s.humidity & 0x7F,
        0x00,
        s.freeze ? 0x80 : 0,
        0x00, 0x00,
    ]);
}

function parseTemp(raw: number, decimals: number, fahrenheit: boolean): number | null {
    if(raw === 0xFF) return null;
    const t = (raw - 50) / 2;
    if(!fahrenheit && decimals) return Math.trunc(t) + (t >= 0 ? decimals : -decimals);
    if(decimals >= 0.5) return Math.trunc(t) + (t >= 0 ? 0.5 : -0.5);
    return t;
}

// p[0] is the response id (0xC0); layout per msmart-ng StateResponse._parse.
export function parseState(p: Buffer): State {
    const fahrenheit = !!(p[10] & 0x04);
    let target       = (p[2] & 0xF) + 16 + (p[2] & 0x10 ? 0.5 : 0);
    if(p[13] & 0x1F) target = (p[13] & 0x1F) + 12 + (p[2] & 0x10 ? 0.5 : 0);
    return {
        power:      !!(p[1] & 0x01),
        mode:       (p[2] >> 5) & 0x7,
        target,
        fan:        p[3] & 0x7F,
        swing:      p[7] & 0xF,
        turbo:      !!(p[8] & 0x20) || !!(p[10] & 0x02),
        followMe:   !!(p[8] & 0x80),
        eco:        !!(p[9] & 0x10),
        purifier:   !!(p[9] & 0x20),
        sleep:      !!(p[10] & 0x01),
        fahrenheit,
        indoor:     parseTemp(p[11], (p[15] & 0xF) / 10, fahrenheit),
        outdoor:    parseTemp(p[12], (p[15] >> 4) / 10, fahrenheit),
        filter:     !!(p[13] & 0x20),
        display:    p[14] !== 0x70,
        error:      p[16],
        humidity:   p.length > 19 ? p[19] & 0x7F : 0,
        freeze:     p.length > 21 ? !!(p[21] & 0x80) : false,
    };
}

// ---- V2 packet (5A5A), carried inside V3 --------------------------------------

export function v2Encode(frame: Buffer, deviceId: bigint): Buffer {
    const enc = aes128Ecb(true, frame);
    const now = new Date();
    const hdr = Buffer.alloc(40);
    hdr.set([0x5A, 0x5A, 0x01, 0x11]);
    hdr.writeUInt16LE(40 + enc.length + 16, 4);
    hdr.writeUInt16LE(0x0020, 6);
    hdr.set([Math.floor(now.getUTCMilliseconds() / 10), now.getUTCSeconds(), now.getUTCMinutes(), now.getUTCHours(),
             now.getUTCDate(), now.getUTCMonth() + 1, now.getUTCFullYear() % 100, Math.floor(now.getUTCFullYear() / 100)], 12);
    hdr.writeBigUInt64LE(deviceId, 20);
    const body = Buffer.concat([hdr, enc]);
    return Buffer.concat([body, md5(Buffer.concat([body, SIGN_KEY]))]);
}

export function v2Decode(pkt: Buffer): Buffer {
    if(pkt[0] !== 0x5A || pkt[1] !== 0x5A) throw new AcError(`bad V2 magic: ${pkt.subarray(0, 4).toString("hex")}`);
    const len  = pkt.readUInt16LE(4);
    const body = pkt.subarray(0, len - 16);
    if(!md5(Buffer.concat([body, SIGN_KEY])).equals(pkt.subarray(len - 16, len))) throw new AcError("bad V2 signature");
    return aes128Ecb(false, pkt.subarray(40, len - 16));
}

// ---- V3 session (8370) ------------------------------------------------------

class Session {
    private buf: Buffer                = Buffer.alloc(0);
    private wake: (() => void) | null  = null;
    private closed                     = false;
    private key: Buffer                = Buffer.alloc(0);
    private packetId                   = 0;

    private constructor(private sock: Socket, private deviceId: bigint) {
        sock.on("data",  d => { this.buf = Buffer.concat([this.buf, d]); this.wake?.(); });
        sock.on("close", () => { this.closed = true; this.wake?.(); });
        sock.on("error", () => { this.closed = true; this.wake?.(); });
    }

    static async open(cfg: Config): Promise<Session> {
        const sock = new Socket();
        await new Promise<void>((resolve, reject) => {
            const t = setTimeout(() => { sock.destroy(); reject(new AcError(`AC not reachable at ${cfg.ip}:${cfg.port}`)); }, TIMEOUT);
            sock.once("error", e => { clearTimeout(t); reject(new AcError(`connect: ${e.message}`)); });
            sock.connect(cfg.port, cfg.ip, () => { clearTimeout(t); resolve(); });
        });
        const s = new Session(sock, BigInt("0x" + cfg.deviceId));
        await s.handshake(Buffer.from(cfg.key, "hex"));
        return s;
    }

    close(): void { this.sock.destroy(); }

    private header(length: number, type: number): Buffer {
        const h = Buffer.from([0x83, 0x70, 0, 0, 0x20, type]);
        h.writeUInt16BE(length, 2);
        return h;
    }

    private nextId(): Buffer {
        const id = Buffer.alloc(2);
        id.writeUInt16BE(this.packetId, 0);
        this.packetId = (this.packetId + 1) & 0xFFF;
        return id;
    }

    private async readPacket(timeout: number, what: string): Promise<Buffer> {
        const deadline = Date.now() + timeout;
        for(;;){
            const start = this.buf.indexOf(Buffer.from([0x83, 0x70]));
            if(start > 0) this.buf = this.buf.subarray(start);
            if(start >= 0 && this.buf.length >= 6){
                const total = this.buf.readUInt16BE(2) + 8;
                if(this.buf.length >= total){
                    const pkt = this.buf.subarray(0, total);
                    this.buf  = this.buf.subarray(total);
                    return pkt;
                }
            }
            if(this.closed) throw new AcError("connection closed by AC");
            const left = deadline - Date.now();
            if(left <= 0) throw new AcTimeout(`timed out waiting for the AC (${what})`);
            await new Promise<void>(r => { const t = setTimeout(r, left); this.wake = () => { clearTimeout(t); r(); }; });
            this.wake = null;
        }
    }

    private async handshake(r3: Buffer): Promise<void> {
        const a     = randomBytes(32);
        const token = Buffer.concat([aes256Cbc(true, r3, a), sha256(a)]);
        this.sock.write(Buffer.concat([this.header(token.length, 0x0), this.nextId(), token]));
        const pkt  = await this.readPacket(TIMEOUT, "handshake");
        const type = pkt[5] & 0xF;
        if(type === 0xF) throw new AcError(`key rejected by the AC; rerun 'ac setup'`);
        if(type !== 0x1) throw new AcError(`unexpected handshake reply type ${type}`);
        const half  = pkt.subarray(8, 40);
        const plain = aes256Cbc(false, a, half);
        if(!sha256(plain).equals(pkt.subarray(40, 72))) throw new AcError("handshake hash mismatch");
        this.key = xor(plain, a);
    }

    private sendFrame(frame: Buffer): void {
        const data   = v2Encode(frame, this.deviceId);
        const rem    = (data.length + 2) % 16;
        const pad    = rem ? 16 - rem : 0;
        const header = this.header(data.length + pad + 32, (pad << 4) | 0x6);
        const plain  = Buffer.concat([this.nextId(), data, randomBytes(pad)]);
        this.sock.write(Buffer.concat([header, aes256Cbc(true, this.key, plain), sha256(Buffer.concat([header, plain]))]));
    }

    private async readFrame(): Promise<Buffer> {
        const pkt  = await this.readPacket(REPLY_MS, "reply");
        const type = pkt[5] & 0xF;
        if(type === 0xF) throw new AcError("AC returned an error packet");
        if(type !== 0x3) throw new AcError(`unexpected packet type ${type}`);
        const header = pkt.subarray(0, 6);
        const plain  = aes256Cbc(false, this.key, pkt.subarray(6, pkt.length - 32));
        if(!sha256(Buffer.concat([header, plain])).equals(pkt.subarray(pkt.length - 32))) throw new AcError("V3 hash mismatch");
        const frame = v2Decode(plain.subarray(2, plain.length - (header[5] >> 4)));
        if(frame[0] !== 0xAA || checksum([...frame.subarray(1, frame.length - 1)]) !== frame[frame.length - 1]) throw new AcError("bad AC frame");
        return frame;
    }

    // Sends a frame and returns the next state report (0xC0); other reports are skipped.
    // Resends on timeout: the module sometimes drops a request while the AC changes state, and
    // set frames carry the full state, so a repeat is harmless.
    async exchange(frame: Buffer): Promise<State> {
        for(let attempt = 1; ; attempt++){
            this.sendFrame(frame);
            try{
                for(;;){
                    const f = await this.readFrame();
                    if(f[10] === 0xC0) return parseState(f.subarray(10, f.length - 2));
                }
            } catch(e){
                if(!(e instanceof AcTimeout) || attempt >= ATTEMPTS) throw e;
            }
        }
    }
}

// ---- discovery and config ------------------------------------------------------

type Discovery = { v3: boolean; port: number; deviceId: bigint; mac: Buffer; sn: string };

// Reply to DISCOVERY_MSG: a 5A5A packet, wrapped in an 8-byte 8370 header (+16-byte trailer) on V3
// modules. Body offsets per MSDeviceScanResult.parseDataBytes(); L is the module's SSID length.
export function parseDiscovery(d: Buffer): Discovery {
    const v3    = d[0] === 0x83 && d[1] === 0x70;
    const inner = v3 ? d.subarray(8, d.length - 16) : d;
    if(inner[0] !== 0x5A || inner[1] !== 0x5A) throw new AcError(`unrecognised discovery reply: ${d.subarray(0, 8).toString("hex")}`);
    const body = aes128Ecb(false, inner.subarray(40, inner.readUInt16LE(4) - 16));
    const L    = body[40];
    return {
        v3,
        port:     body.readUInt16LE(4),
        deviceId: BigInt(inner.readUIntLE(20, 6)),
        mac:      Buffer.from(body.subarray(63 + L, 69 + L)),
        sn:       body.subarray(8, 40).toString("latin1"),
    };
}

function discover(ip: string): Promise<Discovery> {
    const sock = createSocket("udp4");
    return new Promise((resolve, reject) => {
        let tries = 0;
        const send  = () => { tries++; sock.send(DISCOVERY_MSG, DISC_PORT, ip); };
        const timer = setInterval(() => {
            if(tries < 3) return send();
            clearInterval(timer); sock.close();
            reject(new AcError(`no discovery reply from ${ip}:${DISC_PORT}`));
        }, 1500);
        sock.on("message", (msg, rinfo) => {
            if(rinfo.address !== ip) return;
            clearInterval(timer); sock.close();
            try{ resolve(parseDiscovery(msg)); } catch(e){ reject(e); }
        });
        sock.on("error", e => { clearInterval(timer); sock.close(); reject(new AcError(`discovery: ${e.message}`)); });
        send();
    });
}

function loadConfig(): Config {
    try{
        const c = JSON.parse(readFileSync(CONFIG_FILE, "utf8"));
        if(c.ip && c.port && c.deviceId && /^[0-9a-f]{64}$/i.test(c.key)) return c;
    } catch(_){ /* fall through */ }
    throw new AcError(`no usable config at ${CONFIG_FILE}; run 'ac setup <ip> <ssid>' first`);
}

function saveConfig(c: Config): void {
    mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(CONFIG_FILE, JSON.stringify(c, null, 4) + "\n", { mode: 0o600 });
    chmodSync(CONFIG_FILE, 0o600);
}

function readHidden(prompt: string): Promise<string> {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    if(!stdin.isTTY) throw new AcError("setup needs an interactive terminal");
    stdin.setRawMode(true);
    stdin.resume();
    return new Promise(resolve => {
        let s = "";
        const onData = (d: Buffer) => {
            for(const ch of d.toString("utf8")){
                if(ch === "\r" || ch === "\n"){
                    stdin.setRawMode(false); stdin.pause(); stdin.off("data", onData);
                    process.stdout.write("\n");
                    return resolve(s);
                }
                if(ch === "\u0003"){ stdin.setRawMode(false); process.stdout.write("\n"); process.exit(130); }
                if(ch === "\u007f" || ch === "\b") s = s.slice(0, -1);
                else                               s += ch;
            }
        };
        stdin.on("data", onData);
    });
}

// ---- CLI ----------------------------------------------------------------------

function nameOf<T extends Record<string, number>>(map: T, v: number): string {
    return Object.entries(map).find(([, n]) => n === v)?.[0] ?? `${v}`;
}

function show(s: State): void {
    const unit  = s.fahrenheit ? "°F" : "°C";
    const extra = [s.eco && "eco", s.turbo && "turbo", s.sleep && "sleep", s.filter && "FILTER", s.error && `ERROR ${s.error}`].filter(Boolean);
    console.log(`power  ${s.power ? "on" : "off"}`);
    console.log(`mode   ${nameOf(MODES, s.mode)}`);
    console.log(`set    ${s.target}${unit}`);
    console.log(`room   ${s.indoor ?? "?"}${s.indoor === null ? "" : unit}`);
    console.log(`fan    ${nameOf(FANS, s.fan)}`);
    console.log(`swing  ${s.swing ? "on" : "off"}`);
    if(extra.length) console.log(`flags  ${extra.join(" ")}`);
}

const USAGE = `usage: ac [status]                       show state
       ac on | off
       ac mode  auto|cool|dry|heat|fan
       ac temp  17-30
       ac fan   auto|low|med|high
       ac swing on|off
       ac setup <ip> <ssid>             once: find the AC, derive its key from the Wi-Fi it joined
                                        (asks for that network's password), save ~/.config/aircon/config.json

Settings combine: 'ac on cool 22 low'. Bare cool/dry/heat, a number, and low/med/high work
without their keyword; 'auto' and 'fan' need it. Power only changes with on/off.`;

export function applyArgs(args: string[], s: State): State {
    const next = { ...s };
    const pick = <T extends Record<string, number>>(map: T, word: string | undefined, what: string): number => {
        if(word && word in map) return map[word as keyof T];
        throw new AcError(`${what} must be one of: ${Object.keys(map).join(", ")}`);
    };
    for(let i = 0; i < args.length; i++){
        const a = args[i].toLowerCase();
        switch(a){
            case "on":    next.power = true;  break;
            case "off":   next.power = false; break;
            case "mode":  next.mode  = pick(MODES, args[++i]?.toLowerCase(), "mode");  break;
            case "fan":   next.fan   = pick(FANS,  args[++i]?.toLowerCase(), "fan");   break;
            case "swing": next.swing = pick(SWING, args[++i]?.toLowerCase(), "swing"); break;
            case "temp":  next.target = parseTarget(args[++i]); break;
            case "cool": case "dry": case "heat":  next.mode = MODES[a]; break;
            case "low":  case "med": case "high":  next.fan  = FANS[a];  break;
            default:
                if(/^\d+(\.5)?$/.test(a)) next.target = parseTarget(a);
                else throw new AcError(`unknown argument '${args[i]}'\n\n${USAGE}`);
        }
    }
    return next;
}

function parseTarget(v: string | undefined): number {
    const t = Number(v);
    if(!v || !Number.isFinite(t) || t < 17 || t > 30 || (t * 2) % 1) throw new AcError("temp must be 17-30, in 0.5 steps");
    return t;
}

async function main(argv: string[]): Promise<void> {
    const [verb = "status", ...rest] = argv;
    if(verb === "-h" || verb === "--help" || verb === "help"){ console.log(USAGE); return; }

    if(verb === "setup"){
        const [ip, ssid] = rest;
        if(!ip || !ssid) throw new AcError(`setup needs the AC's IP and the SSID it joined\n\n${USAGE}`);
        const d = await discover(ip);
        console.log(`found sn ${d.sn}, mac ${d.mac.toString("hex")}, device id ${d.deviceId.toString(16)}`);
        if(!d.v3) throw new AcError("this module speaks V2 on the LAN (no key needed); use msmart-ng for it");
        const psk = await readHidden(`Password for ${ssid}: `);
        const cfg: Config = { ip, port: d.port, deviceId: d.deviceId.toString(16), mac: d.mac.toString("hex"),
                              key: deriveKey(ssid, psk, d.mac).toString("hex") };
        const s = await Session.open(cfg);
        try{ show(await s.exchange(queryFrame())); } finally{ s.close(); }
        saveConfig(cfg);
        console.log(`key OK, saved to ${CONFIG_FILE}`);
        return;
    }

    if(verb !== "status") applyArgs(argv, {} as State);   // reject bad arguments before connecting
    const session = await Session.open(loadConfig());
    try{
        const state = await session.exchange(queryFrame());
        if(verb === "status"){ show(state); return; }
        show(await session.exchange(setFrame(applyArgs(argv, state))));
    } finally{
        session.close();
    }
}

if(import.meta.main) main(process.argv.slice(2)).catch(e => {
    console.error(`ac: ${e instanceof AcError ? e.message : e?.stack ?? e}`);
    process.exit(1);
});
