# midea-ac-nocloud

Set up and control a Midea Wi-Fi air conditioner entirely on your own network: no MSmartHome app,
no Midea account, and no cloud. That includes the one-time token fetch that other local-control
tools still need.

Two things make that possible, both described in [PROTOCOL.md](PROTOCOL.md):

- **App-free provisioning.** Current modules ignore the old Wi-Fi setup command and want a newer one
  (`0x0070`) with a locally derived "random code". `provision.py` sends it.
- **Cloud-free V3 control.** A module that has never been bound to Midea's cloud accepts a session
  handshake keyed on your Wi-Fi SSID, passphrase and its own MAC. No token or key from Midea is
  needed. `ac.ts` uses it.

> [!NOTE]
> Tested on one unit so far, a Midea MWFF28H window AC. Reports from other units are very
> welcome, especially from modules that *have* been set up with the app at some point (see
> [Open questions](PROTOCOL.md#open-questions)).

## Requirements

- `provision.py`: Linux with NetworkManager, a Wi-Fi interface, and Python 3 with `pycryptodome`.
  It pins its sockets to the Wi-Fi interface because the module's setup network
  (`192.168.1.0/24`) clashes with lots of home LANs and VPNs. That's also why it's Python and not TS.
- `ac.ts`: [Bun](https://bun.sh). It uses only `node:` APIs, so Deno works too:
  `deno run --allow-net --allow-read --allow-write --allow-env ac.ts …`.
- Your Wi-Fi must be 2.4 GHz with WPA2-PSK.

## Usage

1. **Put the AC in AP mode.** On the window AC, hold SWING for 3 s until the display shows `AP`.
   Your unit's manual will have the equivalent. You then have about 8 minutes.
2. **Provision it:**
   ```
   ./provision.py --ssid "YourWiFi"
   ```
   It scans for your router's BSSID and channel, asks for the Wi-Fi passphrase, joins the module's
   `net_xx_XXXX` AP through a temporary NetworkManager profile, checks which protocol the module
   speaks, sends the config, and cleans up. It prints the module's MAC.
3. **Keep it offline (recommended).** Block that MAC from the internet on your router. It works fine
   without it.
4. **Find its IP** in your router's DHCP leases (a static lease helps), then set up `ac.ts`:
   ```
   ./ac.ts setup 192.168.0.50 "YourWiFi"
   ```
   This discovers the module, asks for the Wi-Fi passphrase, derives the key, checks it with a status
   query, and saves `~/.config/aircon/config.json`.
5. **Use it:**
   ```
   ./ac.ts                                # show the current state
   ./ac.ts on | off                       # power; nothing else changes it
   ./ac.ts mode auto|cool|dry|heat|fan    # operating mode
   ./ac.ts temp 17-30                     # target temperature, 0.5 steps
   ./ac.ts fan auto|low|med|high          # fan speed
   ./ac.ts swing on|off                   # louver swing
   ./ac.ts on cool 22 low                 # settings combine; cool/dry/heat, numbers and low/med/high work bare
   ```

## Good to know

- The config file (mode 0600) holds the derived key, not your Wi-Fi passphrase. The key can't be
  turned back into the passphrase, but it does let anyone control the AC, so treat it like one.
- Anyone who knows your Wi-Fi passphrase and is on your network can derive the same key, since the
  module's MAC isn't secret. That's how the module works, not something this repo adds.
- If you change the Wi-Fi passphrase or SSID, provision again and re-run `ac.ts setup`.
- Every command opens a new session, reads the state, and sends back the full state with your
  changes. A request the module drops gets resent automatically.

## Credits

- [msmart-ng](https://github.com/mill1000/midea-msmart) for the packet framing, the V3 transport
  and the AC frame layouts that `ac.ts` ports ([its licence](LICENSE-msmart-ng.md)).
- Midea's [2017 Android SDK](https://github.com/midea-sdk-org/android-sdk) for the legacy
  provisioning commands.
- The new parts came from static analysis of the Midea Air Android app. Details and code pointers
  are in [PROTOCOL.md](PROTOCOL.md).

MIT licensed, see [LICENSE](LICENSE).
