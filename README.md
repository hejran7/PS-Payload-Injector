# PS Payload Injector

A Simple Windows GUI tool for sending payloads to a PS4 or PS5 over the local network.

---

## Features

- **PS4Debug & PS5Debug modes** — switch between PS4 and PS5; injection port defaults automatically (9090 for PS4, 9021 for PS5)
- **Built-in payloads** — comes with latest `ps4debug v1.1.19` and `ps5debug v1.0b5`. special thanks to Ctn123 and SiSTR0.
- **Custom payload support** — browse for any payload  `.bin`, `.elf`, or drag-and-drop it directly onto the path field.
- **Custom port** — type any port number directly into the port field; recent ports are saved in a dropdown.
- **Auto-detect** — probes port 744 on startup; if the debug server is already running the Inject button is disabled and you are notified
- **IP & port history** — recently used IPs and ports are saved and accessible from a dropdown for easy access.
- **Firewall helper** — detects if ports 744 and 755 are blocked and offers to apply the correct inbound rules automatically (UAC-elevated)

---

## Usage

Download the latest release from the [Releases](../../releases) page and run `PS_Payload_Injector.exe` — no installation required.

1. Enter your PlayStation's local IP address
2. Select **PS4Debug** or **PS5Debug** mode
3. Optionally change the port (defaults: 9090 for PS4, 9021 for PS5)
4. Leave the payload on Built-in, click `Use Custom` to browse, or drag-and-drop a `.bin` / `.elf` / `.payload` file onto the path field
5. Click **Inject**

---

## Built-in Payloads

| Mode | File | Version |
|------|------|---------|
| PS4Debug | `ps4debug_v1_1_19.bin` | 1.1.19 |
| PS5Debug | `ps5debug_v1_0b5.elf` | 1.0b5 |

---

## Notes

- The tool must be on the same local network as the console
- Run as a normal user; the firewall helper will request elevation only if needed
- Settings (IP history, port, last mode) are saved to `%USERPROFILE%\Documents\PS_Payload_Injector\data\settings.json`

---

## License

MIT License — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.
