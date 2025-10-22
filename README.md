State Verification and Update Tools for untrustworthy devices.

# x220 Firmware

## How to use (quick examples)

> **All read‑only unless you explicitly run `update-apply`.**

```bash
# 1) Full read-only pipeline on live Tails (recommended)
sudo ./x220_firmware_audit.sh audit

# 2) Offline/dry-run test using a known SPI image (no hardware access)
sudo ./x220_firmware_audit.sh audit --dry-run --image /path/to/spi-full.bin

# 3) Just dump SPI (double read with abort-on-mismatch)
sudo ./x220_firmware_audit.sh dump --count 2

# 4) Analyze previously captured image in current artifacts
sudo ./x220_firmware_audit.sh analyze

# 5) Compare two runs
sudo ./x220_firmware_audit.sh compare --previous /path/old/audit-log.json --current /path/new/audit-log.json

# 6) Read-only update check (will not write to SPI flash)
sudo ./x220_firmware_audit.sh update-check --net

# 7) Guarded update apply (BIOS region only)
#    Place new BIOS region at: ~/Persistent/x220-audit/staging/bios.new.bin
sudo ./x220_firmware_audit.sh update-apply
```

---

## Notes

* **Redundant SPI reads:** `dump` performs two reads and aborts if their SHA‑256 digests differ. The canonical capture is stored as `artifacts/<UTC>/spi-full.bin` with both SHA‑256 and SHA‑512 sidecar files.
* **Region split:** Uses `ifdtool -x` with resilient renaming to `descriptor.bin`, `bios.bin`, `me.bin`, `gbe.bin`.
* **CBFS enumeration & coreboot version:** Lists CBFS (`cbfstool print`) and attempts to extract a version from common files (`etc/version`, `coreboot.version`, etc.). It stores a CBFS summary array in the JSON log.
* **Intel ME analysis (read‑only):** Invokes `me_cleaner.py -S -O /dev/null me.bin` and records version/SKU hints and module notes when available.
* **Disk audit:** Identifies the Samsung 850 Pro if present; otherwise audits the first disk. It collects model/firmware/serial, checks **HPA/DCO** via `hdparm`, hashes the **MBR** (first 512 bytes), scans **first 1 MiB** for “OpenBSD” markers, enumerates unallocated **gaps** using `lsblk` JSON, and flags anomalies as WARN in the log.
* **Inventory:** Compares `lspci -nn` and `lsusb` against a minimal X220 allowlist (bridges, Intel display/SATA/USB/audio, Intel/Realtek Ethernet; Wi‑Fi absence is fine) and logs anomalies.
* **JSON log:** Conforms to your `AuditLog` schema fields; uses `jq` to assemble stable, diff‑friendly JSON (`audit-log.json`). A companion human report is written to `human-report.txt`.
* **Compare:** Strips volatile fields (`timestamp_utc`, `tool_versions`, `disk.serial`) before a unified diff and returns **0 on MATCH**, **2 on MISMATCH**, **3 on error**—as requested.


# USB Mass‑Storage Device Inspect & Wipe (POSIX)

**A single‑file, POSIX‑style shell tool** to safely **inspect** and **securely overwrite** externally attached USB mass‑storage devices.
Runs on **Linux (Ubuntu/Debian, etc.)** and **OpenBSD**, using only POSIX shell features so it works on **dash** (and other `/bin/sh` shells).

> **⚠️ DANGER:** This tool can erase data irreversibly.
> **Do not** target your system/root disk. The script refuses to operate on mounted/root devices and requires explicit typed confirmations before any destructive action.

---

## Highlights

* **Mode 1 – Scan (non‑destructive)**

  * Auto‑detect a newly attached USB mass‑storage device (or operate on a given device path).
  * Collect device facts: size, sector size(s), rotational flag, partition table, partitions & filesystems.
  * USB identity (VID:PID, manufacturer/product, serial) and **composite function** detection (HID/CDC/etc., Linux).
  * **Blankness check**: chunked read to verify if the device is all zeros; record first N non‑zero offsets.
  * Optional:

    * **SMART** info (if pass‑through works),
    * **Hidden areas (HPA/DCO)** queries where applicable,
    * **Read‑only probe** (tiny write/read/restore at start/mid/end),
    * **Firmware scan** (non‑destructive; flags DFU/vendor‑specific interfaces).
  * Writes a **human summary** and a **machine JSON report**, and can append to an **inventory JSONL**.

* **Mode 2 – Wipe (destructive)**

  * Multi‑pass full‑device overwrite with selectable patterns:

    * `random` (/dev/urandom), `zeros`, `ff`, `aa`, or `sequence` (00 → FF → AA cycling by pass).
  * Configurable **chunk size**, **passes** (default 1; supports 1/3/7), and **progress with ETA**.
  * **Verification**: `none` | `sample` (anchors + random samples) | `full` (whole‑device SHA‑256).
  * Detects suspicious **unchanged** or **zero‑only** regions; fails with precise offsets when found.
  * Produces **human + JSON** reports; optional **GPG signatures**; optional **tar.gz export** of logs.

* **POSIX‑first**: uses only portable shell features; gracefully degrades when optional tools aren’t present.

---

## Supported platforms

* **Linux**: Designed for Ubuntu/Debian; should work on most distributions with `lsblk`, `udevadm`, `lsusb`, etc.
* **OpenBSD**: Uses `disklabel`, `sysctl hw.disknames`, `usbconfig` (best‑effort) for descriptors.

> The exact breadth of metadata depends on which optional utilities are available on your system.

---

## Installation

1. Save the script as `usb_device_inspect_wipe.sh`.
2. Make it executable:

   ```sh
   chmod +x usb_device_inspect_wipe.sh
   ```
3. Run with `sudo` or as root:

   ```sh
   sudo ./usb_device_inspect_wipe.sh --help
   ```

---

## Safety first

* Refuses to operate on the **root/system disk** and on **mounted** devices.
* **Typed confirmation** required for wipes (device node, and serial when available).
* **Read‑only probe** (if enabled) writes a tiny marker and restores the original bytes; requires explicit consent.
* **Dry‑run** mode simulates actions and never writes to the device.

---

## Dependencies

**Required (portable core):**

* `sh` (POSIX), `dd`, `grep`, `sed`, `awk`, `od`, `hexdump`, `wc`, `date`

**Linux (used when present):**

* `lsblk`, `blkid`, `udevadm`, `lsusb`
* `sha256sum` (or `sha256` on some distros), `cmp`
* `parted` or `sgdisk` (for partition table details)
* Optional: `smartctl`, `hdparm`, `timeout`, `jq`, `gpg`, `tar`, `xxd`

**OpenBSD (best‑effort):**

* `disklabel`, `fdisk`, `dd`, `sha256`, `dmesg`, `sysctl`, `usbconfig` (or `usbhidctl`)
* Optional: `gpg`, `tar`, `xxd`

> If `xxd` is missing, constant‑byte patterns `ff`/`aa` fall back to `zeros`. Install via your package manager (e.g., `vim-common` on Debian/Ubuntu).

---

## Quick start

### Scan and log

```sh
sudo ./usb_device_inspect_wipe.sh --mode=scan --log-dir=./logs \
  --inventory-log=./logs/inventory.jsonl
# Omit --device to wait for a newly attached USB device.
```

### Wipe (3 passes, sequence 00/FF/AA, sample verify)

```sh
sudo ./usb_device_inspect_wipe.sh --mode=wipe --passes=3 --pattern=sequence \
  --hash-verify=sample --samples=32 --chunk-size=16M --log-dir=./logs
```

### Optional: sign and export logs

```sh
sudo ./usb_device_inspect_wipe.sh --mode=wipe --sign-logs --export-logs
# or choose a specific GPG key:
sudo ./usb_device_inspect_wipe.sh --mode=wipe --sign-logs=YOUR_KEY_ID
```

---

## CLI options

| Flag                   | Values / Default                                        | Description                                                                      |
| ---------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `--mode` / `-m`        | `scan` | `wipe` (or `-m 1/2`)                           | If omitted, interactive menu is shown.                                           |
| `--device`             | `/dev/XXX`                                              | Target device. If omitted, script waits for a new device (best‑effort).          |
| `--dry-run`            | (boolean)                                               | Simulate actions; **never writes**.                                              |
| `--passes`             | `1` (supports `1`, `3`, `7`)                            | Number of overwrite passes.                                                      |
| `--pattern`            | `random` (default) | `zeros` | `ff` | `aa` | `sequence` | Pattern per pass; `sequence` cycles 00 → FF → AA.                                |
| `--chunk-size`         | `16M`                                                   | Read/write/verify chunk size (K/M/G suffixes OK).                                |
| `--hash-verify`        | `sample` (default) | `none` | `full`                    | Verification policy after wipe.                                                  |
| `--samples`            | `32`                                                    | Number of random sample windows (for `sample`).                                  |
| `--inventory-log`      | `PATH`                                                  | Append one JSON line with device fingerprint & last result.                      |
| `--log-dir`            | `./logs`                                                | Directory for per‑session logs & JSON report.                                    |
| `--run-smart`          | (boolean)                                               | Try `smartctl` (if supported) to collect health info.                            |
| `--probe-ro`           | (boolean)                                               | Tiny write/read/restore at start/mid/end (asks for consent; skipped in dry‑run). |
| `--check-hidden`       | (boolean)                                               | Try HPA/DCO queries (Linux `hdparm`); often blocked by USB bridges.              |
| `--export-logs`        | (boolean)                                               | Create `session-YYYYMMDD-HHMMSS.tar.gz` in `--log-dir`.                          |
| `--sign-logs[=GPG_ID]` | (boolean / string)                                      | Sign JSON report (and you can sign the inventory file manually).                 |
| `--firmware-scan`      | (boolean)                                               | Non‑destructive: flag DFU/vendor‑specific/odd interfaces.                        |
| `--force`              | (boolean)                                               | Bypass some interlocks (still requires typed device confirmation).               |
| `--max-findings=NUM`   | `8`                                                     | Max non‑zero offsets to record during blankness check.                           |
| `--openbsd-adapt`      |                                                         | Reserved (present but currently no functional change).                           |

---

## How device selection works

* **If `--device` is omitted**:

  * **Linux**: script polls `lsblk` for a **new disk** (USB/removable preferred) and captures recent `dmesg` lines.
  * **OpenBSD**: script polls `sysctl hw.disknames` for a new disk name.
* **If `--device` is provided**: the script validates the path and uses it directly.

---

## What the scan reports

* **Identity**: vid:pid, manufacturer, product, model, serial (Linux via `udevadm`/`lsusb` where possible).
* **Geometry**: size (bytes), logical & physical sector sizes, rotational flag.
* **Layout**: table type (`gpt`, `msdos`, `disklabel`, etc.), partition list (start/end), filesystem types.
* **Composite interfaces**: lists non‑storage interface classes (HID/CDC/vendor‑specific).
* **Blankness**: reads the device in chunks to check if all bytes are `0x00`, recording first non‑zero offsets.
* **Optional**:

  * **SMART** health attributes,
  * **Hidden areas** via `hdparm` (Linux SATA → often not forwarded by USB bridges),
  * **Read‑only probe** (user‑consented; tiny, reversible),
  * **Firmware/DFU hints** (never flashes).

---

## Wipe behavior

* **Passes & patterns**

  * `random`: `/dev/urandom` (slowest, highest assurance for simple checks).
  * `zeros`: `/dev/zero` (fast).
  * `ff` / `aa`: constant bytes; needs `xxd` for portable generation (falls back to zeros if missing).
  * `sequence`: cycles the above constants per pass (`00` → `FF` → `AA` → repeat).
* **Progress & ETA**: printed per chunk with a simple time estimate (portable; not using GNU `status=progress`).
* **Verification**

  * `sample` (default): hashes fixed anchors (start, quartiles, end) + `--samples` random windows; detects zero‑only chunks and, for constant patterns, content mismatches. For `random`, compares windows to avoid identical hashes (a heuristic).
  * `full`: computes SHA‑256 over the entire device (time‑consuming).
  * `none`: skip verification.
* **Failure conditions**: any unchanged or zero‑only spans after a non‑zero pattern cause failure; offsets are recorded to the JSON.

> **Note:** For SSDs/NVMe, manufacturer **secure erase**/sanitize commands can be preferable to software overwrites. This tool performs software writes only.

---

## Logs, reports & artifacts

Each run creates a session directory:

```
<LOG_DIR>/session-YYYYMMDD-HHMMSS/
  ├── usb-report-YYYYMMDD-HHMMSS.json   # machine report
  ├── session-YYYYMMDD-HHMMSS.log       # running log
  ├── attach-YYYYMMDD-HHMMSS.txt        # recent dmesg capture
  ├── udev-<disk>.properties            # Linux udev properties (if available)
  ├── lsusb-<vid:pid>.txt               # verbose descriptors (if available)
  ├── smart.txt                         # if --run-smart and tool works
  ├── hdparm.txt                        # if --check-hidden on Linux
  ├── device.sha256                     # if --hash-verify=full
  └── (pattern/temp files as needed)
```

* **Inventory JSONL** (`--inventory-log=PATH`): appends per‑device fingerprints and last status, one JSON object per line.
* **Signing** (`--sign-logs[=GPG_ID]`): creates `usb-report-*.json.asc` (detached ASCII signature).
* **Export** (`--export-logs`): bundles the whole session directory as a `.tar.gz` in `--log-dir`.

---

## Example output (scan)

```
=============================================================
USB Device Summary
Device: /dev/sdb  Model: SanDisk Ultra  VID:PID=0781:558A
Serial: 4C530001230904112345  Size: 64000000000 (59.6 GB)
Geometry: 512 logical / 4096 physical  ROTA: 0
Partitions (gpt)  Filesystems: ["vfat","ext4"]
Read-only: no/unknown
Composite interfaces: [{"class":"08","name":"Mass Storage"}]
SMART: unavailable
Hidden areas (HPA/DCO): not_applicable
Blankness: NOT BLANK (first non-zero at ["0x0","0x40000"])
JSON: ./logs/session-20251022-193216/usb-report-20251022-193216.json
=============================================================
```

**JSON report fields (subset):**

```json
{
  "device": "/dev/sdb",
  "bus_dev": "001:009",
  "model": "SanDisk Ultra",
  "vendor_id": "0781",
  "product_id": "558A",
  "manufacturer": "SanDisk",
  "product": "Ultra",
  "serial": "4C530001230904112345",
  "size_bytes": 64000000000,
  "sector_logical": 512,
  "sector_physical": 4096,
  "rota": 0,
  "table_type": "gpt",
  "partitions": [{"name":"/dev/sdb1","start":2048,"end":1026047,"fstype":"vfat"}],
  "filesystems": ["vfat","ext4"],
  "ro_flag": false,
  "composite_functions": [],
  "smart_status": "unavailable",
  "hpa_dco_status": "not_applicable",
  "blank_check": {"is_blank": false, "first_nonzero_offsets": ["0x0","0x40000"]},
  "probe_ro_result": "skipped",
  "firmware_scan_summary": "none",
  "mode": "scan",
  "chunk_size": "16M",
  "errors": [],
  "timestamps": {"start":"2025-10-22T19:32:16Z","end":"2025-10-22T19:32:41Z"},
  "duration_sec": 25
}
```

---

## OpenBSD notes

* Device discovery uses `sysctl hw.disknames`.
* Disk geometry and partitions are parsed from `disklabel`.
* USB descriptors via `usbconfig` (best‑effort).
* Hashing via `sha256`.
* HPA/DCO checks are marked not applicable; SMART often unavailable through USB bridges.
* For loopback testing, use `vnconfig` to attach a file as a virtual disk.

---

## Troubleshooting

* **“insufficient privileges”**: run with `sudo` or as root.
* **“unsafe target” / mounted partitions**: unmount any mounted partitions on the device first.
* **`xxd` missing**: constant patterns `ff`/`aa` fall back to zeros; install `xxd` for exact patterns.
* **SMART/HPA not supported**: common behind USB‑SATA bridges; the tool records this gracefully.
* **Slow random writes**: `/dev/urandom` is intentionally slow; prefer `sequence` or `zeros` if time‑constrained.
* **Progress looks jumpy**: ETA is a simple estimate based on elapsed time and bytes written per chunk.

---

## Exit codes

| Code | Meaning                                           |
| ---: | ------------------------------------------------- |
|    0 | Success                                           |
|    1 | User abort                                        |
|    2 | Device not found                                  |
|    3 | Verification failed                               |
|    4 | Insufficient privileges or missing critical tools |
|    5 | Unsafe target (system/root disk)                  |

---

## Self‑tests & examples

> **Linux (loopback device)**

```sh
# Create a 64 MiB sparse file and attach to a loop device:
sudo fallocate -l 64M /tmp/usb.img
sudo losetup -fP /tmp/usb.img
LOOP=$(losetup -a | awk -F: '/\/tmp\/usb.img/{print $1}')

# 1) Scan (dry-run safe)
sudo ./usb_device_inspect_wipe.sh --mode=scan --device="$LOOP" --dry-run --log-dir=./logs

# 2) Wipe gate (dry-run: requires typed confirmation but performs no writes)
sudo ./usb_device_inspect_wipe.sh --mode=wipe --device="$LOOP" --dry-run

# 3) Sample verification on a small loop device
sudo ./usb_device_inspect_wipe.sh --mode=wipe --device="$LOOP" \
  --pattern=zeros --hash-verify=sample --samples=8 --chunk-size=1M --log-dir=./logs

# Cleanup
sudo losetup -d "$LOOP"
rm -f /tmp/usb.img
```

> **OpenBSD (vnd loopback)**

```sh
# Create and attach a 64 MiB file as vnd0
dd if=/dev/zero of=/tmp/usb.img bs=1m count=64
sudo vnconfig vnd0 /tmp/usb.img

# Scan (dry-run)
sudo ./usb_device_inspect_wipe.sh --mode=scan --device=/dev/vnd0 --dry-run

# Wipe (dry-run)
sudo ./usb_device_inspect_wipe.sh --mode=wipe --device=/dev/vnd0 --dry-run

# Cleanup
sudo vnconfig -u vnd0
rm -f /tmp/usb.img
```

---

## Limitations & notes

* Constant‑byte patterns `ff`/`aa` require `xxd`; otherwise the script falls back to `zeros` for portability.
* HPA/DCO, SMART and some USB descriptor details are **often unavailable behind USB bridges**.
* Verification for `random` writes uses **heuristics** (entropy and hash diversity), not content equality.
* Progress/ETA is approximate and intentionally avoids non‑portable `dd` options like `status=progress`.

---

## Contributing

* Report issues or propose improvements by sharing diffs or suggestions.
* Keep changes **POSIX‑compatible**—avoid bash‑isms and GNU‑only flags when reasonable.
* Prefer feature flags that **degrade gracefully** when optional tools are absent.

