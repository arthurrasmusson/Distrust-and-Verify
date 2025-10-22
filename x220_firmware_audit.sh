#!/usr/bin/env bash
# x220_firmware_audit.sh — Firmware & Hardware Integrity Audit (boot from a live USB on a Lenovo X220 ThinkPad)
# Default: READ-ONLY. Network OFF by default. Update/write path guarded.
# Portability: POSIX shell + common GNU utilities
# SPDX-License-Identifier: MIT

set -Eeuo pipefail
umask 077

#############################
# UI / Logging helpers
#############################
is_tty() { [[ -t 1 ]]; }
if is_tty; then
  RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; BLU=$'\033[34m'; BLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  RED=""; YEL=""; GRN=""; BLU=""; BLD=""; DIM=""; RESET=""
fi

note() { printf "%s%s[NOTE]%s %s\n" "$BLU" "$BLD" "$RESET" "$*"; }
ok()   { printf "%s%s[OK]%s   %s\n" "$GRN" "$BLD" "$RESET" "$*"; }
warn() { printf "%s%s[WARN]%s %s\n" "$YEL" "$BLD" "$RESET" "$*" >&2; }
fail() { printf "%s%s[FAIL]%s %s\n" "$RED" "$BLD" "$RESET" "$*" >&2; }
die()  { fail "$*"; exit 1; }

trap 'fail "Unexpected error at line $LINENO. See report at: $LOG_TEXT"; exit 3' ERR

ts_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ts_short() { date -u +%Y%m%dT%H%M%SZ; }

#############################
# Defaults / Workspace
#############################
WORK_BASE="${HOME}/Persistent/x220-audit"
[[ -d "$WORK_BASE" ]] || WORK_BASE="./x220-audit"
TS="$(ts_short)"
ARTIFACT_DIR="$WORK_BASE/artifacts/$TS"
REG_DIR="$ARTIFACT_DIR/regions"
STAGING="$WORK_BASE/staging"
LOG_JSON="$ARTIFACT_DIR/audit-log.json"
LOG_TEXT="$ARTIFACT_DIR/human-report.txt"

mkdir -p "$ARTIFACT_DIR" "$REG_DIR" "$STAGING"

#############################
# Global flags
#############################
DRY_RUN=0
IMAGE_OVERRIDE=""
NET_OK=0          # network disabled by default
DUMP_COUNT=2      # redundant reads; abort if mismatch
SAFE_BATT_PCT=20  # min battery % for flashing

#############################
# Utils
#############################
have() { command -v "$1" >/dev/null 2>&1; }
need() {
  local miss=()
  for c in "$@"; do have "$c" || miss+=("$c"); done
  if ((${#miss[@]})); then
    warn "Missing tool(s): ${miss[*]}"
    warn "Install hints (if persistence enabled): apt update && apt install ${miss[*]}"
    return 1
  fi
  return 0
}
require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die "This action requires root. Re-run with: sudo $0 $*"
  fi
}

json_init() { printf '{}\n' >"$LOG_JSON"; }
json_set() { # $1: jq filter
  if have jq; then
    jq "$1" "$LOG_JSON" >"$LOG_JSON.tmp" && mv "$LOG_JSON.tmp" "$LOG_JSON"
  else
    warn "jq missing — JSON log will be minimal."
  fi
}

kv_escape() { printf '%s' "$1" | sed 's/"/\\"/g'; }

ver_of() {
  local cmd="$1"
  if ! have "$cmd"; then printf 'missing'; return 0; fi
  case "$cmd" in
    flashrom) "$cmd" --version 2>&1 | head -n1 ;;
    cbfstool) "$cmd" --version 2>&1 | head -n1 || "$cmd" -h 2>&1 | head -n1 ;;
    ifdtool)  "$cmd" -h 2>&1 | head -n1 ;;
    smartctl) "$cmd" -V 2>&1 | head -n1 ;;
    hdparm)   "$cmd" -V 2>&1 | head -n1 ;;
    dmidecode) "$cmd" --version 2>&1 | head -n1 ;;
    me_cleaner.py) "$cmd" -h 2>&1 | head -n1 ;;
    gpg|jq|sha256sum|sha512sum|xxd) "$cmd" --version 2>&1 | head -n1 ;;
    lspci|lsusb|lsblk) "$cmd" --version 2>&1 | head -n1 || echo "$cmd" ;;
    *) "$cmd" --version 2>/dev/null | head -n1 || echo "$cmd" ;;
  esac
}

is_tails() { grep -qi '^ID=tails' /etc/os-release 2>/dev/null; }
is_live()  { grep -q 'boot=live' /proc/cmdline 2>/dev/null || mount | grep -q 'overlay on / '; }

on_ac_power() {
  # Prefer sysfs
  local ac_online
  for p in /sys/class/power_supply/*; do
    [[ -f "$p/online" ]] || continue
    ac_online=$(<"$p/online")
    [[ "$ac_online" == "1" ]] && return 0
  done
  # Fallback to acpi if available
  if have acpi; then acpi -a 2>/dev/null | grep -qi "on-line" && return 0; fi
  return 1
}

battery_percent() {
  local pct=""
  for p in /sys/class/power_supply/BAT*; do
    [[ -d "$p" ]] || continue
    if [[ -f "$p/capacity" ]]; then pct=$(<"$p/capacity"); break; fi
  done
  [[ -n "$pct" ]] || pct=100
  printf '%s' "$pct"
}

write_text() { printf "%s\n" "$*" >>"$LOG_TEXT"; }

#############################
# Step: env-check
#############################
env_check() {
  require_root "$@"

  note "Environment check…"
  if is_tails; then ok "Detected Tails (Amnesic Incognito Live System)."; else warn "Not running on Tails."; fi
  if is_live; then ok "Live environment detected."; else warn "Not live media — audit still possible, but note persistence artifacts."; fi

  local HOST DMI_PRODUCT BIOS_VENDOR CPU_MODEL CHIPSET
  HOST=$(hostname 2>/dev/null || printf 'unknown')
  DMI_PRODUCT=$(dmidecode -s system-product-name 2>/dev/null || printf 'unknown')
  BIOS_VENDOR=$(dmidecode -s bios-vendor 2>/dev/null || printf 'unknown')
  CPU_MODEL=$(awk -F: '/model name/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' /proc/cpuinfo || true)
  CHIPSET=$(lspci -nn 2>/dev/null | awk -F': ' '/Host bridge/{print $3; exit}' || printf 'unknown')

  json_init
  json_set ".system.timestamp_utc = \"$(ts_utc)\" |
            .system.host = \"$(kv_escape "$HOST")\" |
            .system.dmi_product = \"$(kv_escape "$DMI_PRODUCT")\" |
            .system.bios_vendor = \"$(kv_escape "$BIOS_VENDOR")\" |
            .system.cpu_model = \"$(kv_escape "$CPU_MODEL")\" |
            .system.chipset = \"$(kv_escape "$CHIPSET")\" |
            .system.tool_versions = {}"

  for t in flashrom cbfstool ifdtool me_cleaner.py smartctl hdparm lsblk lspci lsusb dmidecode xxd sha256sum sha512sum gpg jq; do
    json_set ".system.tool_versions[\"$t\"] = \"$(kv_escape "$(ver_of "$t")")\""
  done

  mkdir -p "$ARTIFACT_DIR" "$REG_DIR" "$STAGING"
  : >"$LOG_TEXT"
  write_text "# X220 Firmware Audit — $(ts_utc)"
  write_text "Host: $HOST"
  write_text "DMI product: $DMI_PRODUCT | BIOS vendor: $BIOS_VENDOR"
  write_text "CPU: $CPU_MODEL | Chipset: $CHIPSET"
  ok "Workspace: $ARTIFACT_DIR"
}

#############################
# Step: spi-dump (read-only)
#############################
spi_dump() {
  note "SPI dump (read-only)…"
  need flashrom sha256sum sha512sum || warn "flashrom or shasum missing; dump may be skipped."

  local final="$ARTIFACT_DIR/spi-full.bin"
  local rom_size=0
  if (( DRY_RUN )); then
    [[ -n "$IMAGE_OVERRIDE" && -r "$IMAGE_OVERRIDE" ]] || die "DRY-RUN requires --image <path>"
    cp -f -- "$IMAGE_OVERRIDE" "$final"
    ok "Copied provided image to $final"
  else
    require_root
    [[ ${DUMP_COUNT} -ge 2 ]] || DUMP_COUNT=2
    local prev="" i=1 agree=1
    while (( i <= DUMP_COUNT )); do
      local out="$ARTIFACT_DIR/spi-read-$i.bin"
      note "flashrom read #$i…"
      if ! flashrom -p internal -r "$out" | tee -a "$LOG_TEXT"; then
        die "flashrom read failed. If on Tails, you may need 'iomem=relaxed'."
      fi
      local h; h=$(sha256sum "$out" | awk '{print $1}')
      write_text "sha256(spi-read-$i) = $h"
      if [[ -n "$prev" && "$h" != "$prev" ]]; then
        agree=0
      fi
      prev="$h"
      : $((i++))
    done
    if (( ! agree )); then
      fail "Redundant reads mismatch — aborting per policy."
      exit 2
    fi
    mv -f "$ARTIFACT_DIR/spi-read-1.bin" "$final"
    [[ -f "$ARTIFACT_DIR/spi-read-2.bin" ]] && rm -f "$ARTIFACT_DIR/spi-read-2.bin"
    ok "Stable read achieved. Saved: $final"
  fi

  sha256sum "$final" | awk '{print $1}' | tee "$ARTIFACT_DIR/spi-full.bin.sha256" >/dev/null
  sha512sum "$final" | awk '{print $1}' | tee "$ARTIFACT_DIR/spi-full.bin.sha512" >/dev/null
  rom_size=$(stat -c %s "$final" 2>/dev/null || wc -c <"$final")

  json_set ".spi_flash.rom_size_bytes = $rom_size |
            .spi_flash.reads_agree = true |
            .spi_flash.spi_full_sha256 = \"$(<"$ARTIFACT_DIR/spi-full.bin.sha256")\" |
            .spi_flash.spi_full_sha512 = \"$(<"$ARTIFACT_DIR/spi-full.bin.sha512")\""
}

#############################
# Step: spi-parse (IFD/BIOS/ME/GbE + CBFS + ME info)
#############################
lower() { tr '[:upper:]' '[:lower:]'; }
rename_ifd_outputs() {
  # Map ifdtool extraced region files to canonical names
  local f lc
  for f in "$REG_DIR"/*; do
    [[ -f "$f" ]] || continue
    lc="$(basename "$f" | lower)"
    case "$lc" in
      *flashdesc*|*flashdescriptor*) mv -f "$f" "$REG_DIR/descriptor.bin" ;;
      *bios*)                        mv -f "$f" "$REG_DIR/bios.bin" ;;
      *intel_me*|*me.bin|*me-*)     mv -f "$f" "$REG_DIR/me.bin" ;;
      *gbe*|*gbeh*|*intel_gbe*)     mv -f "$f" "$REG_DIR/gbe.bin" ;;
    esac
  done
}
hash_region() { local f="$1"; [[ -f "$f" ]] && sha256sum "$f" | awk '{print $1}' || printf 'absent'; }

spi_parse() {
  local image="$ARTIFACT_DIR/spi-full.bin"
  [[ -f "$image" ]] || die "Missing SPI image at $image. Run 'dump' first or supply --image with --dry-run."

  need ifdtool || warn "ifdtool missing — cannot split regions."
  ( cd "$REG_DIR" && ifdtool -x "$image" >/dev/null 2>&1 || true )
  rename_ifd_outputs

  # Hash regions
  local dsha bsha msha gsha
  dsha=$(hash_region "$REG_DIR/descriptor.bin")
  bsha=$(hash_region "$REG_DIR/bios.bin")
  msha=$(hash_region "$REG_DIR/me.bin")
  gsha=$(hash_region "$REG_DIR/gbe.bin")

  json_set ".spi_flash.regions.descriptor_sha256 = \"$dsha\" |
            .spi_flash.regions.bios_sha256 = \"$bsha\" |
            .spi_flash.regions.me_sha256 = \"$msha\" |
            .spi_flash.regions.gbe_sha256 = \"$gsha\""

  # CBFS enumeration & coreboot version
  local BIOS_BIN="$REG_DIR/bios.bin"
  local coreboot_ver="unknown"
  json_set '.spi_flash.coreboot.cbfs_summary = []'
  if [[ -f "$BIOS_BIN" ]] && have cbfstool; then
    cbfstool "$BIOS_BIN" print >"$ARTIFACT_DIR/cbfs-print.txt" 2>&1 || true
    # Try to extract common version files
    for n in etc/version etc/issue coreboot.version version.txt ; do
      if cbfstool "$BIOS_BIN" extract -n "$n" -f "$ARTIFACT_DIR/$(echo "$n" | tr '/' '_').txt" >/dev/null 2>&1; then
        coreboot_ver=$(head -n1 "$ARTIFACT_DIR/$(echo "$n" | tr '/' '_').txt" | tr -d '\r')
        break
      fi
    done
    # As a fallback, try to parse header/version lines from cbfstool print
    if [[ "$coreboot_ver" == "unknown" ]]; then
      coreboot_ver=$(grep -iE 'coreboot|cbfs v|git' "$ARTIFACT_DIR/cbfs-print.txt" | head -n1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)
      [[ -z "$coreboot_ver" ]] && coreboot_ver="unknown"
    fi
    # Store a concise CBFS listing (file names)
    awk '/^ *File.*/{print $0}' "$ARTIFACT_DIR/cbfs-print.txt" | head -n 200 |
      sed 's/"/\\"/g' | while IFS= read -r line; do
        json_set ".spi_flash.coreboot.cbfs_summary += [\"$line\"]"
      done
  else
    warn "cbfstool missing or BIOS region absent — CBFS listing skipped."
  fi
  json_set ".spi_flash.coreboot.version = \"$(kv_escape "$coreboot_ver")\""

  # Intel ME analysis (read-only)
  json_set '.spi_flash.intel_me.analysis_notes = []'
  local me_ver="unknown" me_sku="unknown"
  if [[ -f "$REG_DIR/me.bin" ]] && have me_cleaner.py; then
    # me_cleaner will only read the file; -O /dev/null ensures no write to disk image.
    local MEA="$ARTIFACT_DIR/me_cleaner_analysis.txt"
    if me_cleaner.py -S -O /dev/null "$REG_DIR/me.bin" >"$MEA" 2>&1 || me_cleaner.py -h >/dev/null 2>&1; then
      me_ver=$(grep -iE 'ME firmware.*version|version *:' "$MEA" | head -n1 | sed 's/.*version[: ]*//I;s/^[[:space:]]*//;s/[[:space:]]*$//' || true)
      me_sku=$(grep -iE 'SKU' "$MEA" | head -n1 | sed 's/.*SKU[: ]*//I;s/^[[:space:]]*//;s/[[:space:]]*$//' || true)
      # Enumerate partitions/modules heuristically
      grep -iE 'partition|module|FPT|FTP|OPR' "$MEA" | head -n 50 | sed 's/"/\\"/g' | while IFS= read -r line; do
        json_set ".spi_flash.intel_me.analysis_notes += [\"$line\"]"
      done
    else
      warn "me_cleaner.py did not run; ME details unavailable."
      json_set ".spi_flash.intel_me.analysis_notes += [\"me_cleaner not available or analysis failed\"]"
    fi
  else
    json_set ".spi_flash.intel_me.analysis_notes += [\"ME region absent or me_cleaner not installed\"]"
  fi
  [[ -z "$me_ver" ]] && me_ver="unknown"
  [[ -z "$me_sku" ]] && me_sku="unknown"
  json_set ".spi_flash.intel_me.version = \"$(kv_escape "$me_ver")\" |
            .spi_flash.intel_me.sku = \"$(kv_escape "$me_sku")\""
}

#############################
# Step: disk-audit (Samsung 850 Pro)
#############################
disk_audit() {
  note "Disk/boot audit (read-only)…"
  need lsblk smartctl hdparm xxd sha256sum || warn "Some disk tools missing; disk audit will be partial."

  # Identify the Samsung 850 Pro if present; else pick the first SATA disk
  local target=""
  if have lsblk; then
    # Try model match first
    target=$(lsblk -d -o NAME,MODEL,TYPE | awk '/disk/ && tolower($0) ~ /850.*pro/ {print $1; exit}')
    if [[ -z "$target" ]]; then
      target=$(lsblk -d -o NAME,TYPE | awk '$2=="disk"{print $1; exit}')
    fi
  fi
  [[ -n "$target" ]] || { warn "No disk found via lsblk."; return 0; }
  local dev="/dev/$target"
  write_text "Disk target: $dev"

  # SMART identify
  local model serial fw verline
  if have smartctl; then
    verline=$(smartctl -i "$dev" 2>/dev/null || true)
    model=$(printf "%s\n" "$verline" | awk -F: '/Device Model|Model Number/{gsub(/^[ \t]+/,"",$2); print $2; exit}')
    serial=$(printf "%s\n" "$verline" | awk -F: '/Serial Number/{gsub(/^[ \t]+/,"",$2); print $2; exit}')
    fw=$(printf "%s\n" "$verline" | awk -F: '/Firmware Version/{gsub(/^[ \t]+/,"",$2); print $2; exit}')
  fi

  # HPA / DCO (read-only identify)
  local max_logical max_native hpa_present="false" dco_present="false"
  if have hdparm; then
    local N; N=$(hdparm -N "$dev" 2>/dev/null || true)
    max_logical=$(printf "%s\n" "$N" | awk -F'[ =,/]+' '/max sectors/{print $(NF-1)}')
    max_native=$(printf "%s\n" "$N" | awk -F'[ =,/]+' '/max sectors/{print $NF}')
    if [[ -n "$max_logical" && -n "$max_native" && "$max_logical" != "$max_native" ]]; then
      hpa_present="true"
    fi
    # DCO heuristic from identify
    if hdparm -I "$dev" 2>/dev/null | grep -qi "device configuration overlay"; then
      dco_present="true"
    fi
  fi

  # Partition map & gaps (unallocated extents)
  local lsblk_json="$ARTIFACT_DIR/lsblk.json"
  lsblk -b -J -o NAME,TYPE,PKNAME,START,SIZE,PATH,MOUNTPOINT,FSTYPE,MODEL >"$lsblk_json" 2>/dev/null || true

  # Gather partitions for the target disk
  local parts_tsv="$ARTIFACT_DIR/parts.tsv"
  if have jq; then
    jq -r --arg disk "$target" '
      .blockdevices[] | select(.name==$disk) |
      .children[]? | [.name, .start, .size, .fstype, .mountpoint] | @tsv' "$lsblk_json" >"$parts_tsv" 2>/dev/null || true
  else
    : >"$parts_tsv"
  fi

  # Compute unexpected partitions & gaps
  local unexpected_json="$ARTIFACT_DIR/unexpected.json"
  printf '[]\n' >"$unexpected_json"
  if [[ -s "$parts_tsv" ]]; then
    # Detect suspicious partitions (no fstype and not mounted)
    while IFS=$'\t' read -r name start size fstype mnt; do
      if [[ -z "${fstype:-}" && -z "${mnt:-}" ]]; then
        if have jq; then
          jq ". + [{\"name\":\"$name\",\"start\":$start,\"size\":$size,\"reason\":\"unformatted/unmounted\"}]" "$unexpected_json" > "$unexpected_json.tmp" && mv "$unexpected_json.tmp" "$unexpected_json"
        fi
      fi
    done < <(sort -k2,2n "$parts_tsv")
    # Gaps between partitions (> 4 MiB)
    local prev_end=0
    local disk_size
    disk_size=$(lsblk -bdno SIZE "$dev" 2>/dev/null || printf 0)
    while IFS=$'\t' read -r name start size fstype mnt; do
      [[ -z "$start" || -z "$size" ]] && continue
      if (( start > prev_end )); then
        local gap=$(( start - prev_end ))
        if (( gap > 4*1024*1024 )); then
          if have jq; then
            jq ". + [{\"name\":\"gap\",\"start\":$prev_end,\"size\":$gap,\"reason\":\"unallocated extent\"}]" "$unexpected_json" > "$unexpected_json.tmp" && mv "$unexpected_json.tmp" "$unexpected_json"
          fi
        fi
      fi
      prev_end=$(( start + size ))
    done < <(sort -k2,2n "$parts_tsv")
    if (( disk_size > prev_end )); then
      local tail_gap=$(( disk_size - prev_end ))
      if (( tail_gap > 4*1024*1024 )) && have jq; then
        jq ". + [{\"name\":\"gap\",\"start\":$prev_end,\"size\":$tail_gap,\"reason\":\"trailing unallocated\"}]" "$unexpected_json" > "$unexpected_json.tmp" && mv "$unexpected_json.tmp" "$unexpected_json"
      fi
    fi
  fi

  # MBR + first 1 MiB hashes
  local mbr_bin="$ARTIFACT_DIR/mbr-512.bin"
  local first1m="$ARTIFACT_DIR/first-1MiB.bin"
  dd if="$dev" of="$mbr_bin" bs=512 count=1 iflag=direct status=none 2>/dev/null || true
  dd if="$dev" of="$first1m" bs=1M count=1 iflag=direct status=none 2>/dev/null || true
  local mbr_sha="unknown"
  [[ -s "$mbr_bin" ]] && mbr_sha=$(sha256sum "$mbr_bin" | awk '{print $1}')

  # Heuristics for OpenBSD boot
  local obsd_detect="false"
  if [[ -s "$first1m" ]]; then
    if grep -qa "OpenBSD" "$first1m" 2>/dev/null; then obsd_detect="true"; fi
  fi

  # Assemble disk JSON
  json_set ".disk.device = \"$dev\" |
            .disk.model = \"$(kv_escape "${model:-unknown}")\" |
            .disk.firmware_version = \"$(kv_escape "${fw:-unknown}")\" |
            .disk.serial = \"$(kv_escape "${serial:-unknown}")\" |
            .disk.capacity_logical = ${max_logical:-0} |
            .disk.capacity_native = ${max_native:-0} |
            .disk.hpa_present = ${hpa_present} |
            .disk.dco_present = ${dco_present} |
            .disk.mbr_sha256 = \"${mbr_sha}\" |
            .disk.openbsd_boot_detected = ${obsd_detect} |
            .disk.unexpected_partitions = $(if have jq; then cat "$unexpected_json"; else printf '[]'; fi) |
            .disk.notes = []"

  if [[ "$hpa_present" == "true" ]]; then json_set '.disk.notes += ["HPA detected: logical < native capacity"]'; fi
  if [[ "$dco_present" == "true" ]]; then json_set '.disk.notes += ["DCO present (read-only identify)"]'; fi
}

#############################
# Step: device-inventory
#############################
pci_usb_inventory() {
  note "PCI/USB inventory vs X220 profile…"
  need lspci lsusb || warn "lspci/lsusb missing — inventory will be partial."

  # PCI allowlist by class/vendor (numeric)
  # Allow: bridge[0600], display[0300], sata[0106], usb[0c03], ethernet[0200] (8086,10ec), audio[0403]
  local total=0 okcount=0
  local pci_anom_json="$ARTIFACT_DIR/pci_anomalies.json"
  printf '[]\n' >"$pci_anom_json"

  if have lspci; then
    while IFS= read -r line; do
      # Example: "00:19.0 Ethernet controller [0200]: Intel Corporation ... [8086:1502]"
      total=$((total+1))
      local class=$(printf "%s" "$line" | sed -n 's/.*\[\([0-9a-fA-F]\{4\}\)\].*$/\1/p' | head -n1)
      local vend=$(printf "%s" "$line" | sed -n 's/.*\[\([0-9a-fA-F]\{4\}\):[0-9a-fA-F]\{4\}\].*$/\1/p' | tail -n1)
      local ok="false"
      case "${class,,}" in
        0600|0300|0106|0c03|0403) ok="true" ;;
        0200) if [[ "${vend,,}" == "8086" || "${vend,,}" == "10ec" ]]; then ok="true"; fi ;;
        0280) ok="true" ;; # Wi-Fi class; absence is fine, presence is not unexpected
      esac
      if [[ "$ok" == "true" ]]; then okcount=$((okcount+1)); else
        if have jq; then
          jq ". + [{\"lspci\":\"$(kv_escape "$line")\"}]" "$pci_anom_json" >"$pci_anom_json.tmp" && mv "$pci_anom_json.tmp" "$pci_anom_json"
        fi
      fi
    done < <(lspci -nn 2>/dev/null)
  fi

  local hit_rate="0"
  if (( total > 0 )); then
    hit_rate=$(awk -v ok="$okcount" -v tot="$total" 'BEGIN{printf "%.3f", (ok/tot)}')
  fi

  # USB anomalies: allow internal hubs, camera, keyboard/trackpoint
  local usb_anom_json="$ARTIFACT_DIR/usb_anomalies.json"
  printf '[]\n' >"$usb_anom_json"
  if have lsusb; then
    while IFS= read -r u; do
      local ul="$(echo "$u" | tr '[:upper:]' '[:lower:]')"
      if echo "$ul" | grep -Eq 'hub|camera|lenovo|thinkpad|chicony|keyboard|trackpoint'; then
        : # allowed
      else
        if have jq; then
          jq ". + [{\"lsusb\":\"$(kv_escape "$u")\"}]" "$usb_anom_json" >"$usb_anom_json.tmp" && mv "$usb_anom_json.tmp" "$usb_anom_json"
        fi
      fi
    done < <(lsusb 2>/dev/null)
  fi

  json_set ".devices.pci_allowlist_hit_rate = ${hit_rate} |
            .devices.pci_anomalies = $(if have jq; then cat "$pci_anom_json"; else printf '[]'; fi) |
            .devices.usb_anomalies = $(if have jq; then cat "$usb_anom_json"; else printf '[]'; fi)"
}

#############################
# Step: summary/report
#############################
summarize_and_report() {
  note "Summarizing…"
  # Simple status heuristics
  local spi_ok="true" disk_ok="true" dev_ok="true"
  # SPI OK if dumps done, BIOS & ME hashes recorded
  if have jq; then
    [[ "$(jq -r '.spi_flash.spi_full_sha256 // empty' "$LOG_JSON")" ]] || spi_ok="false"
    [[ "$(jq -r '.spi_flash.regions.bios_sha256 // empty' "$LOG_JSON")" ]] || spi_ok="false"
    [[ "$(jq -r '.spi_flash.regions.me_sha256 // empty' "$LOG_JSON")" ]] || spi_ok="false"
    # Disk OK if no HPA/DCO and no unexpected partitions
    [[ "$(jq -r '.disk.hpa_present' "$LOG_JSON" 2>/dev/null || echo false)" == "true" ]] && disk_ok="false"
    [[ "$(jq -r '.disk.dco_present' "$LOG_JSON" 2>/dev/null || echo false)" == "true" ]] && disk_ok="false"
    if [[ "$(jq -r '.disk.unexpected_partitions | length' "$LOG_JSON" 2>/dev/null || echo 0)" -gt 0 ]]; then disk_ok="false"; fi
    # Devices OK if anomaly arrays empty
    if [[ "$(jq -r '.devices.pci_anomalies | length' "$LOG_JSON" 2>/dev/null || echo 0)" -gt 0 ]]; then dev_ok="false"; fi
    if [[ "$(jq -r '.devices.usb_anomalies | length' "$LOG_JSON" 2>/dev/null || echo 0)" -gt 0 ]]; then dev_ok="false"; fi
  fi

  local overall="OK"
  [[ "$spi_ok" == "false" || "$disk_ok" == "false" || "$dev_ok" == "false" ]] && overall="WARN"

  json_set ".summary.spi_flash_ok = ${spi_ok} |
            .summary.disk_ok = ${disk_ok} |
            .summary.devices_ok = ${dev_ok} |
            .summary.overall_status = \"${overall}\" |
            .summary.recommendations = []"

  # Recommendations
  if [[ "$spi_ok" == "false" ]]; then
    json_set '.summary.recommendations += ["Re-run SPI dump; consider iomem=relaxed; check internal programmer access."]'
  fi
  if have jq && [[ "$(jq -r '.disk.hpa_present' "$LOG_JSON" 2>/dev/null || echo false)" == "true" ]]; then
    json_set '.summary.recommendations += ["HPA detected — investigate provenance; consider removing HPA only after full forensic capture."]'
  fi
  if have jq && [[ "$(jq -r '.disk.dco_present' "$LOG_JSON" 2>/dev/null || echo false)" == "true" ]]; then
    json_set '.summary.recommendations += ["DCO present — treat as WARN; review drive configuration."]'
  fi

  # Human report
  {
    echo
    echo "== SPI/BIOS/ME =="
    echo "  SPI image:   $ARTIFACT_DIR/spi-full.bin"
    echo "  SHA256:      $( [[ -f $ARTIFACT_DIR/spi-full.bin.sha256 ]] && cat "$ARTIFACT_DIR/spi-full.bin.sha256" || echo "n/a" )"
    echo "  BIOS hash:   $(have jq && jq -r '.spi_flash.regions.bios_sha256 // "n/a"' "$LOG_JSON")"
    echo "  ME hash:     $(have jq && jq -r '.spi_flash.regions.me_sha256 // "n/a"' "$LOG_JSON")"
    echo "  coreboot:    $(have jq && jq -r '.spi_flash.coreboot.version // "unknown"' "$LOG_JSON")"
    echo
    echo "== Disk/Boot =="
    echo "  Device:      $(have jq && jq -r '.disk.device // "n/a"' "$LOG_JSON")"
    echo "  Model/FW:    $(have jq && jq -r '(.disk.model // "n/a") + " / " + (.disk.firmware_version // "n/a")' "$LOG_JSON")"
    echo "  HPA/DCO:     HPA=$(have jq && jq -r '.disk.hpa_present // false' "$LOG_JSON")  DCO=$(have jq && jq -r '.disk.dco_present // false' "$LOG_JSON")"
    echo "  MBR SHA256:  $(have jq && jq -r '.disk.mbr_sha256 // "n/a"' "$LOG_JSON")"
    echo "  OpenBSD boot detected: $(have jq && jq -r '.disk.openbsd_boot_detected // false' "$LOG_JSON")"
    echo "  Unexpected:  $(have jq && jq -r '.disk.unexpected_partitions | length' "$LOG_JSON") item(s)"
    echo
    echo "== Devices =="
    echo "  PCI allowlist hit rate: $(have jq && jq -r '.devices.pci_allowlist_hit_rate // 0' "$LOG_JSON")"
    echo "  PCI anomalies:          $(have jq && jq -r '.devices.pci_anomalies | length' "$LOG_JSON")"
    echo "  USB anomalies:          $(have jq && jq -r '.devices.usb_anomalies | length' "$LOG_JSON")"
    echo
    echo "== Summary =="
    echo "  SPI OK:   $spi_ok"
    echo "  Disk OK:  $disk_ok"
    echo "  Dev OK:   $dev_ok"
    echo "  Overall:  $overall"
    echo "  Recommendations:"
    if have jq; then jq -r '.summary.recommendations[]? | "   - " + .' "$LOG_JSON"; fi
  } >>"$LOG_TEXT"

  if [[ "$overall" == "OK" ]]; then ok "Overall: OK — see $LOG_TEXT"; else warn "Overall: $overall — see $LOG_TEXT"; fi
}

#############################
# Compare (JSON diff)
#############################
cmd_compare() {
  local prev="" curr=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --previous) prev="$2"; shift 2;;
      --current)  curr="$2"; shift 2;;
      *) fail "Unknown compare arg: $1"; exit 3;;
    esac
  done
  [[ -r "$prev" && -r "$curr" ]] || die "compare requires --previous <old.json> --current <new.json>"

  if ! have jq; then
    warn "jq missing — doing raw diff."
    if diff -u "$prev" "$curr"; then
      printf "%s\n" "MATCH"; exit 0
    else
      printf "%s\n" "MISMATCH"; exit 2
    fi
  fi

  local p_stripped="$ARTIFACT_DIR/prev.stripped.json"
  local c_stripped="$ARTIFACT_DIR/curr.stripped.json"
  jq 'del(.system.timestamp_utc, .system.tool_versions, .disk.serial)' "$prev" | jq -S . >"$p_stripped"
  jq 'del(.system.timestamp_utc, .system.tool_versions, .disk.serial)' "$curr" | jq -S . >"$c_stripped"

  if diff -u "$p_stripped" "$c_stripped"; then
    ok "MATCH"
    exit 0
  else
    fail "MISMATCH"
    exit 2
  fi
}

#############################
# Update check (read-only, Tor optional)
#############################
cmd_update_check() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --net) NET_OK=1; shift;;
      *) fail "Unknown update-check arg: $1"; exit 3;;
    esac
  done
  note "Update check (read-only)…"
  json_set '.versions = {}'
  json_set ".versions.coreboot_installed = $(jq -R <<<\"$(have jq && jq -r '.spi_flash.coreboot.version // "unknown"' "$LOG_JSON")\" )"
  json_set ".versions.me_cleaner_installed = \"$(kv_escape "$(ver_of me_cleaner.py)")\""

  if (( ! NET_OK )); then
    warn "Network is OFF by default. Re-run: $0 update-check --net (uses Tor if available)."
    json_set '.versions.coreboot_latest = "offline" |
              .versions.me_cleaner_latest = "offline" |
              .versions.updates_available = false'
    return 0
  fi

  # Best-effort skeleton with Tor; real URL/signature workflow left to operator due to environment variability.
  local torsocks=""; have torsocks && torsocks="torsocks "
  local coreboot_latest="unknown" meclean_latest="unknown"
  if have curl && have gpg; then
    # Example endpoints (operator may adapt):
    # coreboot releases: https://review.coreboot.org/plugins/gitiles/coreboot/+/refs/tags/
    # me_cleaner releases: https://github.com/corna/me_cleaner/releases/latest
    # We do not trust without signature verification; so we only stage metadata here.
    coreboot_latest=$($torsocks curl -fsSL https://review.coreboot.org/plugins/gitiles/coreboot/+/refs/tags/ 2>/dev/null | grep -Eo 'refs/tags/[^ <]+' | tail -n1 | sed 's#refs/tags/##' || echo "unknown")
    meclean_latest=$($torsocks curl -fsSL https://api.github.com/repos/corna/me_cleaner/releases/latest 2>/dev/null | grep -Eo '"tag_name": *"[^"]+"' | head -n1 | cut -d'"' -f4 || echo "unknown")
  else
    warn "curl/gpg missing — cannot query upstream."
  fi

  json_set ".versions.coreboot_latest = \"$(kv_escape "$coreboot_latest")\" |
            .versions.me_cleaner_latest = \"$(kv_escape "$meclean_latest")\""

  local updates=false
  if [[ -n "$coreboot_latest" && "$coreboot_latest" != "unknown" ]]; then
    local installed=$(have jq && jq -r '.spi_flash.coreboot.version // "unknown"' "$LOG_JSON")
    [[ "$installed" != "unknown" && "$installed" != "$coreboot_latest" ]] && updates=true
  fi
  json_set ".versions.updates_available = $updates"
  ok "Update-check staged (read-only). No flashing performed."
}

#############################
# Update apply (guarded write)
#############################
cmd_update_apply() {
  require_root
  note "Guarded update apply — BIOS region only."

  # Safeguards: AC + battery
  if ! on_ac_power; then die "AC power not detected. Plug in before flashing."; fi
  local bpct; bpct=$(battery_percent)
  if (( bpct < SAFE_BATT_PCT )); then die "Battery at ${bpct}%% (< ${SAFE_BATT_PCT}%%). Abort."; fi

  need flashrom || die "flashrom required for update-apply."

  # Confirm phrase
  printf "%s\n" "${YEL}${BLD}Type EXACTLY: I UNDERSTAND AND ACCEPT THE RISK${RESET}"
  read -r confirm
  [[ "$confirm" == "I UNDERSTAND AND ACCEPT THE RISK" ]] || die "Confirmation phrase mismatch."

  # Check write-protect / locks
  if ! flashrom -p internal --wp-status 2>&1 | tee -a "$LOG_TEXT" | grep -qi "not active"; then
    warn "Write-protect or region locks may be active. Attempting IFD write to BIOS region only."
  fi

  local NEW_BIOS="$STAGING/bios.new.bin"
  [[ -r "$NEW_BIOS" ]] || die "Place the prepared BIOS region at: $NEW_BIOS (preserving board data)."

  # Fresh backup
  local pre="$ARTIFACT_DIR/spi-prewrite-backup.bin"
  note "Reading full SPI backup before write…"
  flashrom -p internal -r "$pre" | tee -a "$LOG_TEXT"
  sha256sum "$pre" | awk '{print $1}' >"$ARTIFACT_DIR/spi-prewrite-backup.bin.sha256"

  # Apply write to BIOS region only, preserving descriptor/ME/GbE
  note "Writing BIOS region (IFD aware)…"
  flashrom -p internal --ifd -i bios -w "$NEW_BIOS" | tee -a "$LOG_TEXT"

  # Post-verify
  note "Verifying by re-reading BIOS region…"
  local post="$ARTIFACT_DIR/bios-postwrite-readback.bin"
  flashrom -p internal --ifd -i bios -r "$post" | tee -a "$LOG_TEXT"
  local wsha rsha
  wsha=$(sha256sum "$NEW_BIOS" | awk '{print $1}')
  rsha=$(sha256sum "$post" | awk '{print $1}')
  if [[ "$wsha" == "$rsha" ]]; then
    ok "Post-write verify OK."
  else
    fail "Post-write verify MISMATCH!"
    exit 2
  fi
}

#############################
# High-level commands
#############################
cmd_dump()   { env_check; spi_dump; }
cmd_analyze(){ env_check; [[ -f "$ARTIFACT_DIR/spi-full.bin" ]] || { (( DRY_RUN )) || die "No SPI image; run dump first or use --dry-run --image"; }; spi_parse; }
cmd_audit()  { env_check; spi_dump; spi_parse; disk_audit; pci_usb_inventory; summarize_and_report; ok "Artifacts: $ARTIFACT_DIR"; }

#############################
# CLI parsing
#############################
usage() {
  cat <<EOF
Usage: sudo $0 <command> [options]

Commands:
  audit                 Full read-only pipeline: dump ➜ parse ➜ disk/boot ➜ inventory ➜ report.
  dump                  Dump SPI flash (internal programmer) redundantly and hash artifacts.
  analyze               Split IFD regions; enumerate CBFS; extract coreboot version; ME analysis (read-only).
  compare --previous <old.json> --current <new.json>
                        Compare two AuditLog JSONs; prints unified diff and MATCH/MISMATCH verdict.
  update-check [--net]  Read-only check for latest coreboot/me_cleaner; verify/stage (no flashing). Tor if available.
  update-apply          Guarded: write BIOS region using staged file at \$HOME/Persistent/x220-audit/staging/bios.new.bin.

Global options:
  --dry-run             Do not touch hardware; operate on supplied --image for dump/analyze/report.
  --image <path>        Use the given SPI image (with --dry-run); places it at artifacts.
  --count <N>           Redundant SPI reads (default: 2) for 'dump'/'audit'.
  --help                Show this help.

Constraints:
  • Legal: Audit only systems you own or have permission to inspect.
  • Safety: READ-ONLY by default; flashing only in update-apply with explicit confirmation.
  • Network: OFF by default; update-check requires --net (uses Tor if available) and signature verification steps.
  • Power: Any flashing aborted unless on AC and battery ≥ ${SAFE_BATT_PCT}%.
  • Workspace: $WORK_BASE (artifacts under artifacts/UTC_TIMESTAMP).

EOF
}

main() {
  local cmd=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      audit|dump|analyze|compare|update-check|update-apply) cmd="$1"; shift; break;;
      --help|-h) usage; exit 0;;
      *) break;;
    esac
  done
  # Parse global options
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift;;
      --image) IMAGE_OVERRIDE="${2:-}"; shift 2;;
      --count) DUMP_COUNT="${2:-2}"; shift 2;;
      *) break;;
    esac
  done

  case "$cmd" in
    audit)         cmd_audit ;;
    dump)          cmd_dump ;;
    analyze)       cmd_analyze ;;
    compare)       cmd_compare "$@" ;;
    update-check)  cmd_update_check "$@" ;;
    update-apply)  cmd_update_apply ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"

