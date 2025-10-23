#!/bin/sh
#
# usb_device_inspect_wipe.sh
#
# Purpose : USB Mass‑Storage Device Inspect & Wipe (scan + overwrite + verify)
# Author  : Arthur Rasmusson
# Date    : 2025-10-22
#
# IMPORTANT WARNINGS
# ==================
# * THIS SCRIPT CAN DESTROY DATA. Use at your own risk.
# * Requires root (or sudo). Refuses to touch mounted/root/system disks.
# * Portable/POSIX style (works with dash); optional tooling is used when available.
#
# Exit codes:
#   0 success
#   1 user abort
#   2 device not found
#   3 verification failed
#   4 insufficient privileges or missing critical tools
#   5 unsafe target (system/root disk)
#
# ---------------------------------------------------------------------------

#############################################################################
# Configuration defaults (can be overridden via CLI flags)
#############################################################################

MODE=""                   # "scan" or "wipe"
DEVICE=""                 # e.g. /dev/sdb
DRY_RUN=0
PASSES=1                  # 1,3,7 allowed
PATTERN="random"          # random|zeros|ff|aa|sequence
CHUNK_SIZE="16M"
HASH_VERIFY="sample"      # none|sample|full
SAMPLES=32
INVENTORY_LOG=""          # path to JSONL
LOG_DIR="./logs"
OPENBSD_ADAPT=0
RUN_SMART=0
PROBE_RO=0
CHECK_HIDDEN=0
EXPORT_LOGS=0
SIGN_LOGS=0
SIGN_ID=""
FIRMWARE_SCAN=0
FORCE=0
MAX_FINDINGS=8           # first N non‑zero offsets to record during blankness check
LARGE_WARN_TB=2          # warn if device > 2 TB
SAMPLE_WIN_DEFAULT="1M"  # sample window size for hashing
UMOUNT_TIMEOUT=10
POST_SANITIZE="auto"     # auto|never|force

# Derived later
OS=""
TS=""
SESSION_DIR=""
SESSION_JSON=""
SESSION_LOG=""
ATTACH_LOG=""
INV_APPENDED="false"
GPG_SIG_PATH=""

# Global state collected during detection
BUS_DEV=""           # e.g. "001:009" on Linux
VENDOR_ID=""
PRODUCT_ID=""
MANUFACTURER=""
PRODUCT=""
MODEL=""            # from lsblk/udev if available
SERIAL=""
SIZE_BYTES=0
SECTOR_LOGICAL=""
SECTOR_PHYSICAL=""
ROTA=""             # 1=rotational, 0=flash
TABLE_TYPE=""
RO_FLAG=""
PART_JSON="[]"
FS_LIST="[]"
COMPOSITE_LIST="[]"
SMART_STATUS="unknown"
HPA_DCO_STATUS="unknown"
FIRMWARE_SCAN_SUMMARY="none"
BLANK_IS="unknown"
BLANK_OFFSETS="[]"
PROBE_RO_RESULT="skipped"

VERIFY_PASSED="unknown"
UNCHANGED_RANGES="[]"
ZERO_RANGES="[]"
ERRORS="[]"

# Post-sanitize reporting
SAN_SUPPORTED="false"
SAN_SELECTED_METHOD=""   # nvme_format_s1 | ata_sec_erase_enh | ata_sec_erase | scsi_sanitize_crypto
SAN_RESULT="skipped"
SAN_REASON=""

#############################################################################
# Minimal colors (safe fallback if tput/tty not present)
#############################################################################
is_tty() { [ -t 1 ] || [ -t 2 ]; }
if is_tty && command -v tput >/dev/null 2>&1; then
  RED="$(tput setaf 1 2>/dev/null || printf '')"
  GRN="$(tput setaf 2 2>/dev/null || printf '')"
  YLW="$(tput setaf 3 2>/dev/null || printf '')"
  BLU="$(tput setaf 4 2>/dev/null || printf '')"
  BLD="$(tput bold 2>/dev/null || printf '')"
  RST="$(tput sgr0 2>/dev/null || printf '')"
else
  RED="$(printf '\033[31m')"
  GRN="$(printf '\033[32m')"
  YLW="$(printf '\033[33m')"
  BLU="$(printf '\033[34m')"
  BLD="$(printf '\033[1m')"
  RST="$(printf '\033[0m')"
fi

info()  { printf '%s[i]%s %s\n' "$BLU" "$RST" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$GRN" "$RST" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YLW" "$RST" "$*"; }
err()   { printf '%s[✗]%s %s\n' "$RED" "$RST" "$*"; }

die() {
  code="$1"; shift
  err "$*"
  [ -n "$SESSION_LOG" ] && printf 'ERROR: %s\n' "$*" >>"$SESSION_LOG" 2>/dev/null || true
  exit "$code"
}

append_error() {
  # Append a string (JSON-escaped later) to ERRORS array for report
  # Keep simple: store as raw text with quotes escaped.
  txt="$*"
  esc="$(printf '%s' "$txt" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  if [ "$ERRORS" = "[]" ]; then
    ERRORS='["'"$esc"'"]'
  else
    ERRORS="$(printf '%s' "$ERRORS" | sed 's/]$//')."\"$esc\""]"
  fi
}

#############################################################################
# OS / Root / Tools
#############################################################################
detect_os() {
  case "$(uname -s 2>/dev/null || echo '?')" in
    Linux)   OS="Linux" ;;
    OpenBSD) OS="OpenBSD" ;;
    *)       OS="unknown" ;;
  esac
}

require_root() {
  uid="$(id -u 2>/dev/null || echo 9999)"
  [ "$uid" = "0" ] || die 4 "This script must run as root (or with sudo)."
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

tool_list_record=""
check_tools() {
  # Record presence of useful tools (optional gracefully)
  tools="dd grep sed awk od hexdump wc date"
  for t in $tools; do
    have_cmd "$t" || die 4 "Missing required tool: $t"
  done
  # Optional
  for t in lsblk blkid udevadm lsusb sha256sum sha256 cmp parted sgdisk smartctl hdparm timeout jq gpg tar; do
    if have_cmd "$t"; then
      tool_list_record="$tool_list_record $t"
    fi
  done
  # OpenBSD equivalents (presence checked when used)
  :
}

#############################################################################
# Logging setup
#############################################################################
init_logs() {
  TS="$(date -u +%Y%m%d-%H%M%S 2>/dev/null || date +%Y%m%d-%H%M%S)"
  SESSION_DIR="$LOG_DIR/session-$TS"
  mkdir -p "$SESSION_DIR" || die 4 "Cannot create log dir: $SESSION_DIR"
  SESSION_JSON="$SESSION_DIR/usb-report-$TS.json"
  SESSION_LOG="$SESSION_DIR/session-$TS.log"
  ATTACH_LOG="$SESSION_DIR/attach-$TS.txt"
  umask 077
  {
    printf 'USB Inspect/Wipe Session %s\n' "$TS"
    printf 'OS=%s SHELL=%s\n' "$OS" "${SHELL:-unknown}"
    printf 'Tools:%s\n' "$tool_list_record"
  } >>"$SESSION_LOG" 2>/dev/null || true
}

#############################################################################
# CLI parsing (POSIX; supports --key=value and some short forms)
#############################################################################
usage() {
  cat <<'USAGE_EOF'
Usage:
  usb_device_inspect_wipe.sh [--mode=scan|wipe] [--device=/dev/XXX] [--dry-run]
                             [--passes=N] [--pattern=random|zeros|ff|aa|sequence]
                             [--chunk-size=SIZE] [--hash-verify=none|sample|full]
                             [--samples=N] [--inventory-log=PATH] [--log-dir=PATH]
                             [--openbsd-adapt] [--run-smart] [--probe-ro]
                             [--check-hidden] [--export-logs]
                             [--sign-logs[=GPG_ID]] [--firmware-scan] [--force]
                             [--post-sanitize=auto|never|force]

If --mode is omitted, an interactive menu is shown.
SIZE accepts decimal or K/M/G suffixes (powers of 1024).
USAGE_EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --mode=*) MODE="${1#*=}";;
      -m) shift; MODE="$1";;
      -m*) MODE="${1#-m}";;
      --device=*) DEVICE="${1#*=}";;
      --dry-run) DRY_RUN=1;;
      --passes=*) PASSES="${1#*=}";;
      --pattern=*) PATTERN="${1#*=}";;
      --chunk-size=*) CHUNK_SIZE="${1#*=}";;
      --hash-verify=*) HASH_VERIFY="${1#*=}";;
      --samples=*) SAMPLES="${1#*=}";;
      --inventory-log=*) INVENTORY_LOG="${1#*=}";;
      --log-dir=*) LOG_DIR="${1#*=}";;
      --openbsd-adapt) OPENBSD_ADAPT=1;;
      --run-smart) RUN_SMART=1;;
      --probe-ro) PROBE_RO=1;;
      --check-hidden) CHECK_HIDDEN=1;;
      --export-logs) EXPORT_LOGS=1;;
      --sign-logs) SIGN_LOGS=1;;
      --sign-logs=*) SIGN_LOGS=1; SIGN_ID="${1#*=}";;
      --firmware-scan) FIRMWARE_SCAN=1;;
      --force) FORCE=1;;
      --post-sanitize=*) POST_SANITIZE="$(to_lower "${1#*=}")";;
      --max-findings=*) MAX_FINDINGS="${1#*=}";;
      --help|-h) usage; exit 0;;
      *) err "Unknown argument: $1"; usage; exit 4;;
    esac
    shift
  done

  case "$MODE" in
    1) MODE="scan";;
    2) MODE="wipe";;
    scan|wipe|"") : ;;
    *) die 4 "Invalid --mode: $MODE";;
  esac

  case "$PASSES" in
    1|3|7) : ;;
    *) warn "Non-standard passes=$PASSES; supported values are 1,3,7";;
  esac

  case "$PATTERN" in
    random|zeros|ff|aa|sequence) : ;;
    *) die 4 "Invalid --pattern";;
  esac

  case "$HASH_VERIFY" in
    none|sample|full) : ;;
    *) die 4 "Invalid --hash-verify";;
  esac

  case "$POST_SANITIZE" in
    auto|never|force) : ;;
    *) die 4 "Invalid --post-sanitize (auto|never|force)";;
  esac

  # OpenBSD fallback switch
  if [ "$OPENBSD_ADAPT" -eq 1 ] && [ "$OS" != "OpenBSD" ]; then
    warn "Forcing OpenBSD adaptation paths on non-OpenBSD system."
  fi
}

#############################################################################
# Size parsing / formatting
#############################################################################
to_lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }

parse_size_bytes() {
  # Input like "16M", "1G", "512K", or plain bytes. Returns bytes to stdout.
  s="$(to_lower "$1")"
  case "$s" in
    *k) n="${s%k}"; awk "BEGIN{printf \"%u\", $n*1024}";;
    *m) n="${s%m}"; awk "BEGIN{printf \"%u\", $n*1024*1024}";;
    *g) n="${s%g}"; awk "BEGIN{printf \"%u\", $n*1024*1024*1024}";;
    *t) n="${s%t}"; awk "BEGIN{printf \"%u\", $n*1024*1024*1024*1024}";;
    *)  printf '%s' "$s";;
  esac
}

human_bytes() {
  # Simple humanizer (binary units)
  b="$1"
  # Avoid floating point: use awk for one decimal
  if [ "$b" -ge 1099511627776 ] 2>/dev/null; then
    awk "BEGIN{printf \"%.1f TB\", $b/1099511627776}"
  elif [ "$b" -ge 1073741824 ] 2>/dev/null; then
    awk "BEGIN{printf \"%.1f GB\", $b/1073741824}"
  elif [ "$b" -ge 1048576 ] 2>/dev/null; then
    awk "BEGIN{printf \"%.1f MB\", $b/1048576}"
  elif [ "$b" -ge 1024 ] 2>/dev/null; then
    awk "BEGIN{printf \"%.1f KB\", $b/1024}"
  else
    printf '%s B' "$b"
  fi
}

#############################################################################
# Root/system/mount guards
#############################################################################
linux_root_disk() {
  # Returns parent disk name (e.g., sda) of / on Linux, if discoverable
  rootdev="$(awk '$2=="/"{print $1}' /proc/mounts 2>/dev/null | sed 's/[0-9]*$//')"
  # If like /dev/sda2 -> parent is sda
  if have_cmd lsblk; then
    p="$(lsblk -no PKNAME "$rootdev" 2>/dev/null | head -n1)"
    [ -n "$p" ] && printf '%s\n' "$p" && return 0
  fi
  # Fallback: strip /dev/ prefix and digits
  b="$(basename "$rootdev" 2>/dev/null | sed 's/[0-9]*$//')"
  [ -n "$b" ] && printf '%s\n' "$b" || printf '\n'
}

openbsd_root_disk() {
  # Parses mount(8) to get sdX underlying root (e.g., /dev/sd0a -> sd0)
  r="$(mount 2>/dev/null | awk '$3=="/"{print $1}' | sed 's#.*/##')"
  b="$(printf '%s' "$r" | sed 's/[a-z]$//')"  # remove partition letter
  [ -n "$b" ] && printf '%s\n' "$b" || printf '\n'
}

is_mounted_linux() {
  # $1: device (e.g., /dev/sdb1)
  grep -q "^[^ ]\+ $1 " /proc/self/mounts 2>/dev/null && return 0
  grep -q "^$1 " /proc/mounts 2>/dev/null && return 0
  # safer: query lsblk
  if have_cmd lsblk; then
    lsblk -rn -o NAME,MOUNTPOINT | awk -v d="$(basename "$1")" '$1==d && $2!=""{f=1} END{exit (f?0:1)}'
    return $?
  fi
  return 1
}

guard_unsafe_target() {
  # Refuse to touch system/root disks or mounted devices
  case "$OS" in
    Linux)
      p="$(basename "$DEVICE" 2>/dev/null)"
      sys="$(linux_root_disk)"
      if [ -n "$sys" ] && [ "$p" = "$sys" ]; then
        die 5 "Refusing to operate on system/root disk: $DEVICE"
      fi
      # Refuse if any partition is mounted
      if have_cmd lsblk; then
        if lsblk -rn -o NAME,MOUNTPOINT "$DEVICE" 2>/dev/null | awk '$2!=""{f=1} END{exit (f?0:1)}'; then
          die 5 "Refusing: one or more partitions of $DEVICE are mounted."
        fi
      fi
      ;;
    OpenBSD)
      b="$(basename "$DEVICE" 2>/dev/null)"
      sys="$(openbsd_root_disk)"
      if [ -n "$sys" ] && [ "$b" = "$sys" ] || printf '%s' "$b" | grep -q "^${sys}[a-z]\$"; then
        die 5 "Refusing to operate on system/root disk: $DEVICE"
      fi
      # Mount check
      if mount 2>/dev/null | grep -q "^$DEVICE"; then
        die 5 "Refusing: $DEVICE is mounted."
      fi
      ;;
  esac
}

unmount_all_partitions() {
  case "$OS" in
    Linux)
      if have_cmd lsblk; then
        # Unmount all children partitions
        lsblk -rn -o NAME,MOUNTPOINT "$DEVICE" 2>/dev/null | awk '$2!=""{print $1 " " $2}' |
        while read n mp; do
          [ -n "$mp" ] || continue
          warn "Unmounting $mp"
          umount "$mp" || die 5 "Failed to unmount $mp"
        done
      fi
      ;;
    OpenBSD)
      # Unmount all that begin with device (partition letters)
      mount 2>/dev/null | awk -v d="$(basename "$DEVICE")" '$1 ~ ("/dev/" d){print $3}' |
      while read mp; do
        warn "Unmounting $mp"
        umount "$mp" || die 5 "Failed to unmount $mp"
      done
      ;;
  esac
  sync
}

flush_buffers() {
  sync
  case "$OS" in
    Linux)
      if have_cmd blockdev; then
        blockdev --flushbufs "$DEVICE" 2>/dev/null || true
      fi
      ;;
    OpenBSD) : ;;
  esac
}

#############################################################################
# Device wait / detection
#############################################################################
lsblk_candidates() {
  # List potential new disks: name type tran rm
  lsblk -dn -o NAME,TYPE,TRAN,RM 2>/dev/null | awk '$2=="disk"{print $1 " " $3 " " $4}'
}

linux_wait_for_new_disk() {
  base="$(lsblk_candidates | awk '{print $1}')"
  info "Waiting for a new USB/removable disk to appear (Ctrl-C to abort)…"
  i=0
  while :; do
    sleep 1
    now="$(lsblk_candidates)"
    # find diff
    echo "$now" | while read n tran rm; do
      [ -z "$n" ] && continue
      echo "$base" | grep -q "^$n\$" && continue
      # consider only USB/removable
      if [ "$tran" = "usb" ] || [ "$rm" = "1" ]; then
        printf '/dev/%s\n' "$n"
        return 0
      fi
    done | head -n1 && return 0
    i=$((i+1))
    [ $i -ge 300 ] && break
  done
  return 1
}

openbsd_wait_for_new_disk() {
  base="$(sysctl -n hw.disknames 2>/dev/null | tr ' ' '\n' | sed 's/:.*//' )"
  info "Waiting for a new disk (OpenBSD)…"
  i=0
  while :; do
    sleep 1
    now="$(sysctl -n hw.disknames 2>/dev/null | tr ' ' '\n' | sed 's/:.*//' )"
    for n in $now; do
      echo "$base" | grep -q "^$n\$" && continue
      case "$n" in
        sd*|wd*|cd*) printf '/dev/%s\n' "$n"; return 0;;
      esac
    done
    i=$((i+1)); [ $i -ge 300 ] && break
  done
  return 1
}

resolve_device_or_wait() {
  if [ -n "$DEVICE" ]; then
    [ -e "$DEVICE" ] || die 2 "Device not found: $DEVICE"
    return 0
  fi
  case "$OS" in
    Linux)
      if have_cmd udevadm; then
        # Poll (simpler/more portable than parsing udevadm monitor)
        :
      fi
      dev="$(linux_wait_for_new_disk)" || die 2 "No device detected."
      DEVICE="$dev"
      ;;
    OpenBSD)
      dev="$(openbsd_wait_for_new_disk)" || die 2 "No device detected."
      DEVICE="$dev"
      ;;
    *)
      die 4 "Unsupported OS for auto-detection."
      ;;
  esac
}

#############################################################################
# Attribute collection (Linux / OpenBSD)
#############################################################################
collect_linux_attrs() {
  d="$DEVICE"
  bn="$(basename "$d")"

  # lsblk basics
  if have_cmd lsblk; then
    SIZE_BYTES="$(lsblk -bdn -o SIZE "$d" 2>/dev/null | head -n1)"
    [ -z "$SIZE_BYTES" ] && SIZE_BYTES=0
    MODEL="$(lsblk -dn -o MODEL "$d" 2>/dev/null | head -n1 | sed 's/^ *//; s/ *$//')"
    ROTA="$(lsblk -dn -o ROTA "$d" 2>/dev/null | head -n1)"
    RO_FLAG="$(lsblk -dn -o RO "$d" 2>/dev/null | head -n1)"
  fi

  # sector sizes
  if [ -r "/sys/block/$bn/queue/logical_block_size" ]; then
    SECTOR_LOGICAL="$(cat "/sys/block/$bn/queue/logical_block_size" 2>/dev/null)"
  fi
  if [ -r "/sys/block/$bn/queue/physical_block_size" ]; then
    SECTOR_PHYSICAL="$(cat "/sys/block/$bn/queue/physical_block_size" 2>/dev/null)"
  fi

  # udevadm properties
  if have_cmd udevadm; then
    udevadm info -q property -n "$d" >"$SESSION_DIR/udev-$bn.properties" 2>/dev/null || true
    VENDOR_ID="$(grep '^ID_VENDOR_ID=' "$SESSION_DIR/udev-$bn.properties" 2>/dev/null | tail -n1 | cut -d= -f2)"
    PRODUCT_ID="$(grep '^ID_MODEL_ID='  "$SESSION_DIR/udev-$bn.properties" 2>/dev/null | tail -n1 | cut -d= -f2)"
    MANUFACTURER="$(grep '^ID_VENDOR='   "$SESSION_DIR/udev-$bn.properties" 2>/dev/null | tail -n1 | cut -d= -f2)"
    PRODUCT="$(grep '^ID_MODEL='         "$SESSION_DIR/udev-$bn.properties" 2>/dev/null | tail -n1 | cut -d= -f2)"
    SERIAL="$(grep '^ID_SERIAL_SHORT='   "$SESSION_DIR/udev-$bn.properties" 2>/dev/null | tail -n1 | cut -d= -f2)"
    [ -z "$MODEL" ] && MODEL="$PRODUCT"
  fi

  # partitions & filesystems
  PART_JSON="[]"
  FS_LIST="[]"
  if have_cmd lsblk; then
    lsblk -rn -o NAME,TYPE,START,END,FSTYPE "$d" 2>/dev/null |
    awk 'BEGIN{FS="[ \t]+"} $2=="part"{print $1, $3, $4, $5}' |
    while read n s e fs; do
      [ -z "$n" ] && continue
      item='{"name":"/dev/'"$n"'","start":'"${s:-0}"',"end":'"${e:-0}"',"fstype":"'"${fs:-unknown}"'"}'
      if [ "$PART_JSON" = "[]" ]; then PART_JSON="[$item]"; else PART_JSON="$(printf '%s' "$PART_JSON" | sed 's/]$//'),$item]"; fi
      if [ -n "$fs" ]; then
        if [ "$FS_LIST" = "[]" ]; then FS_LIST='["'"$fs"'"]'; else FS_LIST="$(printf '%s' "$FS_LIST" | sed 's/]$//'),\"'"$fs"'"]"; fi
      fi
    done
  fi

  # partition table type
  if have_cmd sgdisk; then
    TABLE_TYPE="$(sgdisk -p "$d" 2>/dev/null | awk '/found a/[1]{print tolower($4)}' | head -n1)"
  elif have_cmd parted; then
    TABLE_TYPE="$(parted -s "$d" print 2>/dev/null | awk -F: '/Partition Table/ {gsub(/^[ \t]+/,"",$2); print tolower($2)}' | head -n1)"
  fi

  # lsusb composite interfaces
  COMPOSITE_LIST="[]"
  if have_cmd lsusb; then
    # If VID:PID known, query by that; else dump all and best-effort match later
    vp=""
    [ -n "$VENDOR_ID" ] && [ -n "$PRODUCT_ID" ] && vp="$(printf '%s:%s' "$VENDOR_ID" "$PRODUCT_ID")"
    if [ -n "$vp" ]; then
      lsusb -v -d "$vp" 2>/dev/null > "$SESSION_DIR/lsusb-$vp.txt" || true
      awk '/bInterfaceClass/ {print $2}' "$SESSION_DIR/lsusb-$vp.txt" 2>/dev/null |
      while read c; do
        cls="$c"
        name="unknown"
        case "$cls" in
          08) name="Mass Storage" ;;
          03) name="HID" ;;
          02) name="CDC \(Communications\)" ;;
          0a) name="CDC Data" ;;
          0e) name="Video" ;;
          e0) name="Wireless Controller" ;;
          fe) name="Application \(e.g., DFU\)" ;;
          ff) name="Vendor Specific" ;;
        esac
        item='{"class":"'"$cls"'","name":"'"$name"'"}'
        # Append to COMPOSITE_LIST safely using a temporary variable
        if [ "$COMPOSITE_LIST" = "[]" ]; then
          COMPOSITE_LIST="[$item]"
        else
          tmp_comp="$(printf '%s' "$COMPOSITE_LIST" | sed 's/]$//')"
          COMPOSITE_LIST="${tmp_comp},$item]"
        fi
      done
      # bus:dev (best effort from lsusb -t or lsusb plain)
      BUS_DEV="$(lsusb 2>/dev/null | awk -v vp="$vp" '$0 ~ vp {print $2 ":" $4}' | sed 's/.$//' | head -n1)"
    fi
  fi
}

collect_openbsd_attrs() {
  d="$DEVICE"
  # derive diskname for disklabel (sd0 from /dev/sd0 or /dev/sd0c)
  base="$(basename "$d" 2>/dev/null)"
  disk="$(printf '%s' "$base" | sed 's/[a-z]$//' )"

  if have_cmd disklabel; then
    disklabel "$disk" >"$SESSION_DIR/disklabel-$disk.txt" 2>/dev/null || true
    bytes_per_sector="$(awk -F: '/bytes\/sector/ {gsub(/[ \t]/,"",$2); print $2}' "$SESSION_DIR/disklabel-$disk.txt" 2>/dev/null)"
    total_sectors="$(awk -F: '/total sectors/ {gsub(/[ \t]/,"",$2); print $2}' "$SESSION_DIR/disklabel-$disk.txt" 2>/dev/null)"
    [ -n "$bytes_per_sector" ] && [ -n "$total_sectors" ] && SIZE_BYTES="$(awk 'BEGIN{print '"$bytes_per_sector"'*'"$total_sectors"'}')"
    SECTOR_LOGICAL="$bytes_per_sector"
    SECTOR_PHYSICAL=""
    ROTA=""      # unknown on OpenBSD via this path
    RO_FLAG=""
    MODEL="$(dmesg 2>/dev/null | grep -E " $disk at " | tail -n1 | sed 's/.*: //')"
    # partitions and fs
    PART_JSON="[]"; FS_LIST="[]"
    awk '/^[ a-z]:/ {print $1, $2, $3, $4, $5, $6, $7}' "$SESSION_DIR/disklabel-$disk.txt" 2>/dev/null |
    while read a b c d e f g; do
      part="$(printf '%s' "$a" | cut -d: -f1)"
      case "$part" in
        [a-j])
          pname="/dev/${disk}${part}"
          # disklabel prints "size offset fstype"
          off="$f"; sz="$e"; fst="$g"
          [ -z "$off" ] && off=0
          [ -z "$sz" ] && sz=0
          item='{"name":"'"$pname"'","start":'"$off"',"end":'"$sz"',"fstype":"'"${fst:-unknown}"'"}'
          # Append to PART_JSON safely using multi-line if to avoid quoting issues
          if [ "$PART_JSON" = "[]" ]; then
            PART_JSON="[$item]"
          else
            PART_JSON="$(printf '%s' "$PART_JSON" | sed 's/]$//'),$item]"
          fi
          # Append filesystem type to FS_LIST if non-empty
          if [ -n "$fst" ]; then
            if [ "$FS_LIST" = "[]" ]; then
              FS_LIST="[\"$fst\"]"
            else
              FS_LIST="$(printf '%s' "$FS_LIST" | sed 's/]$//'),\"$fst\"]"
            fi
          fi
          ;;
      esac
    done
    TABLE_TYPE="disklabel"
  fi

  # USB descriptors (best effort)
  if have_cmd usbconfig; then
    usbconfig -d ugen0.0 dump_all_desc >"$SESSION_DIR/usbdesc.txt" 2>/dev/null || true
  fi

  # Hash/serial/manufacturer (OpenBSD does not expose the same udev properties)
  SERIAL=""
  MANUFACTURER=""
  PRODUCT=""
  VENDOR_ID=""
  PRODUCT_ID=""
  BUS_DEV=""
}

collect_attrs() {
  case "$OS" in
    Linux)   collect_linux_attrs ;;
    OpenBSD) collect_openbsd_attrs ;;
  esac

  # Attach logs
  if have_cmd dmesg; then
    dmesg 2>/dev/null | tail -n 200 >"$ATTACH_LOG" 2>/dev/null || true
  fi
}

#############################################################################
# Blankness check (read chunks, see if all zeros)
#############################################################################
chunk_all_zero() {
  # Reads from stdin, returns 0 if all zero bytes, 1 otherwise.
  # We convert to hex via POSIX od+awk and check for non-"00"
  od -An -tx1 -v | awk '
    {
      for (i=1;i<=NF;i++) { if ($i != "00") { exit 1 } }
    }
    END { exit 0 }'
}

first_nonzero_offset_in_chunk() {
  # stdin chunk -> prints byte offset of first non-zero within chunk, or -1
  od -An -tx1 -v | awk '
    {
      for (i=1;i<=NF;i++) {
        if ($i != "00") { print pos; exit }
        pos++
      }
    }
    END { if (NR==0) print -1 }' pos=0
}

blankness_scan() {
  cs_bytes="$(parse_size_bytes "$CHUNK_SIZE")"
  [ -z "$cs_bytes" ] && cs_bytes=1048576

  total="$SIZE_BYTES"
  [ "$total" -eq 0 ] && { warn "Unknown device size; blankness check may be slow."; }

  info "Blankness check (chunk=$CHUNK_SIZE)…"
  count_find=0
  offset=0
  BLANK_IS="blank"
  BLANK_OFFSETS="[]"

  while :; do
    # Stop when we reached the end if size known
    if [ "$total" -gt 0 ] && [ "$offset" -ge "$total" ]; then
      break
    fi

    dd if="$DEVICE" bs="$cs_bytes" skip=$((offset / cs_bytes)) count=1 2>/dev/null |
    {
      if chunk_all_zero; then
        : # ok
      else
        # mark non-blank
        BLANK_IS="not_blank"
        # find the first non-zero within this chunk (best effort)
        p="$(dd if="$DEVICE" bs="$cs_bytes" skip=$((offset / cs_bytes)) count=1 2>/dev/null | first_nonzero_offset_in_chunk)"
        if [ -z "$p" ] || [ "$p" -lt 0 ] 2>/dev/null; then
          abs="$offset"
        else
          abs=$((offset + p))
        fi
        hex="$(printf '0x%X' "$abs" 2>/dev/null || printf '%s' "$abs")"
        if [ "$BLANK_OFFSETS" = "[]" ]; then
          BLANK_OFFSETS='["'"$hex"'"]'
        else
          BLANK_OFFSETS="$(printf '%s' "$BLANK_OFFSETS" | sed 's/]$//'),\""$hex\""]"
        fi
        count_find=$((count_find+1))
        [ "$count_find" -ge "$MAX_FINDINGS" ] && break
      fi
    }

    # advance
    offset=$((offset + cs_bytes))
    # Progress (simple)
    if [ "$total" -gt 0 ]; then
      pct=$(( offset * 100 / total ))
      printf '\r.. %s%%' "$pct"
    else
      printf '\r.. %s MB read' "$(awk "BEGIN{print $offset/1048576}")"
    fi
  done
  printf '\n'

  [ "$BLANK_IS" = "blank" ] && ok "Device appears BLANK." || warn "Device NOT blank. First offsets: $BLANK_OFFSETS"
}

#############################################################################
# Optional probing (tiny write/read/restore)
#############################################################################
probe_ro() {
  [ "$DRY_RUN" -eq 1 ] && { PROBE_RO_RESULT="skipped(dry-run)"; return 0; }
  cs_bytes="$(parse_size_bytes "$SAMPLE_WIN_DEFAULT")"
  [ -z "$cs_bytes" ] && cs_bytes=4096

  # Determine three offsets: 0, mid, end-cs
  mid=0
  if [ "$SIZE_BYTES" -gt 0 ]; then
    mid=$(( SIZE_BYTES / 2 ))
    end=$(( SIZE_BYTES - cs_bytes ))
    [ "$end" -lt 0 ] && end=0
  else
    end=0
  fi

  printf '%s\n' "This will write and restore tiny markers at start/middle/end."
  printf '%s' "Proceed? type YES to continue: "
  read ans || ans=""
  [ "$ans" = "YES" ] || { PROBE_RO_RESULT="declined"; return 1; }

  tmp1="$SESSION_DIR/probe_before.bin"
  tmp2="$SESSION_DIR/probe_after.bin"
  marker="$SESSION_DIR/probe_marker.bin"
  # marker = 16 bytes textual tag
  printf 'USBPROBE-%s\n' "$TS" | dd bs=16 count=1 of="$marker" 2>/dev/null

  # A helper function
  _one_probe() {
    off="$1"
    # save original
    dd if="$DEVICE" of="$tmp1" bs="$cs_bytes" skip=$((off / cs_bytes)) count=1 2>/dev/null || return 1
    # write marker at beginning of window
    dd if="$marker" of="$DEVICE" bs=1 seek=$off conv=notrunc 2>/dev/null || return 1
    sync
    dd if="$DEVICE" of="$tmp2" bs="$cs_bytes" skip=$((off / cs_bytes)) count=1 2>/dev/null || return 1
    # restore original
    dd if="$tmp1" of="$DEVICE" bs="$cs_bytes" seek=$((off / cs_bytes)) conv=notrunc 2>/dev/null || true
    # compare
    if cmp -s "$tmp1" "$tmp2" 2>/dev/null; then
      printf 'unchanged@%s ' "$off"
      return 1
    else
      printf 'writable@%s ' "$off"
      return 0
    fi
  }

  res=""
  s=0
  for off in 0 "$mid" "$end"; do
    r="$(_one_probe "$off")" || s=$((s+1))
    res="$res$r"
  done
  printf '\n'
  if [ "$s" -gt 0 ]; then
    PROBE_RO_RESULT="issues($res)"
    warn "Probe indicates potential read-only/unchanged areas: $res"
  else
    PROBE_RO_RESULT="ok($res)"
    ok "Probe writes appear to succeed and change data."
  fi
}

#############################################################################
# SMART / HPA-DCO / Firmware (best-effort)
#############################################################################
maybe_smart() {
  [ "$RUN_SMART" -eq 1 ] || { SMART_STATUS="skipped"; return; }
  if have_cmd smartctl; then
    smartctl -i -H -A "$DEVICE" >"$SESSION_DIR/smart.txt" 2>&1 || true
    st="$(grep -E 'SMART overall-health self-assessment test result|SMART Health Status' "$SESSION_DIR/smart.txt" 2>/dev/null | head -n1 | sed 's/.*: *//')"
    [ -n "$st" ] && SMART_STATUS="$st" || SMART_STATUS="unavailable"
  else
    SMART_STATUS="tool_missing"
  fi
}

maybe_hidden() {
  [ "$CHECK_HIDDEN" -eq 1 ] || { HPA_DCO_STATUS="skipped"; return; }
  case "$OS" in
    Linux)
      if have_cmd hdparm; then
        hdparm -N -I "$DEVICE" >"$SESSION_DIR/hdparm.txt" 2>&1 || true
        if grep -q "not supported" "$SESSION_DIR/hdparm.txt" 2>/dev/null; then
          HPA_DCO_STATUS="not_supported (likely USB bridge)"
        else
          HPA_DCO_STATUS="queried"
        fi
      else
        HPA_DCO_STATUS="tool_missing"
      fi
      ;;
    OpenBSD)
      HPA_DCO_STATUS="not_applicable"
      ;;
  esac
}

maybe_firmware_scan() {
  [ "$FIRMWARE_SCAN" -eq 1 ] || { FIRMWARE_SCAN_SUMMARY="none"; return; }
  # Best-effort: look for DFU / vendor-specific interfaces from composite list
  case "$COMPOSITE_LIST" in
    *'"class":"fe"'*) FIRMWARE_SCAN_SUMMARY="found Application/DFU interface";;
    *'"class":"ff"'*) FIRMWARE_SCAN_SUMMARY="vendor-specific interface present";;
    *) FIRMWARE_SCAN_SUMMARY="none";;
  esac
}

#############################################################################
# Wipe patterns and write loop
#############################################################################
need_xxd=0
gen_pattern_chunk() {
  # Create a CHUNK_SIZE-sized file with constant byte pattern ($1 = "ff"|"aa")
  # Requires: hexdump + xxd. If xxd missing, we try to fail gracefully.
  hex="$1"
  out="$2"
  bs="$(parse_size_bytes "$CHUNK_SIZE")"
  if have_cmd hexdump && have_cmd xxd; then
    # Generate bs*2 hex chars of "$hex", then convert to binary
    # Use a bounded loop: produce 1 MiB of 'hex' and repeat until size reached
    rm -f "$out" 2>/dev/null || true
    one_mb=1048576
    # Create 1MiB hex stream (2 chars per byte)
    tmphex="$SESSION_DIR/_hex_${hex}.txt"
    rm -f "$tmphex" 2>/dev/null || true
    # Use hexdump to repeat "hex" for N bytes: /dev/zero → format prints literal "hex"
    # format: 1/1 "ff" means print 'ff' per input byte.
    dd if=/dev/zero bs=$one_mb count=1 2>/dev/null | hexdump -v -e "1/1 \"${hex}\"" >"$tmphex"
    written=0
    while [ "$written" -lt "$bs" ]; do
      need=$((bs - written))
      if [ "$need" -ge "$one_mb" ]; then
        head -c $((2*one_mb)) "$tmphex" | xxd -r -p >>"$out"
        written=$((written + one_mb))
      else
        # need bytes → 2*need hex chars
        head -c $((2*need)) "$tmphex" | xxd -r -p >>"$out"
        written=$bs
      fi
    done
    return 0
  fi
  need_xxd=1
  return 1
}

write_pattern_pass() {
  passnum="$1"
  mode="$2"   # "random|zeros|ff|aa|sequence"
  bs="$(parse_size_bytes "$CHUNK_SIZE")"
  [ -z "$bs" ] && bs=16777216

  total="$SIZE_BYTES"
  [ "$total" -gt 0 ] || die 4 "Cannot determine device size for wipe."

  blocks=$(( (total + bs - 1) / bs ))
  start_time="$(date +%s 2>/dev/null || echo 0)"

  info "Pass $passnum/$PASSES using pattern=$mode (chunk=$CHUNK_SIZE, blocks=$blocks)…"

  # Determine effective pattern for this pass if sequence
  eff="$mode"
  if [ "$mode" = "sequence" ]; then
    # cycle 0:00, 1:FF, 2:AA (repeat)
    m=$(( (passnum - 1) % 3 ))
    case "$m" in
      0) eff="zeros" ;;
      1) eff="ff" ;;
      2) eff="aa" ;;
    esac
    info "sequence → pass $passnum uses '$eff'"
  fi

  # Prepare constant chunk if needed
  pattern_file=""
  case "$eff" in
    zeros) pattern_file="/dev/zero" ;;
    random) pattern_file="/dev/urandom" ;;
    ff|aa)
      byte_hex="$eff"
      pattern_file="$SESSION_DIR/pattern_${byte_hex}.bin"
      if [ ! -s "$pattern_file" ]; then
        gen_pattern_chunk "$byte_hex" "$pattern_file" || {
          warn "Could not generate constant pattern; falling back to zeros."
          eff="zeros"
          pattern_file="/dev/zero"
        }
      fi
      ;;
  esac

  i=0
  written=0
  while [ $i -lt $blocks ]; do
    # Last block size optimization: still write full chunk; acceptable.
    seek="$i"
    if [ "$DRY_RUN" -eq 1 ]; then
      : # simulate
      sleep 0
    else
      if [ "$eff" = "random" ] || [ "$pattern_file" = "/dev/zero" ]; then
        dd if="$pattern_file" of="$DEVICE" bs="$bs" seek="$seek" count=1 conv=notrunc 2>/dev/null || {
          append_error "dd write failed at block $i"
          die 4 "Write failed."
        }
      else
        # prebuilt chunk file of size bs
        dd if="$pattern_file" of="$DEVICE" bs="$bs" seek="$seek" count=1 conv=notrunc 2>/dev/null || {
          append_error "dd write failed at block $i"
          die 4 "Write failed."
        }
      fi
    fi
    written=$(( (i + 1) * bs ))
    if [ "$written" -gt "$total" ]; then written="$total"; fi

    # Progress + ETA
    now="$(date +%s 2>/dev/null || echo 0)"
    elapsed=$(( now - start_time ))
    [ "$elapsed" -le 0 ] && elapsed=1
    pct=$(( written * 100 / total ))
    rate=$(( written / elapsed ))
    remain=$(( (total - written) / (rate + 1) ))
    printf '\r.. %3s%%  %s / %s  ETA %ss' \
      "$pct" "$(human_bytes "$written")" "$(human_bytes "$total")" "$remain"
    i=$((i+1))
  done
  printf '\n'
  flush_buffers
}

#############################################################################
# Verification
#############################################################################
hash_cmd=""
detect_hash_cmd() {
  if have_cmd sha256sum; then
    hash_cmd="sha256sum"
  elif have_cmd sha256; then
    hash_cmd="sha256"
  else
    hash_cmd=""
  fi
}

hash_region() {
  # args: offset bytes -> prints hex digest
  off="$1"
  cnt="$2"
  if [ -z "$hash_cmd" ]; then
    printf 'nohash\n'
    return 0
  fi
  case "$hash_cmd" in
    sha256sum)
      dd if="$DEVICE" bs=1 skip="$off" count="$cnt" 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}'
      ;;
    sha256)
      dd if="$DEVICE" bs=1 skip="$off" count="$cnt" 2>/dev/null | sha256 2>/dev/null | awk '{print $1}'
      ;;
  esac
}

random_u64() {
  dd if=/dev/urandom bs=8 count=1 2>/dev/null | od -An -tu8 | awk '{print $1+0}'
}

build_sample_offsets() {
  # prints newline-separated offsets for sampling (unique, in-range)
  total="$SIZE_BYTES"
  win_bytes="$(parse_size_bytes "$SAMPLE_WIN_DEFAULT")"
  [ "$win_bytes" -gt "$total" ] && win_bytes=$total

  # fixed anchors (start + quartiles + end-win)
  q1=$(( total / 4 ))
  q2=$(( total / 2 ))
  q3=$(( total * 3 / 4 ))
  end=$(( total - win_bytes ))
  [ "$end" -lt 0 ] && end=0

  printf '0\n' || :
  printf '%s\n' "$q1" "$q2" "$q3" "$end" | awk '!seen[$1]++'

  # random samples
  n="$SAMPLES"
  c=0
  while [ $c -lt "$n" ]; do
    r="$(random_u64)"
    [ -z "$r" ] && r=0
    off=$(( r % (total - win_bytes + 1) ))
    printf '%s\n' "$off"
    c=$((c+1))
  done | awk '!seen[$1]++'
}

verify_after_wipe() {
  detect_hash_cmd
  case "$HASH_VERIFY" in
    none) VERIFY_PASSED="skipped"; return 0;;
  esac

  win_bytes="$(parse_size_bytes "$SAMPLE_WIN_DEFAULT")"
  [ -z "$win_bytes" ] && win_bytes=1048576
  # Pre-write sample hashes (if available) were not persisted; we do best-effort:
  #   For random: ensure not all-zero and that multiple windows differ from one another.
  #   For zeros/ff/aa/sequence: verify windows match the expected pattern (last pass).

  expected=""
  if [ "$PATTERN" = "sequence" ]; then
    # expected is from last effective pass
    last="$PASSES"
    m=$(( (last - 1) % 3 ))
    case "$m" in 0) expected="zeros";; 1) expected="ff";; 2) expected="aa";; esac
  else
    expected="$PATTERN"
  fi

  unchanged="[]"; zero_ranges="[]"; failures=0

  build_sample_offsets | while read off; do
    [ -z "$off" ] && continue
    # Fetch window bytes
    # Optimize: we check zero-only first via od
    dd if="$DEVICE" bs="$win_bytes" skip=$((off / win_bytes)) count=1 2>/dev/null | chunk_all_zero
    is_zero=$?
    if [ $is_zero -eq 0 ]; then
      # Window is all zeros
      if [ "$expected" = "zeros" ]; then
        : # ok
      else
        # suspicious zero chunk after non-zero pattern
        hex="$(printf '0x%X' "$off" 2>/dev/null || printf '%s' "$off")"
        if [ "$zero_ranges" = "[]" ]; then zero_ranges='["'"$hex"'"]'; else zero_ranges="$(printf '%s' "$zero_ranges" | sed 's/]$//'),\"'"$hex"'"]"; fi
        failures=$((failures+1))
      fi
      continue
    fi

    case "$expected" in
      zeros)
        # already handled, so any non-zero now is failure
        hex="$(printf '0x%X' "$off" 2>/dev/null || printf '%s' "$off")"
        append="\"$hex\""
        failures=$((failures+1))
        if [ "$unchanged" = "[]" ]; then unchanged="[$append]"; else unchanged="$(printf '%s' "$unchanged" | sed 's/]$//'),$append]"; fi
        ;;
      ff|aa)
        # Build a small expected window for hashing/comparison if tools present
        if have_cmd hexdump && have_cmd xxd; then
          tmp="$SESSION_DIR/_exp.bin"
          rm -f "$tmp" 2>/dev/null || true
          gen_pattern_chunk "$expected" "$tmp" || true
          # Read actual window and compare to tmp (first win_bytes)
          dd if="$DEVICE" bs="$win_bytes" skip=$((off / win_bytes)) count=1 2>/dev/null | cmp -s - "$tmp" 2>/dev/null || failures=$((failures+1))
          rm -f "$tmp" 2>/dev/null || true
        else
          # fallback: at least ensure not equal to zeros (already)
          :
        fi
        ;;
      random)
        # For random we cannot know exact bytes; assert high entropy relative to zeros:
        # We'll hash two different random sample windows; if hashes equal, suspicious.
        h1="$(hash_region "$off" "$win_bytes")"
        r2=$(( (off + win_bytes*3) % (SIZE_BYTES - win_bytes + 1) ))
        h2="$(hash_region "$r2" "$win_bytes")"
        if [ -n "$h1" ] && [ "$h1" = "$h2" ]; then
          failures=$((failures+1))
        fi
        ;;
      *)
        : # other constants not covered
        ;;
    esac
  done

  # Export results
  [ "$zero_ranges" = "[]" ] || ZERO_RANGES="$zero_ranges"
  if [ "$failures" -gt 0 ]; then
    VERIFY_PASSED="false"
    return 1
  fi

  if [ "$HASH_VERIFY" = "full" ] && [ -n "$hash_cmd" ]; then
    info "Computing full-device SHA-256 (this may take a while)…"
    case "$hash_cmd" in
      sha256sum) dd if="$DEVICE" bs="$CHUNK_SIZE" 2>/dev/null | sha256sum 2>/dev/null | tee "$SESSION_DIR/device.sha256" >/dev/null ;;
      sha256)    dd if="$DEVICE" bs="$CHUNK_SIZE" 2>/dev/null | sha256 2>/dev/null | tee "$SESSION_DIR/device.sha256" >/dev/null ;;
    esac
  fi
  VERIFY_PASSED="true"
  return 0
}

#############################################################################
# Sanitize / Secure Erase capability discovery & execution (best-effort)
#############################################################################

_nvme_ctrl_from_ns() {
  # /dev/nvme0n1 -> /dev/nvme0 ; else return empty
  bn="$(basename "$DEVICE" 2>/dev/null)"
  case "$bn" in
    nvme*n*) printf '/dev/%s\n' "$(printf '%s' "$bn" | sed 's/n[0-9]\+$//')" ;;
    *) printf '\n' ;;
  esac
}

detect_sanitize_support() {
  # Determine if any sanitize/secure-erase method is feasible. Sets:
  #   SAN_SUPPORTED=true|false
  #   SAN_SELECTED_METHOD=nvme_format_s1|ata_sec_erase_enh|ata_sec_erase|scsi_sanitize_crypto
  SAN_SUPPORTED="false"
  SAN_SELECTED_METHOD=""

  # NVMe namespace: prefer 'nvme format -s1' on the namespace node
  if have_cmd nvme; then
    case "$(basename "$DEVICE" 2>/dev/null)" in
      nvme*n*)
        if nvme id-ctrl "$(_nvme_ctrl_from_ns)" >/dev/null 2>&1; then
          SAN_SUPPORTED="true"
          SAN_SELECTED_METHOD="nvme_format_s1"
          return 0
        fi
        ;;
    esac
  fi

  # ATA/SATA via hdparm security (only on sdX, not via most USB bridges)
  if have_cmd hdparm; then
    case "$(basename "$DEVICE" 2>/dev/null)" in
      sd*)
        hdparm -I "$DEVICE" >"$SESSION_DIR/hdparm.ident" 2>&1 || true
        if grep -qi "^Security:" "$SESSION_DIR/hdparm.ident"; then
          if grep -qi "frozen" "$SESSION_DIR/hdparm.ident"; then
            SAN_SUPPORTED="false"
            SAN_REASON="security_frozen"
          else
            if grep -qi "enhanced erase" "$SESSION_DIR/hdparm.ident"; then
              SAN_SUPPORTED="true"; SAN_SELECTED_METHOD="ata_sec_erase_enh"; return 0
            else
              SAN_SUPPORTED="true"; SAN_SELECTED_METHOD="ata_sec_erase"; return 0
            fi
          fi
        fi
        ;;
    esac
  fi

  # SCSI/SAS via sg_sanitize (crypto)
  if have_cmd sg_sanitize; then
    case "$(basename "$DEVICE" 2>/dev/null)" in
      sd*)
        SAN_SUPPORTED="true"
        SAN_SELECTED_METHOD="scsi_sanitize_crypto"
        return 0
        ;;
    esac
  fi

  SAN_SUPPORTED="false"
}

_confirm_post_sanitize() {
  # Returns 0 if approved
  if [ "$POST_SANITIZE" = "force" ]; then
    return 0
  fi
  printf '\n%sPOST-SANITIZE OPTION%s\n' "$BLD" "$RST"
  printf 'A firmware-level erase (%s) is supported on this device.\n' "$SAN_SELECTED_METHOD"
  printf 'This will change device contents after the random pass and may take additional time.\n'
  printf 'Proceed with firmware sanitize now? Type YES to continue: '
  read ans || ans=""
  [ "$ans" = "YES" ]
}

perform_post_sanitize() {
  # Only run if:
  #  * User allowed via POST_SANITIZE (auto/force), and
  #  * A random-data pass was performed (per requirement), OR forced
  #
  # On success, sets:
  #   SAN_RESULT="ok"
  # On skip/failure, sets:
  #   SAN_RESULT="skipped" or "failed"; SAN_REASON filled.
  #
  # Running this invalidates content-based verification; we mark verify as skipped(post-sanitize).

  case "$POST_SANITIZE" in
    never) SAN_RESULT="skipped"; SAN_REASON="policy_never"; return 0 ;;
  esac

  # Must have random pattern in the wipe sequence unless forced
  ran_random="no"
  case "$PATTERN" in
    random) ran_random="yes" ;;
    sequence) ran_random="no" ;;
    *) ran_random="no" ;;
  esac
  if [ "$POST_SANITIZE" != "force" ] && [ "$ran_random" != "yes" ]; then
    SAN_RESULT="skipped"; SAN_REASON="no_random_pass"
    return 0
  fi

  detect_sanitize_support
  if [ "$SAN_SUPPORTED" != "true" ] || [ -z "$SAN_SELECTED_METHOD" ]; then
    SAN_RESULT="skipped"; SAN_REASON="${SAN_REASON:-unsupported}"
    return 0
  fi

  if [ "$POST_SANITIZE" = "auto" ]; then
    _confirm_post_sanitize || { SAN_RESULT="skipped"; SAN_REASON="declined"; return 0; }
  fi

  case "$SAN_SELECTED_METHOD" in
    nvme_format_s1)
      if [ "$DRY_RUN" -eq 1 ]; then
        SAN_RESULT="skipped"; SAN_REASON="dry_run"
      else
        if nvme format "$DEVICE" -s1 >/dev/null 2>&1; then
          SAN_RESULT="ok"
        else
          SAN_RESULT="failed"; SAN_REASON="nvme_format_error"
          append_error "nvme format -s1 failed"
        fi
      fi
      ;;

    ata_sec_erase_enh)
      if [ "$DRY_RUN" -eq 1 ]; then
        SAN_RESULT="skipped"; SAN_REASON="dry_run"
      else
        if hdparm --user-master u --security-set-pass p "$DEVICE" >/dev/null 2>&1; then
          if hdparm --user-master u --security-erase-enhanced p "$DEVICE" >/dev/null 2>&1; then
            SAN_RESULT="ok"
          else
            SAN_RESULT="failed"; SAN_REASON="hdparm_erase_enh_failed"
            append_error "hdparm security-erase-enhanced failed"
          fi
          hdparm --user-master u --security-disable p "$DEVICE" >/dev/null 2>&1 || true
        else
          SAN_RESULT="failed"; SAN_REASON="hdparm_set_pass_failed"
          append_error "hdparm security-set-pass failed"
        fi
      fi
      ;;

    ata_sec_erase)
      if [ "$DRY_RUN" -eq 1 ]; then
        SAN_RESULT="skipped"; SAN_REASON="dry_run"
      else
        if hdparm --user-master u --security-set-pass p "$DEVICE" >/dev/null 2>&1; then
          if hdparm --user-master u --security-erase p "$DEVICE" >/dev/null 2>&1; then
            SAN_RESULT="ok"
          else
            SAN_RESULT="failed"; SAN_REASON="hdparm_erase_failed"
            append_error "hdparm security-erase failed"
          fi
          hdparm --user-master u --security-disable p "$DEVICE" >/dev/null 2>&1 || true
        else
          SAN_RESULT="failed"; SAN_REASON="hdparm_set_pass_failed"
          append_error "hdparm security-set-pass failed"
        fi
      fi
      ;;

    scsi_sanitize_crypto)
      if [ "$DRY_RUN" -eq 1 ]; then
        SAN_RESULT="skipped"; SAN_REASON="dry_run"
      else
        if sg_sanitize --crypto "$DEVICE" >/dev/null 2>&1; then
          SAN_RESULT="ok"
        else
          SAN_RESULT="failed"; SAN_REASON="sg_sanitize_failed"
          append_error "sg_sanitize --crypto failed"
        fi
      fi
      ;;
  esac

  if [ "$SAN_RESULT" = "ok" ]; then
    HASH_VERIFY="none"
    VERIFY_PASSED="skipped(post-sanitize)"
  fi
}

#############################################################################
# Inventory logging / Signing / Export
#############################################################################
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g'; }

append_inventory() {
  [ -n "$INVENTORY_LOG" ] || { INV_APPENDED="false"; return; }
  mkdir -p "$(dirname "$INVENTORY_LOG")" 2>/dev/null || true
  first_seen="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date +%Y-%m-%dT%H:%M:%SZ)"
  line='{"serial":"'"$(json_escape "$SERIAL")"'","vid_pid":"'"$(json_escape "$VENDOR_ID:$PRODUCT_ID")"'","model":"'"$(json_escape "$MODEL")"'","first_seen":"'"$first_seen"'","last_seen":"'"$first_seen"'","last_action":"'"$MODE"'","last_status":"'"$VERIFY_PASSED"'"}'
  printf '%s\n' "$line" >>"$INVENTORY_LOG" 2>/dev/null && INV_APPENDED="true" || INV_APPENDED="false"
}

maybe_sign_logs() {
  [ "$SIGN_LOGS" -eq 1 ] || return 0
  have_cmd gpg || { warn "gpg not available; skipping signing."; return 0; }
  if [ -n "$SIGN_ID" ]; then
    gpg --local-user "$SIGN_ID" --armor --detach-sign --output "$SESSION_JSON.asc" "$SESSION_JSON" 2>/dev/null && GPG_SIG_PATH="$SESSION_JSON.asc"
  else
    gpg --armor --detach-sign --output "$SESSION_JSON.asc" "$SESSION_JSON" 2>/dev/null && GPG_SIG_PATH="$SESSION_JSON.asc"
  fi
}

maybe_export_logs() {
  [ "$EXPORT_LOGS" -eq 1 ] || return 0
  have_cmd tar || { warn "tar not available; skipping export."; return 0; }
  ( cd "$LOG_DIR" && tar -czf "session-$TS.tar.gz" "session-$TS" ) 2>/dev/null || warn "Failed to create log archive."
}

#############################################################################
# Human summary + JSON report
#############################################################################
write_json_report() {
  start_t="$1"
  end_t="$2"
  dur="$(awk "BEGIN{print $end_t-$start_t}")"

  # Build JSON document safely with manual escaping (jq optional)
  {
    printf '{\n'
    printf '  "device": "%s",\n' "$(json_escape "$DEVICE")"
    printf '  "bus_dev": "%s",\n' "$(json_escape "$BUS_DEV")"
    printf '  "model": "%s",\n' "$(json_escape "$MODEL")"
    printf '  "vendor_id": "%s",\n' "$(json_escape "$VENDOR_ID")"
    printf '  "product_id": "%s",\n' "$(json_escape "$PRODUCT_ID")"
    printf '  "manufacturer": "%s",\n' "$(json_escape "$MANUFACTURER")"
    printf '  "product": "%s",\n' "$(json_escape "$PRODUCT")"
    printf '  "serial": "%s",\n' "$(json_escape "$SERIAL")"
    printf '  "size_bytes": %s,\n' "${SIZE_BYTES:-0}"
    printf '  "sector_logical": %s,\n' "${SECTOR_LOGICAL:-0}"
    printf '  "sector_physical": %s,\n' "${SECTOR_PHYSICAL:-0}"
    printf '  "rota": %s,\n' "${ROTA:-0}"
    printf '  "table_type": "%s",\n' "$(json_escape "$TABLE_TYPE")"
    printf '  "partitions": %s,\n' "$PART_JSON"
    printf '  "filesystems": %s,\n' "$FS_LIST"
    printf '  "ro_flag": %s,\n' "$( [ "$RO_FLAG" = "1" ] && printf true || printf false )"
    printf '  "composite_functions": %s,\n' "$COMPOSITE_LIST"
    printf '  "smart_status": "%s",\n' "$(json_escape "$SMART_STATUS")"
    printf '  "hpa_dco_status": "%s",\n' "$(json_escape "$HPA_DCO_STATUS")"
    printf '  "blank_check": {"is_blank": %s, "first_nonzero_offsets": %s},\n' \
      "$( [ "$BLANK_IS" = "blank" ] && printf true || printf false )" "$BLANK_OFFSETS"
    printf '  "probe_ro_result": "%s",\n' "$(json_escape "$PROBE_RO_RESULT")"
    printf '  "firmware_scan_summary": "%s",\n' "$(json_escape "$FIRMWARE_SCAN_SUMMARY")"
    printf '  "mode": "%s",\n' "$(json_escape "$MODE")"
    if [ "$MODE" = "wipe" ]; then
      printf '  "passes": %s,\n' "$PASSES"
      printf '  "pattern": "%s",\n' "$(json_escape "$PATTERN")"
      printf '  "chunk_size": "%s",\n' "$(json_escape "$CHUNK_SIZE")"
      printf '  "hash_policy": "%s",\n' "$(json_escape "$HASH_VERIFY")"
      printf '  "samples": %s,\n' "$SAMPLES"
      printf '  "verify_result": {"passed": %s, "unchanged_ranges": %s, "zero_ranges": %s},\n' \
        "$( [ "$VERIFY_PASSED" = "true" ] && printf true || printf false )" "$UNCHANGED_RANGES" "$ZERO_RANGES"
    else
      printf '  "passes": null,\n  "pattern": null,\n  "chunk_size": "%s",\n  "hash_policy": null,\n  "samples": null,\n  "verify_result": null,\n' "$(json_escape "$CHUNK_SIZE")"
    fi
    printf '  "errors": %s,\n' "$ERRORS"
    printf '  "tool_checks": [%s],\n' "$(printf '%s' "$tool_list_record" | sed 's/^ *//; s/  */ /g; s/ /","/g; s/^/"/; s/$/"/')"
    printf '  "timestamps": {"start":"%s","end":"%s"},\n' \
      "$(date -u -d @"$start_t" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$(date -u -d @"$end_t" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "duration_sec": %s,\n' "$dur"
    printf '  "post_sanitize": {"policy":"%s","supported":%s,"method":"%s","result":"%s","reason":"%s"},\n' \
      "$(json_escape "$POST_SANITIZE")" \
      "$( [ "$SAN_SUPPORTED" = "true" ] && printf true || printf false )" \
      "$(json_escape "$SAN_SELECTED_METHOD")" \
      "$(json_escape "$SAN_RESULT")" \
      "$(json_escape "$SAN_REASON")"
    printf '  "inventory_appended": %s,\n' "$( [ "$INV_APPENDED" = "true" ] && printf true || printf false )"
    printf '  "signatures": {"gpg_sig_path": %s},\n' "$( [ -n "$GPG_SIG_PATH" ] && printf '"%s"' "$(json_escape "$GPG_SIG_PATH")" || printf null )"
    printf '  "exported_archive": %s\n' "$( [ "$EXPORT_LOGS" -eq 1 ] && printf '"%s/session-%s.tar.gz"' "$(json_escape "$LOG_DIR")" "$(json_escape "$TS")" || printf null )"
    printf '}\n'
  } >"$SESSION_JSON"

  if have_cmd jq; then
    tmp="$SESSION_JSON.tmp"
    jq . "$SESSION_JSON" >"$tmp" 2>/dev/null && mv "$tmp" "$SESSION_JSON" 2>/dev/null || true
  fi
}

human_summary() {
  printf '\n=============================================================\n'
  printf 'USB Device %sSummary%s\n' "$BLD" "$RST"
  printf 'Device: %s  Model: %s  VID:PID=%s:%s\n' "$DEVICE" "${MODEL:-unknown}" "${VENDOR_ID:-????}" "${PRODUCT_ID:-????}"
  printf 'Serial: %s  Size: %s (%s)\n' "${SERIAL:-unknown}" "$SIZE_BYTES" "$(human_bytes "$SIZE_BYTES")"
  if [ "$SAN_RESULT" = "ok" ]; then
    printf 'Post-sanitize: %s (%s)\n' "$SAN_RESULT" "$SAN_SELECTED_METHOD"
  else
    printf 'Post-sanitize: %s' "$SAN_RESULT"
    [ -n "$SAN_REASON" ] && printf ' [%s]' "$SAN_REASON"
    printf '\n'
  fi
  printf 'Geometry: %s logical / %s physical  ROTA: %s\n' "${SECTOR_LOGICAL:-?}" "${SECTOR_PHYSICAL:-?}" "${ROTA:-?}"
  printf 'Partitions (%s)  Filesystems: %s\n' "${TABLE_TYPE:-unknown}" "$(printf '%s' "$FS_LIST")"
  printf 'Read-only: %s\n' "$( [ "$RO_FLAG" = "1" ] && printf 'yes' || printf 'no/unknown' )"
  # Composite summary
  if [ "$COMPOSITE_LIST" != "[]" ]; then
    printf 'Composite interfaces: %s\n' "$COMPOSITE_LIST"
  fi
  printf 'SMART: %s\n' "$SMART_STATUS"
  printf 'Hidden areas (HPA/DCO): %s\n' "$HPA_DCO_STATUS"
  printf 'Blankness: %s' "$( [ "$BLANK_IS" = 'blank' ] && printf 'BLANK' || printf 'NOT BLANK' )"
  if [ "$BLANK_IS" != "blank" ]; then printf ' (first non-zero at %s)' "$BLANK_OFFSETS"; fi
  printf '\n'
  if [ "$MODE" = "wipe" ]; then
    printf 'Verification: %s\n' "$( [ "$VERIFY_PASSED" = "true" ] && printf 'PASSED' || printf 'FAILED/UNKNOWN' )"
  fi
  printf 'JSON: %s\n' "$SESSION_JSON"
  printf '=============================================================\n'
}

#############################################################################
# Interactive menu & confirmations
#############################################################################
interactive_menu() {
  printf '%s\n' "Choose mode:"
  printf '  1) Scan (non-destructive)\n'
  printf '  2) Wipe (DESTRUCTIVE)\n'
  printf 'Selection [1/2]: '
  read sel || sel=""
  case "$sel" in
    1) MODE="scan" ;;
    2) MODE="wipe" ;;
    *) die 1 "Aborted."; ;;
  esac
}

confirm_wipe_gate() {
  # Print fingerprint and require typed confirmation
  printf '\n%sDESTRUCTIVE ACTION WARNING%s\n' "$RED$BLD" "$RST"
  printf 'Target device: %s (model: %s, serial: %s, size: %s)\n' "$DEVICE" "${MODEL:-unknown}" "${SERIAL:-unknown}" "$(human_bytes "$SIZE_BYTES")"
  printf 'Pattern: %s   Passes: %s   Chunk: %s   Verify: %s\n' "$PATTERN" "$PASSES" "$CHUNK_SIZE" "$HASH_VERIFY"
  printf 'Type the device node to confirm (%s): ' "$DEVICE"
  read conf1 || conf1=""
  if [ "$conf1" != "$DEVICE" ]; then
    [ "$FORCE" -eq 1 ] || die 1 "Confirmation mismatch."
  fi
  if [ -n "$SERIAL" ] && [ "$FORCE" -ne 1 ]; then
    printf 'Type the exact serial to confirm (%s): ' "$SERIAL"
    read conf2 || conf2=""
    [ "$conf2" = "$SERIAL" ] || die 1 "Serial confirmation mismatch."
  else
    warn "No serial available or --force used; proceeding with device confirmation only."
  fi
}

#############################################################################
# Mode 1: Scan
#############################################################################
mode_scan() {
  start="$(date +%s 2>/dev/null || echo 0)"
  resolve_device_or_wait
  guard_unsafe_target
  collect_attrs

  if [ "$SIZE_BYTES" -gt $((2*1024*1024*1024*LARGE_WARN_TB)) ] 2>/dev/null; then
    warn "Device is larger than ${LARGE_WARN_TB} TB; scans may be long."
  fi

  maybe_smart
  [ "$CHECK_HIDDEN" -eq 1 ] && maybe_hidden
  [ "$FIRMWARE_SCAN" -eq 1 ] && maybe_firmware_scan

  blankness_scan

  if [ "$PROBE_RO" -eq 1 ]; then
    probe_ro || true
  fi

  end="$(date +%s 2>/dev/null || echo 0)"
  write_json_report "$start" "$end"
  human_summary
  append_inventory
  maybe_sign_logs
  maybe_export_logs
}

#############################################################################
# Mode 2: Wipe
#############################################################################
mode_wipe() {
  start="$(date +%s 2>/dev/null || echo 0)"
  resolve_device_or_wait
  guard_unsafe_target
  collect_attrs

  # Large device warning
  tb=$(( 2*1024*1024*1024*LARGE_WARN_TB ))
  if [ "$SIZE_BYTES" -gt "$tb" ] 2>/dev/null; then
    warn "Device > ${LARGE_WARN_TB} TB; operation may take a very long time."
    printf 'Continue? type YES: '
    read ans || ans=""
    [ "$ans" = "YES" ] || die 1 "Aborted."
  fi

  confirm_wipe_gate

  # Unmount and flush
  unmount_all_partitions
  flush_buffers

  # Perform passes
  p=1
  while [ $p -le "$PASSES" ]; do
    write_pattern_pass "$p" "$PATTERN"
    p=$((p+1))
  done

  flush_buffers

  # Optional firmware-level sanitize after random pass (if supported/policy allows)
  perform_post_sanitize

  # Verification (may be skipped if post-sanitize modified contents)
  if verify_after_wipe; then
    ok "Verification PASSED."
  else
    err "Verification FAILED."
  fi

  end="$(date +%s 2>/dev/null || echo 0)"
  write_json_report "$start" "$end"
  human_summary
  append_inventory
  maybe_sign_logs
  maybe_export_logs

  if [ "$VERIFY_PASSED" != "true" ]; then
    exit 3
  fi
}

#############################################################################
# Main
#############################################################################
main() {
  umask 077
  detect_os
  require_root
  check_tools
  init_logs

  # Banner
  printf '%s\n' "$BLD$REDDO NOT RUN ON LIVE SYSTEM DISKS. THIS WILL ERASE DATA.$RST"
  printf '%s\n' "$BLD USB Mass-Storage Device Inspect & Wipe (Enhanced, POSIX) $RST"
  printf 'OS: %s   Logs: %s\n' "$OS" "$SESSION_DIR"

  parse_args "$@"

  # If no mode, show interactive
  [ -n "$MODE" ] || interactive_menu

  case "$MODE" in
    scan) mode_scan ;;
    wipe) mode_wipe ;;
    *) die 4 "Invalid mode." ;;
  esac
}

REDDO="$RED"
main "$@"
exit 0

#############################################################################
# Notes & self-tests (manual)
#
# test1: Dry-run scan with loopback (Linux):
#   fallocate -l 64M /tmp/usb.img
#   sudo losetup -fP /tmp/usb.img
#   LOOP=$(losetup -a | awk -F: '/tmp\/usb.img/{print $1}')
#   sudo ./usb_device_inspect_wipe.sh --mode=scan --device="$LOOP" --dry-run --log-dir=./logs
#
# test2: Dry-run wipe gate:
#   sudo ./usb_device_inspect_wipe.sh --mode=wipe --device="$LOOP" --dry-run
#   (should require typed confirmation, but not write)
#
# test3: Sample-hash verification (small file-as-device):
#   dd if=/dev/urandom of=/tmp/dev.bin bs=1M count=8
#   sudo ./usb_device_inspect_wipe.sh --mode=wipe --device=/tmp/dev.bin --pattern=zeros --hash-verify=sample --samples=8 --log-dir=./logs
#
# Portability:
#   * Uses only POSIX shell features; avoids bashisms.
#   * Optional tooling (lsblk/udevadm/lsusb/smartctl/hdparm/jq/gpg/tar) used when present.
#   * On OpenBSD, device discovery and geometry use sysctl/disklabel best effort.
#
# Limitations / graceful degradation:
#   * Constant patterns ff/aa require hexdump+xxd. If xxd missing, falls back to zeros.
#   * Progress uses simple loop-based ETA (portable), not dd status=progress.
#   * Composite detection best-effort via lsusb (Linux).
#   * Hidden area checks often blocked by USB-SATA bridges.
#############################################################################
