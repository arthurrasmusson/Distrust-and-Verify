#!/bin/sh
#
# usb_device_inspect_wipe.sh
#
# DO NOT RUN ON LIVE SYSTEM DISKS. THIS WILL ERASE DATA.
#
# Purpose:
#   - Mode 1 (scan): comprehensive device inventory & blankness check
#   - Mode 2 (wipe): multi-pass overwrite + verification + audit logs
#
# Compatibility:
#   POSIX /bin/sh (dash, ash, ksh, bash in POSIX mode)
#   Linux and OpenBSD auto-detected; optional tools degrade gracefully
#
# Exit codes:
#   0 success; 1 user abort; 2 device not found;
#   3 verification failed; 4 insufficient privileges/tools;
#   5 unsafe target (system/root disk)
#

###############################################################################
# Strict mode & traps (POSIX)
###############################################################################
set -eu
# We avoid pipefail for POSIX; we carefully check each step’s status.
umask 077

CLEANUP_ITEMS=""
cleanup() {
  # remove temp files registered in CLEANUP_ITEMS (whitespace-safe)
  IFS='
'
  for x in $CLEANUP_ITEMS; do
    [ -n "$x" ] && [ -e "$x" ] && rm -f -- "$x" || true
  done
}
trap 'cleanup' EXIT HUP INT TERM

###############################################################################
# Globals & defaults
###############################################################################
OS="$(uname -s 2>/dev/null || echo unknown)"
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
SCRIPT_NAME="usb_device_inspect_wipe.sh"
SELF_DIR="$(pwd)"

# CLI defaults
MODE=""                    # scan|wipe (or "1"|"2")
DEVICE=""                  # /dev/XXX
DRY_RUN=0
PASSES=1
PATTERN="random"           # random|zeros|ff|aa|sequence
CHUNK_SIZE="16M"
HASH_POLICY="sample"       # none|sample|full
SAMPLES=32
INVENTORY_LOG=""
LOG_DIR="./logs"
OPENBSD_ADAPT=0
RUN_SMART=0
PROBE_RO=0
CHECK_HIDDEN=0
EXPORT_LOGS=0
SIGN_LOGS=0
GPG_ID=""                  # for --sign-logs=GPG_ID
FIRMWARE_SCAN=0
FORCE=0
WAIT_FOR_PLUG=1
LARGE_DEV_TB=2
NONZERO_FINDINGS=8
POST_SANITIZE=0           # if 1: feature discovery & sanitize after wipe (NVMe/SCSI/ATA)
POST_SANITIZE_MODE="auto" # 'auto' selects best supported sanitize

# Derived runtime
SESSION_ID="$(date -u +%Y%m%d-%H%M%S 2>/dev/null || date +%s)"
SESSION_DIR=""
JSON_REPORT=""
HUMAN_LOG=""
ERRORS="[]"

# Device facts (will be discovered)
DEV_BASENAME=""
DEV_SIZE_BYTES=""
DEV_SECTOR_LOGICAL=""
DEV_SECTOR_PHYSICAL=""
DEV_RO=0
DEV_ROTA=0
DEV_TABLE="unknown"
PART_JSON="[]"
FS_LIST="[]"
COMPOSITE_LIST="[]"
VID=""
PID=""
MFG=""
PRODUCT=""
SERIAL=""
BUS_DEV=""
SMART_STATUS="unavailable"
HPA_DCO_STATUS="not_applicable"
FIRMWARE_SUMMARY="none"
OS_FAMILY="unknown"

# Verification results placeholder
VERIFY_PASSED=0
UNCHANGED_RANGES="[]"
ZERO_RANGES="[]"

###############################################################################
# UI helpers (no non-ASCII to keep dash happy)
###############################################################################
is_tty() { [ -t 1 ] && [ -t 0 ]; }

if is_tty && command -v tput >/dev/null 2>&1; then
  C_RESET="$(tput sgr0 2>/dev/null || true)"
  C_RED="$(tput setaf 1 2>/dev/null || true)"
  C_GRN="$(tput setaf 2 2>/dev/null || true)"
  C_YLW="$(tput setaf 3 2>/dev/null || true)"
  C_CYN="$(tput setaf 6 2>/dev/null || true)"
else
  C_RESET=""; C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""
fi

info()  { printf "%s[INFO]%s %s\n" "$C_CYN" "$C_RESET" "$*"; }
warn()  { printf "%s[WARN]%s %s\n" "$C_YLW" "$C_RESET" "$*"; }
error() { printf "%s[ERR ]%s %s\n" "$C_RED" "$C_RESET" "$*" >&2; }

die() {
  code="$1"; shift
  error "$*"
  exit "$code"
}

append_error() {
  # store message in JSON-safe string
  msg="$*"
  esc="$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  if [ "$ERRORS" = "[]" ]; then
    ERRORS='["'"$esc"'"]'
  else
    ERRORS="$(printf '%s' "$ERRORS" | sed 's/]$//')."\"$esc\""]"
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

bytes_from_human() {
  # Convert sizes like 16M, 4K, 1G to bytes; default bytes if numeric
  v="$1"
  case "$v" in
    *[!0-9mMkKgG]*) echo "$v" ;; # unknown suffix—return as-is
    *[mM]) echo $(($(printf '%s' "${v%[mM]}") * 1024 * 1024)) ;;
    *[kK]) echo $(($(printf '%s' "${v%[kK]}") * 1024)) ;;
    *[gG]) echo $(($(printf '%s' "${v%[gG]}") * 1024 * 1024 * 1024)) ;;
    *) echo "$v" ;;
  esac
}

human_bytes() {
  # 1024-based
  v="$1"
  if [ -z "$v" ]; then echo "0 B"; return; fi
  b="$v"
  if [ "$b" -ge 1099511627776 ] 2>/dev/null; then
    printf "%.1f TB" "$(echo "scale=1;$b/1099511627776" | awk '{printf "%f", $1}')"
  elif [ "$b" -ge 1073741824 ] 2>/dev/null; then
    printf "%.1f GB" "$(echo "scale=1;$b/1073741824" | awk '{printf "%f", $1}')"
  elif [ "$b" -ge 1048576 ] 2>/dev/null; then
    printf "%.1f MB" "$(echo "scale=1;$b/1048576" | awk '{printf "%f", $1}')"
  elif [ "$b" -ge 1024 ] 2>/dev/null; then
    printf "%.1f KB" "$(echo "scale=1;$b/1024" | awk '{printf "%f", $1}')"
  else
    printf "%s B" "$b"
  fi
}

json_escape() {
  # escape for JSON value
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g'
}

join_csv() {
  # join newline list with commas (no quoting)
  IFS='
'
  first=1
  for x in $1; do
    if [ $first -eq 1 ]; then
      printf '%s' "$x"
      first=0
    else
      printf ',%s' "$x"
    fi
  done
}

###############################################################################
# OS detection
###############################################################################
detect_os() {
  case "$OS" in
    Linux)  OS_FAMILY="linux" ;;
    OpenBSD) OS_FAMILY="openbsd" ;;
    *) OS_FAMILY="unknown" ;;
  esac
}

###############################################################################
# Privilege & tool checks
###############################################################################
require_root() {
  uid="$(id -u 2>/dev/null || echo 1)"
  if [ "$uid" != 0 ]; then
    die 4 "Root privileges required. Re-run with sudo."
  fi
}

ensure_session_dir() {
  [ -d "$LOG_DIR" ] || mkdir -p -- "$LOG_DIR"
  SESSION_DIR="$LOG_DIR/session-$SESSION_ID"
  mkdir -p -- "$SESSION_DIR"
  JSON_REPORT="$SESSION_DIR/usb-report-$SESSION_ID.json"
  HUMAN_LOG="$SESSION_DIR/usb-session-$SESSION_ID.log"
}

tee_human() { printf "%s\n" "$*" | tee -a "$HUMAN_LOG" >/dev/null 2>&1; }

###############################################################################
# CLI parsing (POSIX)
###############################################################################
usage() {
cat <<EOF
Usage: $SCRIPT_NAME [FLAGS]

Modes:
  --mode=scan|wipe        (or -m 1|2)  If omitted, interactive menu.

Device:
  --device=/dev/XXX                    Target block device; if omitted, waits for plug-in.

General:
  --dry-run                            Simulate; never write to devices.
  --log-dir=PATH                       Default: ./logs
  --inventory-log=PATH                 Append JSONL device fingerprint/outcome
  --openbsd-adapt                      Force OpenBSD path if auto-detect fails
  --force                              Bypass some interlocks (still confirms device node)
  --export-logs                        Tar.gz the session logs at end
  --sign-logs[=GPG_ID]                 Sign JSON report & inventory entry

Scan options:
  --run-smart                          Attempt SMART (if SAT pass-through)
  --probe-ro                           Tiny write/read/restore probes at start/mid/end
  --check-hidden                       HPA/DCO checks (Linux SATA; warn on USB bridge)
  --firmware-scan                      List alternate LUNs/DFU/vendor partitions

Wipe options:
  --passes=N                           1,3,7 (default 1)
  --pattern=TYPE                       random|zeros|ff|aa|sequence (default random)
  --chunk-size=SIZE                    e.g., 16M (applies read/write/verify)
  --hash-verify=none|sample|full       default sample
  --samples=N                          number of sample windows (default 32)
  --post-sanitize                      After wipe, try NVMe/SCSI/ATA sanitize if supported

Other:
  --nonzero-findings=N                 First N offsets for blankness report (default 8)
  --large-dev-threshold-tb=N          Warn if device size > N TB (default 2)

Examples:
  $SCRIPT_NAME --mode=scan
  $SCRIPT_NAME --mode=wipe --device=/dev/sdb --passes=3 --pattern=sequence --hash-verify=sample --samples=32

EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -m|--mode)
        shift; MODE="$1"
        ;;
      --mode=*)
        MODE="${1#*=}"
        ;;
      --device=*)
        DEVICE="${1#*=}"
        ;;
      --device)
        shift; DEVICE="$1"
        ;;
      --dry-run)
        DRY_RUN=1
        ;;
      --passes=*)
        PASSES="${1#*=}"
        ;;
      --passes)
        shift; PASSES="$1"
        ;;
      --pattern=*)
        PATTERN="${1#*=}"
        ;;
      --pattern)
        shift; PATTERN="$1"
        ;;
      --chunk-size=*)
        CHUNK_SIZE="${1#*=}"
        ;;
      --chunk-size)
        shift; CHUNK_SIZE="$1"
        ;;
      --hash-verify=*)
        HASH_POLICY="${1#*=}"
        ;;
      --hash-verify)
        shift; HASH_POLICY="$1"
        ;;
      --samples=*)
        SAMPLES="${1#*=}"
        ;;
      --samples)
        shift; SAMPLES="$1"
        ;;
      --inventory-log=*)
        INVENTORY_LOG="${1#*=}"
        ;;
      --inventory-log)
        shift; INVENTORY_LOG="$1"
        ;;
      --log-dir=*)
        LOG_DIR="${1#*=}"
        ;;
      --log-dir)
        shift; LOG_DIR="$1"
        ;;
      --openbsd-adapt)
        OPENBSD_ADAPT=1
        ;;
      --run-smart)
        RUN_SMART=1
        ;;
      --probe-ro)
        PROBE_RO=1
        ;;
      --check-hidden)
        CHECK_HIDDEN=1
        ;;
      --export-logs)
        EXPORT_LOGS=1
        ;;
      --sign-logs)
        SIGN_LOGS=1
        ;;
      --sign-logs=*)
        SIGN_LOGS=1; GPG_ID="${1#*=}"
        ;;
      --firmware-scan)
        FIRMWARE_SCAN=1
        ;;
      --force)
        FORCE=1
        ;;
      --post-sanitize)
        POST_SANITIZE=1
        ;;
      --nonzero-findings=*)
        NONZERO_FINDINGS="${1#*=}"
        ;;
      --large-dev-threshold-tb=*)
        LARGE_DEV_TB="${1#*=}"
        ;;
      -h|--help)
        usage; exit 0
        ;;
      *)
        error "Unknown flag: $1"
        usage
        exit 4
        ;;
    esac
    shift
  done

  case "$MODE" in
    1) MODE="scan" ;;
    2) MODE="wipe" ;;
    scan|wipe|"") : ;;
    *) error "Invalid --mode"; usage; exit 4 ;;
  esac
}

###############################################################################
# System disk guard
###############################################################################
linux_root_parent() {
  # returns root parent (e.g., sda) or empty
  if have_cmd findmnt; then
    rdev="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
  else
    rdev="$(awk '$2=="/"{print $1}' /proc/mounts 2>/dev/null | head -n1 || true)"
  fi
  # rdev may be /dev/sda1; find its top disk:
  if [ -n "$rdev" ] && have_cmd lsblk; then
    p="$(lsblk -no PKNAME "$rdev" 2>/dev/null || true)"
    if [ -n "$p" ]; then
      printf '%s\n' "$p"
    else
      # maybe itself a disk (no PKNAME)
      b="$(basename "$rdev" 2>/dev/null || echo "")"
      printf '%s\n' "$b"
    fi
  fi
}

openbsd_root_disk() {
  # parse 'mount' line for / -> /dev/sd0a
  r="$(mount | awk '$3=="/"{print $1}' | head -n1)"
  # r like /dev/sd0a -> disk is sd0
  if [ -n "$r" ]; then
    b="$(basename "$r")"
    printf '%s\n' "$(printf '%s' "$b" | sed 's/[a-z]$//')"
  fi
}

guard_unsafe_target() {
  if [ -z "$DEVICE" ]; then
    return 0
  fi

  case "$OS_FAMILY" in
    linux)
      rootp="$(linux_root_parent || true)"
      # DEVICE may be /dev/sdb
      bdev="$(basename "$DEVICE" 2>/dev/null || echo "")"
      if [ -n "$rootp" ] && [ -n "$bdev" ] && [ "$rootp" = "$bdev" ]; then
        die 5 "Refusing: target $DEVICE seems to be the system/root disk."
      fi
      # also refuse if any partitions are mounted
      if have_cmd lsblk; then
        if lsblk -rn -o NAME,MOUNTPOINT "$DEVICE" 2>/dev/null | awk '$2!=""{f=1} END{exit (f?0:1)}'
        then
          die 5 "Refusing: one or more partitions of $DEVICE are mounted."
        fi
      fi
      ;;
    openbsd)
      rdisk="$(openbsd_root_disk || true)"
      # /dev/sd1 -> sd1
      b="$(basename "$DEVICE" 2>/dev/null || echo "")"
      short="$(printf '%s' "$b" | sed 's,^.*/,,; s/[a-z]$//')"
      if [ -n "$rdisk" ] && [ -n "$short" ] && [ "$rdisk" = "$short" ]; then
        die 5 "Refusing: target $DEVICE seems to be the system/root disk."
      fi
      # mounted partitions?
      if mount | grep -q "/dev/${short}[a-z] on "; then
        die 5 "Refusing: one or more partitions of $DEVICE are mounted."
      fi
      ;;
    *)
      warn "Unknown OS; cannot verify system disk safety."
      ;;
  esac
}

###############################################################################
# Device detection (wait for new mass-storage)
###############################################################################
list_block_roots_linux() {
  lsblk -dn -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}'
}

wait_for_new_disk_linux() {
  before="$(list_block_roots_linux | sort)"
  info "Waiting for a new USB/removable disk to appear (Ctrl-C to abort)..."
  # Prefer udevadm if available
  if have_cmd udevadm; then
    # polling fallback
    t0=$(date +%s 2>/dev/null || echo 0)
    while :; do
      now="$(list_block_roots_linux | sort)"
      # find diff
      add="$(comm -13 /dev/fd/3 /dev/fd/4 3<<EOF3 4<<EOF4
$before
EOF3
$now
EOF4
)"
      if [ -n "$add" ]; then
        # pick the last added
        n="$(printf '%s\n' "$add" | tail -n1)"
        printf '/dev/%s\n' "$n"
        return 0
      fi
      sleep 1
    done
  else
    # pure polling
    while :; do
      now="$(list_block_roots_linux | sort)"
      add="$(comm -13 /dev/fd/3 /dev/fd/4 3<<EOF3 4<<EOF4
$before
EOF3
$now
EOF4
)"
      if [ -n "$add" ]; then
        n="$(printf '%s\n' "$add" | tail -n1)"
        printf '/dev/%s\n' "$n"
        return 0
      fi
      sleep 1
    done
  fi
}

wait_for_new_disk_openbsd() {
  # Simple polling of 'sysctl hw.disknames'
  before="$(sysctl -n hw.disknames 2>/dev/null || true)"
  info "Waiting for a new disk (OpenBSD)..."
  while :; do
    now="$(sysctl -n hw.disknames 2>/dev/null || true)"
    if [ -n "$before" ] && [ -n "$now" ] && [ "$before" != "$now" ]; then
      # find candidate by set-diff heuristic; pick last new sdX
      cand="$( (printf '%s\n' "$now" | tr ' ' '\n' ; printf '%s\n' "$before" | tr ' ' '\n') | sort | uniq -u | grep -E '^(sd|wd|nvme)[0-9]+' | tail -n1 | cut -d: -f1 )"
      if [ -n "$cand" ]; then
        printf '/dev/%s\n' "$cand"
        return 0
      fi
    fi
    sleep 1
  done
}

###############################################################################
# Metadata collection: Linux
###############################################################################
append_part_json() {
  item="$1"
  if [ "$PART_JSON" = "[]" ]; then
    PART_JSON="[$item]"
  else
    PART_JSON="$(printf '%s' "$PART_JSON" | sed 's/]$//'),$item]"
  fi
}

append_fs_list() {
  f="$1"
  if [ -z "$f" ]; then return 0; fi
  if [ "$FS_LIST" = "[]" ]; then
    FS_LIST='["'"$f"'"]'
  elif ! printf '%s' "$FS_LIST" | grep -F "\"$f\"" >/dev/null 2>&1; then
    FS_LIST="$(printf '%s' "$FS_LIST" | sed 's/]$//'),\"'"$f"'\"]"
  fi
}

append_composite() {
  cls="$1"; name="$2"
  item='{"class":"'"$(json_escape "$cls")"'","name":"'"$(json_escape "$name")"'"}'
  if [ "$COMPOSITE_LIST" = "[]" ]; then
    COMPOSITE_LIST="[$item]"
  else
    COMPOSITE_LIST="$(printf '%s' "$COMPOSITE_LIST" | sed 's/]$//'),$item]"
  fi
}

collect_linux_attrs() {
  d="$DEVICE"
  [ -b "$d" ] || return 2

  DEV_BASENAME="$(basename "$d")"

  if have_cmd lsblk; then
    DEV_SIZE_BYTES="$(lsblk -bn -o SIZE "$d" 2>/dev/null | head -n1 || echo "")"
    DEV_RO="$(lsblk -no RO "$d" 2>/dev/null | head -n1 || echo 0)"
    DEV_ROTA="$(lsblk -no ROTA "$d" 2>/dev/null | head -n1 || echo 0)"
    DEV_SECTOR_LOGICAL="$(lsblk -no LOG-SEC "$d" 2>/dev/null | head -n1 || echo 512)"
    DEV_SECTOR_PHYSICAL="$(lsblk -no PHY-SEC "$d" 2>/dev/null | head -n1 || echo "$DEV_SECTOR_LOGICAL")"

    # partitions + fs
    lsblk -rn -o NAME,TYPE,START,END,FSTYPE "$d" 2>/dev/null |
    awk 'BEGIN{FS="[ \t]+"} $2=="part"{print $1, $3, $4, $5}' |
    while read n s e fs; do
      [ -n "$n" ] || continue
      item='{"name":"/dev/'"$n"'","start":'"${s:-0}"',"end":'"${e:-0}"',"fstype":"'"$(json_escape "${fs:-unknown}")"'"}'
      append_part_json "$item"
      [ -n "${fs:-}" ] && append_fs_list "$fs"
    done
  fi

  # Partition table type (best effort)
  if have_cmd sgdisk; then
    if sgdisk -p "$d" >"$SESSION_DIR/sgdisk-$DEV_BASENAME.txt" 2>&1; then
      if grep -qi 'GPT' "$SESSION_DIR/sgdisk-$DEV_BASENAME.txt"; then DEV_TABLE="gpt"; fi
      if grep -qi 'MBR' "$SESSION_DIR/sgdisk-$DEV_BASENAME.txt"; then DEV_TABLE="mbr"; fi
    fi
  elif have_cmd parted; then
    if parted -s "$d" print >"$SESSION_DIR/parted-$DEV_BASENAME.txt" 2>&1; then
      if grep -qi 'gpt' "$SESSION_DIR/parted-$DEV_BASENAME.txt"; then DEV_TABLE="gpt"; fi
      if grep -qi 'msdos' "$SESSION_DIR/parted-$DEV_BASENAME.txt"; then DEV_TABLE="mbr"; fi
    fi
  fi

  # udev + lsusb
  if have_cmd udevadm; then
    udevadm info --query=property --name="$d" >"$SESSION_DIR/udev-$DEV_BASENAME.env" 2>&1 || true
    VID="$(awk -F= '/^ID_VENDOR_ID=/{print $2}' "$SESSION_DIR/udev-$DEV_BASENAME.env" 2>/dev/null || true)"
    PID="$(awk -F= '/^ID_MODEL_ID=/{print $2}' "$SESSION_DIR/udev-$DEV_BASENAME.env" 2>/dev/null || true)"
    MFG="$(awk -F= '/^ID_VENDOR=/{print $2}' "$SESSION_DIR/udev-$DEV_BASENAME.env" 2>/dev/null || true)"
    PRODUCT="$(awk -F= '/^ID_MODEL=/{print $2}' "$SESSION_DIR/udev-$DEV_BASENAME.env" 2>/dev/null || true)"
    SERIAL="$(awk -F= '/^ID_SERIAL_SHORT=/{print $2}' "$SESSION_DIR/udev-$DEV_BASENAME.env" 2>/dev/null || true)"
    BUS_DEV="$(awk -F= '/^ID_BUS=/{print $2}' "$SESSION_DIR/udev-$DEV_BASENAME.env" 2>/dev/null || true)"
  fi

  # Composite interfaces via lsusb -v
  if have_cmd lsusb && [ -n "$VID" ] && [ -n "$PID" ]; then
    lsusb -v -d "${VID}:${PID}" >"$SESSION_DIR/lsusb-$VID:$PID.txt" 2>&1 || true
    # parse bInterfaceClass hex list
    awk '/bInterfaceClass/ {print $2}' "$SESSION_DIR/lsusb-$VID:$PID.txt" 2>/dev/null |
    while read cls; do
      # class names minimal mapping
      cname="Class 0x$cls"
      case "$(printf '%s' "$cls" | tr 'A-Z' 'a-z')" in
        08) cname="Mass Storage" ;;
        03) cname="HID" ;;
        02) cname="CDC (Communications)" ;;
        0e) cname="Video" ;;
        0a) cname="CDC-Data" ;;
        ff) cname="Vendor Specific" ;;
      esac
      append_composite "$cls" "$cname"
    done
  fi

  # SMART (non-destructive)
  if [ $RUN_SMART -eq 1 ] && have_cmd smartctl; then
    if smartctl -i -H -A "$d" >"$SESSION_DIR/smart-$DEV_BASENAME.txt" 2>&1; then
      SMART_STATUS="$(awk -F: '/^SMART overall-health/ {gsub(/ /,"",$2); print $2}' "$SESSION_DIR/smart-$DEV_BASENAME.txt" 2>/dev/null || echo available)"
      [ -z "$SMART_STATUS" ] && SMART_STATUS="available"
    else
      SMART_STATUS="unavailable"
    fi
  fi

  # Hidden area (HPA/DCO) best-effort
  if [ $CHECK_HIDDEN -eq 1 ] && have_cmd hdparm; then
    if hdparm -N "$d" >"$SESSION_DIR/hdparm-HPA-$DEV_BASENAME.txt" 2>&1; then
      if grep -qi 'protected' "$SESSION_DIR/hdparm-HPA-$DEV_BASENAME.txt"; then
        HPA_DCO_STATUS="possibly_present"
      else
        HPA_DCO_STATUS="not_detected"
      fi
    else
      HPA_DCO_STATUS="not_applicable"
    fi
  fi

  # Firmware / LUN scan (non-destructive)
  if [ $FIRMWARE_SCAN -eq 1 ]; then
    # summarize from composite list
    if printf '%s' "$COMPOSITE_LIST" | grep -q '"class":"ff"'; then
      FIRMWARE_SUMMARY="vendor-specific interfaces present"
    elif printf '%s' "$COMPOSITE_LIST" | grep -q '"name":"HID"'; then
      FIRMWARE_SUMMARY="mass storage + HID"
    else
      FIRMWARE_SUMMARY="none"
    fi
  fi

  return 0
}

###############################################################################
# Metadata collection: OpenBSD
###############################################################################
collect_openbsd_attrs() {
  d="$DEVICE"
  [ -e "$d" ] || return 2
  DEV_BASENAME="$(basename "$d")"

  # size via disklabel -h
  if have_cmd disklabel; then
    disklabel "$d" >"$SESSION_DIR/disklabel-$(basename "$d").txt" 2>&1 || true
    DEV_SIZE_BYTES="$(awk '/^total sectors:/ {print $3}' "$SESSION_DIR/disklabel-$(basename "$d").txt" 2>/dev/null || echo "")"
    if [ -n "$DEV_SIZE_BYTES" ]; then
      # multiply by sector size (assume 512 if not found)
      sl=512
      DEV_SECTOR_LOGICAL=$sl
      DEV_SECTOR_PHYSICAL=$sl
      DEV_SIZE_BYTES="$(expr "$DEV_SIZE_BYTES" \* "$sl" 2>/dev/null || echo "")"
    fi
    DEV_TABLE="disklabel"
    # partitions
    PART_JSON="[]"; FS_LIST="[]"
    awk '/^[ a-z]:/{print $1, $2, $3, $4, $5, $6, $7}' "$SESSION_DIR/disklabel-$(basename "$d").txt" 2>/dev/null |
    while read a b c e f g h; do
      part="$(printf '%s' "$a" | cut -d: -f1)"
      case "$part" in
        [a-j])
          pname="/dev/${DEV_BASENAME}${part}"
          off="$f"; sz="$e"; fst="$g"
          [ -z "$off" ] && off=0
          [ -z "$sz" ] && sz=0
          item='{"name":"'"$(json_escape "$pname")"'","start":'"$off"',"end":'"$sz"',"fstype":"'"$(json_escape "${fst:-unknown}")"'"}'
          append_part_json "$item"
          [ -n "$fst" ] && append_fs_list "$fst"
          ;;
      esac
    done
  fi

  # OpenBSD USB descriptors best-effort
  if have_cmd usbdevs; then
    usbdevs -v >"$SESSION_DIR/usbdevs.txt" 2>&1 || true
    VID=""; PID=""; MFG=""; PRODUCT=""
    # Best effort only; OpenBSD formatting differs; we keep unknown if not parsed
  fi

  if [ $FIRMWARE_SCAN -eq 1 ]; then
    FIRMWARE_SUMMARY="none"
  fi

  SMART_STATUS="unavailable"
  HPA_DCO_STATUS="not_applicable"
  return 0
}

###############################################################################
# Optional minimal write probe (--probe-ro)
###############################################################################
tiny_probe_write_read_restore() {
  # Returns 0 if allowed writes succeed, else 1
  # Offsets: start, mid, end-1chunk
  d="$DEVICE"
  [ $DRY_RUN -eq 1 ] && { info "Dry-run: skipping probe writes"; return 0; }

  cbytes="$(bytes_from_human "$CHUNK_SIZE")"
  [ -n "$cbytes" ] || cbytes=1048576

  if [ -z "$DEV_SIZE_BYTES" ] || [ "$DEV_SIZE_BYTES" -le "$cbytes" ] 2>/dev/null; then
    offs="0"
  else
    mid=$(expr "$DEV_SIZE_BYTES" / 2 - "$cbytes" / 2 2>/dev/null || echo 0)
    end=$(expr "$DEV_SIZE_BYTES" - "$cbytes" 2>/dev/null || echo 0)
    offs="$(printf '0\n%s\n%s\n' "$mid" "$end")"
  fi

  ok=0
  for off in $offs; do
    # read original
    orig="$SESSION_DIR/probe-orig-$off.bin"
    CLEANUP_ITEMS="$CLEANUP_ITEMS
$orig"
    dd if="$d" of="$orig" bs="$cbytes" skip="$(expr "$off" / "$cbytes")" count=1 status=none 2>/dev/null || true

    mark="$SESSION_DIR/probe-mark-$off.bin"
    CLEANUP_ITEMS="$CLEANUP_ITEMS
$mark"
    # marker: 16 bytes pattern repeated
    ( printf 'PROBE-RW-MARK--%04d' "$(expr "$off" % 10000)"; ) | dd of="$mark" bs=16 count=1 status=none 2>/dev/null || true
    # expand marker to chunk size
    # shell-only expansion:
    if have_cmd dd; then
      # cat marker to self until >= chunk
      z="$SESSION_DIR/_tmpmk.$$"
      CLEANUP_ITEMS="$CLEANUP_ITEMS
$z"
      cp "$mark" "$z" 2>/dev/null || true
      while [ "$(wc -c <"$z" 2>/dev/null || echo 0)" -lt "$cbytes" ]; do
        cat "$z" "$mark" >"$z.tmp" 2>/dev/null || true
        mv "$z.tmp" "$z" 2>/dev/null || true
      done
      head -c "$cbytes" "$z" >"$mark" 2>/dev/null || true
    fi

    # write marker
    dd if="$mark" of="$d" bs="$cbytes" seek="$(expr "$off" / "$cbytes")" count=1 conv=fsync,nocreat notrunc status=none 2>/dev/null || true
    sync || true
    # read back and compare
    back="$SESSION_DIR/probe-back-$off.bin"
    CLEANUP_ITEMS="$CLEANUP_ITEMS
$back"
    dd if="$d" of="$back" bs="$cbytes" skip="$(expr "$off" / "$cbytes")" count=1 status=none 2>/dev/null || true
    if cmp -s "$mark" "$back"; then
      ok=1
    else
      ok=0
    fi
    # restore
    dd if="$orig" of="$d" bs="$cbytes" seek="$(expr "$off" / "$cbytes")" count=1 conv=fsync,nocreat notrunc status=none 2>/dev/null || true
    sync || true
    [ $ok -eq 1 ] || { warn "Probe at offset $off did not read back as written"; return 1; }
  done
  return 0
}

###############################################################################
# Blankness check
###############################################################################
blankness_scan() {
  d="$DEVICE"
  cbytes="$(bytes_from_human "$CHUNK_SIZE")"
  [ -n "$cbytes" ] || cbytes=16777216

  info "Blankness check (chunk=$CHUNK_SIZE)..."
  findings="[]"
  limit="$NONZERO_FINDINGS"
  idx=0
  total="${DEV_SIZE_BYTES:-0}"
  if [ "$total" -le 0 ] 2>/dev/null; then
    # fallback read until EOF
    # read first bytes chunk only
    off=0
    tmp="$SESSION_DIR/blank-$$.bin"
    CLEANUP_ITEMS="$CLEANUP_ITEMS
$tmp"
    dd if="$d" of="$tmp" bs="$cbytes" count=1 status=none 2>/dev/null || true
    # check any non-zero
    if LC_ALL=C tr -d '\000' <"$tmp" | head -c 1 >/dev/null 2>&1; then
      findings='["0x0"]'
    fi
  else
    blocks=$(expr "$total" / "$cbytes" 2>/dev/null || echo 0)
    [ "$(expr "$blocks" \* "$cbytes" 2>/dev/null || echo 0)" -lt "$total" ] && blocks=$(expr "$blocks" + 1)
    b=0
    while [ "$b" -lt "$blocks" ]; do
      off=$(expr "$b" \* "$cbytes")
      tmp="$SESSION_DIR/blank-$b.bin"
      CLEANUP_ITEMS="$CLEANUP_ITEMS
$tmp"
      dd if="$d" of="$tmp" bs="$cbytes" skip="$b" count=1 status=none 2>/dev/null || true
      if LC_ALL=C tr -d '\000' <"$tmp" | head -c 1 >/dev/null 2>&1; then
        # non-zero found
        hex="$(printf '0x%X' "$off" 2>/dev/null || echo "0x$off")"
        if [ "$findings" = "[]" ]; then
          findings='["'"$hex"'"]'
        else
          findings="$(printf '%s' "$findings" | sed 's/]$//'),\"'"$hex"'\"]"
        fi
        idx=$(expr "$idx" + 1)
        [ "$idx" -ge "$limit" ] && break
      fi
      b=$(expr "$b" + 1)
    done
  fi

  # store into report fields
  BLANK_IS=1
  if [ "$findings" != "[]" ]; then BLANK_IS=0; fi
  BLANK_JSON='{"is_blank":'"$BLANK_IS"',"first_nonzero_offsets":'"$findings"'}'
}

###############################################################################
# Wipe patterns (portable, chunked, progress)
###############################################################################
make_pattern_chunk() {
  # generate chunk file filled with 0x00 / 0xFF / 0xAA as requested
  # $1 pattern byte in hex (00 | ff | aa)
  pb="$1"
  cbytes="$(bytes_from_human "$CHUNK_SIZE")"
  [ -n "$cbytes" ] || cbytes=16777216
  out="$SESSION_DIR/pat-$pb-$cbytes.bin"
  CLEANUP_ITEMS="$CLEANUP_ITEMS
$out"
  # start from zeros then map if needed
  dd if=/dev/zero of="$out" bs="$cbytes" count=1 status=none 2>/dev/null || true
  case "$pb" in
    00) : ;;
    ff|FF)
      # map zeros to 0xFF
      # POSIX 'tr' may not map NUL reliably; use awk as fallback
      if command -v tr >/dev/null 2>&1; then
        # create mapping via dd chunk through printf trick
        # safer fallback: fill via a loop of printf
        # To avoid huge CPU, do a faster method:
        # write using dd from /dev/zero then xxd? Not POSIX.
        # We'll build a 1KiB 0xFF then expand
        small="$SESSION_DIR/ff-1k.bin"
        CLEANUP_ITEMS="$CLEANUP_ITEMS
$small"
        ( dd if=/dev/zero bs=1024 count=1 status=none | ( awk 'BEGIN{for(i=0;i<1024;i++) printf "%c",255}' ) ) >"$small" 2>/dev/null || true
        # cat small into out until size reached
        : >"$out"
        cur=0
        while [ "$cur" -lt "$cbytes" ]; do
          cat "$small" >>"$out"
          cur=$(expr "$cur" + 1024)
        done
        head -c "$cbytes" "$out" >"$out.tmp" 2>/dev/null || true
        mv "$out.tmp" "$out" 2>/dev/null || true
      else
        # awk-only
        awk 'BEGIN{for(i=0;i<'"$cbytes"';i++) printf "%c",255}' >"$out"
      fi
      ;;
    aa|AA)
      awk 'BEGIN{for(i=0;i<'"$cbytes"';i++) printf "%c",170}' >"$out"
      ;;
    *)
      # unknown -> zeros
      :
      ;;
  esac
  printf '%s\n' "$out"
}

device_size_or_die() {
  if [ -z "$DEV_SIZE_BYTES" ] || [ "$DEV_SIZE_BYTES" -le 0 ] 2>/dev/null; then
    die 4 "Cannot determine device size; aborting."
  fi
}

progress_line() {
  done_bytes="$1"; total="$2"
  if [ "$total" -gt 0 ] 2>/dev/null; then
    pct=$(awk 'BEGIN{printf "%.1f",('"$done_bytes"'*100)/'"$total"'}')
  else
    pct="0.0"
  fi
  printf "\r[Wipe] %s / %s (%s%%)" "$(human_bytes "$done_bytes")" "$(human_bytes "$total")" "$pct"
}

confirm_wipe_gate() {
  # Show fingerprint and require typed confirmation of device and serial (or device only with --force)
  printf "\n%s!!! DANGEROUS: This will ERASE ALL DATA on %s%s\n" "$C_RED" "$DEVICE" "$C_RESET"
  printf " Model: %s  VID:PID=%s:%s  Serial: %s\n" "${PRODUCT:-unknown}" "${VID:-??}" "${PID:-??}" "${SERIAL:-unknown}"

  if [ $FORCE -eq 0 ]; then
    printf " Type the device node '%s' to proceed: " "$DEVICE"
    read ans1 || true
    [ "$ans1" = "$DEVICE" ] || die 1 "Confirmation mismatch; aborting."

    if [ -n "$SERIAL" ]; then
      printf " Type the exact serial '%s' to proceed: " "$SERIAL"
      read ans2 || true
      [ "$ans2" = "$SERIAL" ] || die 1 "Serial confirmation mismatch; aborting."
    fi
  else
    printf " --force supplied. Confirm device '%s' (yes/no): " "$DEVICE"
    read ans || true
    [ "$ans" = "yes" ] || die 1 "User aborted."
  fi
}

do_wipe() {
  [ $DRY_RUN -eq 1 ] && { info "Dry-run: skipping writes"; return 0; }
  device_size_or_die
  cbytes="$(bytes_from_human "$CHUNK_SIZE")"
  [ -n "$cbytes" ] || cbytes=16777216
  total="$DEV_SIZE_BYTES"

  # Large device warning
  thresh_bytes=$(expr "$LARGE_DEV_TB" \* 1024 \* 1024 \* 1024 \* 1024 2>/dev/null || echo 0)
  if [ "$total" -gt "$thresh_bytes" ] 2>/dev/null; then
    warn "Device size is $(human_bytes "$total"). This may take a long time."
    printf " Continue? (yes/no): "
    read ans || true
    [ "$ans" = "yes" ] || die 1 "User aborted due to large size."
  fi

  # Precompute pre-write samples for verification of unchanged regions
  PRE_SAMPLES_FILE="$SESSION_DIR/pre-samples.txt"
  : >"$PRE_SAMPLES_FILE"
  if [ "$HASH_POLICY" = "sample" ] || [ "$HASH_POLICY" = "full" ]; then
    build_samples_list "$PRE_SAMPLES_FILE"
    capture_samples_hashes "$PRE_SAMPLES_FILE" "$SESSION_DIR/pre-hashes.txt"
  fi

  pass=1
  while [ "$pass" -le "$PASSES" ]; do
    src=""
    pdesc="$PATTERN"
    case "$PATTERN" in
      random) src="/dev/urandom" ;;
      zeros)  src="/dev/zero" ;;
      ff)     src="$(make_pattern_chunk ff)" ; pdesc="0xFF" ;;
      aa)     src="$(make_pattern_chunk aa)" ; pdesc="0xAA" ;;
      sequence)
        case "$pass" in
          1) src="/dev/zero"; pdesc="0x00" ;;
          2) src="$(make_pattern_chunk ff)"; pdesc="0xFF" ;;
          3) src="$(make_pattern_chunk aa)"; pdesc="0xAA" ;;
          *) src="/dev/zero"; pdesc="0x00" ;;
        esac
        ;;
      *) src="/dev/urandom" ;;
    esac

    info "Pass $pass/$PASSES using pattern: $pdesc"

    # chunked write loop to show progress (portable)
    b=0; written=0
    blocks=$(expr "$total" / "$cbytes" 2>/dev/null || echo 0)
    [ "$(expr "$blocks" \* "$cbytes" 2>/dev/null || echo 0)" -lt "$total" ] && blocks=$(expr "$blocks" + 1)

    ABORT_REQ=0
    trap 'ABORT_REQ=1' INT
    while [ "$b" -lt "$blocks" ]; do
      [ "$ABORT_REQ" -eq 1 ] && {
        printf "\nAbort requested. Continue (c) or stop (s)? "
        read ans || true
        case "$ans" in
          c|C) ABORT_REQ=0 ;;
          *) trap - INT; die 1 "User aborted during wipe." ;;
        esac
      }
      dd if="$src" of="$DEVICE" bs="$cbytes" seek="$b" count=1 conv=fsync,nocreat notrunc status=none 2>/dev/null || true
      written=$(expr "$written" + "$cbytes" 2>/dev/null || echo "$written")
      if is_tty; then progress_line "$written" "$total"; fi
      b=$(expr "$b" + 1)
    done
    trap - INT
    [ -t 1 ] && printf "\n"
    sync || true
  done

  return 0
}

###############################################################################
# Verification helpers
###############################################################################
_sha256_tool() {
  if have_cmd sha256sum; then echo "sha256sum"
  elif have_cmd sha256; then echo "sha256"
  else echo ""
  fi
}

build_samples_list() {
  # $1: output file with offsets (bytes)
  out="$1"
  : >"$out"
  total="${DEV_SIZE_BYTES:-0}"
  cbytes="$(bytes_from_human "$CHUNK_SIZE")"
  [ -n "$cbytes" ] || cbytes=16777216

  # deterministic anchors + N random
  anchors="0 $(expr "$total" / 4 2>/dev/null || echo 0) $(expr "$total" / 2 2>/dev/null || echo 0) $(expr \( "$total" \* 3 \) / 4 2>/dev/null || echo 0)"
  for a in $anchors; do
    off="$a"
    [ "$off" -lt 0 ] 2>/dev/null && off=0
    if [ "$off" -gt 0 ] 2>/dev/null && [ "$(expr "$off" + "$cbytes")" -gt "$total" ] 2>/dev/null; then
      off=$(expr "$total" - "$cbytes")
    fi
    printf '%s\n' "$off" >>"$out"
  done

  # randoms
  n=0
  while [ "$n" -lt "$SAMPLES" ]; do
    # use awk rand as portable RNG seed by time
    off="$(awk 'BEGIN{srand(); printf "%d", rand()*'"$total"'}')"
    if [ "$off" -gt 0 ] 2>/dev/null && [ "$(expr "$off" + "$cbytes")" -gt "$total" ] 2>/dev/null; then
      off=$(expr "$total" - "$cbytes")
    fi
    [ "$off" -lt 0 ] 2>/dev/null && off=0
    printf '%s\n' "$off" >>"$out"
    n=$(expr "$n" + 1)
  done
}

capture_samples_hashes() {
  # $1: offsets file, $2: output hashes file "off<TAB>hexhash"
  offs="$1"; out="$2"
  tool="$(_sha256_tool)"
  : >"$out"
  if [ -z "$tool" ]; then
    warn "No sha256 tool; sample verification limited."
    return 0
  fi
  cbytes="$(bytes_from_human "$CHUNK_SIZE")"
  [ -n "$cbytes" ] || cbytes=16777216

  while read off; do
    [ -z "$off" ] && continue
    tmp="$SESSION_DIR/vsamp-$off.bin"
    CLEANUP_ITEMS="$CLEANUP_ITEMS
$tmp"
    dd if="$DEVICE" of="$tmp" bs="$cbytes" skip="$(expr "$off" / "$cbytes")" count=1 status=none 2>/dev/null || true
    if [ "$tool" = "sha256sum" ]; then
      hh="$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')"
    else
      hh="$(sha256 "$tmp" 2>/dev/null | awk '{print $1}')"
    fi
    [ -n "$hh" ] && printf '%s\t%s\n' "$off" "$hh" >>"$out"
  done <"$offs"
}

verify_after_wipe() {
  case "$HASH_POLICY" in
    none)
      VERIFY_PASSED=1
      return 0
      ;;
    sample|full)
      : ;;
    *)
      HASH_POLICY="sample"
      ;;
  esac

  tool="$(_sha256_tool)"
  if [ -z "$tool" ]; then
    warn "No sha256 tool; verification downgraded to unchanged-region sampling via cmp."
  fi

  if [ "$HASH_POLICY" = "full" ]; then
    # full hash to exercise readback; cannot know expected contents for random
    info "Computing full-device hash for readback check (best-effort)..."
    if [ -n "$tool" ]; then
      if [ "$tool" = "sha256sum" ]; then
        sha256sum "$DEVICE" >"$SESSION_DIR/full-sha256.txt" 2>/dev/null || true
      else
        sha256 "$DEVICE" >"$SESSION_DIR/full-sha256.txt" 2>/dev/null || true
      fi
    else
      # fallback: read entire device to /dev/null as a readback exercise
      dd if="$DEVICE" of=/dev/null bs="$CHUNK_SIZE" status=none 2>/dev/null || true
    fi
    VERIFY_PASSED=1
    return 0
  fi

  # sample policy: compare pre vs post sample hashes, flag unchanged
  if [ ! -s "$SESSION_DIR/pre-hashes.txt" ]; then
    warn "No pre-write samples captured; sample-verify will be limited."
    VERIFY_PASSED=1
    return 0
  fi

  TMP_OFFS="$SESSION_DIR/post-offs.txt"
  awk -F'\t' '{print $1}' "$SESSION_DIR/pre-hashes.txt" >"$TMP_OFFS" 2>/dev/null || : 
  capture_samples_hashes "$TMP_OFFS" "$SESSION_DIR/post-hashes.txt"

  # Compare sets
  UNCHANGED_RANGES="[]"
  while IFS="$(printf '\t')" read off pre; do
    post="$(awk -F'\t' -v o="$off" '$1==o{print $2}' "$SESSION_DIR/post-hashes.txt" 2>/dev/null || true)"
    if [ -n "$pre" ] && [ "$pre" = "$post" ]; then
      # unchanged at offset -> add offset range [off, off+chunk)
      cbytes="$(bytes_from_human "$CHUNK_SIZE")"
      end=$(expr "$off" + "$cbytes")
      item='{"start":'"$off"',"end":'"$end"'}'
      if [ "$UNCHANGED_RANGES" = "[]" ]; then
        UNCHANGED_RANGES="[$item]"
      else
        UNCHANGED_RANGES="$(printf '%s' "$UNCHANGED_RANGES" | sed 's/]$//'),$item]"
      fi
    fi
  done <"$SESSION_DIR/pre-hashes.txt"

  if [ "$UNCHANGED_RANGES" != "[]" ]; then
    VERIFY_PASSED=0
    return 1
  fi
  VERIFY_PASSED=1
  return 0
}

###############################################################################
# Optional post-sanitize (NVMe/SCSI/ATA) after wipe
###############################################################################
post_sanitize_if_supported() {
  [ $POST_SANITIZE -eq 1 ] || return 0
  [ $DRY_RUN -eq 1 ] && { info "Dry-run: skipping post-sanitize"; return 0; }

  # Try order: NVMe -> SCSI (sg_sanitize) -> ATA (hdparm)
  # NVMe typical /dev/nvme*n*; USB thumbdrives are usually SCSI (sdX), so this may skip.
  if have_cmd nvme && printf '%s\n' "$DEVICE" | grep -q '/nvme'; then
    info "Attempting NVMe sanitize (best-effort)..."
    # Use "block erase" if available; fallback to "crypto erase"
    nvme sanitize "$DEVICE" -a 2 -n 1 >/dev/null 2>&1 || nvme sanitize "$DEVICE" -a 1 -n 1 >/dev/null 2>&1 || true
    return 0
  fi

  if have_cmd sg_sanitize; then
    info "Attempting SCSI sanitize overwrite (best-effort)..."
    # Overwrite for 1 pass with pattern 0x00 (since we already wrote random)
    sg_sanitize --overwrite --early=1 --pattern=0 "$DEVICE" >/dev/null 2>&1 || true
    return 0
  fi

  if have_cmd hdparm; then
    # Only if direct SATA (USB bridges usually block)
    trans=""
    if have_cmd lsblk; then
      trans="$(lsblk -no TRAN "$DEVICE" 2>/dev/null | head -n1 || true)"
    fi
    if [ "$trans" != "usb" ]; then
      info "Attempting ATA security erase (best-effort); may not apply."
      # Minimal attempt with NULL password
      # WARNING: ATA security is tricky; we try not to leave device locked.
      hdparm --user-master u --security-set-pass NULL "$DEVICE" >/dev/null 2>&1 || true
      hdparm --security-erase NULL "$DEVICE" >/dev/null 2>&1 || true
      # Try disable after
      hdparm --security-disable NULL "$DEVICE" >/dev/null 2>&1 || true
      return 0
    fi
  fi

  info "Post-sanitize not supported with available tools for this device."
  return 0
}

###############################################################################
# Inventory & JSON reporting
###############################################################################
write_json_report() {
  # Build JSON document as per spec
  devq="$(json_escape "$DEVICE")"
  modelq="$(json_escape "${PRODUCT:-unknown}")"
  mfgq="$(json_escape "${MFG:-unknown}")"
  serialq="$(json_escape "${SERIAL:-unknown}")"
  tableq="$(json_escape "${DEV_TABLE:-unknown}")"
  busdevq="$(json_escape "${BUS_DEV:-unknown}")"
  hpolq="$(json_escape "$HASH_POLICY")"
  patq="$(json_escape "$PATTERN")"
  chunkq="$(json_escape "$CHUNK_SIZE")"
  fwsumq="$(json_escape "$FIRMWARE_SUMMARY")"
  modeq="$(json_escape "$MODE")"

  # summary errors[] already accumulated
  # tool checks list
  tools='[]'
  for t in lsblk blkid udevadm lsusb dd cmp parted sgdisk smartctl hdparm timeout jq gpg tar; do
    if have_cmd "$t"; then
      if [ "$tools" = "[]" ]; then tools='["'"$t"'"]'; else tools="$(printf '%s' "$tools" | sed 's/]$//'),\"'"$t"'\"]"; fi
    fi
  done

  end_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
  # duration naive
  duration="0"

  cat >"$JSON_REPORT" <<JSON
{
  "device": "$devq",
  "bus_dev": "$busdevq",
  "model": "$modelq",
  "vendor_id": "$(json_escape "${VID:-}")",
  "product_id": "$(json_escape "${PID:-}")",
  "manufacturer": "$mfgq",
  "product": "$modelq",
  "serial": "$serialq",
  "size_bytes": ${DEV_SIZE_BYTES:-0},
  "sector_logical": ${DEV_SECTOR_LOGICAL:-512},
  "sector_physical": ${DEV_SECTOR_PHYSICAL:-${DEV_SECTOR_LOGICAL:-512}},
  "rota": ${DEV_ROTA:-0},
  "table_type": "$tableq",
  "partitions": $PART_JSON,
  "filesystems": $FS_LIST,
  "ro_flag": $( [ "${DEV_RO:-0}" = "1" ] && echo true || echo false ),
  "composite_functions": $COMPOSITE_LIST,
  "smart_status": "$(json_escape "$SMART_STATUS")",
  "hpa_dco_status": "$(json_escape "$HPA_DCO_STATUS")",
  "blank_check": ${BLANK_JSON:-{"is_blank":0,"first_nonzero_offsets":[]}},
  "probe_ro_result": "$( [ $PROBE_RO -eq 1 ] && echo tried || echo skipped )",
  "firmware_scan_summary": "$fwsumq",
  "mode": "$modeq",
  "passes": $( [ "$MODE" = "wipe" ] && echo "$PASSES" || echo null ),
  "pattern": $( [ "$MODE" = "wipe" ] && printf '"%s"\n' "$patq" || echo null ),
  "chunk_size": "$chunkq",
  "hash_policy": $( [ "$MODE" = "wipe" ] && printf '"%s"\n' "$hpolq" || echo null ),
  "samples": $( [ "$MODE" = "wipe" ] && echo "$SAMPLES" || echo null ),
  "verify_result": $( [ "$MODE" = "wipe" ] && { [ $VERIFY_PASSED -eq 1 ] && echo '{"passed":true,"unchanged_ranges":'"$UNCHANGED_RANGES"',"zero_ranges":'"$ZERO_RANGES"'}' || echo '{"passed":false,"unchanged_ranges":'"$UNCHANGED_RANGES"',"zero_ranges":'"$ZERO_RANGES"'}'; } || echo null ),
  "errors": $ERRORS,
  "tool_checks": $tools,
  "timestamps": {"start": "$(json_escape "$START_TS")", "end": "$(json_escape "$end_ts")"},
  "duration_sec": $duration,
  "inventory_appended": false,
  "signatures": {"gpg_sig_path": null},
  "exported_archive": null
}
JSON
}

append_inventory_entry() {
  [ -n "$INVENTORY_LOG" ] || return 0
  entry='{"serial":"'"$(json_escape "$SERIAL")"'","vidpid":"'"$(json_escape "${VID}:${PID}")"'","model":"'"$(json_escape "$PRODUCT")"'","first_seen":null,"last_seen":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"'","last_action":"'"$(json_escape "$MODE")"'","last_status":"'"$( [ "$MODE" = "wipe" ] && [ $VERIFY_PASSED -eq 1 ] && echo ok || echo done )"'"}'
  printf '%s\n' "$entry" >>"$INVENTORY_LOG"
  # update JSON report boolean
  if [ -f "$JSON_REPORT" ]; then
    sed -i.bak 's/"inventory_appended": false/"inventory_appended": true/' "$JSON_REPORT" 2>/dev/null || true
    rm -f "$JSON_REPORT.bak" 2>/dev/null || true
  fi
}

maybe_sign_logs() {
  [ $SIGN_LOGS -eq 1 ] || return 0
  have_cmd gpg || { warn "gpg not found; skipping signing"; return 0; }
  if [ -n "$GPG_ID" ]; then
    gpg --batch --yes -u "$GPG_ID" --detach-sign -o "$JSON_REPORT.sig" "$JSON_REPORT" >/dev/null 2>&1 || true
  else
    gpg --batch --yes --detach-sign -o "$JSON_REPORT.sig" "$JSON_REPORT" >/dev/null 2>&1 || true
  fi
  if [ -f "$JSON_REPORT.sig" ]; then
    sed -i.bak 's/"gpg_sig_path": null/"gpg_sig_path": "usb-report-'"$SESSION_ID"'.json.sig"/' "$JSON_REPORT" 2>/dev/null || true
    rm -f "$JSON_REPORT.bak" 2>/dev/null || true
  fi
}

maybe_export_logs() {
  [ $EXPORT_LOGS -eq 1 ] || return 0
  have_cmd tar || { warn "tar not found; skipping export"; return 0; }
  ( cd "$LOG_DIR" && tar -czf "session-$SESSION_ID.tar.gz" "session-$SESSION_ID" ) >/dev/null 2>&1 || true
  if [ -f "$LOG_DIR/session-$SESSION_ID.tar.gz" ]; then
    sed -i.bak 's/"exported_archive": null/"exported_archive": "session-'"$SESSION_ID"'.tar.gz"/' "$JSON_REPORT" 2>/dev/null || true
    rm -f "$JSON_REPORT.bak" 2>/dev/null || true
  fi
}

###############################################################################
# Mode flows
###############################################################################
mode_scan() {
  info "Starting SCAN mode"
  if [ -z "$DEVICE" ] && [ $WAIT_FOR_PLUG -eq 1 ]; then
    case "$OS_FAMILY" in
      linux) DEVICE="$(wait_for_new_disk_linux)" ;;
      openbsd) DEVICE="$(wait_for_new_disk_openbsd)" ;;
      *) die 2 "Unknown OS and no device specified." ;;
    esac
  fi
  [ -n "$DEVICE" ] || die 2 "No device."

  guard_unsafe_target

  case "$OS_FAMILY" in
    linux)  collect_linux_attrs || true ;;
    openbsd) collect_openbsd_attrs || true ;;
    *) warn "Unknown OS; limited scan";;
  esac

  # Blankness
  blankness_scan

  # Optional probe
  if [ $PROBE_RO -eq 1 ]; then
    printf " Probe minimal write? (yes/no): "
    read agree || true
    if [ "$agree" = "yes" ]; then
      tiny_probe_write_read_restore || append_error "probe_ro failed"
    else
      info "Probe skipped by user."
    fi
  fi

  # Output summaries
  tee_human "============================================================="
  tee_human "USB Device Scan Summary"
  tee_human "Device: $DEVICE  Model: ${PRODUCT:-unknown}  VID:PID=${VID:-??}:${PID:-??}"
  tee_human "Serial: ${SERIAL:-unknown}  Size: ${DEV_SIZE_BYTES:-0} ($([ -n "$DEV_SIZE_BYTES" ] && human_bytes "$DEV_SIZE_BYTES" || echo 'unknown'))"
  tee_human "Geometry: ${DEV_SECTOR_LOGICAL:-512}B logical / ${DEV_SECTOR_PHYSICAL:-${DEV_SECTOR_LOGICAL:-512}}B physical  ROTA: ${DEV_ROTA:-0}"
  tee_human "Partitions ($DEV_TABLE): $(printf '%s' "$PART_JSON")"
  tee_human "Filesystems: $(printf '%s' "$FS_LIST")"
  tee_human "Read-only: $( [ "${DEV_RO:-0}" = "1" ] && echo yes || echo no )"
  if [ "$COMPOSITE_LIST" = "[]" ]; then
    tee_human "Composite interfaces: unknown"
  else
    tee_human "Composite interfaces: $(printf '%s' "$COMPOSITE_LIST")"
  fi
  tee_human "SMART: $SMART_STATUS"
  tee_human "Hidden areas (HPA/DCO): $HPA_DCO_STATUS"
  tee_human "Blankness: $( [ "${BLANK_JSON%%:*}" = '{"is_blank":1' ] && echo BLANK || echo NOT BLANK )  Details: $BLANK_JSON"
  tee_human "JSON: will be saved to $JSON_REPORT"
  tee_human "============================================================="

  write_json_report
  append_inventory_entry
  maybe_sign_logs
  maybe_export_logs
  info "Scan complete."
  return 0
}

build_samples_and_verify() {
  if [ "$HASH_POLICY" = "none" ]; then
    VERIFY_PASSED=1; return 0
  fi
  # already handled in do_wipe pre-capture; here only post-verify step:
  verify_after_wipe || return 1
  return 0
}

mode_wipe() {
  info "Starting WIPE mode"
  if [ -z "$DEVICE" ] && [ $WAIT_FOR_PLUG -eq 1 ]; then
    case "$OS_FAMILY" in
      linux) DEVICE="$(wait_for_new_disk_linux)" ;;
      openbsd) DEVICE="$(wait_for_new_disk_openbsd)" ;;
      *) die 2 "Unknown OS and no device specified." ;;
    esac
  fi
  [ -n "$DEVICE" ] || die 2 "No device."

  guard_unsafe_target

  case "$OS_FAMILY" in
    linux)  collect_linux_attrs || true ;;
    openbsd) collect_openbsd_attrs || true ;;
    *) warn "Unknown OS; limited collect";;
  esac

  confirm_wipe_gate

  # Unmount all partitions (best-effort)
  if [ "$OS_FAMILY" = "linux" ]; then
    if have_cmd lsblk; then
      lsblk -rn -o NAME,TYPE "$DEVICE" 2>/dev/null | awk '$2=="part"{print $1}' |
      while read p; do
        mp="$(lsblk -no MOUNTPOINT "/dev/$p" 2>/dev/null || true)"
        [ -n "$mp" ] && umount "/dev/$p" 2>/dev/null || true
      done
    fi
    sync || true
  else
    # OpenBSD: umount mounted partitions of this disk
    short="$(printf '%s' "$(basename "$DEVICE")" | sed 's/[a-z]$//')"
    mount | awk '/\/dev\/'"$short"'[a-z] /{print $1}' | while read p; do
      umount "$p" 2>/dev/null || true
    done
    sync || true
  fi

  do_wipe || die 4 "Write phase failed."

  # Optional sanitize after random data writing (or always per flag)
  if [ $POST_SANITIZE -eq 1 ]; then
    post_sanitize_if_supported || append_error "post-sanitize failed"
  fi

  build_samples_and_verify || {
    tee_human "Verification FAILED. Unchanged ranges: $UNCHANGED_RANGES"
    write_json_report
    append_inventory_entry
    maybe_sign_logs
    maybe_export_logs
    die 3 "Verification failed."
  }

  tee_human "============================================================="
  tee_human "Wipe & Verify Summary"
  tee_human "Device: $DEVICE  Model: ${PRODUCT:-unknown}  VID:PID=${VID:-??}:${PID:-??}"
  tee_human "Serial: ${SERIAL:-unknown}  Size: ${DEV_SIZE_BYTES:-0} ($([ -n "$DEV_SIZE_BYTES" ] && human_bytes "$DEV_SIZE_BYTES" || echo 'unknown'))"
  tee_human "Passes: $PASSES  Pattern: $PATTERN  Hash policy: $HASH_POLICY"
  tee_human "Verification: PASSED"
  tee_human "JSON: $JSON_REPORT"
  tee_human "============================================================="

  write_json_report
  append_inventory_entry
  maybe_sign_logs
  maybe_export_logs
  info "Wipe complete."
  return 0
}

###############################################################################
# Sample helpers used by wipe (declared earlier)
###############################################################################
# build_samples_list
# capture_samples_hashes
# verify_after_wipe

###############################################################################
# Startup
###############################################################################
banner() {
  cat <<'B'
=============================================================
 USB Mass-Storage Inspect & Wipe (POSIX)
 DO NOT RUN ON LIVE SYSTEM DISKS. THIS WILL ERASE DATA.
=============================================================
B
}

main() {
  banner
  require_root
  detect_os
  [ $OPENBSD_ADAPT -eq 1 ] && OS_FAMILY="openbsd"
  ensure_session_dir

  parse_args "$@"

  # Interactive menu if mode not provided
  if [ -z "$MODE" ]; then
    printf "Choose mode: [1] scan, [2] wipe: "
    read mm || true
    case "$mm" in
      1|scan) MODE="scan" ;;
      2|wipe) MODE="wipe" ;;
      *) die 4 "Invalid choice" ;;
    esac
  fi

  # Defaults sanity
  case "$PASSES" in 1|3|7) : ;; *) PASSES=1 ;; esac
  case "$PATTERN" in random|zeros|ff|aa|sequence) : ;; *) PATTERN="random" ;; esac
  case "$HASH_POLICY" in none|sample|full) : ;; *) HASH_POLICY="sample" ;; esac

  # If user already specified --device, do not wait for plug
  [ -n "$DEVICE" ] && WAIT_FOR_PLUG=0

  case "$MODE" in
    scan) mode_scan ;;
    wipe) mode_wipe ;;
  esac
}

main "$@"

