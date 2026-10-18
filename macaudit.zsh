#!/bin/zsh
#
# macaudit — macOS security posture audit
#
# Checks common macOS security settings and gives you a score.
# Read-only by default. Use --fix to be offered safe fixes, one at a time.
# Every run is saved to a Markdown report and a history CSV so you can
# track your score over time.
#
# Usage: ./macaudit.zsh [--fix] [--history] [-o DIR] [--no-color] [--help]
#
# Only run this on Macs you own or are authorized to administer.

emulate -L zsh
setopt pipe_fail
zmodload zsh/datetime

VERSION="1.0.0"
FIX=0
SHOW_HISTORY=0
NO_COLOR=0
OUT_DIR="${HOME}/macaudit-reports"
FW=/usr/libexec/ApplicationFirewall/socketfilterfw

usage() {
  cat <<'EOF'
macaudit — audit common macOS security settings

Usage: macaudit.zsh [options]

  --fix            After the audit, offer to fix failed items (asks before each one; uses sudo)
  --history        Show score history from previous runs and exit
  -o, --output DIR Where to save reports (default: ~/macaudit-reports)
  --no-color       Disable colored output
  -v, --version    Print version
  -h, --help       Show this help

Exit code: 0 if no checks failed, 1 if any check failed, 2 on bad usage.
EOF
}

# ---------- Parse arguments ----------
while (( $# )); do
  case $1 in
    --fix) FIX=1 ;;
    --history) SHOW_HISTORY=1 ;;
    -o|--output)
      if [[ -z ${2:-} ]]; then print -u2 "Missing value for $1"; exit 2; fi
      OUT_DIR=$2; shift ;;
    --no-color) NO_COLOR=1 ;;
    -v|--version) print "macaudit $VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) print -u2 "Unknown option: $1"; usage >&2; exit 2 ;;
  esac
  shift
done

HISTORY_FILE="$OUT_DIR/history.csv"

if [[ $(uname -s) != Darwin ]]; then
  print -u2 "macaudit only runs on macOS."
  exit 1
fi

# ---------- Colors ----------
if (( NO_COLOR )) || [[ ! -t 1 ]]; then
  C_PASS="" C_FAIL="" C_WARN="" C_DIM="" C_BOLD="" C_RESET=""
else
  C_PASS=$'\e[32m' C_FAIL=$'\e[31m' C_WARN=$'\e[33m'
  C_DIM=$'\e[2m' C_BOLD=$'\e[1m' C_RESET=$'\e[0m'
fi

# ---------- History view ----------
if (( SHOW_HISTORY )); then
  if [[ ! -f $HISTORY_FILE ]]; then
    print "No history yet. Run macaudit first."
    exit 0
  fi
  column -t -s, "$HISTORY_FILE"
  runs=$(( $(wc -l < "$HISTORY_FILE") - 1 ))
  first=$(sed -n '2p' "$HISTORY_FILE" | cut -d, -f7)
  last=$(tail -n 1 "$HISTORY_FILE" | cut -d, -f7)
  avg_ms=$(awk -F, 'NR>1 {s+=$8; n++} END {if (n) printf "%.0f", s/n}' "$HISTORY_FILE")
  print ""
  print "${C_BOLD}Runs:${C_RESET} $runs   ${C_BOLD}First score:${C_RESET} ${first}%   ${C_BOLD}Latest score:${C_RESET} ${last}%   ${C_BOLD}Change:${C_RESET} $(( last - first )) points   ${C_BOLD}Avg audit time:${C_RESET} ${avg_ms} ms"
  exit 0
fi

# ---------- Result storage ----------
typeset -a NAMES STATUSES DETAILS FIX_CMDS

# record NAME STATUS DETAIL [FIX_COMMAND]
record() {
  local name=$1 check_status=$2 detail=$3 fix_cmd=${4:-} color
  NAMES+=("$name"); STATUSES+=("$check_status"); DETAILS+=("$detail"); FIX_CMDS+=("$fix_cmd")
  case $check_status in
    PASS) color=$C_PASS ;;
    WARN) color=$C_WARN ;;
    *)    color=$C_FAIL ;;
  esac
  printf "  %s[%s]%s %-26s %s%s%s\n" "$color" "$check_status" "$C_RESET" "$name" "$C_DIM" "$detail" "$C_RESET"
}

pref() { defaults read "$1" "$2" 2>/dev/null; }

# ---------- Checks ----------
check_filevault() {
  local out; out=$(fdesetup status 2>/dev/null)
  if [[ $out == *"in progress"* ]]; then
    record "FileVault encryption" WARN "Encryption is still in progress"
  elif [[ $out == *"FileVault is On"* ]]; then
    record "FileVault encryption" PASS "Startup disk is encrypted"
  else
    record "FileVault encryption" FAIL "Disk not encrypted. Turn on in System Settings > Privacy & Security > FileVault"
  fi
}

check_firewall() {
  local out; out=$("$FW" --getglobalstate 2>/dev/null)
  if [[ $out == *"State = 1"* || $out == *"State = 2"* ]]; then
    record "Firewall" PASS "Application firewall is on"
  else
    record "Firewall" FAIL "Application firewall is off" "sudo $FW --setglobalstate on"
  fi
}

check_stealth() {
  local out; out=$("$FW" --getstealthmode 2>/dev/null)
  if [[ $out == *"mode is on"* || $out == *"mode enabled"* ]]; then
    record "Firewall stealth mode" PASS "Mac ignores unsolicited network probes"
  else
    record "Firewall stealth mode" WARN "Mac responds to pings and port probes" "sudo $FW --setstealthmode on"
  fi
}

check_gatekeeper() {
  local out; out=$(spctl --status 2>/dev/null)
  if [[ $out == *"assessments enabled"* ]]; then
    record "Gatekeeper" PASS "Only trusted apps can run"
  else
    record "Gatekeeper" FAIL "Unverified apps can run without warning" "sudo spctl --master-enable"
  fi
}

check_sip() {
  local out; out=$(csrutil status 2>/dev/null)
  if [[ $out == *"status: enabled"* ]]; then
    record "System Integrity Protect." PASS "SIP protects system files"
  else
    record "System Integrity Protect." FAIL "SIP is off. Re-enable from Recovery mode with: csrutil enable"
  fi
}

# check_update_pref NAME KEY DESCRIPTION
check_update_pref() {
  local name=$1 key=$2 what=$3 val
  local fix="sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate $key -bool true"
  val=$(pref /Library/Preferences/com.apple.SoftwareUpdate "$key")
  case $val in
    1) record "$name" PASS "$what is on" ;;
    0) record "$name" FAIL "$what is off" "$fix" ;;
    *) record "$name" WARN "$what not explicitly set (using system default)" "$fix" ;;
  esac
}

check_screen_lock() {
  local out secs
  out=$(sysadminctl -screenLock status 2>&1)
  if [[ $out == *"immediate"* ]]; then
    record "Screen lock" PASS "Password required immediately after sleep"
  elif [[ $out =~ 'delay is ([0-9]+) seconds' ]]; then
    secs=$match[1]
    if (( secs <= 300 )); then
      record "Screen lock" PASS "Password required after ${secs}s"
    else
      record "Screen lock" WARN "Password required only after ${secs}s (5 min or less recommended)"
    fi
  elif [[ $out == *"off"* ]]; then
    record "Screen lock" FAIL "No password needed after sleep. Fix in System Settings > Lock Screen"
  else
    record "Screen lock" WARN "Could not read setting. Check System Settings > Lock Screen"
  fi
}

LISTENING=$(netstat -an -p tcp 2>/dev/null | grep LISTEN)
port_open() { print -r -- "$LISTENING" | grep -Eq "[.:]$1[[:space:]]"; }

check_ssh() {
  if port_open 22; then
    record "Remote Login (SSH)" WARN "SSH is on. Turn off if you don't use it" "sudo systemsetup -f -setremotelogin off"
  else
    record "Remote Login (SSH)" PASS "SSH is off"
  fi
}

check_screen_sharing() {
  if port_open 5900; then
    record "Screen Sharing" WARN "Screen Sharing is on. Turn off in System Settings > General > Sharing"
  else
    record "Screen Sharing" PASS "Screen Sharing is off"
  fi
}

check_file_sharing() {
  if port_open 445; then
    record "File Sharing (SMB)" WARN "File Sharing is on. Turn off in System Settings > General > Sharing"
  else
    record "File Sharing (SMB)" PASS "File Sharing is off"
  fi
}

check_guest() {
  local val; val=$(pref /Library/Preferences/com.apple.loginwindow GuestEnabled)
  if [[ $val == 1 ]]; then
    record "Guest account" FAIL "Guest user can log in" "sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"
  else
    record "Guest account" PASS "Guest login is disabled"
  fi
}

check_autologin() {
  local val; val=$(pref /Library/Preferences/com.apple.loginwindow autoLoginUser)
  if [[ -n $val ]]; then
    record "Automatic login" FAIL "Auto-login is on. Turn off in System Settings > Users & Groups"
  else
    record "Automatic login" PASS "Password required at startup"
  fi
}

# ---------- Run audit ----------
os_version=$(sw_vers -productVersion)
print ""
print "${C_BOLD}macaudit $VERSION${C_RESET}  ${C_DIM}macOS $os_version${C_RESET}"
print ""

start=$EPOCHREALTIME
check_filevault
check_firewall
check_stealth
check_gatekeeper
check_sip
check_update_pref "Auto update check"    AutomaticCheckEnabled "Automatic update checking"
check_update_pref "Auto update download" AutomaticDownload     "Background update download"
check_update_pref "Security responses"   CriticalUpdateInstall "Automatic security response install"
check_screen_lock
check_ssh
check_screen_sharing
check_file_sharing
check_guest
check_autologin
end=$EPOCHREALTIME

duration_ms=$(printf "%.0f" $(( (end - start) * 1000 )))
total=${#STATUSES}
pass=${#${(M)STATUSES:#PASS}}
warn=${#${(M)STATUSES:#WARN}}
fail=${#${(M)STATUSES:#FAIL}}
score=$(( pass * 100 / total ))

print ""
print "${C_BOLD}Score: ${score}%${C_RESET}  (${C_PASS}$pass passed${C_RESET}, ${C_WARN}$warn warnings${C_RESET}, ${C_FAIL}$fail failed${C_RESET} of $total checks in ${duration_ms} ms)"

# ---------- Optional fixes ----------
integer fixes_applied=0
if (( FIX )); then
  typeset -a fixable
  for i in {1..$total}; do
    if [[ ${STATUSES[i]} != PASS && -n ${FIX_CMDS[i]} ]]; then fixable+=($i); fi
  done
  if (( ${#fixable} == 0 )); then
    print "\nNothing can be fixed automatically. Manual steps are listed in the report."
  else
    print "\n${C_BOLD}Fixes${C_RESET}  ${C_DIM}(you'll be asked before each one; sudo may ask for your password)${C_RESET}"
    for i in $fixable; do
      print ""
      print -r -- "  ${NAMES[i]}: ${DETAILS[i]}"
      print -r -- "  ${C_DIM}Command: ${FIX_CMDS[i]}${C_RESET}"
      if read -q "?  Apply this fix? [y/N] "; then
        print ""
        if eval "${FIX_CMDS[i]}"; then
          (( ++fixes_applied ))
          print "  ${C_PASS}Applied${C_RESET}"
        else
          print "  ${C_FAIL}Fix failed${C_RESET} (some commands need Full Disk Access for Terminal)"
        fi
      else
        print "\n  Skipped"
      fi
    done
    if (( fixes_applied )); then
      print "\nApplied $fixes_applied fix(es). Run macaudit again to measure your new score."
    fi
  fi
fi

# ---------- Save report + history ----------
mkdir -p "$OUT_DIR"
ts=$(strftime '%Y-%m-%d %H:%M:%S' $EPOCHSECONDS)
file_ts=$(strftime '%Y%m%d-%H%M%S' $EPOCHSECONDS)
report="$OUT_DIR/macaudit-$file_ts.md"

{
  print -r -- "# macaudit report"
  print ""
  print -r -- "- **Date:** $ts"
  print -r -- "- **macOS:** $os_version"
  print -r -- "- **Score:** ${score}% ($pass of $total passed, $warn warnings, $fail failed)"
  print -r -- "- **Audit time:** ${duration_ms} ms"
  print -r -- "- **Fixes applied this run:** $fixes_applied"
  print ""
  print -r -- "| Check | Result | Details |"
  print -r -- "|---|---|---|"
  for i in {1..$total}; do
    print -r -- "| ${NAMES[i]} | ${STATUSES[i]} | ${DETAILS[i]} |"
  done
} > "$report"

if [[ ! -f $HISTORY_FILE ]]; then
  print "timestamp,macos_version,checks,passed,warnings,failed,score_pct,duration_ms,fixes_applied" > "$HISTORY_FILE"
fi
print "$ts,$os_version,$total,$pass,$warn,$fail,$score,$duration_ms,$fixes_applied" >> "$HISTORY_FILE"

print ""
print "${C_DIM}Report saved: $report${C_RESET}"
print "${C_DIM}History: $HISTORY_FILE  (view with --history)${C_RESET}"
print ""

(( fail == 0 )) || exit 1
exit 0
