# macaudit

A zsh script that audits 14 macOS security settings in under a second, scores your Mac, and offers to fix what's wrong. Every run is logged, so you can track your score over time.

> Only run this on Macs you own or are authorized to administer.

## What it checks

| Check | Why it matters | Auto-fix |
|---|---|---|
| FileVault | Encrypts the disk if the laptop is lost or stolen | Manual |
| Firewall | Blocks unwanted incoming connections | Yes |
| Firewall stealth mode | Hides the Mac from pings and port scans | Yes |
| Gatekeeper | Blocks unverified apps | Yes |
| System Integrity Protection | Protects core system files from tampering | Manual (Recovery mode) |
| Automatic update checks | Finds security patches | Yes |
| Automatic update downloads | Gets patches ready to install | Yes |
| Automatic security responses | Installs urgent security fixes | Yes |
| Screen lock | Requires a password after sleep (5 min or less) | Manual |
| Remote Login (SSH) | Open remote access is an attack surface | Yes |
| Screen Sharing | Remote control of the Mac | Manual |
| File Sharing (SMB) | Exposes files on the network | Manual |
| Guest account | Lets anyone log in without a password | Yes |
| Automatic login | Skips the password at startup | Manual |

## Install

```zsh
git clone https://github.com/<your-username>/macaudit.git
cd macaudit
chmod +x macaudit.zsh
```

## Usage

```zsh
./macaudit.zsh            # run the audit (read-only, no sudo needed)
./macaudit.zsh --fix      # audit, then offer each fix one at a time
./macaudit.zsh --history  # show score history across runs
./macaudit.zsh --help
```

Reports are saved to `~/macaudit-reports/`:
- `macaudit-<date>.md` is a full report for each run
- `history.csv` holds one row per run (score, pass/warn/fail counts, audit time, fixes applied)

The script exits with `1` if any check fails, so it can be used in automation.

## Example output

```
macaudit 1.0.0  macOS 15.4

  [PASS] FileVault encryption       Startup disk is encrypted
  [FAIL] Firewall                   Application firewall is off
  [WARN] Remote Login (SSH)         SSH is on. Turn off if you don't use it
  ...

Score: 64%  (9 passed, 3 warnings, 2 failed of 14 checks in 120 ms)
```

## Scoring

Score = passed checks ÷ total checks. Warnings count as not passed. Some fixes (like `systemsetup`) need Full Disk Access for Terminal: System Settings > Privacy & Security > Full Disk Access.

## Built with

zsh and built-in macOS tools only (`fdesetup`, `socketfilterfw`, `spctl`, `csrutil`, `defaults`, `sysadminctl`, `netstat`). No dependencies.

## Roadmap

- JSON output
- Weekly scheduled runs with `launchd`
- Map checks to CIS macOS Benchmark controls
# macaudit
