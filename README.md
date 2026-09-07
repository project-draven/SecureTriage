# SecureTriage

Single-file PowerShell endpoint triage for ransomware indicators. Runs from any RMM or standalone. No dependencies, no agent, no install.

Built for a real problem: an MSP SOC gets an EDR alert on a client endpoint at 11pm and needs to know within five minutes whether this is a false positive or the staging phase of a ransomware deployment. Vendor consoles tell you what fired. They don't tell you what else is on the box.

## What it checks

16 sections across the pre-encryption kill chain — the window where you can still do something.

| Category | Looking for |
|---|---|
| Auth | Failed logon spikes, RDP logon activity |
| Process | Known C2/RAT/credential-dumping binaries, LOLBin abuse, execution from writable paths |
| PowerShell | Script block log patterns, exfil commands in per-user PSReadLine history |
| Network | Established connections on known C2 ports, exfil tools with live sockets |
| Accounts | Recent local account creation, non-standard enabled accounts |
| Persistence | Recently installed services verified by **Authenticode signature**, scheduled tasks with suspicious actions, Run keys across **every** user hive |
| Exposure | RDP enabled, NLA not enforced |
| Exfil | rclone, MEGAsync, b2.exe, WinSCP/PuTTY/FileZilla in non-standard paths, dropped curl/wget — plus their config files, which are the actual IR gold |
| Credential theft | Mimikatz-family, LaZagne, ProcDump outside Sysinternals, comsvcs LSASS dump in history |
| AD recon | SharpHound binaries, BloodHound output ZIPs, recon commands in history |
| Impact prep | Ransom notes by group-specific filename, encrypted file extensions across 25+ families, VSS deletion |
| Cloud pivot | Entra Connect on a workstation, unexplained MSOL_/AAD_ accounts |

Detections are path-aware where it matters. WinSCP in `Program Files` is a MEDIUM "verify authorized." WinSCP in `C:\Windows\Temp` is a CRITICAL. Same binary, different story.

## The design decision that matters

**A check that couldn't run is not a check that passed.**

Most triage scripts wrap everything in `-ErrorAction SilentlyContinue`. Run one without admin rights and the Security log returns nothing — not an error, nothing. Every auth check evaluates as zero hits, scores as clean, and you close the ticket on a host you never actually inspected. That's worse than a crash, because a crash tells you something went wrong.

SecureTriage probes each data source before using it and distinguishes "empty" from "unreadable." Checks that can't run are recorded as `UNAVAILABLE`, excluded from the score denominator, and reported by name with the reason:

```
RISK LEVEL  : CLEAN  (INCOMPLETE  -  61% coverage)
SCORE       : 4 / 100  (of checks that completed)
COVERAGE    : 61%  (7 check(s) could not run)

*** THIS RUN IS INCOMPLETE. A low score does NOT mean the host is clean. ***

  [UNAVAILABLE] Auth | Brute Force  -  Failed Logon Spike
                CHECK DID NOT RUN: Access denied reading 'Security' log (requires elevation)
```

The score answers "how bad is what I looked at." Coverage answers "how much did I look at." Conflating those is how you file a clean ticket on a compromised host.

An incomplete run never exits 0. In an RMM the exit code is the only thing anyone actually sees — if "I couldn't check part of this host" and "this host is clean" both return 0, the coverage reporting is decoration on a report nobody opens.

### The design found a bug in my own detection logic

On the first run after profile reconciliation was added, the tool reported that one of two on-disk user profiles had no matching registry entry and its Run keys were never examined. That profile was the machine's primary user.

The cause: profile enumeration filtered on SIDs matching `S-1-5-21-`, which covers local and on-prem Active Directory accounts. Microsoft Entra ID accounts get `S-1-12-1-`. On any Entra-joined endpoint — most of a modern M365 fleet — the primary user's Run keys were being skipped entirely.

That bug existed in every prior version. It was invisible for exactly as long as the tool only reported findings, and it surfaced within one run of the tool starting to report what it *hadn't* checked.

### Silent failure has more than one mechanism

Three distinct ones turned up in this codebase, all producing the same outcome — a confident answer about something that never happened:

1. `-ErrorAction SilentlyContinue` on `Get-WinEvent` returns nothing for both "log is empty" and "access denied."
2. A SID filter quietly excluded an entire account type.
3. A `param()` block without `[CmdletBinding()]` swallows unrecognized parameters into `$args`, so `-LookbackDayz 30` runs against the default and reports a result nobody asked for.

Different mechanisms, one pattern. Worth looking for in any tool whose output someone will act on.

## Service verification: signatures, not name matching

Section 7 originally matched recently installed services against a vendor allow-list of names and paths. On a healthy test machine that flagged five antivirus drivers as HIGH — `rtp1`, `rtp2`, `rtp_elam`, `BdSentry.sys`, `KslD.sys`. None of those strings contain a vendor name.

The fix was not a longer allow-list. `rtp1` is three characters and anyone can name a service that. Service names are attacker-controlled; certificates are not. The check now resolves the image path from the 7045 event and runs `Get-AuthenticodeSignature`, routing on the result:

| Status | Treatment |
|---|---|
| Valid, recognized publisher | Pass |
| Valid, unrecognized publisher | MEDIUM — review |
| Unsigned or invalid signature | HIGH |
| Binary no longer on disk | MEDIUM — install-then-delete and a superseded app version look identical from the event log |
| Access denied or unresolvable path | **UNAVAILABLE** — not a finding |
| MSIX/AppX package | INFO — Windows enforces signing at install (reduced confidence: developer-mode sideloading can relax this) |

The access-denied row is the important one. An unreadable file is not evidence about that file. Reporting it as HIGH is the same category error as reporting an unelevated run as clean.

## Usage

Must run elevated. Non-elevated runs are refused by default rather than silently degraded.

```powershell
# Standalone
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SecureTriage.ps1

# Longer lookback, JSON output for ingestion
.\SecureTriage.ps1 -LookbackDays 30 -ExportJSON

# Declare baseline accounts so fleet-standard ones don't fire every run
.\SecureTriage.ps1 -KnownAccounts 'svc-backup','imaging-admin'

# File server  -  narrows disk scan scope
.\SecureTriage.ps1 -FileServer

# Degraded run, clearly labelled INCOMPLETE
.\SecureTriage.ps1 -AllowUnelevated
```

| Parameter | Default | Purpose |
|---|---|---|
| `-LookbackDays` | 7 | Event log window |
| `-ServiceDays` | 30 | Service install window |
| `-FileServer` | off | Narrows disk scan scope |
| `-ExportJSON` | off | Adds `findings.json` |
| `-OutputPath` | `C:\ProgramData\SecureTriage` | Output root |
| `-KnownAccounts` | empty | Baseline accounts — downgraded to INFO, never hidden |
| `-AllowUnelevated` | off | Run without admin, reduced coverage |

`-KnownAccounts` validates parameter *names*, not *values*. A misspelled parameter is a hard error; an account name that doesn't exist on a given machine is silently ignored, because failing a triage run over a baseline account missing from one endpoint would be worse than ignoring it.

**RMM deployment:** drop it in as a script component. Exit code drives alerting, output folder holds the artifacts. Nothing vendor-specific in the script.

| Exit | Meaning |
|---|---|
| 0 | Clean / low |
| 1 | Moderate, **or** any check could not run |
| 2 | Critical — escalate |
| 3 | Could not start (not elevated, OS query failed, output path unwritable) |

## Output

```
C:\ProgramData\SecureTriage\SecureTriage_<HOST>_<TIMESTAMP>\
  findings.csv    every check, severity-sorted  -  Excel/pivot friendly
  summary.txt     issues only  -  paste into the ticket
  rawlog.txt      full run log
  findings.json   optional, with host metadata and coverage
```

## Things worth knowing

**Registry Run keys are checked for all profiles.** Most scripts read `HKCU` and call it done — under SYSTEM that's the wrong hive entirely, and under a tech's account it's the tech's hive, not the compromised user's. SecureTriage enumerates `ProfileList` (local, AD, and Entra ID SIDs), uses `HKEY_USERS` for logged-on users, and mounts `NTUSER.DAT` for the rest. Hives are unloaded in a `finally` block with a forced GC first, because PowerShell holds registry handles and the unload fails silently without it. On-disk profiles are reconciled against the registry, so a folder the enumeration never visited gets reported rather than ignored.

**The disk scan is a single pass.** All target filenames compile into one regex; each directory tree is walked once and matched in memory. An earlier version wrapped the tree walk in a per-filename loop — roughly 30 names across 40 paths meant about 1,200 traversals of the same directories, and a scan that ran over five minutes. It now completes in about 25 seconds on a typical workstation.

**It won't hydrate OneDrive.** Files with the `Offline` attribute are skipped and walks are depth-limited. An unbounded `-Recurse` across a redirected Documents folder can pull down every cloud-only file in the profile, which is its own incident when you're doing it to a client on a Tuesday afternoon.

**Scanning is targeted, not exhaustive.** Staging directories, user profile paths, temp locations. A full `C:\` crawl adds 20+ minutes for near-zero additional yield — attackers stage in predictable places. This is a triage tool, not forensic imaging.

**Reparse points are skipped** so junction loops can't hang the walk.

## Requirements

Windows 10/11, Server 2016+. PowerShell 5.1 or 7.x. Local administrator.

Language features used require PowerShell 3.0+, and version fallbacks are included for older hosts — ADSI and `net user` when `Get-LocalUser` is absent, `netstat` parsing when `Get-NetTCPConnection` is, `schtasks.exe` when `Get-ScheduledTask` is. Those fallback paths are written but not verified.

## Limitations

Signature and heuristic based. It finds known tooling in known places. A competent operator using living-off-the-land techniques exclusively, with clean opsec, will not trip most of this — and nothing here replaces EDR. What it does is answer "what else is on this box" faster than clicking through a console, and produce an artifact you can attach to a ticket.

False positives are expected on admin workstations. ProcDump, Angry IP Scanner, and WinSCP are real tools that real techs use. They're flagged for verification, not automatic escalation, and severity is calibrated accordingly.

Tested end to end on Windows 11 with PowerShell 7.x. Server 2012 R2, PowerShell 5.1, domain controllers, and multi-user terminal servers have not been tested; the compatibility fallbacks for those environments exist in code and are unverified.

## License

<!-- Pick one. MIT if you want it used, GPL if you want changes shared back. -->

---

<!--
TODO before publishing:
  - Fill in the License section and add a LICENSE file
  - Add a sanitized summary.txt from a lab VM run (neutral hostname, no real account names)
  - Run once on Server 2016+ and PS 5.1, then tighten or keep the Limitations wording
-->
