# Changelog

## Unreleased (v3.4)

### Added
- Pester 5 test suite in `tests/`, run in CI on Windows PowerShell 5.1 and PowerShell 7.
- Regression tests for both v3.3 false negatives, including that the
  PowerShell check does not flag SecureTriage's own logging.
- Structural tests: the script parses, is plain ASCII, defines every function
  before the script body calls it, and keeps the 4720 check outside the
  `-KnownAccounts` block.

### Changed
- Section 4 filtering moved into `Select-SuspiciousPSEvent` so it can be
  tested with synthetic events. Same logic, no change in results.

### Fixed
- **PS history check flagged ordinary commands as CRITICAL (#2).** `-e ` and
  `-enc ` matched anywhere, so `winget install ... -e`, `docker run -e`,
  `git grep -e` and `-enc UTF8` exited 2 on clean admin workstations. Encoded
  commands now have to be a `powershell`/`pwsh` launch with a base64 argument.
- **PS history check missed `irm <url> | iex`.** `IEX[^P]` needed a character
  after `IEX`, so the most common download cradle never matched. `iex` is now
  matched as a whole word, which still excludes `iexplore`.
- **PS history check missed `powershell -ec <base64>`**, a valid
  `-EncodedCommand` alias.
- 4103 events with an empty "Script Name" (interactive sessions) reported the
  next context line, "Command Path =", as the event source. Detection was not
  affected; the source shown in the report was wrong.

## v3.3 (hotfix)

Found through a structured code review of v3.2. Both detection bugs were
false negatives: the checks reported PASS on hosts where they should have fired.

### Fixed
- **Suspicious PowerShell check never fired.** The 4103/4104 noise filters ran
  against the full rendered event message. Every 4104 message begins
  "Creating Scriptblock text" and every 4103 message contains
  "Shell ID = Microsoft.PowerShell", and both strings were in the exclusion
  lists, so every event was dropped. Patterns now match the logged script
  text only, and the script's own logged source is excluded by file name
  rather than by generic cmdlet names.
- **New local accounts check (Event 4720) was skipped by default.** A
  misplaced brace nested it inside the `-KnownAccounts` block, so it only ran
  when that parameter was passed, and was not reported as UNAVAILABLE either.
- **Failed event queries passed as clean** for the two checks above. Only
  "no events found" now counts as clean; any other query error is UNAVAILABLE.
  Other sections still use `-ErrorAction SilentlyContinue` and are scheduled
  for v3.4.
- **Exit code documentation.** The script header said exit 2 meant
  High/Critical. The code (and README) exit 2 for Critical only; HIGH exits 1.
  The header now matches the code. Alerting behaviour is unchanged.

### Upgrade note
Runs after this update can report HIGH "Suspicious PowerShell" and
"Local Accounts Created" findings on hosts that previously showed PASS for
those checks. That is the fix working, not a regression.
