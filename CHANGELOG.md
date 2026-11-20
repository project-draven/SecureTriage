# Changelog

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
