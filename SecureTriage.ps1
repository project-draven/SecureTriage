# =============================================================================
#  SecureTriage.ps1
#  Endpoint Security Triage  -  Ransomware Edition
#  Version 3.2  -  RMM-agnostic / Cross-Platform Compatible
#
#  Runs standalone or from any RMM (Datto, NinjaOne, ConnectWise, Kaseya, etc).
#  No RMM-specific dependencies. Results are written to disk and signalled
#  via exit code.
#
#  Compatibility: Windows 10/11, Server 2016+  |  PowerShell 5.1 and 7.x
#  Language features used require PS 3.0+, and version fallbacks are included
#  for older hosts (ADSI/net user, netstat, schtasks.exe). Those paths are
#  written but NOT verified  -  only 7.x has been tested end to end.
#
#  -------------------------------------------------------------------------
#  STANDALONE USAGE
#  -------------------------------------------------------------------------
#    Must run ELEVATED. Non-elevated runs cannot read the Security event log
#    or other user profiles, and the script will mark those checks
#    UNAVAILABLE rather than silently reporting them as clean.
#
#    From an elevated prompt:
#      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SecureTriage.ps1
#
#    If the file was downloaded or copied from a share, unblock it first:
#      Unblock-File .\SecureTriage.ps1
#
#    Read the result:
#      $LASTEXITCODE
#
#    Suppress known-good baseline accounts to MEDIUM -> INFO (never hidden):
#      .\SecureTriage.ps1 -KnownAccounts 'svc-backup','imaging-admin'
#
#    Do NOT dot-source this script (. .\SecureTriage.ps1). It is guarded
#    against closing your session, but the exit code will not be set.
#
#  -------------------------------------------------------------------------
#  OUTPUT
#  -------------------------------------------------------------------------
#    <OutputPath>\SecureTriage_HOSTNAME_YYYYMMDD_HHMMSS\
#      findings.csv    -  all findings, sortable in Excel
#      summary.txt     -  issues only, paste into ticket/email
#      rawlog.txt      -  full verbose run log
#
#    Default OutputPath: C:\ProgramData\SecureTriage
#
#  -------------------------------------------------------------------------
#  SCORING
#  -------------------------------------------------------------------------
#    Score = (weight of checks that HIT) / (weight of checks that COMPLETED)
#
#    Checks that could not run are EXCLUDED from the denominator and reported
#    separately as coverage. A run with reduced coverage is labelled
#    INCOMPLETE. A low score on an incomplete run does not mean clean.
#
#  Exit codes:
#    0 = Clean/Low   1 = Moderate OR incomplete coverage   2 = High/Critical   3 = Could not run
# =============================================================================

# [CmdletBinding()] makes this an advanced script, which means an unrecognized
# parameter is a hard error instead of being silently swallowed into $args.
# Without it, `-KnownAcounts` (typo) or `-LookbackDayz 30` run happily against
# the defaults and report a result the caller did not ask for.
[CmdletBinding()]
param(
    [int]$LookbackDays = 7,
    [int]$ServiceDays  = 30,
    [switch]$FileServer,                              # Limits disk scan scope on file servers (faster)
    [switch]$ExportJSON,
    [string]$OutputPath = "C:\ProgramData\SecureTriage",
    [string[]]$KnownAccounts = @(),                   # Baseline accounts expected on this fleet
    [switch]$AllowUnelevated                          # Run anyway, with reduced coverage
)

# =============================================================================
# ELEVATION CHECK
# Datto and most RMMs execute as SYSTEM, so this is always satisfied there.
# Standalone runs are where this matters.
# =============================================================================
$IsElevated = $false
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal       = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $IsElevated      = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsElevated = $false
}

if (-not $IsElevated -and -not $AllowUnelevated) {
    Write-Warning "SecureTriage must run elevated."
    Write-Warning "Without admin rights it cannot read the Security event log or other user"
    Write-Warning "profiles, which means it would report an uninspected host as CLEAN."
    Write-Warning ""
    Write-Warning "Re-run from an elevated PowerShell prompt:"
    Write-Warning "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SecureTriage.ps1"
    Write-Warning ""
    Write-Warning "To run anyway with reduced coverage (results will be marked INCOMPLETE):"
    Write-Warning "  ... -File .\SecureTriage.ps1 -AllowUnelevated"
    exit 3
}

# =============================================================================
# ENVIRONMENT DETECTION
# Get-CimInstance works in Windows PowerShell 3+ AND PowerShell 7.
# Get-WmiObject does not exist in PS7 and would return $null silently,
# causing the script to misidentify a DC as a workstation.
# =============================================================================
$OSInfo = $null
try {
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
} catch {
    # Fallback for hosts where the CIM/WinRM stack is broken but WMI/DCOM works
    if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
        try { $OSInfo = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop } catch {}
    }
}

if (-not $OSInfo) {
    Write-Warning "Could not query Win32_OperatingSystem via CIM or WMI."
    Write-Warning "OS detection drives scan scope and server-specific checks, so aborting"
    Write-Warning "rather than running with wrong assumptions."
    exit 3
}

$PSVer      = $PSVersionTable.PSVersion.Major
$OSCaption  = $OSInfo.Caption
$OSBuild    = [int]$OSInfo.BuildNumber
$IsServer   = $OSInfo.ProductType -ne 1        # 1=Workstation 2=DC 3=Server
$IsDC       = $OSInfo.ProductType -eq 2
$HostName   = $env:COMPUTERNAME

# Build number thresholds
# Server 2012        = 9200   Server 2012 R2 = 9600
# Server 2016        = 14393  Server 2019   = 17763  Server 2022 = 20348
# Win 10 (1507)      = 10240  Win 11        = 22000+
$IsWin2012  = ($OSBuild -le 9600 -and $IsServer)
$HasPS5     = ($PSVer -ge 5)

# =============================================================================
# OUTPUT FOLDER SETUP
# =============================================================================
$RunStamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$BaseDir     = $OutputPath
$RunDir      = Join-Path $BaseDir "SecureTriage_${HostName}_${RunStamp}"
$CsvPath     = Join-Path $RunDir  "findings.csv"
$SummaryPath = Join-Path $RunDir  "summary.txt"
$LogPath     = Join-Path $RunDir  "rawlog.txt"

try {
    if (-not (Test-Path $BaseDir)) { New-Item -ItemType Directory -Path $BaseDir -Force -ErrorAction Stop | Out-Null }
    New-Item -ItemType Directory -Path $RunDir -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "Could not create output folder '$RunDir': $($_.Exception.Message)"
    Write-Warning "Specify a writable location with -OutputPath."
    exit 3
}

# =============================================================================
# CORE FUNCTIONS
# =============================================================================

function Write-Log {
    param([string]$Message)
    $ts   = Get-Date -Format 'HH:mm:ss'
    $line = "[$ts] $Message"
    Write-Output $line
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
}

# PS 4 compatible findings list (no ::new())
$findings           = New-Object System.Collections.ArrayList
$totalWeight        = 0     # weight of checks that actually completed
$totalHitScore      = 0
$unavailableWeight  = 0     # weight of checks that could not run
$unavailableCount   = 0

function Add-Check {
    param(
        [string]$Category,
        [string]$Name,
        [int]   $Weight,
        [int]   $HitScore,
        [bool]  $Hit,
        [string]$Severity,   # CRITICAL / HIGH / MEDIUM / LOW / INFO / PASS
        [string]$Detail = ''
    )
    $script:totalWeight   += $Weight
    if ($Hit) { $script:totalHitScore += $HitScore }
    $eff = if ($Hit) { $Severity } else { 'PASS' }
    [void]$script:findings.Add([PSCustomObject]@{
        Severity = $eff
        Category = $Category
        Name     = $Name
        Hit      = $Hit
        Detail   = if ($Hit) { $Detail } else { 'No issues found' }
    })
}

# Register a check that could NOT be evaluated.
# This is the difference between "we looked and found nothing" and
# "we never looked". The second one must never appear as PASS.
function Add-Unavailable {
    param(
        [string]$Category,
        [string]$Name,
        [int]   $Weight,
        [string]$Reason = 'Unknown'
    )
    $script:unavailableWeight += $Weight
    $script:unavailableCount  += 1
    [void]$script:findings.Add([PSCustomObject]@{
        Severity = 'UNAVAILABLE'
        Category = $Category
        Name     = $Name
        Hit      = $false
        Detail   = "CHECK DID NOT RUN: $Reason"
    })
}

function Write-Section {
    param([string]$Title)
    Write-Log ""
    Write-Log ("=" * 60)
    Write-Log "  $Title"
    Write-Log ("=" * 60)
}

# Distinguish "log is empty" from "log is unreadable".
# Get-WinEvent -ErrorAction SilentlyContinue returns nothing in BOTH cases,
# which is how an unelevated run produces a false CLEAN verdict.
function Test-EventLogAccess {
    param([string]$LogName)
    try {
        $null = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
        return @{ Accessible = $true;  Reason = '' }
    } catch {
        $msg = $_.Exception.Message
        # Readable but empty
        if ($msg -match 'No events were found') {
            return @{ Accessible = $true; Reason = '' }
        }
        if ($_.Exception -is [System.UnauthorizedAccessException] -or $msg -match 'Access is denied|not accessible') {
            return @{ Accessible = $false; Reason = "Access denied reading '$LogName' log (requires elevation)" }
        }
        if ($msg -match 'There is not an event log|could not be found') {
            return @{ Accessible = $false; Reason = "Event log '$LogName' not present on this host" }
        }
        return @{ Accessible = $false; Reason = "Could not read '$LogName' log: $msg" }
    }
}

Write-Log "SecureTriage v3.2  -  starting pre-flight checks..."

$SecurityLogAccess = Test-EventLogAccess -LogName 'Security'
$SystemLogAccess   = Test-EventLogAccess -LogName 'System'
$PSLogAccess       = Test-EventLogAccess -LogName 'Microsoft-Windows-PowerShell/Operational'

# -----------------------------------------------------------------------------
# USER PROFILE ENUMERATION + ACCESS TEST
# An unelevated run can only read its own profile. Every profile-based check
# (PS history, file staging, B2/rclone config) is blind to the rest.
# Count and report that instead of pretending the host is clean.
# -----------------------------------------------------------------------------
$UserProfiles          = @()
$InaccessibleProfiles  = @()

try {
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' } |
        ForEach-Object {
            $accessible = $false
            try {
                $null = Get-ChildItem $_.FullName -ErrorAction Stop | Select-Object -First 1
                $accessible = $true
            } catch {
                $accessible = $false
            }
            if ($accessible) {
                $UserProfiles += $_
            } else {
                $InaccessibleProfiles += $_.Name
            }
        }
} catch {}

if ($InaccessibleProfiles.Count -gt 0) {
    Write-Log "  [WARN] $($InaccessibleProfiles.Count) user profile(s) not readable: $($InaccessibleProfiles -join ', ')"
    Write-Log "         Profile-scoped checks are incomplete for these users."
}

# Safe disk scan  -  limits depth and handles file server mode
# Returns file objects, never throws.
# Skips reparse points (junction loops) and OneDrive cloud-only placeholders
# so a scan cannot trigger mass file hydration on a live client endpoint.
function Get-FileSafe {
    param(
        [string[]]$Paths,
        [string[]]$Filters,
        [int]$MaxDepth = 5,
        [switch]$NoDepthLimit
    )

    # Directories to never recurse into  -  large OS/app internals with near-zero attacker value
    $skipDirPatterns = @(
        'Windows\\System32', 'Windows\\SysWOW64', 'Windows\\WinSxS',
        'Windows\\servicing', 'Windows\\assembly', 'Windows\\Microsoft\.NET',
        'Program Files\\WindowsApps',
        '\$Recycle\.Bin', 'System Volume Information',
        'AppData\\Local\\Packages',
        'AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache',
        'AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache',
        'node_modules', '\.git'
    )

    $offlineFlag = [System.IO.FileAttributes]::Offline
    $reparseFlag = [System.IO.FileAttributes]::ReparsePoint

    # Build ONE compiled regex from every target filename.
    #
    # The previous version wrapped the whole tree walk in `foreach ($filter in
    # $Filters)`, which meant ~30 target names x ~40 scan paths = ~1200 full
    # traversals of the same directories. It claimed to be a single pass and
    # was not. This walks each tree exactly once and tests each filename
    # against the combined pattern in memory, which is where the matching
    # belongs.
    $patternParts = @()
    foreach ($f in $Filters) {
        $patternParts += ('^' + [regex]::Escape($f).Replace('\*', '.*') + '$')
    }
    $combined = $patternParts -join '|'
    $nameRegex = New-Object System.Text.RegularExpressions.Regex(
        $combined,
        ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
         [System.Text.RegularExpressions.RegexOptions]::Compiled)
    )

    # ArrayList, not `$results += ...`. Array append reallocates the whole
    # array every time, which is O(n^2) and is its own source of slowness
    # once a scan starts finding hits.
    $results = New-Object System.Collections.ArrayList

    # Guard against re-walking the same tree when scan paths overlap
    # (e.g. C:\ProgramData listed alongside a nested path under it).
    $visited = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($basePath in $Paths) {
        if (-not (Test-Path $basePath)) { continue }

        # C:\ root  -  top level only, never recurse
        # All subdirectories worth scanning are listed explicitly in $ScanPaths
        $effectiveDepth = if ($basePath -match '^[A-Za-z]:\\?$') { 0 } else { $MaxDepth }

        try {
            if ($NoDepthLimit) {
                Get-ChildItem $basePath -Recurse -ErrorAction SilentlyContinue -Force -File |
                    Where-Object {
                        (-not ($_.Attributes -band $offlineFlag)) -and
                        $nameRegex.IsMatch($_.Name)
                    } |
                    ForEach-Object {
                        [void]$results.Add(($_ | Select-Object FullName, Name, Extension, LastWriteTime, Length))
                    }
            } else {
                # Manual depth-limited walk  -  PS 3/4 compatible
                $queue = New-Object System.Collections.Queue
                [void]$queue.Enqueue([PSCustomObject]@{ Path = $basePath; Depth = 0 })

                while ($queue.Count -gt 0) {
                    $item = $queue.Dequeue()

                    if (-not $visited.Add($item.Path)) { continue }

                    try {
                        # One enumeration per directory, matched in memory.
                        Get-ChildItem $item.Path -ErrorAction SilentlyContinue -Force |
                            ForEach-Object {
                                if ($_.PSIsContainer) {
                                    if ($item.Depth -lt $effectiveDepth) {
                                        $d = $_.FullName
                                        # Skip junctions/symlinks  -  prevents traversal loops
                                        if (-not ($_.Attributes -band $reparseFlag)) {
                                            $skip = $false
                                            foreach ($pat in $skipDirPatterns) {
                                                if ($d -match $pat) { $skip = $true; break }
                                            }
                                            if (-not $skip) {
                                                [void]$queue.Enqueue([PSCustomObject]@{
                                                    Path  = $d
                                                    Depth = ($item.Depth + 1)
                                                })
                                            }
                                        }
                                    }
                                } elseif ((-not ($_.Attributes -band $offlineFlag)) -and $nameRegex.IsMatch($_.Name)) {
                                    [void]$results.Add(($_ | Select-Object FullName, Name, Extension, LastWriteTime, Length))
                                }
                            }
                    } catch {}
                }
            }
        } catch {}
    }

    return @($results)
}

# Get local users  -  PS 4 / Server 2012 compatible fallback
function Get-LocalUserCompat {
    $users = @()
    if ($HasPS5) {
        try {
            $users = Get-LocalUser -ErrorAction SilentlyContinue
            if ($users) { return $users }
        } catch {}
    }
    # Fallback: ADSI / WMI for PS 4 / Server 2012
    try {
        $computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
        $computer.Children | Where-Object { $_.SchemaClassName -eq 'user' } | ForEach-Object {
            $flags       = $_.UserFlags.Value
            $lastLogon   = $null
            $description = ''
            try { $lastLogon   = [datetime]::FromFileTime($_.LastLogin[0]) } catch {}
            try { $description = $_.Description[0] }                         catch {}
            $users += [PSCustomObject]@{
                Name            = $_.Name[0]
                Enabled         = -not [bool]($flags -band 0x2)
                LastLogon       = $lastLogon
                PasswordLastSet = $null
                Description     = $description
            }
        }
    } catch {
        # Final fallback: net user output parsing
        try {
            $netOutput = net user 2>$null
            $netOutput | Select-String '^\S' | ForEach-Object {
                $_.Line.Trim() -split '\s{2,}' | Where-Object { $_ -and $_ -ne 'User accounts for' } |
                    ForEach-Object {
                        $users += [PSCustomObject]@{
                            Name = $_; Enabled = $true; LastLogon = $null
                            PasswordLastSet = $null; Description = ''
                        }
                    }
            }
        } catch {}
    }
    return $users
}

# Get TCP connections  -  compatible fallback for 2012
function Get-TCPConnectionCompat {
    if ($HasPS5 -or $PSVer -eq 4) {
        try {
            $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
            if ($conns) { return $conns }
        } catch {}
    }
    # netstat fallback
    $results = @()
    try {
        $lines = netstat -ano 2>$null | Where-Object { $_ -match 'TCP' }
        foreach ($line in $lines) {
            $parts = $line.Trim() -split '\s+'
            if ($parts.Count -ge 5) {
                $local      = $parts[1] -split ':'
                $remote     = $parts[2] -split ':'
                $localPort  = 0
                $remotePort = 0
                $owningPid  = 0
                try { $localPort  = [int]$local[-1]  } catch {}
                try { $remotePort = [int]$remote[-1] } catch {}
                try { $owningPid  = [int]$parts[4]   } catch {}
                $results += [PSCustomObject]@{
                    LocalAddress  = $local[0]
                    LocalPort     = $localPort
                    RemoteAddress = $remote[0]
                    RemotePort    = $remotePort
                    State         = $parts[3]
                    OwningProcess = $owningPid
                }
            }
        }
    } catch {}
    return $results
}

# Read a PS history file for every readable profile.
# Returns matched lines tagged with the owning user.
function Search-PSHistory {
    param([string]$Pattern)
    $hits = @()
    foreach ($prof in $UserProfiles) {
        $histFile = Join-Path $prof.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path $histFile) {
            try {
                $lines = Get-Content $histFile -ErrorAction Stop
                if ($lines) {
                    $lines | Where-Object { $_ -match $Pattern } | ForEach-Object {
                        $hits += "$($prof.Name): $_"
                    }
                }
            } catch {}
        }
    }
    return $hits
}

# Resolve a service image path from a 7045 event into a real file path.
# 7045 gives you whatever the installer wrote, which can be:
#   system32\DRIVERS\foo.sys        (relative to %SystemRoot%)
#   \??\C:\Program Files\x\y.exe    (NT object path)
#   \SystemRoot\System32\z.sys      (SystemRoot alias)
#   "C:\path\svc.exe" -k netsvcs    (quoted, with arguments)
function Resolve-ServiceImagePath {
    param([string]$RawPath)

    if ([string]::IsNullOrWhiteSpace($RawPath)) { return $null }
    $p = $RawPath.Trim()

    # Quoted path  -  take what's inside the quotes and drop arguments
    if ($p.StartsWith('"')) {
        $close = $p.IndexOf('"', 1)
        if ($close -gt 1) { $p = $p.Substring(1, $close - 1) }
    } else {
        # Unquoted with arguments  -  cut after the executable extension
        foreach ($ext in @('.sys','.exe','.dll')) {
            $idx = $p.ToLower().IndexOf($ext)
            if ($idx -ge 0) { $p = $p.Substring(0, $idx + $ext.Length); break }
        }
    }

    # NT object path prefixes
    if ($p -match '^\\\?\?\\')      { $p = $p -replace '^\\\?\?\\', '' }
    if ($p -match '^\\SystemRoot\\'){ $p = $p -replace '^\\SystemRoot\\', ($env:SystemRoot + '\') }

    $p = [Environment]::ExpandEnvironmentVariables($p)

    # Relative to %SystemRoot%  -  e.g. "system32\DRIVERS\foo.sys"
    if ($p -notmatch '^[A-Za-z]:\\' -and $p -notmatch '^\\\\') {
        $p = Join-Path $env:SystemRoot $p.TrimStart('\')
    }

    return $p
}

# Authenticode verdict for a binary.
# Returns: Status (Valid/Invalid/Unsigned/Unresolved), Signer (cert subject), Path
$script:SigCache = @{}
function Get-BinarySignature {
    param([string]$Path)

    if (-not $Path) {
        return [PSCustomObject]@{ Status = 'Unresolved'; Signer = ''; Path = '' }
    }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }

    # Statuses are deliberately granular. Collapsing "not signed" and
    # "could not be read" into one bucket is how a blind spot gets reported
    # as a detection  -  the exact failure this tool exists to avoid.
    #
    #   Valid            signature present and trusted
    #   Unsigned         no signature  -  real finding
    #   Invalid          signature present but broken/untrusted  -  real finding
    #   Missing          path resolved, file is not there
    #   AccessDenied     file exists, ACL blocks reading it  -  NOT a finding
    #   PlatformVerified MSIX/AppX package  -  see note below
    #   Unresolved       could not build a usable path at all  -  NOT a finding
    $result = [PSCustomObject]@{ Status = 'Unresolved'; Signer = ''; Path = $Path }

    # MSIX/AppX packages under WindowsApps are signature-checked by Windows at
    # install time and the directory is ACL'd to TrustedInstaller, so an
    # Authenticode read fails even elevated. Treat as platform-verified rather
    # than pretending we checked it.
    # Caveat: sideloading with developer mode enabled can relax the install-time
    # signature requirement, so this is a reduced-confidence pass, not a proof.
    if ($Path -match '\\Program Files\\WindowsApps\\') {
        $result = [PSCustomObject]@{ Status = 'PlatformVerified'; Signer = 'MSIX/AppX package'; Path = $Path }
        $script:SigCache[$Path] = $result
        return $result
    }

    $item = $null
    $access = 'ok'
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch [System.UnauthorizedAccessException] {
        $access = 'denied'
    } catch {
        $access = 'missing'
    }

    if ($access -eq 'denied') {
        $result = [PSCustomObject]@{ Status = 'AccessDenied'; Signer = ''; Path = $Path }
    } elseif ($access -eq 'missing' -or -not $item) {
        $result = [PSCustomObject]@{ Status = 'Missing'; Signer = ''; Path = $Path }
    } else {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $signer = ''
            if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }

            switch ($sig.Status) {
                'Valid'     { $result = [PSCustomObject]@{ Status = 'Valid';    Signer = $signer; Path = $Path } }
                'NotSigned' { $result = [PSCustomObject]@{ Status = 'Unsigned'; Signer = '';      Path = $Path } }
                default     { $result = [PSCustomObject]@{ Status = 'Invalid';  Signer = $signer; Path = $Path } }
            }
        } catch [System.UnauthorizedAccessException] {
            $result = [PSCustomObject]@{ Status = 'AccessDenied'; Signer = ''; Path = $Path }
        } catch {
            $result = [PSCustomObject]@{ Status = 'Unresolved'; Signer = ''; Path = $Path }
        }
    }

    $script:SigCache[$Path] = $result
    return $result
}

# Determine disk scan paths based on mode
# Core principle: scan where attackers actually drop tools, not the whole drive.
# Attackers use predictable staging locations. Deep app/OS folder scanning
# adds hours of runtime for near-zero additional detection value.

# Targeted paths common to both workstations and servers
$coreStagingPaths = @(
    "C:\",                              # Root level only (shallow)
    "C:\Windows\Temp",
    "C:\Temp",
    "C:\Tmp",
    "C:\Tools",
    "C:\Scripts",
    "C:\Install",
    "C:\Staging",
    "C:\ProgramData",
    "C:\Users\Public"
)

# Per-user profile paths  -  built dynamically from readable profiles only
$profileScanPaths = @()
foreach ($prof in $UserProfiles) {
    $userRoot = $prof.FullName

    $profileScanPaths += @(
        "$userRoot\Desktop",
        "$userRoot\Downloads",
        "$userRoot\Documents",
        "$userRoot\AppData\Local\Temp",
        "$userRoot\AppData\Local\Programs",
        "$userRoot\AppData\Roaming",
        "$userRoot\AppData\Local\Microsoft\WindowsApps"
    )

    # OneDrive  -  personal and corporate variants
    # Attackers dropping tools in synced folders = automatic cloud exfil
    # Corporate installs often redirect Desktop/Documents into OneDrive
    $profileScanPaths += "$userRoot\OneDrive"

    # Catches "OneDrive - Acme Corp", "OneDrive - Personal" style folders
    Get-ChildItem $userRoot -Directory -Filter "OneDrive - *" -ErrorAction SilentlyContinue |
        ForEach-Object { $profileScanPaths += $_.FullName }
}

if ($FileServer -or $IsServer) {
    # Servers: same targeted paths + slightly deeper on AppData
    $ScanPaths = $coreStagingPaths + $profileScanPaths
    $ScanPaths += @("C:\Windows\System32\Tasks")
    $ScanDepth  = 4
} else {
    # Workstations: targeted paths only  -  no full C:\ crawl
    # Rationale: attackers stage in Temp/AppData/Desktop/Downloads.
    # A full C:\ scan adds 20+ minutes and catches nothing a targeted
    # scan would miss in practice.
    $ScanPaths = $coreStagingPaths + $profileScanPaths
    $ScanDepth  = 5
}

# Remove paths that don't exist to avoid wasted traversal attempts
$ScanPaths = @($ScanPaths | Where-Object { Test-Path $_ })

# =============================================================================
# HEADER
# =============================================================================
Write-Log ""
Write-Log "SecureTriage v3.2  -  Ransomware Edition"
Write-Log "Host       : $HostName"
Write-Log "OS         : $OSCaption (Build $OSBuild)"
Write-Log "PowerShell : v$PSVer ($($PSVersionTable.PSEdition))"
Write-Log "Type       : $(if ($IsDC) { 'Domain Controller' } elseif ($IsServer) { 'Server' } else { 'Workstation' })"
Write-Log "Elevated   : $(if ($IsElevated) { 'YES' } else { 'NO  -  REDUCED COVERAGE' })"
Write-Log "FileServer : $(if ($FileServer) { 'YES  -  limited scan scope' } else { 'No' })"
Write-Log "Profiles   : $($UserProfiles.Count) readable, $($InaccessibleProfiles.Count) not readable"
Write-Log "Date/Time  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Output     : $RunDir"
Write-Log ""
Write-Log "Event log access:"
Write-Log "  Security                : $(if ($SecurityLogAccess.Accessible) { 'OK' } else { 'UNAVAILABLE  -  ' + $SecurityLogAccess.Reason })"
Write-Log "  System                  : $(if ($SystemLogAccess.Accessible)   { 'OK' } else { 'UNAVAILABLE  -  ' + $SystemLogAccess.Reason })"
Write-Log "  PowerShell/Operational  : $(if ($PSLogAccess.Accessible)       { 'OK' } else { 'UNAVAILABLE  -  ' + $PSLogAccess.Reason })"
Write-Log ""
if ($IsWin2012) {
    Write-Log "  [NOTE] Server 2012 detected  -  using compatible fallbacks for some checks"
    Write-Log ""
}

# =============================================================================
# SECTION 1  -  FAILED LOGON / BRUTE FORCE
# =============================================================================
Write-Section "1. Failed Logon Attempts (Brute Force)"
if (-not $SecurityLogAccess.Accessible) {
    Add-Unavailable -Category "Auth" -Name "Brute Force  -  Failed Logon Spike" `
        -Weight 20 -Reason $SecurityLogAccess.Reason
    Write-Log "  [UNAVAIL] $($SecurityLogAccess.Reason)"
} else {
    try {
        $cutoff       = (Get-Date).AddDays(-$LookbackDays)
        $failedLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $cutoff
        } -ErrorAction SilentlyContinue

        $count   = if ($failedLogons) { @($failedLogons).Count } else { 0 }
        $isBrute = $count -ge 10

        Add-Check -Category "Auth" -Name "Brute Force  -  Failed Logon Spike" `
            -Weight 20 -HitScore 20 -Hit $isBrute -Severity HIGH `
            -Detail "$count failed logon(s) in last $LookbackDays days (threshold: 10)"

        if ($isBrute) {
            Write-Log "  [!!] $count failed logons  -  possible brute force"
            $failedLogons | ForEach-Object {
                try { $_.Properties[5].Value } catch { $null }
            } | Where-Object { $_ -and $_ -ne '-' } |
                Group-Object | Sort-Object Count -Descending | Select-Object -First 5 |
                ForEach-Object { Write-Log "       $($_.Count)x  $($_.Name)" }
        } else {
            Write-Log "  [OK] $count failed logon(s)  -  below threshold"
        }
    } catch {
        Add-Unavailable -Category "Auth" -Name "Brute Force  -  Failed Logon Spike" `
            -Weight 20 -Reason $_.Exception.Message
        Write-Log "  [UNAVAIL] Failed logon check: $_"
    }
}

# =============================================================================
# SECTION 2  -  RDP LOGONS
# =============================================================================
Write-Section "2. Remote Desktop (RDP) Logons"
if (-not $SecurityLogAccess.Accessible) {
    Add-Unavailable -Category "Auth" -Name "RDP Logons Detected" `
        -Weight 15 -Reason $SecurityLogAccess.Reason
    Write-Log "  [UNAVAIL] $($SecurityLogAccess.Reason)"
} else {
    try {
        $cutoff    = (Get-Date).AddDays(-$LookbackDays)
        $rdpLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = $cutoff
        } -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Properties[8].Value -eq 10 } catch { $false }
        }

        $rdpCount = if ($rdpLogons) { @($rdpLogons).Count } else { 0 }

        Add-Check -Category "Auth" -Name "RDP Logons Detected" `
            -Weight 15 -HitScore 10 -Hit ($rdpCount -gt 0) -Severity MEDIUM `
            -Detail "$rdpCount RDP logon(s) in last $LookbackDays days"

        if ($rdpCount -gt 0) {
            Write-Log "  [!!] $rdpCount RDP logon(s) in lookback window"
        } else {
            Write-Log "  [OK] No RDP logons detected"
        }
    } catch {
        Add-Unavailable -Category "Auth" -Name "RDP Logons Detected" `
            -Weight 15 -Reason $_.Exception.Message
        Write-Log "  [UNAVAIL] RDP logon check: $_"
    }
}

# =============================================================================
# SECTION 3  -  SUSPICIOUS PROCESSES
# =============================================================================
Write-Section "3. Suspicious Processes"
try {
    $knownMalicious = @(
        # Credential dumping tools
        'mimikatz','safetykatz','nanodump','procdump','pwdump',
        'gsecdump','wce','fgdump','lazagne','lsassy','dumpert','donpapi',

        # C2 frameworks / beacons / RATs
        # These should never appear as running processes on a managed endpoint
        'cobaltstrike','cobalt','beacon','meterpreter',
        'sliver',                           # Modern C2, growing in ransomware use
        'havoc',                            # Open source C2, used by multiple threat actors
        'bruteratel','brc4',                # Commercial C2, used by ransomware affiliates
        'mythic',                           # Open source C2 platform
        'poshc2',                           # PowerShell C2
        'empire',                           # PowerShell/Python C2
        'koadic',                           # COM-based C2
        'merlin',                           # Go-based C2
        'quasar',                           # Remote admin RAT
        'remcos',                           # Commercial RAT, heavily abused
        'njrat',                            # RAT, common in targeted attacks
        'asyncrat',                         # Open source RAT
        'darkcomet',                        # RAT
        'warzone',                          # Commercial RAT
        'xworm',                            # RAT, rising prevalence
        'netwire',                          # RAT

        # Lateral movement / remote execution frameworks
        'paexec',                           # PsExec alternative
        'wmiexec',                          # WMI-based execution
        'smbexec',                          # SMB-based execution
        'atexec',                           # AT service execution
        'crackmapexec',                     # Network pentesting / lateral movement
        'impacket',                         # Python attack framework

        # AD attack tools
        'rubeus',                           # Kerberos attack tool
        'kerbrute',                         # Kerberos brute force

        # Post-exploitation / recon frameworks
        'seatbelt',                         # Post-exploitation recon
        'winpeas',                          # Windows privilege escalation recon
        'powerview',                        # AD recon (standalone)
        'powersploit',                      # PowerShell attack framework
        'nishang',                          # PowerShell attack framework
        'ghostpack',                        # .NET attack tools collection
        'sharpsploit',                      # .NET attack framework
        'invokeobfuscation'                 # PowerShell obfuscation framework
    )

    $suspiciousNames = @(
        # Script execution LOLBins  -  legitimate but heavily abused
        # Flagged by PRESENCE when no legitimate use expected on endpoint
        'mshta',                            # HTML App host  -  rare legitimate use
        'wscript',                          # Windows Script Host
        'cscript',                          # Console Script Host
        'regsvr32',                         # DLL registration  -  proxy execution abuse
        'regasm',                           # .NET assembly registration
        'regsvcs',                          # .NET component services
        'installutil',                      # .NET install utility  -  LOLBin
        'msbuild',                          # Build tool  -  code execution LOLBin
        'hh',                               # HTML Help  -  rarely used legitimately

        # Download / transfer LOLBins
        'certutil',                         # Certificate tool  -  commonly used for downloads
        'bitsadmin',                        # BITS transfer  -  download LOLBin

        # Execution / lateral movement
        'psexec','psexesvc',                # Remote execution
        'wmic',                             # WMI command line  -  being deprecated
        'nltest',                           # Domain trust enumeration

        # Security tampering
        'vssadmin',                         # Shadow copy management
        'wbadmin',                          # Backup admin  -  used to delete backups
        'esentutl'                          # Database utility  -  used for credential access
    )

    $allProcs = Get-Process -ErrorAction SilentlyContinue
    if (-not $allProcs) { throw "Get-Process returned no results" }

    # NOTE: unelevated runs cannot read .Path for processes owned by other users,
    # so the temp-path check below is degraded (not absent) without elevation.
    $confirmedMalicious = $allProcs | Where-Object {
        $n = $_.ProcessName.ToLower()
        ($knownMalicious | Where-Object { $n -match $_ }).Count -gt 0
    }
    $suspProcs = $allProcs | Where-Object {
        $n = $_.ProcessName.ToLower()
        $suspiciousNames -contains $n
    }
    # Exclusions match the FULL PATH, not just the process name. Installers and
    # updaters routinely extract to a random Temp directory and run from there
    # under a generic binary name  -  the giveaway is the vendor string in the
    # path, e.g. ...\Temp\04z5bjsw.ccs\...\Microsoft.VisualStudio.Setup.Service\
    $tempProcExclusions = 'setup|install|update|edge|chrome|firefox|' +
                          'Microsoft\.VisualStudio|VSIXInstaller|ServiceHub|' +
                          'Microsoft\.Update|OneDriveSetup|' +
                          'squirrel|Teams\\current|' +
                          'GoogleUpdate|MozillaMaintenance'
    $tempProcs = $allProcs | Where-Object {
        $_.Path -and $_.Path -match '\\(Temp|AppData\\Local\\Temp|Users\\Public|Downloads)\\'
    } | Where-Object {
        ($_.ProcessName -notmatch $tempProcExclusions) -and ($_.Path -notmatch $tempProcExclusions)
    }

    $cmCount = if ($confirmedMalicious) { @($confirmedMalicious).Count } else { 0 }
    $spCount = if ($suspProcs)          { @($suspProcs).Count }          else { 0 }
    $tpCount = if ($tempProcs)          { @($tempProcs).Count }          else { 0 }

    Add-Check -Category "Process" -Name "Known Malicious Process Running" `
        -Weight 60 -HitScore 60 -Hit ($cmCount -gt 0) -Severity CRITICAL `
        -Detail "ESCALATE: $(($confirmedMalicious | Select-Object -ExpandProperty ProcessName -Unique) -join ', ')"

    Add-Check -Category "Process" -Name "Suspicious Process Names Running" `
        -Weight 25 -HitScore 25 -Hit ($spCount -gt 0) -Severity HIGH `
        -Detail "$(($suspProcs | Select-Object -ExpandProperty ProcessName -Unique) -join ', ')"

    if ($IsElevated) {
        Add-Check -Category "Process" -Name "Processes Running from Temp/User Paths" `
            -Weight 15 -HitScore 15 -Hit ($tpCount -gt 0) -Severity MEDIUM `
            -Detail "$(($tempProcs | Select-Object -First 3 | ForEach-Object { $_.ProcessName + ' -> ' + $_.Path }) -join '; ')"
    } else {
        Add-Unavailable -Category "Process" -Name "Processes Running from Temp/User Paths" `
            -Weight 15 -Reason "Process image paths for other users' processes require elevation"
    }

    if ($cmCount -gt 0) {
        Write-Log "  [!!!] KNOWN MALICIOUS PROCESS  -  ESCALATE IMMEDIATELY"
        $confirmedMalicious | ForEach-Object { Write-Log "        PID $($_.Id): $($_.ProcessName) | $($_.Path)" }
    } elseif ($spCount -gt 0) {
        Write-Log "  [!!] Suspicious: $(($suspProcs | Select-Object -ExpandProperty ProcessName -Unique) -join ', ')"
    } else {
        Write-Log "  [OK] No suspicious processes"
    }
    if ($tpCount -gt 0) {
        Write-Log "  [!!] Processes in writable paths:"
        $tempProcs | Select-Object -First 3 | ForEach-Object { Write-Log "       $($_.ProcessName) -> $($_.Path)" }
    }
} catch {
    Add-Unavailable -Category "Process" -Name "Known Malicious Process Running"        -Weight 60 -Reason $_.Exception.Message
    Add-Unavailable -Category "Process" -Name "Suspicious Process Names Running"       -Weight 25 -Reason $_.Exception.Message
    Add-Unavailable -Category "Process" -Name "Processes Running from Temp/User Paths" -Weight 15 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Process check: $_"
}

# =============================================================================
# SECTION 4  -  SUSPICIOUS POWERSHELL
# =============================================================================
Write-Section "4. PowerShell Activity"
if (-not $PSLogAccess.Accessible) {
    Add-Unavailable -Category "PowerShell" -Name "Suspicious PowerShell Commands in Event Log" `
        -Weight 25 -Reason $PSLogAccess.Reason
    Write-Log "  [UNAVAIL] $($PSLogAccess.Reason)"
    Write-Log "            If script block logging is not enabled, enable it:"
    Write-Log "            Computer Config > Admin Templates > Windows Components > PowerShell"
} else {
    try {
        $cutoff   = (Get-Date).AddDays(-$LookbackDays)
        $psEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-PowerShell/Operational'
            Id        = @(4103, 4104)
            StartTime = $cutoff
        } -ErrorAction SilentlyContinue

        $suspPS = if ($psEvents) {
            @($psEvents | Where-Object {
                $msg = $_.Message
                # Must match a suspicious pattern
                ($msg -match 'IEX\s|Invoke-Expression|DownloadString|DownloadFile|FromBase64String|-EncodedCommand|-enc\s+[A-Za-z0-9+/]{20}|WebClient.*Download|Start-BitsTransfer|VirtualAlloc|b2\.exe|MEGAsync|rclone\.exe|backblaze') -and
                # Exclude noise generated by the script running itself
                ($msg -notmatch 'Add-Type|Creating Scriptblock text|CommandInvocation\(Add-Type\)|SecureTriage|New-SecureTriage|Get-WinEvent|Get-ChildItem|ConvertTo-Json|Export-Csv|Out-File') -and
                # Exclude known-safe tools that legitimately use these patterns
                ($msg -notmatch 'WindowsDefender|MpCmdRun|Microsoft\.PowerShell|PSReadLine|ChocolateyInstall|winget')
            })
        } else { @() }

        Add-Check -Category "PowerShell" -Name "Suspicious PowerShell Commands in Event Log" `
            -Weight 25 -HitScore 25 -Hit ($suspPS.Count -gt 0) -Severity HIGH `
            -Detail "$($suspPS.Count) suspicious PS event(s)"

        if ($suspPS.Count -gt 0) {
            Write-Log "  [!!] $($suspPS.Count) suspicious PowerShell event(s)"
            $suspPS | Select-Object -First 3 | ForEach-Object {
                Write-Log "       $(($_.Message -split "`n" | Select-Object -First 1).Trim())"
            }
        } else {
            Write-Log "  [OK] No suspicious PS patterns in event log"
        }
    } catch {
        Add-Unavailable -Category "PowerShell" -Name "Suspicious PowerShell Commands in Event Log" `
            -Weight 25 -Reason $_.Exception.Message
        Write-Log "  [UNAVAIL] PS event log check: $_"
    }
}

# PS history file check  -  all readable user profiles
try {
    $histHits = Search-PSHistory -Pattern 'b2\.exe|MEGAsync|rclone|backblaze|vssadmin.*delete|wmic.*shadowcopy|Invoke-Expression|IEX[^P]|EncodedCommand|-enc |-e '

    Add-Check -Category "PowerShell" -Name "Exfil/Ransomware Tool Commands in PS History" `
        -Weight 40 -HitScore 40 -Hit ($histHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Commands: $(($histHits | Select-Object -First 5) -join ' | ')"

    if ($histHits.Count -gt 0) {
        Write-Log "  [!!!] Ransomware/exfil commands in PS history:"
        $histHits | Select-Object -First 5 | ForEach-Object { Write-Log "        $_" }
    } else {
        Write-Log "  [OK] No exfil commands in PS history files ($($UserProfiles.Count) profile(s) checked)"
    }

    if ($InaccessibleProfiles.Count -gt 0) {
        Add-Unavailable -Category "PowerShell" -Name "PS History  -  Unreadable Profiles" `
            -Weight 40 -Reason "$($InaccessibleProfiles.Count) profile(s) not readable: $($InaccessibleProfiles -join ', ')"
    }
} catch {
    Add-Unavailable -Category "PowerShell" -Name "Exfil/Ransomware Tool Commands in PS History" `
        -Weight 40 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] PS history check: $_"
}

# =============================================================================
# SECTION 5  -  NETWORK CONNECTIONS
# =============================================================================
Write-Section "5. Network Connections"
try {
    $suspPorts = @(4444, 1337, 31337, 8888, 9001, 9002, 1234)
    $allConns  = Get-TCPConnectionCompat
    $connCount = if ($allConns) { @($allConns).Count } else { 0 }

    if ($connCount -gt 0) {
        $suspConns = @($allConns | Where-Object {
            ($_.RemotePort -in $suspPorts -or $_.LocalPort -in $suspPorts) -and
            $_.State -match 'Established|ESTABLISHED'
        })

        # Check for exfil tool network activity by process name
        $exfilConns = @($allConns | Where-Object { $_.State -match 'Established|ESTABLISHED' } | ForEach-Object {
            try {
                $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                if ($proc -and $proc.ProcessName -match 'b2|megasync|rclone|bitsadmin') {
                    [PSCustomObject]@{ ProcName = $proc.ProcessName; Remote = "$($_.RemoteAddress):$($_.RemotePort)" }
                }
            } catch {}
        } | Where-Object { $_ })

        Add-Check -Category "Network" -Name "Connections on Known C2 Ports" `
            -Weight 20 -HitScore 20 -Hit ($suspConns.Count -gt 0) -Severity HIGH `
            -Detail "$($suspConns.Count) connection(s) on suspicious ports"

        Add-Check -Category "Network" -Name "Exfil Tool Active Network Connection" `
            -Weight 50 -HitScore 50 -Hit ($exfilConns.Count -gt 0) -Severity CRITICAL `
            -Detail "Process(es): $(($exfilConns | Select-Object -ExpandProperty ProcName -Unique) -join ', ')"

        if ($suspConns.Count -gt 0) {
            Write-Log "  [!!] Suspicious port connections:"
            $suspConns | Select-Object -First 5 | ForEach-Object {
                Write-Log "       $($_.RemoteAddress):$($_.RemotePort) (PID $($_.OwningProcess))"
            }
        } else {
            Write-Log "  [OK] No connections on known C2 ports"
        }
        if ($exfilConns.Count -gt 0) {
            Write-Log "  [!!!] Exfil tool active:"
            $exfilConns | ForEach-Object { Write-Log "        $($_.ProcName) -> $($_.Remote)" }
        }
    } else {
        Write-Log "  [UNAVAIL] Could not enumerate network connections"
        Add-Unavailable -Category "Network" -Name "Connections on Known C2 Ports" `
            -Weight 20 -Reason "Get-NetTCPConnection and netstat both returned no data"
        Add-Unavailable -Category "Network" -Name "Exfil Tool Active Network Connection" `
            -Weight 50 -Reason "Get-NetTCPConnection and netstat both returned no data"
    }
} catch {
    Add-Unavailable -Category "Network" -Name "Connections on Known C2 Ports"        -Weight 20 -Reason $_.Exception.Message
    Add-Unavailable -Category "Network" -Name "Exfil Tool Active Network Connection" -Weight 50 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Network check: $_"
}

# =============================================================================
# SECTION 6  -  LOCAL ACCOUNTS
# =============================================================================
Write-Section "6. Local User Accounts"
try {
    $cutoff     = (Get-Date).AddDays(-30)
    $localUsers = Get-LocalUserCompat

    $nonDefault = @($localUsers | Where-Object {
        $_.Name -notmatch '^(Administrator|DefaultAccount|Guest|WDAGUtilityAccount|krbtgt)$'
    })

    # Accounts named in -KnownAccounts are downgraded to INFO, never suppressed.
    # This is a caller-supplied baseline, not a built-in allow-list: hardcoding
    # specific account names into a published tool would be the same mistake as
    # allow-listing a service name, since both are attacker-controllable.
    $baselineAccts  = @($nonDefault | Where-Object { $KnownAccounts -contains $_.Name })
    $unexpectedAccts= @($nonDefault | Where-Object { $KnownAccounts -notcontains $_.Name })

    Add-Check -Category "Accounts" -Name "Non-Standard Enabled Local Accounts" `
        -Weight 15 -HitScore 10 -Hit ($unexpectedAccts.Count -gt 0) -Severity MEDIUM `
        -Detail "Account(s): $(($unexpectedAccts | Select-Object -ExpandProperty Name) -join ', ')"

    if ($baselineAccts.Count -gt 0) {
        Add-Check -Category "Accounts" -Name "Baseline Accounts Present (Declared Known)" `
            -Weight 0 -HitScore 0 -Hit $true -Severity INFO `
            -Detail "Declared via -KnownAccounts: $(($baselineAccts | Select-Object -ExpandProperty Name) -join ', ')"

    # Account creation events  -  Security log, requires elevation
    if (-not $SecurityLogAccess.Accessible) {
        Add-Unavailable -Category "Accounts" -Name "Local Accounts Created in Last 30 Days" `
            -Weight 30 -Reason $SecurityLogAccess.Reason
        Write-Log "  [UNAVAIL] Account creation events: $($SecurityLogAccess.Reason)"
    } else {
        $newAcctEvents = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4720
            StartTime = $cutoff
        } -ErrorAction SilentlyContinue)

        Add-Check -Category "Accounts" -Name "Local Accounts Created in Last 30 Days" `
            -Weight 30 -HitScore 30 -Hit ($newAcctEvents.Count -gt 0) -Severity HIGH `
            -Detail "$($newAcctEvents.Count) account creation event(s)  -  verify each is legitimate"

        if ($newAcctEvents.Count -gt 0) {
            Write-Log "  [!!] $($newAcctEvents.Count) new local account(s) in last 30 days:"
            $newAcctEvents | Select-Object -First 5 | ForEach-Object {
                try { Write-Log "       $($_.Properties[0].Value)" } catch {}
            }
        } else {
            Write-Log "  [OK] No new local accounts in last 30 days"
        }
    }

    }

    Write-Log "  Enabled non-default accounts:"
    if ($nonDefault.Count -gt 0) {
        $nonDefault | ForEach-Object {
            $tag = if ($KnownAccounts -contains $_.Name) { '  [declared baseline]' } else { '' }
            Write-Log "    $($_.Name) | LastLogon: $($_.LastLogon)$tag"
        }
    } else {
        Write-Log "    None"
    }
} catch {
    Add-Unavailable -Category "Accounts" -Name "Local Accounts Created in Last 30 Days" -Weight 30 -Reason $_.Exception.Message
    Add-Unavailable -Category "Accounts" -Name "Non-Standard Enabled Local Accounts"    -Weight 15 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Local account check: $_"
}

# =============================================================================
# SECTION 7  -  RECENTLY INSTALLED SERVICES (Event ID 7045)
# =============================================================================
Write-Section "7. Recently Installed Services (Last $ServiceDays Days)"
if (-not $SystemLogAccess.Accessible) {
    Add-Unavailable -Category "Persistence" -Name "Service Installed with Unsigned or Invalid Binary" `
        -Weight 35 -Reason $SystemLogAccess.Reason
    Add-Unavailable -Category "Persistence" -Name "Service Installed by Unrecognized Publisher" `
        -Weight 15 -Reason $SystemLogAccess.Reason
    Add-Unavailable -Category "Persistence" -Name "Service Binary No Longer on Disk" `
        -Weight 15 -Reason $SystemLogAccess.Reason
    Write-Log "  [UNAVAIL] $($SystemLogAccess.Reason)"
} else {
    try {
        $cutoff    = (Get-Date).AddDays(-$ServiceDays)
        $svcEvents = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 7045
            StartTime = $cutoff
        } -ErrorAction SilentlyContinue)

        # Trusted signing publishers, matched against the Authenticode certificate
        # SUBJECT  -  not the service name and not the file path.
        #
        # Service names are attacker-controlled. A real Bitdefender driver is
        # named "rtp1" and a malicious one can be too. The certificate is the
        # part that is expensive to forge, so that is what gets checked.
        $trustedPublishers = 'Microsoft Corporation|Microsoft Windows|' +
                             'Bitdefender|Avira|CrowdStrike|SentinelOne|Sophos|' +
                             'Symantec|Broadcom|McAfee|Musarubra|Trellix|' +
                             'ESET|Avast|AVG|Gen Digital|NortonLifeLock|' +
                             'Malwarebytes|Webroot|Carbon Black|Cylance|BlackBerry|' +
                             'Trend Micro|VIPRE|Kaspersky|F-Secure|WithSecure|' +
                             'Huntress|ThreatLocker|Automox|Arctic Wolf|Blackpoint|' +
                             'Datto|Kaseya|ConnectWise|NinjaOne|NinjaRMM|Atera|Addigy|' +
                             'VMware|Broadcom|Oracle|Citrix|Parallels|' +
                             'Intel |Advanced Micro Devices|NVIDIA|Realtek|' +
                             'Dell |Hewlett|HP Inc|Lenovo|' +
                             'Google LLC|Mozilla|Adobe|Cisco|Zoom Video|Dropbox|Box, Inc'

        $unsignedSvc     = @()   # unsigned or broken signature  -  HIGH
        $unknownPubSvc   = @()   # validly signed, publisher not recognized  -  MEDIUM
        $missingSvc      = @()   # binary no longer on disk  -  MEDIUM
        $unverifiableSvc = @()   # could not read the binary  -  UNAVAILABLE, not a finding
        $platformSvc     = @()   # MSIX/AppX  -  informational

        foreach ($evt in $svcEvents) {
            $svcName = ''
            $svcRaw  = ''
            try { $svcName = $evt.Properties[0].Value } catch {}
            try { $svcRaw  = $evt.Properties[1].Value } catch {}

            $resolved = Resolve-ServiceImagePath -RawPath $svcRaw
            $sig      = Get-BinarySignature -Path $resolved

            $record = [PSCustomObject]@{
                Name    = $svcName
                RawPath = $svcRaw
                Path    = $resolved
                Status  = $sig.Status
                Signer  = $sig.Signer
                Time    = $evt.TimeCreated
            }

            switch ($sig.Status) {
                'Valid' {
                    if ($sig.Signer -notmatch $trustedPublishers) { $unknownPubSvc += $record }
                }
                'Unsigned'         { $unsignedSvc     += $record }
                'Invalid'          { $unsignedSvc     += $record }
                'Missing'          { $missingSvc      += $record }
                'AccessDenied'     { $unverifiableSvc += $record }
                'Unresolved'       { $unverifiableSvc += $record }
                'PlatformVerified' { $platformSvc     += $record }
                default            { $unverifiableSvc += $record }
            }
        }

        # Collapse repeats  -  an app that updates weekly emits one 7045 per
        # version, and fourteen lines for one service name is noise, not signal.
        function Format-SvcGroup {
            param($Records, [int]$Max = 4)
            $groups = $Records | Group-Object Name
            $parts  = @($groups | Select-Object -First $Max | ForEach-Object {
                if ($_.Count -gt 1) { "$($_.Name) x$($_.Count) [$($_.Group[0].Status)]" }
                else                { "$($_.Name) [$($_.Group[0].Status)] $($_.Group[0].Path)" }
            })
            if ($groups.Count -gt $Max) { $parts += "(+$($groups.Count - $Max) more)" }
            return ($parts -join '; ')
        }

        Add-Check -Category "Persistence" -Name "Service Installed with Unsigned or Invalid Binary" `
            -Weight 35 -HitScore 35 -Hit ($unsignedSvc.Count -gt 0) -Severity HIGH `
            -Detail "$($unsignedSvc.Count) event(s): $(Format-SvcGroup -Records $unsignedSvc)"

        Add-Check -Category "Persistence" -Name "Service Installed by Unrecognized Publisher" `
            -Weight 15 -HitScore 12 -Hit ($unknownPubSvc.Count -gt 0) -Severity MEDIUM `
            -Detail "$($unknownPubSvc.Count) event(s): $(Format-SvcGroup -Records $unknownPubSvc)"

        # Binary gone is genuinely ambiguous: install-then-delete is a real
        # persistence pattern, and a superseded app version looks identical
        # from the event log. MEDIUM, for a human to disambiguate.
        Add-Check -Category "Persistence" -Name "Service Binary No Longer on Disk" `
            -Weight 15 -HitScore 12 -Hit ($missingSvc.Count -gt 0) -Severity MEDIUM `
            -Detail "$($missingSvc.Count) event(s): $(Format-SvcGroup -Records $missingSvc)  -  superseded app version or install-then-delete"

        if ($unverifiableSvc.Count -gt 0) {
            Add-Unavailable -Category "Persistence" -Name "Service Binary Signature Not Verifiable" `
                -Weight 20 -Reason "$($unverifiableSvc.Count) event(s) whose binary could not be read: $(Format-SvcGroup -Records $unverifiableSvc)"
        }

        if ($unsignedSvc.Count -gt 0) {
            Write-Log "  [!!] $($unsignedSvc.Count) service event(s) with unsigned/invalid binaries:"
            $unsignedSvc | Group-Object Name | ForEach-Object {
                Write-Log "       Name  : $($_.Name)$(if ($_.Count -gt 1) { "  (x$($_.Count) install events)" })"
                Write-Log "       Path  : $($_.Group[0].Path)"
                Write-Log "       Sig   : $($_.Group[0].Status)"
                Write-Log "       Latest: $(($_.Group | Sort-Object Time -Descending | Select-Object -First 1).Time)"
            }
        }
        if ($unknownPubSvc.Count -gt 0) {
            Write-Log "  [!] $($unknownPubSvc.Count) signed service event(s) from unrecognized publisher:"
            $unknownPubSvc | Group-Object Name | ForEach-Object {
                Write-Log "       Name  : $($_.Name)$(if ($_.Count -gt 1) { "  (x$($_.Count))" })"
                Write-Log "       Signer: $($_.Group[0].Signer)"
            }
        }
        if ($missingSvc.Count -gt 0) {
            Write-Log "  [!] $($missingSvc.Count) service event(s) whose binary is no longer on disk:"
            $missingSvc | Group-Object Name | ForEach-Object {
                Write-Log "       Name  : $($_.Name)$(if ($_.Count -gt 1) { "  (x$($_.Count) install events  -  likely app updates)" })"
                Write-Log "       Path  : $($_.Group[0].Path)"
            }
        }
        if ($unverifiableSvc.Count -gt 0) {
            Write-Log "  [UNAVAIL] $($unverifiableSvc.Count) service event(s) could not be signature-checked:"
            $unverifiableSvc | Group-Object Name | ForEach-Object {
                Write-Log "            $($_.Name)$(if ($_.Count -gt 1) { " (x$($_.Count))" })  [$($_.Group[0].Status)]"
            }
        }
        if ($platformSvc.Count -gt 0) {
            Write-Log "  [INFO] $($platformSvc.Count) MSIX/AppX service event(s)  -  signature enforced by Windows at install:"
            $platformSvc | Group-Object Name | ForEach-Object {
                Write-Log "         $($_.Name)$(if ($_.Count -gt 1) { " (x$($_.Count) version updates)" })"
            }
        }
        if ($unsignedSvc.Count -eq 0 -and $unknownPubSvc.Count -eq 0 -and $missingSvc.Count -eq 0) {
            Write-Log "  [OK] $($svcEvents.Count) service install event(s) in last $ServiceDays days, none requiring review"
        }
    } catch {
        Add-Unavailable -Category "Persistence" -Name "Service Installed with Unsigned or Invalid Binary" `
            -Weight 35 -Reason $_.Exception.Message
        Add-Unavailable -Category "Persistence" -Name "Service Installed by Unrecognized Publisher" `
            -Weight 15 -Reason $_.Exception.Message
        Add-Unavailable -Category "Persistence" -Name "Service Binary No Longer on Disk" `
            -Weight 15 -Reason $_.Exception.Message
        Write-Log "  [UNAVAIL] Service event check: $_"
    }
}

# =============================================================================
# SECTION 8  -  SCHEDULED TASKS (Suspicious Actions)
# =============================================================================
Write-Section "8. Scheduled Tasks  -  Suspicious Actions"
try {
    $recentTasks = @()

    # Known-safe task patterns  -  legitimate software that runs from AppData/user paths
    # Intentionally excludes: Discord, Steam, Spotify (not expected on corporate devices)
    $taskSafeList = 'Zoom\\bin\\Zoom\.exe|' +
                    'PowerToys\.exe|' +
                    'hpatchmon|' +
                    'dsregcmd\.exe|' +
                    'OneDrive\.exe|' +
                    'Teams\.exe|MicrosoftTeams|' +
                    'Slack\.exe|' +
                    'GoogleUpdate|GoogleDriveFS|' +
                    'MozillaUpdate|firefox\.exe|' +
                    'chrome\.exe|msedge\.exe|' +
                    'AdobeARM|Acrobat|' +
                    'SumatraPDF|' +
                    '\\\\WindowsApps\\\\'

    $taskEnumOk = $false

    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        if ($allTasks) {
            $taskEnumOk  = $true
            $recentTasks = @($allTasks | Where-Object {
                $actionStr = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
                # Must match suspicious pattern AND not match the safe list
                ($actionStr -match '\\Temp\\|\\AppData\\|\\Users\\Public\\|powershell.*-e[nc]|cmd.*/c|wscript|mshta|b2\.exe|megasync|rclone|backblaze|-EncodedCommand') -and
                ($actionStr -notmatch $taskSafeList)
            } | ForEach-Object {
                $actionStr = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
                [PSCustomObject]@{ Name = $_.TaskName; Path = $_.TaskPath; Actions = $actionStr }
            })
        }
    }

    if (-not $taskEnumOk) {
        # Fallback: parse schtasks /query output  -  works on all versions
        $schtasksOut = schtasks /query /fo CSV /v 2>$null
        if ($schtasksOut) {
            $taskEnumOk = $true
            $schtasksOut | ConvertFrom-Csv -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.'Task To Run' -match '\\Temp\\|\\AppData\\|cmd.*/c|wscript|mshta|powershell.*-e' -and
                    $_.'Task To Run' -notmatch $taskSafeList
                } |
                ForEach-Object {
                    $recentTasks += [PSCustomObject]@{
                        Name    = $_.TaskName
                        Path    = ''
                        Actions = $_.'Task To Run'
                    }
                }
        }
    }

    if ($taskEnumOk) {
        Add-Check -Category "Persistence" -Name "Scheduled Tasks with Suspicious Actions" `
            -Weight 35 -HitScore 35 -Hit ($recentTasks.Count -gt 0) -Severity HIGH `
            -Detail "$($recentTasks.Count) task(s) with suspicious execution paths"

        if ($recentTasks.Count -gt 0) {
            Write-Log "  [!!] Suspicious scheduled task(s):"
            $recentTasks | ForEach-Object {
                Write-Log "       Task: $($_.Name)"
                Write-Log "       Action: $($_.Actions)"
            }
        } else {
            Write-Log "  [OK] No scheduled tasks with suspicious actions"
        }
    } else {
        Add-Unavailable -Category "Persistence" -Name "Scheduled Tasks with Suspicious Actions" `
            -Weight 35 -Reason "Neither Get-ScheduledTask nor schtasks.exe returned task data"
        Write-Log "  [UNAVAIL] Could not enumerate scheduled tasks"
    }
} catch {
    Add-Unavailable -Category "Persistence" -Name "Scheduled Tasks with Suspicious Actions" `
        -Weight 35 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Scheduled task check: $_"
}

# =============================================================================
# SECTION 9  -  REGISTRY RUN KEYS
# Loads each user's NTUSER.DAT so run keys are checked for EVERY profile,
# not just whoever happens to be running the script.
# =============================================================================
Write-Section "9. Registry Run Key Persistence"

$loadedHives = @()   # tracked so we always unload in the finally block

try {
    $runValuePattern = '\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\|b2\.exe|megasync|rclone|powershell.*-e[nc]|wscript|mshta|-EncodedCommand'

    $suspRunEntries   = @()
    $hiveErrors       = @()
    $userHivesChecked = 0

    # --- Machine-wide run keys ---
    $machineKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($key in $machineKeys) {
        if (-not (Test-Path $key)) { continue }
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                Where-Object { $_.Value -match $runValuePattern } |
                ForEach-Object { $suspRunEntries += "$key -> $($_.Name) = $($_.Value)" }
        }
    }

    # --- Per-user run keys ---
    # Map profile SIDs to paths. Loaded hives appear under HKEY_USERS already
    # (user is logged in). Unloaded hives are mounted temporarily.
    #
    # SID prefixes that matter here:
    #   S-1-5-21-*   local accounts and on-prem Active Directory accounts
    #   S-1-12-1-*   Microsoft Entra ID (Azure AD) accounts
    #
    # Filtering on S-1-5-21 alone skips the primary user on every Entra-joined
    # endpoint, which on a modern M365 fleet is most of them.
    $profileList = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-|^S-1-12-1-' })

    # Track which on-disk profiles the registry-driven loop actually covers.
    # The loop iterates ProfileList, not C:\Users  -  a profile folder with no
    # ProfileList entry is never visited at all, and without this reconciliation
    # it disappears from the run with no error and no coverage penalty.
    $coveredProfilePaths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($profileKey in $profileList) {
        $sid       = $profileKey.PSChildName
        $imagePath = $null
        try { $imagePath = (Get-ItemProperty $profileKey.PSPath -ErrorAction Stop).ProfileImagePath } catch {}

        # Every branch below MUST either read a hive or record why it could not.
        # A silent `continue` here is what let a 2-profile host report 100%
        # coverage while only checking 1 hive.
        if (-not $imagePath) {
            $hiveErrors += "SID $sid : ProfileImagePath missing or unreadable"
            continue
        }

        $profLabel = Split-Path $imagePath -Leaf
        $hiveRoot  = $null
        [void]$coveredProfilePaths.Add($imagePath)

        if (Test-Path "Registry::HKEY_USERS\$sid") {
            # Already loaded  -  user is logged on
            $hiveRoot = "Registry::HKEY_USERS\$sid"
        } elseif (-not $IsElevated) {
            $hiveErrors += "$profLabel : requires elevation to load NTUSER.DAT"
        } else {
            $ntuser = Join-Path $imagePath 'NTUSER.DAT'
            if (-not (Test-Path $ntuser)) {
                $hiveErrors += "$profLabel : NTUSER.DAT not found at $ntuser"
            } else {
                $mountPoint = "ST_$($sid -replace '[^0-9A-Za-z]','_')"
                $regOut = reg load "HKU\$mountPoint" "$ntuser" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $hiveRoot     = "Registry::HKEY_USERS\$mountPoint"
                    $loadedHives += $mountPoint
                } else {
                    $hiveErrors += "$profLabel : reg load failed  -  $regOut"
                }
            }
        }

        if ($hiveRoot) {
            $userHivesChecked++
            foreach ($sub in @('Software\Microsoft\Windows\CurrentVersion\Run',
                               'Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
                $fullKey = Join-Path $hiveRoot $sub
                if (-not (Test-Path $fullKey)) { continue }
                $props = Get-ItemProperty -Path $fullKey -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties |
                        Where-Object { $_.Name -notmatch '^PS' } |
                        Where-Object { $_.Value -match $runValuePattern } |
                        ForEach-Object {
                            $suspRunEntries += "[$(Split-Path $imagePath -Leaf)] $sub -> $($_.Name) = $($_.Value)"
                        }
                }
            }
        }
    }

    # Reconcile on-disk profiles against ProfileList. A C:\Users folder with no
    # registry entry is an orphaned or hand-made profile directory  -  its Run
    # keys were never examined, and that has to show up as reduced coverage
    # rather than vanishing silently.
    foreach ($prof in $UserProfiles) {
        if (-not $coveredProfilePaths.Contains($prof.FullName)) {
            $hiveErrors += "$($prof.Name) : no matching ProfileList entry with a recognized SID  -  Run keys not checked (orphaned folder, or an account type this filter does not cover)"
        }
    }

    Add-Check -Category "Persistence" -Name "Suspicious Registry Run Entries" `
        -Weight 30 -HitScore 30 -Hit ($suspRunEntries.Count -gt 0) -Severity HIGH `
        -Detail "$($suspRunEntries.Count) suspicious entry(ies): $(($suspRunEntries | Select-Object -First 3) -join ' | ')"

    if ($hiveErrors.Count -gt 0) {
        Add-Unavailable -Category "Persistence" -Name "Run Keys  -  Unreadable User Hives" `
            -Weight 30 -Reason "$($hiveErrors.Count) profile hive(s) not checked: $(($hiveErrors | Select-Object -First 3) -join ' | ')"
    }

    Write-Log "  User hives checked: $userHivesChecked of $($UserProfiles.Count) on-disk profile(s)"
    if ($suspRunEntries.Count -gt 0) {
        Write-Log "  [!!] Suspicious run key entries:"
        $suspRunEntries | ForEach-Object { Write-Log "       $_" }
    } else {
        Write-Log "  [OK] No suspicious registry run key entries"
    }
    if ($hiveErrors.Count -gt 0) {
        Write-Log "  [UNAVAIL] $($hiveErrors.Count) profile hive(s) could not be read:"
        $hiveErrors | ForEach-Object { Write-Log "            $_" }
    }
} catch {
    Add-Unavailable -Category "Persistence" -Name "Suspicious Registry Run Entries" `
        -Weight 30 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Registry check: $_"
} finally {
    # Always unload. PowerShell holds registry handles, so collect first
    # or the unload fails and the hive stays mounted after the script exits.
    if ($loadedHives.Count -gt 0) {
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        foreach ($mount in $loadedHives) {
            $unloadOut = reg unload "HKU\$mount" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Log "  [WARN] Could not unload hive HKU\$mount  -  $unloadOut"
                Write-Log "         Unload manually: reg unload HKU\$mount"
            }
        }
    }
}

# =============================================================================
# SECTION 10  -  RDP CONFIGURATION
# =============================================================================
Write-Section "10. RDP Configuration"
try {
    $tsKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

    $rdpEnabled = $false
    $nlaEnabled = $false
    $rdpPort    = 3389

    if (Test-Path $tsKey) {
        $tsProp     = Get-ItemProperty $tsKey -ErrorAction SilentlyContinue
        $rdpEnabled = ($tsProp.fDenyTSConnections -eq 0)
    }
    if (Test-Path $rdpKey) {
        $rdpProp    = Get-ItemProperty $rdpKey -ErrorAction SilentlyContinue
        $nlaEnabled = ($rdpProp.UserAuthentication -eq 1)
        if ($rdpProp.PortNumber) { $rdpPort = $rdpProp.PortNumber }
    }

    Add-Check -Category "Exposure" -Name "RDP Enabled" `
        -Weight 20 -HitScore 15 -Hit $rdpEnabled -Severity MEDIUM `
        -Detail "Port: $rdpPort | NLA enforced: $nlaEnabled"

    Add-Check -Category "Exposure" -Name "RDP Enabled Without NLA" `
        -Weight 20 -HitScore 20 -Hit ($rdpEnabled -and -not $nlaEnabled) -Severity HIGH `
        -Detail "RDP on but NLA not enforced  -  credential exposure risk"

    if ($rdpEnabled) {
        Write-Log "  [!!] RDP enabled | Port: $rdpPort | NLA: $nlaEnabled"
    } else {
        Write-Log "  [OK] RDP disabled"
    }
} catch {
    Add-Unavailable -Category "Exposure" -Name "RDP Enabled"             -Weight 20 -Reason $_.Exception.Message
    Add-Unavailable -Category "Exposure" -Name "RDP Enabled Without NLA" -Weight 20 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] RDP check: $_"
}

# =============================================================================
# SECTION 11  -  [RANSOMWARE] EXFIL TOOL DETECTION
# Single disk pass  -  all tool names collected in one traversal
# =============================================================================
Write-Section "11. [RANSOMWARE] Exfiltration Tool Detection"

# All target filenames in one list  -  disk is walked once, results filtered per tool
$allTargetFiles = @(
    # Confirmed ransomware exfil tools
    'b2.exe',
    'MEGAsync.exe','MEGAsyncSetup64.exe','MEGAsyncSetup.exe',
    'rclone.exe',
    # File transfer tools  -  legit but abused for exfil
    'WinSCP.exe','WinSCP.com',
    'pscp.exe','psftp.exe',           # PuTTY SCP/SFTP components
    'filezilla.exe',
    # Curl/wget dropped manually  -  suspicious on Windows (built-in curl is system32\curl.exe)
    'wget.exe',
    # RMM tools checked for path anomalies
    'AnyDesk.exe',
    'SimpleHelp*',
    'ScreenConnect.Client.exe','ScreenConnect.WindowsClient.exe',
    # Network recon
    'netscan.exe','nmap.exe','masscan.exe',
    'angry_ip_scanner.exe','NetworkScanner.exe','SoftPerfect*',
    # Credential theft tools
    'lazagne.exe',
    'procdump.exe','procdump64.exe',
    'wce.exe','fgdump.exe','pwdump*.exe',
    'mimikatz.exe','mimi*.exe',
    # AD recon
    'SharpHound.exe',
    'ADRecon.ps1',
    # Dropped curl  -  attackers drop their own copy in staging paths
    'curl.exe'
)

Write-Log "  Running single disk pass for all tool signatures..."
Write-Log "  (one pass replaces separate per-tool scans)"
$diskScanOk    = $false
$allFoundFiles = @()
try {
    $diskScanStart = Get-Date
    $allFoundFiles = Get-FileSafe -Paths $ScanPaths -Filters $allTargetFiles -MaxDepth $ScanDepth
    $diskScanSecs  = [int]((Get-Date) - $diskScanStart).TotalSeconds
    $diskScanOk    = $true
    Write-Log "  Disk scan complete in $diskScanSecs second(s)  -  $(@($allFoundFiles).Count) target file(s) found"
    Write-Log "  Paths scanned: $($ScanPaths.Count) | Max depth: $ScanDepth"
} catch {
    Write-Log "  [UNAVAIL] Disk scan failed: $_"
}

# Helper  -  every disk-based check below depends on the single pass above.
# If that pass failed, none of them are valid, so they all go to UNAVAILABLE.
function Add-DiskCheck {
    param(
        [string]$Category,[string]$Name,[int]$Weight,[int]$HitScore,
        [bool]$Hit,[string]$Severity,[string]$Detail
    )
    if ($script:diskScanOk) {
        Add-Check -Category $Category -Name $Name -Weight $Weight -HitScore $HitScore `
            -Hit $Hit -Severity $Severity -Detail $Detail
    } else {
        Add-Unavailable -Category $Category -Name $Name -Weight $Weight `
            -Reason "Disk scan did not complete"
    }
}

# --- b2.exe ---
try {
    $b2Hits = @($allFoundFiles | Where-Object { $_.Name -eq 'b2.exe' })

    Add-DiskCheck -Category "Ransomware" -Name "b2.exe (Backblaze Exfil Tool) on Disk" `
        -Weight 75 -HitScore 75 -Hit ($b2Hits.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($b2Hits | Select-Object -ExpandProperty FullName) -join '; ')"

    if ($b2Hits.Count -gt 0) {
        Write-Log "  [!!!] b2.exe FOUND  -  confirmed INC Ransom exfil tool"
        $b2Hits | ForEach-Object { Write-Log "        $($_.FullName) | Modified: $($_.LastWriteTime)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] b2.exe not found"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "b2.exe (Backblaze Exfil Tool) on Disk" -Weight 75 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] b2.exe check: $_"
}

# --- Backblaze B2 config file  -  targeted user profile check, not a disk scan ---
try {
    $b2ConfigPaths = @()
    foreach ($prof in $UserProfiles) {
        $p = Join-Path $prof.FullName '.b2'
        if (Test-Path $p) {
            $b2ConfigPaths += Get-ChildItem $p -ErrorAction SilentlyContinue |
                Select-Object FullName, LastWriteTime
        }
    }

    Add-Check -Category "Ransomware" -Name "Backblaze B2 Config File Found (Credentials)" `
        -Weight 80 -HitScore 80 -Hit ($b2ConfigPaths.Count -gt 0) -Severity CRITICAL `
        -Detail "$(($b2ConfigPaths | Select-Object -ExpandProperty FullName) -join '; ')  -  contains account ID + bucket name"

    if ($b2ConfigPaths.Count -gt 0) {
        Write-Log "  [!!!] B2 config file(s) found  -  COPY THESE FOR IR INVESTIGATION"
        $b2ConfigPaths | ForEach-Object { Write-Log "        $($_.FullName)" }
    } else {
        Write-Log "  [OK] No B2 config files found"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "Backblaze B2 Config File Found (Credentials)" -Weight 80 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] B2 config check: $_"
}

# --- MEGAsync ---
try {
    $megaHits = @($allFoundFiles | Where-Object { $_.Name -match '^MEGAsync(Setup64|Setup)?\.exe$' })

    Add-DiskCheck -Category "Ransomware" -Name "MEGAsync (Cloud Exfil Tool) on Disk" `
        -Weight 70 -HitScore 70 -Hit ($megaHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($megaHits | Select-Object -ExpandProperty FullName) -join '; ')"

    if ($megaHits.Count -gt 0) {
        Write-Log "  [!!!] MEGAsync found  -  known INC Ransom exfil tool"
        $megaHits | ForEach-Object { Write-Log "        $($_.FullName)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] MEGAsync not found"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "MEGAsync (Cloud Exfil Tool) on Disk" -Weight 70 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] MEGAsync check: $_"
}

# --- rclone ---
try {
    $rcloneHits = @($allFoundFiles | Where-Object { $_.Name -eq 'rclone.exe' })

    # Config file  -  targeted path check only
    $rcloneConfigs = @()
    foreach ($prof in $UserProfiles) {
        $rcp = Join-Path $prof.FullName 'AppData\Roaming\rclone'
        if (Test-Path $rcp) {
            $rcloneConfigs += Get-ChildItem $rcp -ErrorAction SilentlyContinue |
                Select-Object FullName, LastWriteTime
        }
    }

    Add-DiskCheck -Category "Ransomware" -Name "rclone Exfil Tool on Disk" `
        -Weight 70 -HitScore 70 -Hit ($rcloneHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($rcloneHits | Select-Object -ExpandProperty FullName) -join '; ')"

    Add-Check -Category "Ransomware" -Name "rclone Config File Found" `
        -Weight 75 -HitScore 75 -Hit ($rcloneConfigs.Count -gt 0) -Severity CRITICAL `
        -Detail "Config(s): $(($rcloneConfigs | Select-Object -ExpandProperty FullName) -join '; ')"

    if ($rcloneHits.Count -gt 0) {
        Write-Log "  [!!!] rclone found: $(($rcloneHits | Select-Object -ExpandProperty FullName) -join '; ')"
    } elseif ($diskScanOk) {
        Write-Log "  [OK] rclone not found"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "rclone Exfil Tool on Disk" -Weight 70 -Reason $_.Exception.Message
    Add-Unavailable -Category "Ransomware" -Name "rclone Config File Found"  -Weight 75 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] rclone check: $_"
}

# --- WinSCP  -  path-aware severity ---
try {
    $winscpAll = @($allFoundFiles | Where-Object { $_.Name -match '^WinSCP\.(exe|com)$' })
    $winscpBad = @($winscpAll | Where-Object { $_.FullName -notmatch 'Program Files|AppData\\Local\\Programs' })

    Add-DiskCheck -Category "Ransomware" -Name "WinSCP in Non-Standard Path (Exfil Risk)" `
        -Weight 55 -HitScore 55 -Hit ($winscpBad.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($winscpBad | Select-Object -ExpandProperty FullName) -join '; ')"

    Add-DiskCheck -Category "Tooling" -Name "WinSCP Present (Standard Path  -  Verify Authorized)" `
        -Weight 10 -HitScore 8 -Hit ($winscpAll.Count -gt 0 -and $winscpBad.Count -eq 0) -Severity MEDIUM `
        -Detail "Path(s): $(($winscpAll | Select-Object -ExpandProperty FullName) -join '; ')  -  confirm use is authorized"

    if ($winscpBad.Count -gt 0) {
        Write-Log "  [!!!] WinSCP in unexpected path  -  likely exfil staging"
        $winscpBad | ForEach-Object { Write-Log "        $($_.FullName)" }
    } elseif ($winscpAll.Count -gt 0) {
        Write-Log "  [!!] WinSCP found in standard path  -  verify authorized"
        $winscpAll | ForEach-Object { Write-Log "       $($_.FullName)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] WinSCP not found"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "WinSCP in Non-Standard Path (Exfil Risk)"            -Weight 55 -Reason $_.Exception.Message
    Add-Unavailable -Category "Tooling"    -Name "WinSCP Present (Standard Path  -  Verify Authorized)" -Weight 10 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] WinSCP check: $_"
}

# --- PuTTY components (pscp/psftp)  -  path-aware severity ---
try {
    $puttyAll = @($allFoundFiles | Where-Object { $_.Name -match '^(pscp|psftp)\.exe$' })
    $puttyBad = @($puttyAll | Where-Object { $_.FullName -notmatch 'Program Files|AppData\\Local\\Programs|PuTTY' })

    Add-DiskCheck -Category "Ransomware" -Name "PuTTY SCP/SFTP in Non-Standard Path (Exfil Risk)" `
        -Weight 55 -HitScore 55 -Hit ($puttyBad.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($puttyBad | Select-Object -ExpandProperty FullName) -join '; ')"

    Add-DiskCheck -Category "Tooling" -Name "PuTTY SCP/SFTP Present (Standard Path  -  Verify Authorized)" `
        -Weight 10 -HitScore 8 -Hit ($puttyAll.Count -gt 0 -and $puttyBad.Count -eq 0) -Severity MEDIUM `
        -Detail "Path(s): $(($puttyAll | Select-Object -ExpandProperty FullName) -join '; ')  -  confirm use is authorized"

    if ($puttyBad.Count -gt 0) {
        Write-Log "  [!!!] PuTTY SCP/SFTP in unexpected path  -  exfil risk"
        $puttyBad | ForEach-Object { Write-Log "        $($_.FullName)" }
    } elseif ($puttyAll.Count -gt 0) {
        Write-Log "  [!!] PuTTY SCP/SFTP in standard path  -  verify authorized"
        $puttyAll | ForEach-Object { Write-Log "       $($_.FullName)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] PuTTY SCP/SFTP not found"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "PuTTY SCP/SFTP in Non-Standard Path (Exfil Risk)"            -Weight 55 -Reason $_.Exception.Message
    Add-Unavailable -Category "Tooling"    -Name "PuTTY SCP/SFTP Present (Standard Path  -  Verify Authorized)" -Weight 10 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] PuTTY check: $_"
}

# --- FileZilla in non-standard path ---
try {
    $filezillaAll = @($allFoundFiles | Where-Object { $_.Name -match '^filezilla\.exe$' })
    $filezillaBad = @($filezillaAll | Where-Object { $_.FullName -notmatch 'Program Files|AppData\\Local\\Programs|FileZilla' })

    Add-DiskCheck -Category "Ransomware" -Name "FileZilla in Non-Standard Path (Exfil Risk)" `
        -Weight 50 -HitScore 50 -Hit ($filezillaBad.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($filezillaBad | Select-Object -ExpandProperty FullName) -join '; ')"

    if ($filezillaBad.Count -gt 0) {
        Write-Log "  [!!!] FileZilla in unexpected path  -  exfil risk"
        $filezillaBad | ForEach-Object { Write-Log "        $($_.FullName)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] FileZilla not found in non-standard paths"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "FileZilla in Non-Standard Path (Exfil Risk)" -Weight 50 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] FileZilla check: $_"
}

# --- Angry IP Scanner  -  always flag, no legitimate standard path ---
try {
    $angryipHits = @($allFoundFiles | Where-Object { $_.Name -match '^angry_ip_scanner\.exe$' })

    Add-DiskCheck -Category "Tooling" -Name "Angry IP Scanner Found  -  Verify Authorized" `
        -Weight 20 -HitScore 20 -Hit ($angryipHits.Count -gt 0) -Severity HIGH `
        -Detail "Path(s): $(($angryipHits | Select-Object -ExpandProperty FullName) -join '; ')  -  legitimate for techs but flag for awareness"

    if ($angryipHits.Count -gt 0) {
        Write-Log "  [!!] Angry IP Scanner found  -  confirm authorized tech use"
        $angryipHits | ForEach-Object { Write-Log "       $($_.FullName)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] Angry IP Scanner not found"
    }
} catch {
    Add-Unavailable -Category "Tooling" -Name "Angry IP Scanner Found  -  Verify Authorized" -Weight 20 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Angry IP Scanner check: $_"
}

# --- wget.exe  -  not native to Windows, always suspicious ---
try {
    $wgetHits = @($allFoundFiles | Where-Object { $_.Name -eq 'wget.exe' })

    Add-DiskCheck -Category "Ransomware" -Name "wget.exe Found  -  Not Native to Windows" `
        -Weight 45 -HitScore 45 -Hit ($wgetHits.Count -gt 0) -Severity HIGH `
        -Detail "Path(s): $(($wgetHits | Select-Object -ExpandProperty FullName) -join '; ')  -  manually dropped, no standard Windows install"

    if ($wgetHits.Count -gt 0) {
        Write-Log "  [!!] wget.exe found  -  not a Windows native binary"
        $wgetHits | ForEach-Object { Write-Log "       $($_.FullName)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] wget.exe not found"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "wget.exe Found  -  Not Native to Windows" -Weight 45 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] wget check: $_"
}

# --- curl.exe in non-system path ---
try {
    $curlHits = @($allFoundFiles | Where-Object {
        $_.Name -eq 'curl.exe' -and $_.FullName -notmatch 'System32|SysWOW64|Program Files'
    })

    Add-DiskCheck -Category "Ransomware" -Name "curl.exe Outside System32 (Manually Dropped)" `
        -Weight 40 -HitScore 40 -Hit ($curlHits.Count -gt 0) -Severity HIGH `
        -Detail "Path(s): $(($curlHits | Select-Object -ExpandProperty FullName) -join '; ')  -  Windows ships curl in System32, a separate copy suggests manual staging"

    if ($curlHits.Count -gt 0) {
        Write-Log "  [!!] Dropped curl.exe found outside System32"
        $curlHits | ForEach-Object { Write-Log "       $($_.FullName)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] No manually dropped curl.exe found"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "curl.exe Outside System32 (Manually Dropped)" -Weight 40 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] curl check: $_"
}

# --- Credential Theft Tools ---
try {
    $laZagneHits = @($allFoundFiles | Where-Object { $_.Name -match '^[Ll]a[Zz]agne\.exe$' })
    $procDumpHits = @($allFoundFiles | Where-Object {
        $_.Name -match '^procdump(64)?\.exe$' -and
        # ProcDump in SysInternals standard path is expected for sysadmins
        $_.FullName -notmatch 'SysInternals|Program Files'
    })
    $mimeHits = @($allFoundFiles | Where-Object {
        $_.Name -match '^(mimikatz|mimi32|mimi64|wce|fgdump|pwdump).*\.exe$'
    })

    # Also check PS history for LSASS dump via comsvcs.dll (no external tool needed)
    $lsassDumpHits = Search-PSHistory -Pattern 'comsvcs.*MiniDump|MiniDump.*lsass|rundll32.*comsvcs|Out-Minidump|lsass.*dump'

    Add-DiskCheck -Category "CredTheft" -Name "LaZagne Credential Harvester Found" `
        -Weight 80 -HitScore 80 -Hit ($laZagneHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($laZagneHits | Select-Object -ExpandProperty FullName) -join '; ')"

    Add-DiskCheck -Category "CredTheft" -Name "ProcDump in Non-Standard Path (LSASS Dump Risk)" `
        -Weight 60 -HitScore 60 -Hit ($procDumpHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($procDumpHits | Select-Object -ExpandProperty FullName) -join '; ')  -  commonly used to dump LSASS credentials"

    Add-DiskCheck -Category "CredTheft" -Name "Known Credential Theft Tool Found" `
        -Weight 90 -HitScore 90 -Hit ($mimeHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Tool(s): $(($mimeHits | Select-Object -ExpandProperty FullName) -join '; ')"

    Add-Check -Category "CredTheft" -Name "LSASS Dump Command in PS History" `
        -Weight 75 -HitScore 75 -Hit ($lsassDumpHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Command(s): $(($lsassDumpHits | Select-Object -First 2) -join ' | ')"

    if ($mimeHits.Count -gt 0) {
        Write-Log "  [!!!] CREDENTIAL THEFT TOOL FOUND  -  ESCALATE"
        $mimeHits | ForEach-Object { Write-Log "        $($_.FullName)" }
    }
    if ($laZagneHits.Count -gt 0) {
        Write-Log "  [!!!] LaZagne found  -  credential harvester"
        $laZagneHits | ForEach-Object { Write-Log "        $($_.FullName)" }
    }
    if ($procDumpHits.Count -gt 0) {
        Write-Log "  [!!!] ProcDump outside SysInternals path"
        $procDumpHits | ForEach-Object { Write-Log "        $($_.FullName)" }
    }
    if ($lsassDumpHits.Count -gt 0) {
        Write-Log "  [!!!] LSASS dump command in PS history:"
        $lsassDumpHits | Select-Object -First 3 | ForEach-Object { Write-Log "        $_" }
    }
    if ($mimeHits.Count -eq 0 -and $laZagneHits.Count -eq 0 -and $procDumpHits.Count -eq 0 -and $lsassDumpHits.Count -eq 0) {
        Write-Log "  [OK] No credential theft tools detected"
    }
} catch {
    Add-Unavailable -Category "CredTheft" -Name "LaZagne Credential Harvester Found"              -Weight 80 -Reason $_.Exception.Message
    Add-Unavailable -Category "CredTheft" -Name "ProcDump in Non-Standard Path (LSASS Dump Risk)" -Weight 60 -Reason $_.Exception.Message
    Add-Unavailable -Category "CredTheft" -Name "Known Credential Theft Tool Found"               -Weight 90 -Reason $_.Exception.Message
    Add-Unavailable -Category "CredTheft" -Name "LSASS Dump Command in PS History"                -Weight 75 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Credential theft check: $_"
}

# --- AD Recon Tools (SharpHound / BloodHound) ---
try {
    $sharpHoundHits = @($allFoundFiles | Where-Object { $_.Name -match '^[Ss]harp[Hh]ound.*\.exe$' })

    # SharpHound also drops ZIP files with GUID-style names containing BloodHound data
    $bhZipHits  = @()
    $bhZipPaths = @("C:\Windows\Temp","C:\Temp")
    foreach ($prof in $UserProfiles) {
        $bhZipPaths += @(
            (Join-Path $prof.FullName 'Desktop'),
            (Join-Path $prof.FullName 'Downloads'),
            (Join-Path $prof.FullName 'AppData\Local\Temp')
        )
    }
    foreach ($p in $bhZipPaths) {
        if (Test-Path $p) {
            $hits = Get-ChildItem $p -Filter "*.zip" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_BloodHound\.zip$|BloodHound.*\.zip$' }
            if ($hits) { $bhZipHits += $hits }
        }
    }

    $adReconHits = Search-PSHistory -Pattern 'ADRecon|Invoke-ADRecon|SharpHound|bloodhound'

    Add-DiskCheck -Category "ADRecon" -Name "SharpHound AD Recon Tool Found" `
        -Weight 70 -HitScore 70 -Hit ($sharpHoundHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($sharpHoundHits | Select-Object -ExpandProperty FullName) -join '; ')  -  used to map AD for lateral movement planning"

    Add-Check -Category "ADRecon" -Name "BloodHound Data ZIP Found" `
        -Weight 65 -HitScore 65 -Hit ($bhZipHits.Count -gt 0) -Severity CRITICAL `
        -Detail "File(s): $(($bhZipHits | Select-Object -ExpandProperty FullName) -join '; ')  -  BloodHound output indicates AD recon already completed"

    Add-Check -Category "ADRecon" -Name "AD Recon Commands in PS History" `
        -Weight 60 -HitScore 60 -Hit ($adReconHits.Count -gt 0) -Severity HIGH `
        -Detail "Command(s): $(($adReconHits | Select-Object -First 2) -join ' | ')"

    if ($sharpHoundHits.Count -gt 0) {
        Write-Log "  [!!!] SharpHound found  -  AD mapping tool, pre-ransomware indicator"
        $sharpHoundHits | ForEach-Object { Write-Log "        $($_.FullName)" }
    }
    if ($bhZipHits.Count -gt 0) {
        Write-Log "  [!!!] BloodHound data ZIP found  -  AD recon already ran"
        $bhZipHits | ForEach-Object { Write-Log "        $($_.FullName)" }
    }
    if ($adReconHits.Count -gt 0) {
        Write-Log "  [!!] AD recon commands in PS history"
        $adReconHits | Select-Object -First 3 | ForEach-Object { Write-Log "        $_" }
    }
    if ($sharpHoundHits.Count -eq 0 -and $bhZipHits.Count -eq 0 -and $adReconHits.Count -eq 0) {
        Write-Log "  [OK] No AD recon tools detected"
    }
} catch {
    Add-Unavailable -Category "ADRecon" -Name "SharpHound AD Recon Tool Found"   -Weight 70 -Reason $_.Exception.Message
    Add-Unavailable -Category "ADRecon" -Name "BloodHound Data ZIP Found"        -Weight 65 -Reason $_.Exception.Message
    Add-Unavailable -Category "ADRecon" -Name "AD Recon Commands in PS History"  -Weight 60 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] AD recon check: $_"
}

# =============================================================================
# SECTION 12  -  [RANSOMWARE] ENCRYPTED FILE EXTENSIONS
# Depth-limited and offline-aware. An unbounded -Recurse across redirected
# Documents folders can hydrate every cloud-only OneDrive file in the profile,
# which on a live client endpoint is its own incident.
# =============================================================================
Write-Section "12. [RANSOMWARE] Encrypted File Extensions"
try {
    $ransomExtensions = @(
        # Original set
        '\.INC$','\.enc$','\.encrypted$','\.locked$','\.crypted$','\.crypt$',
        '\.ransom$','\.WNCRY$','\.WCRY$','\.zepto$','\.cerber$','\.locky$',
        '\.ryuk$','\.RYK$','\.hive$','\.RESET$','\.BACKUP$','\.pays$',
        # Akira (2023-present  -  active, targets SMB and enterprise)
        '\.akira$',
        # Black Basta (2022-present  -  high volume, targets healthcare/finance)
        '\.basta$',
        # LockBit 3.0
        '\.lockbit$','\.abcd$',
        # BlackSuit / Royal (evolved from Conti)
        '\.blacksuit$','\.royal$',
        # ALPHV / BlackCat affiliate extensions
        '\.alphv$',
        # Qilin (VMware ESXi focus)
        '\.qilin$',
        # Rhysida (targets healthcare)
        '\.rhysida$',
        # Play ransomware
        '\.play$'
    )
    $extPattern = $ransomExtensions -join '|'

    # Only scan user data paths for file extensions (not system paths)
    $encScanPaths = @()
    foreach ($prof in $UserProfiles) {
        $encScanPaths += @(
            (Join-Path $prof.FullName 'Documents'),
            (Join-Path $prof.FullName 'Desktop'),
            (Join-Path $prof.FullName 'Downloads')
        )
    }
    $encScanPaths = @($encScanPaths | Where-Object { Test-Path $_ })

    # Depth 4 from each of Documents/Desktop/Downloads. Ransomware encrypts
    # breadth-first across a profile, so shallow depth still catches it.
    $encCandidates  = Get-FileSafe -Paths $encScanPaths -Filters @('*') -MaxDepth 4
    $encryptedFiles = @($encCandidates | Where-Object {
        $_.Extension -match $extPattern -or $_.Name -match $extPattern
    })

    Add-Check -Category "Ransomware" -Name "Files with Ransomware Extensions Found" `
        -Weight 90 -HitScore 90 -Hit ($encryptedFiles.Count -gt 0) -Severity CRITICAL `
        -Detail "$($encryptedFiles.Count) file(s). First 3: $(($encryptedFiles | Select-Object -First 3 | Select-Object -ExpandProperty FullName) -join '; ')"

    if ($encryptedFiles.Count -gt 0) {
        Write-Log "  [!!!] RANSOMWARE EXTENSIONS FOUND  -  $($encryptedFiles.Count) file(s)"
        $encryptedFiles | Select-Object -First 5 | ForEach-Object { Write-Log "        $($_.FullName)" }
    } else {
        Write-Log "  [OK] No ransomware file extensions in user paths (depth 4, $($encScanPaths.Count) path(s))"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "Files with Ransomware Extensions Found" -Weight 90 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Encrypted file scan: $_"
}

# Ransom note search  -  check common drop locations
try {
    $noteSearchPaths = @("C:\", "C:\Users\Public")
    foreach ($prof in $UserProfiles) { $noteSearchPaths += $prof.FullName }
    $noteSearchPaths = @($noteSearchPaths | Where-Object { Test-Path $_ })

    # Note filename patterns per known group
    $noteFilters = @(
        'INC-README.txt',           # INC Ransom
        'README_FOR_DECRYPT*',      # Generic / multiple groups
        'HOW_TO_DECRYPT*',          # Generic / multiple groups
        'HOW_TO_RESTORE*',          # LockBit variants
        'LockBit_README.txt',       # LockBit 3.0
        'akira_readme.txt',         # Akira
        'readme.txt.basta',         # Black Basta
        'INSTRUCTIONS.txt',         # Black Basta variant
        'BlackSuit.txt',            # BlackSuit
        'README.BlackSuit',
        'ROYAL_README.TXT',         # Royal
        'rhysida-readme.txt',       # Rhysida
        'Play-readme.txt',          # Play
        'RECOVER-*-FILES.txt',      # Qilin
        'RECOVER_FILES.txt'
    )

    $ransomNotes = @()
    foreach ($p in $noteSearchPaths) {
        foreach ($filter in $noteFilters) {
            $hits = Get-ChildItem $p -Filter $filter -ErrorAction SilentlyContinue -Force -File
            if ($hits) { $ransomNotes += $hits }
        }
    }

    Add-Check -Category "Ransomware" -Name "Ransom Note File Found on Disk" `
        -Weight 90 -HitScore 90 -Hit ($ransomNotes.Count -gt 0) -Severity CRITICAL `
        -Detail "Note(s): $(($ransomNotes | Select-Object -ExpandProperty FullName) -join '; ')"

    if ($ransomNotes.Count -gt 0) {
        Write-Log "  [!!!] RANSOM NOTE FOUND:"
        $ransomNotes | ForEach-Object { Write-Log "        $($_.FullName) | Modified: $($_.LastWriteTime)" }
    } else {
        Write-Log "  [OK] No ransom notes in common drop locations"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "Ransom Note File Found on Disk" -Weight 90 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Ransom note scan: $_"
}

# =============================================================================
# SECTION 13  -  [RANSOMWARE] SHADOW COPY DELETION
# =============================================================================
Write-Section "13. [RANSOMWARE] Shadow Copy Deletion"

# 13a  -  VSS deletion events (System log)
if (-not $SystemLogAccess.Accessible) {
    Add-Unavailable -Category "Ransomware" -Name "VSS Deletion Events in System Log" `
        -Weight 60 -Reason $SystemLogAccess.Reason
    Write-Log "  [UNAVAIL] VSS events: $($SystemLogAccess.Reason)"
} else {
    try {
        $cutoff    = (Get-Date).AddDays(-$LookbackDays)
        $vssEvents = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = @(524, 513)
            StartTime = $cutoff
        } -ErrorAction SilentlyContinue)

        Add-Check -Category "Ransomware" -Name "VSS Deletion Events in System Log" `
            -Weight 60 -HitScore 60 -Hit ($vssEvents.Count -gt 0) -Severity CRITICAL `
            -Detail "$($vssEvents.Count) VSS deletion event(s) in last $LookbackDays days"

        if ($vssEvents.Count -gt 0) {
            Write-Log "  [!!!] VSS deletion events: $($vssEvents.Count)"
        } else {
            Write-Log "  [OK] No VSS deletion events"
        }
    } catch {
        Add-Unavailable -Category "Ransomware" -Name "VSS Deletion Events in System Log" `
            -Weight 60 -Reason $_.Exception.Message
        Write-Log "  [UNAVAIL] VSS event check: $_"
    }
}

# 13b  -  VSS deletion commands in PS history
try {
    $vssHistHits = Search-PSHistory -Pattern 'vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no'

    Add-Check -Category "Ransomware" -Name "Shadow Copy Deletion in PS History" `
        -Weight 70 -HitScore 70 -Hit ($vssHistHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Commands: $(($vssHistHits | Select-Object -First 3) -join ' | ')"

    if ($vssHistHits.Count -gt 0) {
        Write-Log "  [!!!] vssadmin delete in PS history:"
        $vssHistHits | ForEach-Object { Write-Log "        $_" }
    } else {
        Write-Log "  [OK] No shadow copy deletion commands in PS history"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "Shadow Copy Deletion in PS History" `
        -Weight 70 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] VSS history check: $_"
}

# 13c  -  Current shadow copy presence
# vssadmin requires elevation. Unelevated it fails, and the old code read that
# failure as "shadow copies present" and passed the check.
try {
    $vssOutput   = & vssadmin list shadows 2>&1
    $vssExitCode = $LASTEXITCODE
    $vssText     = ($vssOutput | Out-String)

    if ($vssText -match 'Access is denied|requires administrator|elevated' -or ($vssExitCode -ne 0 -and $vssText -notmatch 'No items found')) {
        Add-Unavailable -Category "Ransomware" -Name "No Shadow Copies Present on Server" `
            -Weight 30 -Reason "vssadmin returned exit code $vssExitCode  -  requires elevation"
        Write-Log "  [UNAVAIL] Could not query shadow copies (vssadmin exit $vssExitCode)"
    } else {
        $noShadows = $vssText -match 'No items found|no shadow copies'

        Add-Check -Category "Ransomware" -Name "No Shadow Copies Present on Server" `
            -Weight 30 -HitScore 25 -Hit ($noShadows -and $IsServer) -Severity HIGH `
            -Detail "No VSS shadow copies found on a server  -  may have been deleted by ransomware"

        if ($noShadows -and $IsServer) {
            Write-Log "  [!!] No shadow copies on server"
        } elseif ($noShadows) {
            Write-Log "  [INFO] No shadow copies (workstation  -  often normal)"
        } else {
            Write-Log "  [OK] Shadow copies present"
        }
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "No Shadow Copies Present on Server" `
        -Weight 30 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Shadow copy presence check: $_"
}

# =============================================================================
# SECTION 14  -  [RANSOMWARE] UNAUTHORIZED RMM TOOLS
# Uses cached $allFoundFiles  -  no additional disk I/O
# =============================================================================
Write-Section "14. [RANSOMWARE] Unauthorized RMM Tools"

# AnyDesk in non-standard path
try {
    $anydeskAll = @($allFoundFiles | Where-Object { $_.Name -eq 'AnyDesk.exe' })
    $anydeskBad = @($anydeskAll | Where-Object { $_.FullName -notmatch 'Program Files|AppData\\Local\\Programs' })

    Add-DiskCheck -Category "Ransomware" -Name "AnyDesk in Non-Standard Path" `
        -Weight 50 -HitScore 50 -Hit ($anydeskBad.Count -gt 0) -Severity CRITICAL `
        -Detail "Path(s): $(($anydeskBad | Select-Object -ExpandProperty FullName) -join '; ')"

    if ($anydeskBad.Count -gt 0) {
        Write-Log "  [!!!] AnyDesk in unexpected path:"
        $anydeskBad | ForEach-Object { Write-Log "        $($_.FullName)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] AnyDesk not found in non-standard paths"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "AnyDesk in Non-Standard Path" -Weight 50 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] AnyDesk check: $_"
}

# SimpleHelp  -  confirmed INC Ransom CVE-2024-57726/57727/57728
try {
    $shKnownPaths = @(
        "C:\Program Files\SimpleHelp",
        "C:\Program Files (x86)\SimpleHelp",
        "C:\SimpleHelp"
    )
    $shFoundPaths = @($shKnownPaths | Where-Object { Test-Path $_ })
    $shFiles      = @($allFoundFiles | Where-Object { $_.Name -match '^SimpleHelp' })
    $shAny        = ($shFoundPaths.Count -gt 0 -or $shFiles.Count -gt 0)

    Add-Check -Category "Ransomware" -Name "SimpleHelp RMM Found (INC Ransom Initial Access)" `
        -Weight 60 -HitScore 60 -Hit $shAny -Severity CRITICAL `
        -Detail "INC exploits CVE-2024-57726/57727/57728. Found: $($shFoundPaths -join '; ')"

    if ($shAny) {
        Write-Log "  [!!!] SimpleHelp found  -  known INC initial access vector"
        $shFoundPaths | ForEach-Object { Write-Log "        Path: $_" }
        $shFiles | Select-Object -First 3 | ForEach-Object { Write-Log "        File: $($_.FullName)" }
    } else {
        Write-Log "  [OK] SimpleHelp not detected"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "SimpleHelp RMM Found (INC Ransom Initial Access)" -Weight 60 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] SimpleHelp check: $_"
}

# ScreenConnect in non-standard path
try {
    $scAll = @($allFoundFiles | Where-Object { $_.Name -match '^ScreenConnect\.(Client|WindowsClient)\.exe$' })
    $scBad = @($scAll | Where-Object { $_.FullName -notmatch 'Program Files' })

    Add-DiskCheck -Category "Ransomware" -Name "ScreenConnect in Non-Standard Path" `
        -Weight 40 -HitScore 40 -Hit ($scBad.Count -gt 0) -Severity HIGH `
        -Detail "Path(s): $(($scBad | Select-Object -ExpandProperty FullName) -join '; ')"

    if ($scBad.Count -gt 0) {
        Write-Log "  [!!] ScreenConnect in unexpected path:"
        $scBad | ForEach-Object { Write-Log "        $($_.FullName)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] ScreenConnect not found in non-standard paths"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "ScreenConnect in Non-Standard Path" -Weight 40 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] ScreenConnect check: $_"
}

# =============================================================================
# SECTION 15  -  [RANSOMWARE] ENTRA CONNECT (Azure AD Connect)
# =============================================================================
Write-Section "15. [RANSOMWARE] Microsoft Entra Connect"
try {
    $entraPaths = @(
        "C:\Program Files\Microsoft Azure AD Sync",
        "C:\Program Files\Microsoft Azure Active Directory Connect",
        "C:\Program Files (x86)\Microsoft Azure AD Sync"
    )
    $entraFoundPaths = @($entraPaths | Where-Object { Test-Path $_ })

    $entraInstall = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Azure AD Connect|Entra Connect' })

    $entraAnywhere      = ($entraFoundPaths.Count -gt 0 -or $entraInstall.Count -gt 0)
    $entraOnWorkstation = $entraAnywhere -and -not $IsServer

    # Check for MSOL_/AAD_ accounts  -  created by Entra Connect setup
    $syncAccounts = @(Get-LocalUserCompat | Where-Object { $_.Name -match '^(MSOL_|AAD_)' })

    Add-Check -Category "Ransomware" -Name "Entra Connect on Workstation (Cloud Pivot)" `
        -Weight 70 -HitScore 70 -Hit $entraOnWorkstation -Severity CRITICAL `
        -Detail "Entra Connect on a workstation = likely attacker-staged cloud pivot attempt"

    Add-Check -Category "Ransomware" -Name "Entra Connect Present  -  Verify Install Date" `
        -Weight 40 -HitScore 30 -Hit ($entraAnywhere -and $IsServer) -Severity HIGH `
        -Detail "Install date(s): $(($entraInstall | Select-Object -ExpandProperty InstallDate) -join ', ') | Verify this was intentionally configured"

    Add-Check -Category "Ransomware" -Name "MSOL_/AAD_ Sync Accounts Present" `
        -Weight 40 -HitScore 40 -Hit ($syncAccounts.Count -gt 0) -Severity HIGH `
        -Detail "Account(s): $(($syncAccounts | Select-Object -ExpandProperty Name) -join ', ')  -  if Entra Connect was not intentionally set up, these are attacker-created"

    if ($entraOnWorkstation) {
        Write-Log "  [!!!] Entra Connect on WORKSTATION  -  cloud pivot attack vector"
    } elseif ($entraAnywhere) {
        Write-Log "  [!!] Entra Connect found on server  -  verify install was intentional"
        $entraInstall | ForEach-Object { Write-Log "       $($_.DisplayName) | Installed: $($_.InstallDate)" }
    } else {
        Write-Log "  [OK] Entra Connect not detected"
    }
    if ($syncAccounts.Count -gt 0) {
        Write-Log "  [!!] Sync accounts: $(($syncAccounts | Select-Object -ExpandProperty Name) -join ', ')"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "Entra Connect on Workstation (Cloud Pivot)"  -Weight 70 -Reason $_.Exception.Message
    Add-Unavailable -Category "Ransomware" -Name "Entra Connect Present  -  Verify Install Date" -Weight 40 -Reason $_.Exception.Message
    Add-Unavailable -Category "Ransomware" -Name "MSOL_/AAD_ Sync Accounts Present"             -Weight 40 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Entra Connect check: $_"
}

# =============================================================================
# SECTION 16  -  [RANSOMWARE] RECON TOOLS (NETSCAN etc.)
# Uses cached $allFoundFiles  -  no additional disk I/O
# =============================================================================
Write-Section "16. [RANSOMWARE] Network Reconnaissance Tools"
try {
    $reconNames = @('netscan.exe','nmap.exe','masscan.exe','angry_ip_scanner.exe','networkscanner.exe')
    $reconHits  = @($allFoundFiles | Where-Object {
        ($reconNames -contains $_.Name.ToLower()) -or ($_.FullName -match 'SoftPerfect')
    })

    Add-DiskCheck -Category "Ransomware" -Name "Network Recon Tools Found on Disk" `
        -Weight 50 -HitScore 50 -Hit ($reconHits.Count -gt 0) -Severity CRITICAL `
        -Detail "Tool(s): $(($reconHits | Select-Object -ExpandProperty FullName) -join '; ')  -  NETSCAN.EXE is a confirmed INC Ransom tool"

    if ($reconHits.Count -gt 0) {
        Write-Log "  [!!!] Recon tool(s) found:"
        $reconHits | ForEach-Object { Write-Log "        $($_.FullName) | Modified: $($_.LastWriteTime)" }
    } elseif ($diskScanOk) {
        Write-Log "  [OK] No recon tools found"
    }
} catch {
    Add-Unavailable -Category "Ransomware" -Name "Network Recon Tools Found on Disk" -Weight 50 -Reason $_.Exception.Message
    Write-Log "  [UNAVAIL] Recon tool check: $_"
}

# =============================================================================
# SCORING + REPORT OUTPUT
# =============================================================================
Write-Section "FINDINGS SUMMARY"

$severityOrder  = @{ CRITICAL = 1; HIGH = 2; MEDIUM = 3; LOW = 4; INFO = 5; UNAVAILABLE = 6; PASS = 7 }
$sortedFindings = $findings | Sort-Object { $severityOrder[$_.Severity] }

$critCount   = @($findings | Where-Object { $_.Severity -eq 'CRITICAL'    }).Count
$highCount   = @($findings | Where-Object { $_.Severity -eq 'HIGH'        }).Count
$medCount    = @($findings | Where-Object { $_.Severity -eq 'MEDIUM'      }).Count
$passCount   = @($findings | Where-Object { $_.Severity -eq 'PASS'        }).Count
$unavailList = @($findings | Where-Object { $_.Severity -eq 'UNAVAILABLE' })

# Score denominator is COMPLETED weight only. Coverage is reported separately
# so a low score on a partial run cannot be misread as a clean host.
$score = 0
if ($totalWeight -gt 0) {
    $score = [math]::Round(($totalHitScore / $totalWeight) * 100)
}

$plannedWeight = $totalWeight + $unavailableWeight
$coveragePct   = 100
if ($plannedWeight -gt 0) {
    $coveragePct = [math]::Round(($totalWeight / $plannedWeight) * 100)
}

# The label is driven by the WORST finding, not only by the weighted score.
# A single HIGH under a "CLEAN" banner is how a real finding gets closed
# without being read.
if     ($critCount -gt 0)                  { $riskLabel = "CRITICAL - ESCALATE NOW" }
elseif ($highCount -gt 0 -or $score -ge 60) { $riskLabel = "HIGH - REVIEW REQUIRED" }
elseif ($score -ge 30)                     { $riskLabel = "MODERATE SUSPICION" }
elseif ($medCount -gt 0 -or $score -ge 10) { $riskLabel = "LOW - VERIFY" }
else                                       { $riskLabel = "CLEAN" }

if ($unavailableCount -gt 0) {
    $riskLabel = "$riskLabel  (INCOMPLETE  -  $coveragePct% coverage)"
}

Write-Log ""
Write-Log "  RISK LEVEL  : $riskLabel"
Write-Log "  SCORE       : $score / 100  (of checks that completed)"
Write-Log "  COVERAGE    : $coveragePct%  ($unavailableCount check(s) could not run)"
Write-Log "  CRITICAL    : $critCount"
Write-Log "  HIGH        : $highCount"
Write-Log "  MEDIUM      : $medCount"
Write-Log "  PASS        : $passCount"
Write-Log "  UNAVAILABLE : $unavailableCount"
Write-Log ""

if ($unavailableCount -gt 0) {
    Write-Log "  *** THIS RUN IS INCOMPLETE. A low score does NOT mean the host is clean. ***"
    Write-Log ""
    Write-Log "  Checks that did not run:"
    $unavailList | ForEach-Object {
        Write-Log "    [UNAVAILABLE] $($_.Category) | $($_.Name)"
        Write-Log "                  $($_.Detail)"
    }
    Write-Log ""
}

$sortedFindings | Where-Object { $_.Severity -notin @('PASS','UNAVAILABLE') } | ForEach-Object {
    Write-Log "  [$($_.Severity.PadRight(11))] $($_.Category) | $($_.Name)"
    if ($_.Detail) { Write-Log "                $($_.Detail)" }
}

# ---------------------------------------------------------------------------
# CSV EXPORT
# ---------------------------------------------------------------------------
try {
    $sortedFindings |
        Select-Object Severity, Category, Name, Hit, Detail |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Log ""
    Write-Log "  CSV     : $CsvPath"
} catch { Write-Log "  [WARN] CSV export failed: $_" }

# ---------------------------------------------------------------------------
# SUMMARY TXT
# ---------------------------------------------------------------------------
try {
    $lines = @(
        "SecureTriage Summary",
        "====================",
        "Host      : $HostName",
        "OS        : $OSCaption (Build $OSBuild)",
        "Elevated  : $(if ($IsElevated) { 'Yes' } else { 'NO  -  reduced coverage' })",
        "Profiles  : $($UserProfiles.Count) readable, $($InaccessibleProfiles.Count) not readable",
        "Date/Time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "Risk      : $riskLabel",
        "Score     : $score / 100 (of checks that completed)",
        "Coverage  : $coveragePct%",
        "CRITICAL: $critCount  HIGH: $highCount  MEDIUM: $medCount  PASS: $passCount  UNAVAILABLE: $unavailableCount",
        ""
    )

    if ($unavailableCount -gt 0) {
        $lines += "*** INCOMPLETE RUN  -  a low score does NOT mean the host is clean ***"
        $lines += ""
        $lines += "CHECKS THAT DID NOT RUN"
        $lines += "-----------------------"
        $unavailList | ForEach-Object {
            $lines += "[UNAVAILABLE] $($_.Category)  -  $($_.Name)"
            $lines += "  -> $($_.Detail)"
            $lines += ""
        }
    }

    $lines += "FINDINGS"
    $lines += "--------"
    $sortedFindings | Where-Object { $_.Severity -notin @('PASS','UNAVAILABLE') } | ForEach-Object {
        $lines += "[$($_.Severity)] $($_.Category)  -  $($_.Name)"
        if ($_.Detail) { $lines += "  -> $($_.Detail)" }
        $lines += ""
    }

    $lines | Out-File -FilePath $SummaryPath -Encoding UTF8
    Write-Log "  Summary : $SummaryPath"
    Write-Log "  Log     : $LogPath"
} catch { Write-Log "  [WARN] Summary export failed: $_" }

# ---------------------------------------------------------------------------
# JSON (optional)
# ---------------------------------------------------------------------------
if ($ExportJSON) {
    try {
        $jsonPath = Join-Path $RunDir "findings.json"
        [PSCustomObject]@{
            Host        = $HostName
            OS          = $OSCaption
            Build       = $OSBuild
            Elevated    = $IsElevated
            ScanTime    = (Get-Date -Format 'o')
            RiskLabel   = $riskLabel
            Score       = $score
            CoveragePct = $coveragePct
            Counts      = [PSCustomObject]@{
                Critical    = $critCount
                High        = $highCount
                Medium      = $medCount
                Pass        = $passCount
                Unavailable = $unavailableCount
            }
            Findings    = $sortedFindings
        } | ConvertTo-Json -Depth 6 | Out-File $jsonPath -Encoding UTF8
        Write-Log "  JSON    : $jsonPath"
    } catch { Write-Log "  [WARN] JSON export failed: $_" }
}

Write-Log ""
Write-Log "Output folder: $RunDir"

# ---------------------------------------------------------------------------
# EXIT CODE
# ---------------------------------------------------------------------------
# An incomplete run never exits 0. Exit code is the only thing an RMM alerts
# on, so "we could not check part of this host" has to be distinguishable from
# "this host is clean"  -  otherwise the coverage reporting is decoration.
if     ($critCount -gt 0)                   { $exitCode = 2 }
elseif ($highCount -gt 0 -or $score -ge 30) { $exitCode = 1 }
elseif ($unavailableCount -gt 0)            { $exitCode = 1 }
else                                        { $exitCode = 0 }

Write-Log "Exit code  : $exitCode  (0=Clean  1=Moderate or incomplete  2=Critical  3=Could not run)"

# Guard against dot-sourcing closing the caller's session.
if ($MyInvocation.InvocationName -eq '.') {
    Write-Log "[NOTE] Script was dot-sourced  -  exit code not set. Run with -File instead."
    $global:SecureTriageExitCode = $exitCode
} else {
    exit $exitCode
}
