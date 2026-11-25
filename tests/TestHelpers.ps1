# Test helpers for SecureTriage.
#
# SecureTriage.ps1 is a single file that runs a full scan from top to bottom
# and ends with `exit`, because it is deployed by pasting it into an RMM
# component. It cannot be dot-sourced or imported without running the scan.
#
# Instead, this helper parses the script and defines only its functions in
# the caller's scope. Nothing in the script body runs. Dot-source this file
# from a Pester BeforeAll block:
#
#   BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

$script:SecureTriagePath = (Resolve-Path (Join-Path $PSScriptRoot '..\SecureTriage.ps1')).Path

$parseTokens = $null
$parseErrors = $null
$script:SecureTriageAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $script:SecureTriagePath, [ref]$parseTokens, [ref]$parseErrors)

if ($parseErrors -and $parseErrors.Count -gt 0) {
    $first = $parseErrors[0]
    throw "SecureTriage.ps1 does not parse: line $($first.Extent.StartLineNumber): $($first.Message)"
}

# Top-level function definitions only (not functions nested inside functions).
$functionAsts = $script:SecureTriageAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $false)

foreach ($fn in $functionAsts) {
    . ([scriptblock]::Create($fn.Extent.Text))
}

# ---------------------------------------------------------------------------
# Synthetic event builders
# ---------------------------------------------------------------------------
# Shaped like the EventLogRecord objects Get-WinEvent returns, as far as the
# script uses them: Id, TimeCreated, Properties[n].Value, and Message.
# Message is filled in the real Windows format on purpose: v3.2 filtered on
# .Message and its exclusions matched every real event. If any code goes back
# to reading .Message, these realistic values will make the tests fail.

function New-TestEvent4104 {
    param(
        [Parameter(Mandatory)][string]$ScriptBlockText,
        [string]$Path = '',
        [datetime]$TimeCreated = (Get-Date)
    )
    [PSCustomObject]@{
        Id          = 4104
        TimeCreated = $TimeCreated
        Message     = "Creating Scriptblock text (1 of 1):`r`n$ScriptBlockText`r`n`r`nScriptBlock ID: 00000000-0000-0000-0000-000000000000`r`nPath: $Path"
        Properties  = @(
            [PSCustomObject]@{ Value = 1 }                                      # MessageNumber
            [PSCustomObject]@{ Value = 1 }                                      # MessageTotal
            [PSCustomObject]@{ Value = $ScriptBlockText }                       # ScriptBlockText
            [PSCustomObject]@{ Value = '00000000-0000-0000-0000-000000000000' } # ScriptBlockId
            [PSCustomObject]@{ Value = $Path }                                  # Path
        )
    }
}

function New-TestEvent4103 {
    param(
        [string]$HostApplication = 'powershell.exe',
        [string]$ScriptName = '',
        [string]$Payload = '',
        [datetime]$TimeCreated = (Get-Date)
    )
    $context = @(
        '        Severity = Informational'
        '        Host Name = ConsoleHost'
        '        Host Version = 5.1.22621.4391'
        '        Host ID = 00000000-0000-0000-0000-000000000000'
        "        Host Application = $HostApplication"
        '        Engine Version = 5.1.22621.4391'
        '        Runspace ID = 00000000-0000-0000-0000-000000000000'
        '        Pipeline ID = 1'
        '        Command Name = Write-Output'
        '        Command Type = Cmdlet'
        "        Script Name = $ScriptName"
        '        Command Path = '
        '        Sequence Number = 1'
        '        User = LAB\testuser'
        '        Connected User = '
        '        Shell ID = Microsoft.PowerShell'
    ) -join "`r`n"
    [PSCustomObject]@{
        Id          = 4103
        TimeCreated = $TimeCreated
        Message     = "$Payload`r`n`r`n`r`nContext:`r`n$context`r`n`r`n`r`nUser Data:`r`n"
        Properties  = @(
            [PSCustomObject]@{ Value = $context } # ContextInfo
            [PSCustomObject]@{ Value = '' }       # UserData
            [PSCustomObject]@{ Value = $Payload } # Payload
        )
    }
}
