# Whole-script checks. These run against the script file without executing it.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $scriptText = Get-Content -Path $script:SecureTriagePath -Raw
}

Describe 'SecureTriage.ps1 file' {

    It 'parses without errors in this PowerShell edition' {
        # TestHelpers throws on parse errors, so reaching this line means it
        # parsed. CI runs these tests in both Windows PowerShell 5.1 and 7.
        $script:SecureTriageAst | Should -Not -BeNullOrEmpty
    }

    It 'is plain ASCII, so Windows PowerShell 5.1 reads it correctly without a BOM' {
        $bytes   = [System.IO.File]::ReadAllBytes($script:SecureTriagePath)
        $nonAscii = @($bytes | Where-Object { $_ -gt 127 })
        $nonAscii | Should -HaveCount 0
    }

    It 'defines each function before the script body first calls it' {
        # The script runs top to bottom, so a function called above its
        # definition fails at runtime with "not recognized".
        $definitions = $script:SecureTriageAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $false)

        foreach ($def in $definitions) {
            $name = $def.Name
            $firstCall = $script:SecureTriageAst.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.CommandAst] -and
                $n.GetCommandName() -eq $name
            }, $true) |
                # Calls inside other function bodies run later, when that function
                # is called; only calls in the script body itself matter here.
                Where-Object {
                    $p = $_.Parent
                    $insideFunction = $false
                    while ($p) {
                        if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $insideFunction = $true; break }
                        $p = $p.Parent
                    }
                    -not $insideFunction
                } |
                Sort-Object { $_.Extent.StartOffset } |
                Select-Object -First 1

            if ($firstCall) {
                $because = "$name is called on line $($firstCall.Extent.StartLineNumber) but defined on line $($def.Extent.StartLineNumber)"
                $firstCall.Extent.StartOffset | Should -BeGreaterThan $def.Extent.EndOffset -Because $because
            }
        }
    }
}

Describe 'Section 6: new local accounts (event 4720)' {

    It 'queries event 4720' {
        $scriptText | Should -Match 'Id\s*=\s*4720'
    }

    It 'is not nested inside the -KnownAccounts block (v3.2 bug)' {
        # v3.2 had a misplaced brace that put the 4720 check inside
        # "if ($baselineAccts.Count -gt 0) { ... }", so it only ran when
        # -KnownAccounts was passed, and silently skipped otherwise.
        $knownAccountsIf = @($script:SecureTriageAst.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.IfStatementAst] -and
            $n.Clauses[0].Item1.Extent.Text -match '\$baselineAccts\.Count\s+-gt\s+0'
        }, $true))

        $knownAccountsIf | Should -HaveCount 1
        $knownAccountsIf[0].Extent.Text | Should -Not -Match '4720'
        $knownAccountsIf[0].Extent.Text | Should -Not -Match 'Local Accounts Created in Last 30 Days'
    }
}

Describe 'Section 4: wiring' {

    It 'passes the event log results through Select-SuspiciousPSEvent' {
        # Guards against the filter being inlined again and drifting from
        # the tested function.
        $scriptText | Should -Match 'Select-SuspiciousPSEvent\s+-Events\s+\$psEvents'
    }
}
