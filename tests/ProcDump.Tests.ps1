# Section 11: ProcDump (LSASS dump risk).
# Issue #3: a Microsoft Store install of Sysinternals creates a zero-byte app
# execution alias at %LOCALAPPDATA%\Microsoft\WindowsApps\procdump.exe, which
# v3.3 reported as CRITICAL. The same code also trusted any path containing
# "SysInternals" or "Program Files", both of which an attacker can create.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $roots = @('C:\Program Files', 'C:\Program Files (x86)')
    $msPublisher = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    $storeAlias = 'C:\Users\tech\AppData\Local\Microsoft\WindowsApps\procdump.exe'
}

Describe 'Get-ProcDumpSeverity' {

    Context 'admin-installed locations are expected' {

        It 'passes ProcDump under a real Program Files root: <Path>' -ForEach @(
            @{ Path = 'C:\Program Files\SysinternalsSuite\procdump.exe' }
            @{ Path = 'C:\Program Files (x86)\Tools\procdump64.exe' }
            @{ Path = 'c:\program files\sysinternals\procdump.exe' }
        ) {
            (Get-ProcDumpSeverity -FullName $Path -ProgramFilesRoots $roots).Severity | Should -Be 'PASS'
        }
    }

    Context 'Microsoft Store alias (issue #3)' {

        It 'is MEDIUM (verify), not CRITICAL, for a Store alias owned by a Microsoft package' {
            $r = Get-ProcDumpSeverity -FullName $storeAlias -IsAppExecAlias $true `
                    -AliasPackage 'Microsoft.SysinternalsSuite_8wekyb3d8bbwe' `
                    -AliasPublisher $msPublisher -AliasSignatureKind 'Store' -ProgramFilesRoots $roots
            $r.Severity | Should -Be 'MEDIUM'
            $r.Reason   | Should -Match 'Microsoft.SysinternalsSuite'
        }

        It 'stays CRITICAL when a file at that path is not an alias (a dropped binary)' {
            (Get-ProcDumpSeverity -FullName $storeAlias -IsAppExecAlias $false -ProgramFilesRoots $roots).Severity |
                Should -Be 'CRITICAL'
        }

        It 'stays CRITICAL when no installed package owns the alias' {
            (Get-ProcDumpSeverity -FullName $storeAlias -IsAppExecAlias $true -ProgramFilesRoots $roots).Severity |
                Should -Be 'CRITICAL'
        }

        It 'stays CRITICAL when the owning package is not from Microsoft' {
            (Get-ProcDumpSeverity -FullName $storeAlias -IsAppExecAlias $true -AliasPackage 'Contoso.Tools_abc' `
                -AliasPublisher 'CN=Contoso' -AliasSignatureKind 'Store' -ProgramFilesRoots $roots).Severity |
                Should -Be 'CRITICAL'
        }

        It 'stays CRITICAL for a sideloaded package that only claims to be Microsoft' {
            # Self-signed packages can put any name in the publisher field.
            # Only Store/System signature kinds are verified by Windows.
            (Get-ProcDumpSeverity -FullName $storeAlias -IsAppExecAlias $true -AliasPackage 'Microsoft.SysinternalsSuite_x' `
                -AliasPublisher $msPublisher -AliasSignatureKind 'Developer' -ProgramFilesRoots $roots).Severity |
                Should -Be 'CRITICAL'
        }
    }

    Context 'paths an attacker can create are not trusted' {

        It 'is CRITICAL in a user-writable location even inside a "SysInternals" folder: <Path>' -ForEach @(
            @{ Path = 'C:\Users\Public\SysInternals\procdump.exe' }
            @{ Path = 'C:\Windows\Temp\sysinternals\procdump64.exe' }
            @{ Path = 'C:\ProgramData\SysinternalsSuite\procdump.exe' }
        ) {
            (Get-ProcDumpSeverity -FullName $Path -ProgramFilesRoots $roots).Severity | Should -Be 'CRITICAL'
        }

        It 'is CRITICAL in a fake "Program Files" folder: <Path>' -ForEach @(
            @{ Path = 'C:\Users\tech\Program Files\procdump.exe' }
            @{ Path = 'C:\Program Files Evil\procdump.exe' }
        ) {
            (Get-ProcDumpSeverity -FullName $Path -ProgramFilesRoots $roots).Severity | Should -Be 'CRITICAL'
        }

        It 'is CRITICAL in a normal staging folder: <Path>' -ForEach @(
            @{ Path = 'C:\Users\tech\Downloads\procdump64.exe' }
            @{ Path = 'C:\PerfLogs\procdump.exe' }
            @{ Path = 'C:\procdump.exe' }
        ) {
            (Get-ProcDumpSeverity -FullName $Path -ProgramFilesRoots $roots).Severity | Should -Be 'CRITICAL'
        }

        It 'is MEDIUM (verify) in an admin-style SysInternals folder outside user-writable locations' {
            # Common sysadmin habit (C:\Tools\SysinternalsSuite). Kept visible
            # rather than trusted, because C:\ subfolders are user-creatable.
            (Get-ProcDumpSeverity -FullName 'C:\Tools\SysinternalsSuite\procdump.exe' -ProgramFilesRoots $roots).Severity |
                Should -Be 'MEDIUM'
        }
    }
}

Describe 'Section 11 ProcDump check: wiring' {

    BeforeAll { $scriptText = Get-Content -Path $script:SecureTriagePath -Raw }

    It 'decides severity through Get-ProcDumpSeverity' {
        $scriptText | Should -Match 'Get-ProcDumpSeverity\s'
    }

    It 'reports MEDIUM ProcDump findings as their own check instead of dropping them' {
        $scriptText | Should -Match 'ProcDump Present \(Verify Installation\)'
    }
}
