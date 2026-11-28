# Filesystem-only regressions for install.ps1. Runs without building Sync_Gate or using system settings.
param([ValidateSet('GuestHint', 'Lock', 'Rollback', 'References', 'Journal', 'ResumeLayout')][string[]]$Only = @('GuestHint', 'Lock', 'Rollback', 'References', 'Journal', 'ResumeLayout'))

$ErrorActionPreference = 'Stop'
$previousEnv = @{}
foreach ($name in 'SYNC_GATE_INSTALL_NO_MAIN', 'SYNC_GATE_INSTALL_DIR', 'USERPROFILE', 'LOCALAPPDATA', 'CLAUDE_CONFIG_DIR', 'CODEX_HOME', 'SYNC_GATE_TASK_NAME', 'SYNC_GATE_ENV_KEY', 'SYNC_GATE_PROFILE_PATHS') {
    $previousEnv[$name] = [Environment]::GetEnvironmentVariable($name)
}

function Assert-That {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$folder = Join-Path ([IO.Path]::GetTempPath()) ('trabalho\sync_gate\install-recovery-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($folder)
try {
    $env:SYNC_GATE_INSTALL_NO_MAIN = '1'
    . (Join-Path $PSScriptRoot 'install.ps1')
    if ($Only -contains 'GuestHint') {
        $config = Join-Path $folder 'config.toml'
        $layout = @{ Overrides = @{ SYNC_GATE_DATA_DIR = 'test' } }
        $cases = @(
            @{ Text = 'guests = ["@restricted"]'; Warn = $true },
            @{ Text = "'guests' = ['@restricted']"; Warn = $true },
            @{ Text = "guests = [ # heading`r`n # entry`r`n '@restricted',`r`n]"; Warn = $true },
            @{ Text = "guests = [ # no 'entries'`r`n]"; Warn = $false },
            @{ Text = '# guests = ["@restricted"]'; Warn = $false }
        )
        $wrong = @(foreach ($case in $cases) {
            [IO.File]::WriteAllText($config, $case.Text)
            $lines = (Write-SgGuestHint $layout $config 6>&1) -join "`n"
            if (($lines -match 'your config lists guests') -ne $case.Warn) { $case.Text }
        })
        $file = [IO.File]::Open($config, 'Open', 'Read', 'None')
        try {
            try { $lines = (Write-SgGuestHint $layout $config 6>&1) -join "`n" }
            catch { $wrong += "config read escaped the diagnostic: $($_.Exception.Message)" }
            if ($lines -notmatch 'warning:.*config.*guest') { $wrong += 'a locked config should produce a diagnostic' }
        } finally { $file.Dispose() }
        $lines = (Write-SgGuestHint $layout (Join-Path $folder 'missing.toml') 6>&1) -join "`n"
        if ($lines) { $wrong += 'a missing config should stay silent' }
        Assert-That ($wrong.Count -eq 0) ($wrong -join "`n")
        Write-Host 'PASS guest hint for TOML array forms and unavailable config'
    }
    if ($Only -contains 'Lock') {
        $installer = Join-Path $PSScriptRoot 'install.ps1'
        $child = Join-Path $folder 'probe.ps1'
        @'
param($Installer)
$env:SYNC_GATE_INSTALL_NO_MAIN = '1'
. $Installer
function Get-SgIntegrity { 'Medium Mandatory Level' }
function Invoke-SyncGateUninstall { Write-SgLine 'entered uninstall' }
Invoke-SyncGateMain -Uninstall
'@ | Set-Content -LiteralPath $child -Encoding ASCII
        $root = Join-Path $folder 'inst'
        $alias = Join-Path $folder 'junction'
        [void][IO.Directory]::CreateDirectory($root)
        [void](New-Item -ItemType Junction -Path $alias -Target $root)
        $env:SYNC_GATE_INSTALL_DIR = $root
        function Invoke-LockProbe([string]$Root) {
            Invoke-SgNative -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
                -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $child, $installer) `
                -Env @{ SYNC_GATE_INSTALL_DIR = $Root }
        }
        function Get-SgIntegrity { 'Medium Mandatory Level' }
        function Invoke-SyncGateInstall {
            $results.Same = Invoke-LockProbe ($root.ToUpperInvariant() + '\.')
            $results.Alias = Invoke-LockProbe $alias
            $results.Different = Invoke-LockProbe (Join-Path $folder 'other-inst')
        }
        $results = @{}
        try { Invoke-SyncGateMain } finally { [IO.Directory]::Delete($alias, $false) }
        $after = Invoke-LockProbe $root
        Assert-That ($after.ExitCode -eq 0 -and $after.Out -match 'entered uninstall') "lock stayed held: $($after.Out)$($after.Err)"
        foreach ($entry in $results.GetEnumerator()) {
            $probe = $entry.Value
            Assert-That ($probe.ExitCode -eq 1 -and $probe.Out -match 'another .*install' -and $probe.Out -notmatch 'entered uninstall') `
                "a $($entry.Key) contender reached shared installer resources: $($probe.Out)$($probe.Err)"
        }
        Assert-That (-not (Test-Path -LiteralPath (Join-Path $folder 'other-inst'))) 'locking alone created an install root'
        Write-Host 'PASS installer excludes contenders across paths and releases the lock'
    }
    if ($Only -contains 'Rollback') { & {
        $root = Join-Path $folder 'uninstall'
        $rb = Join-Path $root 'rollback'
        $bin = Join-Path $root 'bin'
        $savedBin = Join-Path $rb 'bin'
        $marker = Join-Path $rb 'in-progress'
        $layout = @{
            Root = $root; Bin = $bin; Rollback = $rb; Overrides = @{}; State = @{}
            Launcher = Join-Path $root 'launcher.cmd'; StatePath = Join-Path $root 'install-state.json'
            Log = Join-Path $root 'daemon.log'; Task = 'fixture'
        }
        [void][IO.Directory]::CreateDirectory($savedBin)
        [void][IO.Directory]::CreateDirectory($bin)
        [IO.File]::WriteAllText($marker, 'U7')
        [IO.File]::WriteAllText((Join-Path $rb 'meta.json'), '{"fresh":false,"stamp":"test"}')
        foreach ($name in 'path', 'vars', 'wrote') { [IO.File]::WriteAllText((Join-Path $rb "$name.json"), '{}') }
        [IO.File]::WriteAllText((Join-Path $rb 'profiles.json'), '[]')
        [IO.File]::WriteAllText((Join-Path $rb 'task.xml'), '<fixture/>')
        [IO.File]::WriteAllText((Join-Path $savedBin 'sync_gate.exe'), 'snapshot')
        [IO.File]::WriteAllText((Join-Path $bin 'sync_gated.exe.old-test'), 'renamed')
        [IO.File]::WriteAllText((Join-Path $bin 'sync_gate_mcp.exe'), 'new')

        # Exercise the real recovery and U7 while substituting registry, daemon and MCP operations.
        function Read-SgPathRaw { @{} }
        function Open-SgEnvKey { param($Key, [switch]$Write) [IO.MemoryStream]::new() }
        function Unregister-ScheduledTask { param($TaskName, $Confirm, $ErrorAction) }
        function Get-SgFreshEnv { @{ Path = '' } }
        $calls = [Collections.Generic.List[string]]::new()
        function Register-ScheduledTask { param($TaskName, $Xml, [switch]$Force) $calls.Add('task registration') }
        function Start-SyncGateDaemon { param($Layout) $calls.Add('daemon start') }
        function Invoke-SgNative { param($File, $Arguments, $Env) $calls.Add(($Arguments -join ' ')); @{ ExitCode = 0 } }
        function Get-SyncGateLayout { $layout }
        # The judge is bin\sync_gate.exe of the layout's root; what it checks is covered by test-install.ps1.
        function Get-SgInstallRoot { Split-Path -Parent $layout.Bin }
        function Assert-SgPrivateFiles { }
        function Get-SyncGatePaths { @{} }
        function Find-SgConfigReferences { }
        function Save-SyncGateRollback { param($Layout, $Fresh, $Stamp, $FirstStep) [IO.File]::WriteAllText($marker, $FirstStep) }
        function Invoke-SgStep {
            param($Layout, $Step, $Body)
            if ($Step -eq 'U7') { Set-SgStep $Layout $Step; & $Body }
        }
        $committedAtDelete = [Collections.Generic.List[bool]]::new()
        function Remove-Item {
            [CmdletBinding()]
            param([string]$LiteralPath, [switch]$Recurse, [switch]$Force)
            if ($LiteralPath -like (Join-Path $bin '*.old-*')) { $committedAtDelete.Add(-not [IO.File]::Exists($marker)) }
            Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
        }

        $problems = @(Restore-SyncGateRollback $layout)
        $restoredSnapshot = (Test-Path -LiteralPath (Join-Path $bin 'sync_gate.exe')) -and [IO.File]::ReadAllText((Join-Path $bin 'sync_gate.exe')) -eq 'snapshot'
        $restoredRenamed = [IO.File]::ReadAllText((Join-Path $bin 'sync_gated.exe')) -eq 'renamed'
        $keptNew = [IO.File]::ReadAllText((Join-Path $bin 'sync_gate_mcp.exe')) -eq 'new'
        Assert-That (($calls -join '|') -match 'task registration' -and ($calls -join '|') -match 'shims install' -and $calls[-1] -eq 'daemon start') 'consistent recovery did not resume the old install'
        $calls.Clear()
        [IO.File]::WriteAllText((Join-Path $bin 'sync_gate.exe'), 'fixture')
        [IO.File]::WriteAllText((Join-Path $savedBin 'sync_gated.exe'), 'renamed')
        [IO.File]::WriteAllText((Join-Path $bin 'sync_gated.exe'), 'new daemon')
        $conflict = @(Restore-SyncGateRollback $layout)
        Assert-That ($conflict.Count -eq 2 -and $conflict[0] -match 'sync_gate.exe .*changed by someone else' -and $conflict[1] -match 'sync_gated.exe .*changed by someone else') 'U7 failed to report both replacement conflicts'
        Assert-That ([IO.File]::ReadAllText((Join-Path $bin 'sync_gate.exe')) -eq 'fixture') 'U7 overwrote a replacement'
        Assert-That ($calls.Count -eq 0) "U7 tried to activate an inconsistent install: $($calls -join ', ')"
        try { Invoke-SyncGateUninstall; throw 'uninstall advanced past failed U7 recovery' }
        catch { Assert-That ($_.Exception.Message -match 'could not restore .*files kept' -and [IO.File]::Exists($marker)) 'uninstall failed to keep and report the rollback journal' }
        Assert-That ($calls.Count -eq 0) 'uninstall called an executable after U7 recovery failed'
        [IO.File]::Delete((Join-Path $savedBin 'sync_gate.exe'))
        $missing = @(Restore-SyncGateRollback $layout)
        Assert-That ($missing[0] -match 'sync_gate.exe .*previous binary is missing' -and $calls.Count -eq 0) 'U7 accepted a replacement without a previous binary to verify it against'
        Remove-Item -LiteralPath $marker -Force
        $foreign = Join-Path $bin 'tool.exe.old-20000101000000'
        [IO.File]::WriteAllText($foreign, 'foreign')
        $null = Invoke-SyncGateUninstall 6>&1
        $failures = @()
        if ($problems.Count -ne 0 -or -not ($restoredSnapshot -and $restoredRenamed -and $keptNew)) { $failures += 'U7 rollback lost the snapshot, renamed original or unrelated file' }
        if ($committedAtDelete.Count -ne 3) { $failures += 'U7 did not delete exactly the three installed executables' }
        if ($committedAtDelete -contains $false) { $failures += 'U7 deleted old executables while the journal was still in progress' }
        if (-not [IO.File]::Exists($foreign)) { $failures += 'U7 cleanup deleted a foreign file' }
        Assert-That ($failures.Count -eq 0) ($failures -join "`n")
        Write-Host 'PASS U7 snapshot recovery and journal completion before deletion'
    } }
    if ($Only -contains 'References') { & {
        $env:USERPROFILE = Join-Path $folder 'profile'
        $env:CLAUDE_CONFIG_DIR = ''
        $env:CODEX_HOME = ''
        $bin = Join-Path $folder 'bin'
        $claudeHome = Join-Path $folder 'claude-agent'
        $codexHome = Join-Path $folder 'codex-agent'
        foreach ($dir in $bin, (Join-Path $env:USERPROFILE '.codex'), $claudeHome, $codexHome) {
            [void][IO.Directory]::CreateDirectory($dir)
        }
        $exe = Join-Path $bin 'sync_gate.exe'
        [IO.File]::WriteAllText($exe, 'fixture')
        $defaultClaude = Join-Path $env:USERPROFILE '.claude.json'
        $defaultCodex = Join-Path $env:USERPROFILE '.codex\config.toml'
        $customClaude = Join-Path $claudeHome '.claude.json'
        $customCodex = Join-Path $codexHome 'config.toml'
        $alternate = Join-Path $folder 'alternate.config'
        [IO.File]::WriteAllText($alternate, '')
        foreach ($config in $defaultClaude, $defaultCodex, $customClaude, $customCodex) {
            [IO.File]::WriteAllText($config, $exe)
        }
        $layout = @{ Bin = $bin; Rollback = (Join-Path $folder 'unused'); Overrides = @{} }
        $seen = @{}
        function Get-SyncGateLayout { $layout }
        # The judge is bin\sync_gate.exe of the layout's root; what it checks is covered by test-install.ps1.
        function Get-SgInstallRoot { Split-Path -Parent $layout.Bin }
        function Assert-SgPrivateFiles { }
        function Get-SyncGatePaths { @{} }
        function Invoke-SgNative { param($File, $Arguments, $Env) $seen.Restore = $Arguments; @{ ExitCode = 0 } }
        function Save-SyncGateRollback { throw 'uninstall advanced past the config guard' }

        $wrong = @(foreach ($case in @(
            @{ Ref = $defaultClaude; Flags = '' },
            @{ ClaudeOverride = $alternate; Ref = $defaultCodex; Flags = "|--claude-config|$alternate" },
            @{ CodexOverride = $alternate; Ref = $defaultClaude; Flags = "|--codex-config|$alternate" },
            @{ CodexOverride = $alternate; ClaudeDir = $claudeHome; Ref = $customClaude; Flags = "|--codex-config|$alternate" },
            @{ ClaudeOverride = $alternate; CodexDir = $codexHome; Ref = $customCodex; Flags = "|--claude-config|$alternate" }
        )) {
            $layout.ClaudeConfig = $case.ClaudeOverride
            $layout.CodexConfig = $case.CodexOverride
            $env:CLAUDE_CONFIG_DIR = $case.ClaudeDir
            $env:CODEX_HOME = $case.CodexDir
            $output = @( & {
                try { Invoke-SyncGateUninstall } catch { $_.Exception.Message }
            } 6>&1) -join "`n"
            $restore = $seen.Restore -join '|'
            if (-not $output.Contains("$($case.Ref):1") -or [IO.File]::ReadAllText($exe) -ne 'fixture') {
                "uninstall did not protect $($case.Ref): $output"
            }
            if ($restore -ne "mcp|restore|--strict$($case.Flags)") {
                "restore filtered the adoption record using inferred configs: $restore"
            }
        })
        Assert-That ($wrong.Count -eq 0) ($wrong -join "`n")
        Write-Host 'PASS strict adoption restore keeps its scope and each agent config is guarded'

        $env:LOCALAPPDATA = Join-Path $folder 'local-app-data'
        $defaultBin = Join-Path $env:LOCALAPPDATA 'sync_labs\sync_gate\bin'
        [void][IO.Directory]::CreateDirectory($defaultBin)
        [IO.File]::WriteAllText((Join-Path $defaultBin 'sync_gate.exe'), 'fixture')
        $layout.Bin = $defaultBin
        $layout.ClaudeConfig = $defaultClaude
        $layout.CodexConfig = $defaultCodex
        $checkout = Join-Path $folder 'projects\sync_labs\sync_gate'
        $marketplace = @{ source = @{ source = 'directory'; path = $checkout } } | ConvertTo-Json -Depth 4
        [IO.File]::WriteAllText($defaultClaude, $marketplace)
        [IO.File]::WriteAllText($defaultCodex, "[projects.'$checkout']`ntrust_level = 'trusted'")
        $refs = @(Find-SgConfigReferences -Bin $defaultBin -Files @($defaultClaude, $defaultCodex))
        Assert-That ($refs.Count -eq 0) "checkout metadata blocked uninstall: $refs"
        try { Invoke-SyncGateUninstall }
        catch { Assert-That ($_.Exception.Message -eq 'uninstall advanced past the config guard') $_.Exception.Message }

        $launcher = Join-Path $defaultBin 'sync_gate_mcp.exe'
        $json = @{ command = $launcher } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText($defaultClaude, $json)
        [IO.File]::WriteAllLines($defaultCodex, @(
            'command = ''%LOCALAPPDATA%\sync_labs\sync_gate\bin\sync_gate.exe''',
            'args = [''${env:LOCALAPPDATA}/sync_labs/sync_gate/bin/SYNC_GATED'']',
            ('command = ''{0}''' -f $launcher.Replace('\', '//')),
            "command = '$defaultBin-extra\sync_gate.exe'",
            "command = '$launcher.backup'",
            "command = '$checkout\bin\sync_gate.exe'"
        ))
        $refs = @(Find-SgConfigReferences -Bin $defaultBin -Files @($defaultClaude, $defaultCodex))
        $expected = "${defaultClaude}:1|${defaultCodex}:1|${defaultCodex}:2|${defaultCodex}:3"
        Assert-That (($refs -join '|') -eq $expected) "the guard reported the wrong executable references: $refs"
        $refs = @(Find-SgConfigReferences -Bin $bin -Files @($defaultClaude, $defaultCodex))
        Assert-That ($refs.Count -eq 0) "a different install root blocked uninstall: $refs"
        Write-Host 'PASS checkout metadata does not block uninstall and only installed executable paths are guarded'

        $accent = [string][char]0x00e9
        $layout.Bin = Join-Path $folder "install-${accent}\bin"
        [void][IO.Directory]::CreateDirectory($layout.Bin)
        $installed = Join-Path $layout.Bin 'sync_gate.exe'
        $dotPath = $layout.Bin + '\.\sync_gate.exe'
        [IO.File]::WriteAllText($installed, 'fixture')
        [IO.File]::WriteAllText($defaultCodex, '')
        $wrong = @(foreach ($case in @(
            @{ Name = 'JSON Unicode escape'; Command = $installed; EncodeAccent = $true },
            @{ Name = 'dot path segment'; Command = $dotPath }
        )) {
            Assert-That ([IO.File]::Exists($case.Command)) "$($case.Name) did not point to a fixture"
            $json = @{ mcpServers = @{ example = @{ command = $case.Command } } } | ConvertTo-Json -Depth 4 -Compress
            if ($case.EncodeAccent) { $json = $json.Replace($accent, '\u00e9') }
            [IO.File]::WriteAllText($defaultClaude, $json)
            $output = @( & {
                try { Invoke-SyncGateUninstall } catch { $_.Exception.Message }
            } 6>&1) -join "`n"
            if (-not $output.Contains("${defaultClaude}:1") -or [IO.File]::ReadAllText($installed) -ne 'fixture') {
                "uninstall did not protect $($case.Name): $output"
            }
        })
        Assert-That ($wrong.Count -eq 0) ($wrong -join "`n")
        Write-Host 'PASS uninstall protects executable paths with JSON Unicode escapes and dot segments'
    } }
    if ($Only -contains 'Journal') { & {
        $rb = Join-Path $folder 'journal'
        [void][IO.Directory]::CreateDirectory($rb)
        $layout = @{ Rollback = $rb }
        $marker = Join-Path $rb 'in-progress'
        Set-SgStep $layout 'U6'
        & {
            function Write-SgTextFile {
                param($Path, $Text)
                [IO.File]::WriteAllText($Path, '')
                throw 'interrupted marker write'
            }
            try { Set-SgStep $layout 'U7' } catch {
                if ($_.Exception.Message -ne 'interrupted marker write') { throw }
            }
        }
        Assert-That ([IO.File]::ReadAllText($marker) -eq 'U6') 'interrupted publication destroyed the last complete step'
        Set-SgStep $layout 'U7'
        Assert-That ([IO.File]::ReadAllText($marker) -eq 'U7') 'retry did not replace the old marker'
        [IO.File]::WriteAllText($marker, '')
        try { Restore-SyncGateRollback $layout; throw 'an empty marker was accepted' }
        catch { Assert-That ($_.Exception.Message -match 'unknown rollback step' -and [IO.File]::Exists($marker)) 'empty marker gave no recovery diagnostic' }

        $observed = [Collections.Generic.List[bool]]::new()
        function Restore-SyncGateRollback { }
        function Remove-Item {
            [CmdletBinding()]
            param($LiteralPath, [switch]$Recurse, [switch]$Force)
            if ($LiteralPath -eq $rb -and $Recurse) { $observed.Add(-not [IO.File]::Exists($marker)) }
            Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
        }
        Resolve-SgFailure -Layout $layout -What 'fixture' -Step 'U7' -Cause 'fixture' -Fresh $true 6>$null
        Assert-That ($observed.Count -eq 1 -and $observed[0]) 'rollback cleanup began while the marker was active'
        Write-Host 'PASS atomic journal marker and rollback cleanup order'
    } }
    if ($Only -contains 'ResumeLayout') { & {
        $root = Join-Path $folder 'resume'
        $rb = Join-Path $root 'rollback'
        [void][IO.Directory]::CreateDirectory($rb)
        $env:SYNC_GATE_INSTALL_DIR = $root
        $env:SYNC_GATE_TASK_NAME = ''
        $env:SYNC_GATE_ENV_KEY = ''
        $env:SYNC_GATE_PROFILE_PATHS = ''
        $profilePath = Join-Path $folder 'fixture.ps1'
        $old = @{ test = @{
            SYNC_GATE_TASK_NAME = 'FixtureOriginal'
            SYNC_GATE_ENV_KEY = 'HKCU:\Software\FixtureOriginal'
            SYNC_GATE_PROFILE_PATHS = $profilePath
        } }
        [IO.File]::WriteAllText((Join-Path $rb 'in-progress'), 'U7')
        [IO.File]::WriteAllText((Join-Path $rb 'install-state.json'), ($old | ConvertTo-Json))
        $saved = Get-SyncGateLayout
        Assert-That ($saved.Task -eq 'FixtureOriginal' -and $saved.EnvKey -eq 'HKCU:\Software\FixtureOriginal' -and $saved.Profiles[0].Path -eq $profilePath) 'resume resolved defaults after U6 deleted install-state.json'

        $old.test.SYNC_GATE_TASK_NAME = 'FixtureAttempt'
        [IO.File]::WriteAllText((Join-Path $rb 'meta.json'), (@{ test = $old.test } | ConvertTo-Json))
        $env:SYNC_GATE_TASK_NAME = 'FixtureNext'
        $active = Get-SyncGateLayout
        Assert-That ($active.Task -eq 'FixtureAttempt') 'resume applied a new override instead of the recorded rollback target'
        [IO.File]::Delete((Join-Path $rb 'in-progress'))
        $next = Get-SyncGateLayout
        Assert-That ($next.Task -eq 'FixtureNext') 'an inactive journal overrode the next run'
        Write-Host 'PASS resume restores targets from the active journal'
    } }
} finally {
    foreach ($entry in $previousEnv.GetEnumerator()) { [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value) }
    Remove-Item -LiteralPath $folder -Recurse -Force
}
