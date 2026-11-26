<#
.SYNOPSIS
  Scenario tests for install.ps1 (3.1 to 3.15 and a few binary-free unit scenarios, "u" suffix).
.DESCRIPTION
  test-install.ps1 -BinDir <folder with sync_gate.exe, sync_gated.exe, sync_gate_mcp.exe> [-Only 3.1,3.6u]
  Everything runs in a throwaway area: install folder, data folder, config, pipe name, task name, registry
  key, profiles and agent configs all use random test names. It refuses to run as administrator or when any
  of them equals the real value, and it checks before and after: scheduled tasks, the real user variables
  key, the real daemon pid (if one runs) and the real data folder listing.
  Needs the binaries of Tasks 1, 1b and 2 (`sync_gate paths`, `mcp restore --strict`, SYNC_GATE_SOCKET).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BinDir,
    [string[]]$Only
)

$ErrorActionPreference = 'Stop'
if ($Only) { $Only = @($Only | ForEach-Object { $_ -split ',' }) }   # `-File ... -Only a,b` arrives as one string
$script:Installer = Join-Path $PSScriptRoot 'install.ps1'
$env:SYNC_GATE_INSTALL_NO_MAIN = '1'
. $script:Installer

# ---------------------------------------------------------------- guards and setup

if ((Get-SgIntegrity) -notin @('Medium Mandatory Level', 'Low Mandatory Level')) {
    throw 'refusing to run: this process is elevated (the installer and its tests must run as a normal user)'
}
# The ONE place that deletes a registry key. It refuses anything that is not a key the test itself created
# (Software\synclabs-test-<8 hex> and below) and never passes a bare first segment such as 'Software'.
function Assert-SgTestKeyPath {
    param([string]$SubKey)
    # \z (not $, which accepts a trailing newline) and -cmatch (case-sensitive).
    if ($SubKey -cnotmatch '^Software\\synclabs-test-[0-9a-f]{8}(\\[^\\\r\n][^\r\n]*)?\z' -or $SubKey -cmatch '(^|\\)\.\.(\\|\z)') {
        throw "refusing to touch registry key '$SubKey': not a Software\synclabs-test-<8 hex> key"
    }
}
function Remove-SgTestKey {
    param([string]$SubKey)
    Assert-SgTestKeyPath $SubKey
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($SubKey, $false)
}
# Guard self-check: runs before anything else that touches the registry (it deletes nothing that exists).
foreach ($bad in 'Software', 'Software\Microsoft', '', 'Software\synclabs-test-zz', 'Software\synclabs-test-abcd1234x', 'Software\synclabs-test-abcd1234\..\..', 'Software\synclabs-test-abcd1234\', 'Environment', "Software\synclabs-test-0123abcd`n", 'SOFTWARE\SYNCLABS-TEST-0123ABCD') {
    $threw = $false; try { Remove-SgTestKey $bad } catch { $threw = $true }
    if (-not $threw) { throw "key guard failed: '$bad' was accepted" }
}
Assert-SgTestKeyPath 'Software\synclabs-test-abcd1234'
Assert-SgTestKeyPath 'Software\synclabs-test-abcd1234\Environment'
Remove-SgTestKey 'Software\synclabs-test-00000000'   # valid name that does not exist: a no-op
Write-Host 'PASS guard (registry key guard)'

function Assert-SgIsolated {
    # What the binary resolves under the test environment must differ from the real socket, data and config;
    # an old build, or a variable ignored on some path, would otherwise put the test daemon next to the real one.
    # The daemon of an install is started by Task Scheduler, so a fake account name cannot be injected into it
    # (and would make the CLI a guest); the resolved names are the check.
    param([string]$Bin, [hashtable]$TestEnv, [hashtable]$Real)
    $got = Get-SyncGatePaths -Bin $Bin -Env $TestEnv
    if ($got.socket -eq $Real.socket) { throw "refusing to run: with the test environment the binary resolves the REAL socket '$($got.socket)'" }
    if (Test-SgSamePath $got.data $Real.data) { throw "refusing to run: with the test environment the binary resolves the REAL data folder '$($got.data)'" }
    if ($got.config -eq $Real.config) { throw "refusing to run: with the test environment the binary resolves the REAL config '$($got.config)'" }
}

$BinDir = (Resolve-Path -LiteralPath $BinDir).Path
foreach ($n in $script:SgExes) { if (-not (Test-Path -LiteralPath (Join-Path $BinDir $n))) { throw "$n not found in $BinDir" } }

$run = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$work = Join-Path ([IO.Path]::GetTempPath()) "trabalho\sync_gate\$((Get-Date).ToString('yyyy-MM-dd'))-install"
$tmp = Join-Path $work "run-$run"
$assets = Join-Path $work 'assets'
[void](New-Item -ItemType Directory -Force -Path $tmp, $assets)

# Real values, from the binary itself with a clean SYNC_GATE_* environment (the test never touches them).
$realPaths = Get-SyncGatePaths -Bin (Join-Path $BinDir 'sync_gate.exe') -Env @{}
$realRoot = Join-Path $env:LOCALAPPDATA 'sync_labs\sync_gate'

$script:Base = [ordered]@{
    SYNC_GATE_INSTALL_DIR    = Join-Path $tmp 'inst'
    SYNC_GATE_DATA_DIR       = Join-Path $tmp 'data'
    SYNC_GATE_CONFIG         = Join-Path $tmp 'config.toml'
    SYNC_GATE_SOCKET         = "sync_gate-t3-$run"
    SYNC_GATE_TASK_NAME      = "sync_gate_t3_$run"
    SYNC_GATE_ENV_KEY        = "HKCU:\Software\synclabs-test-$run\Environment"
    SYNC_GATE_PROFILE_PATHS  = (Join-Path $tmp 'prof\ps5\profile.ps1') + ';' + (Join-Path $tmp 'prof\ps7\profile.ps1')
    SYNC_GATE_CLAUDE_CONFIG  = Join-Path $tmp 'claude.json'
    SYNC_GATE_CODEX_CONFIG   = Join-Path $tmp 'codex.toml'
    SYNC_GATE_TEST_POLICY    = 'RemoteSigned'
}
$B = $script:Base
$real = @{
    install = $realRoot; data = $realPaths.data; config = $realPaths.config; socket = $realPaths.socket
    task = 'sync_gate'; key = 'HKCU:\Environment'
}
if ((Test-SgSamePath $B.SYNC_GATE_INSTALL_DIR $real.install) -or (Test-SgSamePath $B.SYNC_GATE_DATA_DIR $real.data) -or
    $B.SYNC_GATE_CONFIG -eq $real.config -or $B.SYNC_GATE_SOCKET -eq $real.socket -or
    $B.SYNC_GATE_TASK_NAME -eq $real.task -or $B.SYNC_GATE_ENV_KEY -eq $real.key) {
    throw 'refusing to run: a test name equals the real one'
}
$testEnv = @{}; foreach ($k in $B.Keys) { $testEnv[$k] = $B[$k] }
Assert-SgIsolated -Bin (Join-Path $BinDir 'sync_gate.exe') -TestEnv $testEnv -Real $real
foreach ($k in $B.Keys) { Set-Item -Path "env:$k" -Value $B[$k] }   # this process only, for Get-SyncGateLayout

function Get-RealDataListing {
    if (-not (Test-Path -LiteralPath $real.data)) { return 'absent' }
    $s = Get-ChildItem -LiteralPath $real.data -Recurse -Force -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.FullName)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" }
    ($s -join "`n")
}
function Get-RealKeyDump {
    $k = Open-SgEnvKey $real.key
    try { ($k.GetValueNames() | Sort-Object | ForEach-Object { "$_=$($k.GetValue($_, $null, 'DoNotExpandEnvironmentNames'))" }) -join "`n" } finally { $k.Dispose() }
}
function Get-RealDaemonPids {
    @(Get-SgDaemonProcesses | Where-Object { $_.Path -and -not $_.Path.StartsWith($tmp, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { $_.Pid } | Sort-Object)
}
$before = @{
    Tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue).Count
    Key = Get-RealKeyDump; Pids = (Get-RealDaemonPids) -join ','; Data = Get-RealDataListing
}

# ---------------------------------------------------------------- assets: "new" zip, "old" zip (+16 bytes, P59)

$ver = ((& (Join-Path $BinDir 'sync_gate.exe') --version) -replace '^\S+\s+(\d+\.\d+\.\d+).*$', '$1')
if ($ver -notmatch '^\d+\.\d+\.\d+$') { throw "cannot read the version from sync_gate --version: $ver" }
$zipName = "sync_gate-$ver-$script:SgTarget.zip"
function New-Release {
    param([string]$Name, [switch]$Pad)
    $dir = Join-Path $assets $Name
    $stage = Join-Path $dir 'stage'
    [void](New-Item -ItemType Directory -Force -Path $stage)
    foreach ($n in $script:SgExes) {
        Copy-Item -LiteralPath (Join-Path $BinDir $n) -Destination (Join-Path $stage $n)
        if ($Pad) { $fs = [IO.File]::Open((Join-Path $stage $n), 'Append'); try { $fs.Write([byte[]](1..16), 0, 16) } finally { $fs.Close() } }
    }
    Set-Content -LiteralPath (Join-Path $stage 'LICENSE-MIT') -Value 'test'
    Set-Content -LiteralPath (Join-Path $stage 'LICENSE-APACHE') -Value 'test'
    $zip = Join-Path $dir $zipName
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
    $h = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
    Set-Content -LiteralPath (Join-Path $dir 'SHA256SUMS') -Value "$h  $zipName" -Encoding ASCII
    Remove-Item -LiteralPath $stage -Recurse -Force
    $dir
}
$FromNew = New-Release 'new'
$FromOld = New-Release 'old' -Pad
$HashNew = @{}; $HashOld = @{}   # exe name -> hash, for the comparisons below
foreach ($n in $script:SgExes) {
    $HashNew[$n] = (Get-FileHash -LiteralPath (Join-Path $BinDir $n)).Hash
    $f = Join-Path $BinDir $n
    $HashOld[$n] = (& { $bytes = [IO.File]::ReadAllBytes($f) + [byte[]](1..16); Get-SgHash $bytes })
}

# ---------------------------------------------------------------- harness

$script:Fails = 0
$script:Ran = 0
function Assert-That { param([bool]$Cond, [string]$Msg) if (-not $Cond) { throw $Msg } }

function Invoke-Scenario {
    param([string]$Id, [scriptblock]$Body)
    if ($Only -and -not ($Only | Where-Object { $Id -eq $_ -or $Id -like "$_*" })) { return }
    $script:Ran++
    try { Reset-Area; & $Body; Write-Host "PASS $Id" }
    catch { $script:Fails++; Write-Host "FAIL ${Id}: $($_.Exception.Message)" }
}

function Invoke-Inst {
    param([string]$From, [hashtable]$Extra = @{}, [string[]]$Without = @(), [string[]]$Arguments = @(), [switch]$Uninstall)
    $e = @{}; foreach ($k in $B.Keys) { $e[$k] = $B[$k] }
    foreach ($w in $Without) { $e.Remove($w) }
    foreach ($k in $Extra.Keys) { $e[$k] = $Extra[$k] }
    if ($From) { $e['SYNC_GATE_INSTALL_FROM'] = $From }
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:Installer) + $Arguments
    if ($Uninstall) { $a += '-Uninstall' }
    $r = Invoke-SgNative -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Arguments $a -Env $e -TimeoutSec 400
    [pscustomobject]@{ Code = $r.ExitCode; Text = ($r.Out + $r.Err) }
}

function Get-TestLayout { Get-SyncGateLayout }
function Get-InstEnv { $e = @{}; foreach ($k in $B.Keys) { $e[$k] = $B[$k] }; $e }
function Invoke-Bin { param([string[]]$Arguments, [hashtable]$Env)
    $e = $Env; if (-not $e) { $e = Get-InstEnv }
    Invoke-SgNative -File (Join-Path $B.SYNC_GATE_INSTALL_DIR 'bin\sync_gate.exe') -Arguments $Arguments -Env $e -TimeoutSec 60 }

function Stop-TestDaemons {
    foreach ($p in (Get-SgDaemonProcesses)) {
        if ($p.Path -and $p.Path.StartsWith($tmp, [StringComparison]::OrdinalIgnoreCase)) { Stop-Process -Id $p.Pid -Force -ErrorAction SilentlyContinue }
    }
    foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($tmp, [StringComparison]::OrdinalIgnoreCase) })) {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function Reset-Area {
    Stop-ScheduledTask -TaskName $B.SYNC_GATE_TASK_NAME -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $B.SYNC_GATE_TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    Stop-TestDaemons
    $sub = $B.SYNC_GATE_ENV_KEY -replace '^HKCU:\\', ''
    # Only the random test key (two levels down); Remove-SgTestKey throws for anything else.
    Remove-SgTestKey ((($sub -split '\\')[0..1]) -join '\')
    foreach ($d in 'inst', 'data', 'prof', 'stranger') { $p = Join-Path $tmp $d; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } }
    foreach ($f in 'config.toml', 'claude.json', 'codex.toml', 'mark.txt') { $p = Join-Path $tmp $f; if (Test-Path -LiteralPath $p) { Set-ItemProperty -LiteralPath $p -Name IsReadOnly -Value $false; Remove-Item -LiteralPath $p -Force } }
    foreach ($k in $B.Keys) { Set-Item -Path "env:$k" -Value $B[$k] }
}

function Set-TestPath {
    param([string]$Raw, [string]$Kind)
    $k = Open-SgEnvKey $B.SYNC_GATE_ENV_KEY -Write
    try { $k.SetValue('Path', $Raw, [Microsoft.Win32.RegistryValueKind]$Kind) } finally { $k.Dispose() }
}

function Get-Snap {
    $L = Get-TestLayout
    $task = ''
    if (Get-ScheduledTask -TaskName $L.Task -ErrorAction SilentlyContinue) { $task = ([string](Export-ScheduledTask -TaskName $L.Task)) -replace '<Date>[^<]*</Date>', '' }
    $vars = [ordered]@{}; foreach ($n in $script:SgOwnNames) { $vars[$n] = Read-SgUserVar $L.EnvKey $n }
    $prof = @($L.Profiles | ForEach-Object { Get-SgHash $(if (Test-Path -LiteralPath $_.Path) { [IO.File]::ReadAllBytes($_.Path) } else { $null }) })
    $bin = @(); if (Test-Path -LiteralPath $L.Bin) { $bin = @(Get-ChildItem -LiteralPath $L.Bin -Force | Sort-Object Name | ForEach-Object { "$($_.Name)=$((Get-FileHash -LiteralPath $_.FullName).Hash)" }) }
    $hf = { param($p) if (Test-Path -LiteralPath $p) { (Get-FileHash -LiteralPath $p).Hash } else { 'absent' } }
    ConvertTo-Json -Compress -Depth 5 ([ordered]@{
        task = $task; path = (Read-SgPathRaw $L.EnvKey); vars = $vars; profiles = $prof; bin = $bin
        state = (& $hf $L.StatePath); launcher = (& $hf $L.Launcher); rollback = (Test-Path -LiteralPath $L.Rollback)
    })
}

function Get-ParentChain {
    param([int]$ProcId)
    $names = @()
    $cur = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcId"
    for ($i = 0; $i -lt 6 -and $cur; $i++) {
        $cur = Get-CimInstance Win32_Process -Filter "ProcessId=$($cur.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($cur) { $names += $cur.Name }
    }
    , $names
}
function Get-BinDaemon {
    $L = Get-TestLayout
    @(Get-SgDaemonProcesses | Where-Object { Test-SgSamePath $_.Path (Join-Path $L.Bin 'sync_gated.exe') })
}
function Wait-Until { param([scriptblock]$Cond, [int]$Sec = 30) $d = [DateTime]::UtcNow.AddSeconds($Sec); while ([DateTime]::UtcNow -lt $d) { if (& $Cond) { return $true }; Start-Sleep -Milliseconds 300 }; $false }

function Start-Bg {
    param([string]$File, [string[]]$Arguments, [hashtable]$Env, [switch]$Stdin)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = (($Arguments | ForEach-Object { ConvertTo-SgQuotedArg $_ }) -join ' ')
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = [bool]$Stdin
    foreach ($k in @($psi.EnvironmentVariables.Keys)) { if ($k -match '^SYNC_GATE_') { $psi.EnvironmentVariables.Remove($k) } }
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    $p = [Diagnostics.Process]::Start($psi)
    [void]$p.StandardOutput.ReadToEndAsync(); [void]$p.StandardError.ReadToEndAsync()
    $p
}

function Install-Ok { param($From) $r = Invoke-Inst -From $From; Assert-That ($r.Code -eq 0) "install exited $($r.Code): $($r.Text)"; $r }

# ---------------------------------------------------------------- binary-free unit scenarios

Invoke-Scenario '3.6u' {
    $bin = 'C:\t\bin'; $shims = 'C:\t\shims'
    $seed = '%USERPROFILE%\x;C:\t\bin;C:\y'
    Set-TestPath $seed 'ExpandString'
    $r = Set-SyncGatePath -Key $B.SYNC_GATE_ENV_KEY -Front @($shims, $bin)
    $now = Read-SgPathRaw $B.SYNC_GATE_ENV_KEY
    Assert-That ($now.Kind -eq 'ExpandString' -and $now.Raw -ceq "$shims;$bin;$seed") "raw after install: $($now.Raw)"
    [void](Set-SyncGatePath -Key $B.SYNC_GATE_ENV_KEY -Front @($shims, $bin) -Placed @($shims, $bin))
    Assert-That ((Read-SgPathRaw $B.SYNC_GATE_ENV_KEY).Raw -ceq "$shims;$bin;$seed") 're-run changed the text'
    [void](Set-SyncGatePath -Key $B.SYNC_GATE_ENV_KEY -Placed @($shims, $bin) -Remove)
    $end = Read-SgPathRaw $B.SYNC_GATE_ENV_KEY
    Assert-That ($end.Raw -ceq $seed -and $end.Kind -eq 'ExpandString') "raw after uninstall: $($end.Raw)"
    $threw = $false; try { Test-SgPathEntries $B.SYNC_GATE_ENV_KEY @('C:\a;b') } catch { $threw = $true }
    Assert-That $threw "';' entry was not refused"
    $threw = $false; try { Test-SgPathEntries $B.SYNC_GATE_ENV_KEY @('C:\50%') } catch { $threw = $true }
    Assert-That $threw "'%' with an expanding PATH was not refused"
}

Invoke-Scenario '3.7' {
    Remove-Item env:SYNC_GATE_TEST_POLICY   # the override is for the other scenarios; Reset-Area puts it back
    foreach ($p in 'Restricted', 'AllSigned') { Assert-That (-not (Test-SyncGateProfileAllowed -Policy $p)) "$p allowed" }
    foreach ($p in 'RemoteSigned', 'Unrestricted', 'Bypass') { Assert-That (Test-SyncGateProfileAllowed -Policy $p) "$p refused" }
}

Invoke-Scenario '3.7u' {
    $dir = Join-Path $tmp 'prof\u'; [void](New-Item -ItemType Directory -Force -Path $dir)
    $f = Join-Path $dir 'profile.ps1'
    $orig = [Text.Encoding]::UTF8.GetBytes("# mine`r`nSet-Alias x Get-Item")
    [IO.File]::WriteAllBytes($f, $orig)
    $profiles = @(@{ Path = $f; Host = 'powershell' })
    $env:SYNC_GATE_TEST_POLICY = 'Restricted'
    [void](Set-SyncGateProfileBlock -Profiles $profiles -Shims 'C:\s h\O''B')
    Assert-That ((Get-SgHash ([IO.File]::ReadAllBytes($f))) -eq (Get-SgHash $orig)) 'blocked policy changed the profile'
    $env:SYNC_GATE_TEST_POLICY = 'RemoteSigned'
    $ent = Set-SyncGateProfileBlock -Profiles $profiles -Shims 'C:\s h\O''B'
    Assert-That ([IO.File]::ReadAllText($f).Contains($script:SgBlockStart)) 'block not written'
    [void](Set-SyncGateProfileBlock -Profiles $profiles -Shims 'C:\s h\O''B' -Previous $ent)
    $txt = [IO.File]::ReadAllText($f)
    Assert-That (([regex]::Matches($txt, [regex]::Escape($script:SgBlockStart))).Count -eq 1) 're-run duplicated the block'
    $env:SYNC_GATE_TEST_POLICY = 'Restricted'
    [void](Set-SyncGateProfileBlock -Profiles $profiles -Remove -Previous $ent)
    Assert-That ((Get-SgHash ([IO.File]::ReadAllBytes($f))) -eq (Get-SgHash $orig)) 'remove did not restore the bytes (policy must not matter)'
    $env:SYNC_GATE_TEST_POLICY = 'RemoteSigned'
    $nf = Join-Path $dir 'new\profile.ps1'
    $ent2 = Set-SyncGateProfileBlock -Profiles @(@{ Path = $nf; Host = 'powershell' }) -Shims 'C:\s'
    Assert-That (Test-Path -LiteralPath $nf) 'new profile not created'
    [void](Set-SyncGateProfileBlock -Profiles @() -Remove -Previous $ent2)
    Assert-That (-not (Test-Path -LiteralPath $nf)) 'created profile not deleted when empty'
}

Invoke-Scenario '3.14u' {
    $shims = Join-Path $tmp "Sync Gate O'Brien %TEMP% & ^!\data\shims"
    $block = Get-SyncGateBlockText $shims
    $err = $null; [void][Management.Automation.Language.Parser]::ParseInput($block, [ref]$null, [ref]$err)
    Assert-That ($err.Count -eq 0) 'block does not parse'
    $prof = Join-Path $tmp 'apply-profile.ps1'; Set-Content -LiteralPath $prof -Value $block
    $apply = Join-Path $tmp 'apply.ps1'; Set-Content -LiteralPath $apply -Value 'param($p) . $p; ($env:Path -split '';'')[0]'
    $r = Invoke-SgNative -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $apply, $prof)
    Assert-That ($r.Out.Trim() -ceq $shims) "child Path starts with '$($r.Out.Trim())'"
    $L = Get-TestLayout
    $L.Overrides['SYNC_GATE_DATA_DIR'] = "C:\a'b %x% & ^!"
    [void](New-Item -ItemType Directory -Force -Path $L.Root)
    Write-SyncGateLauncher -Layout $L
    $txt = [IO.File]::ReadAllText($L.Launcher)
    Assert-That ($txt.Contains('set "SYNC_GATE_DATA_DIR=C:\a''b %%x%% & ^!"')) 'launcher did not double % in the set line'
    Assert-That ($txt.Contains('setlocal DisableDelayedExpansion')) 'launcher lacks DisableDelayedExpansion'
}

Invoke-Scenario '3.13u' {
    # -ClearOverrides is checked without starting a daemon: without the values the daemon would use the real pipe and data.
    [void](New-Item -ItemType Directory -Force -Path $B.SYNC_GATE_INSTALL_DIR)
    $L = Get-TestLayout
    $vars = Set-SyncGateUserVars -Key $L.EnvKey -Vars $L.Overrides
    Write-SyncGateLauncher -Layout $L
    Save-SgState -Layout $L -Version '0.0.0' -PathPlaced @() -Vars $vars -ProfileEntries @()
    foreach ($n in 'SYNC_GATE_SOCKET', 'SYNC_GATE_DATA_DIR', 'SYNC_GATE_CONFIG') {
        Assert-That ($null -ne (Read-SgUserVar $L.EnvKey $n)) "$n not in the key"
        Assert-That ([IO.File]::ReadAllText($L.Launcher).Contains("set `"$n=")) "$n not in the launcher"
        Assert-That ($null -ne (Read-SgState $L.StatePath).overrides.$n) "$n not in the state"
    }
    $L2 = Get-SyncGateLayout -ClearOverrides
    Assert-That ($L2.Overrides.Count -eq 0) '-ClearOverrides left values in the layout'
    [void](Set-SyncGateUserVars -Key $L2.EnvKey -Vars $L2.Overrides -Previous (Read-SgState $L.StatePath).vars)
    Write-SyncGateLauncher -Layout $L2
    Save-SgState -Layout $L2 -Version '0.0.0' -PathPlaced @() -Vars @{} -ProfileEntries @()
    foreach ($n in 'SYNC_GATE_SOCKET', 'SYNC_GATE_DATA_DIR', 'SYNC_GATE_CONFIG') {
        Assert-That ($null -eq (Read-SgUserVar $L.EnvKey $n)) "$n still in the key"
        Assert-That (-not [IO.File]::ReadAllText($L.Launcher).Contains("set `"$n=")) "$n still in the launcher"
        Assert-That ($null -eq (Read-SgState $L.StatePath).overrides.$n) "$n still in the state"
    }
}

Invoke-Scenario '3.0g' {
    # I-4: a binary that ignores the test variables (here a stand-in that always prints the real values) is refused.
    $leaky = Join-Path $tmp 'leaky.cmd'
    $lines = @('@echo off', "echo config=$($real.config)", "echo data=$($real.data)", 'echo shims=x', 'echo adopted=x', "echo socket=$($real.socket)", 'echo hub=x')
    Set-Content -LiteralPath $leaky -Value $lines -Encoding ASCII
    $msg = ''
    try { Assert-SgIsolated -Bin $leaky -TestEnv $testEnv -Real $real } catch { $msg = $_.Exception.Message }
    Assert-That ($msg -like 'refusing to run: with the test environment the binary resolves the REAL*') "the leaky binary was not refused: '$msg'"
    Assert-SgIsolated -Bin (Join-Path $BinDir 'sync_gate.exe') -TestEnv $testEnv -Real $real
}

Invoke-Scenario '3.7p' {
    # I-3: the effective policy must not depend on the policy the PARENT was started with (-ExecutionPolicy ...).
    Remove-Item env:SYNC_GATE_TEST_POLICY
    try {
        $env:PSExecutionPolicyPreference = 'AllSigned'; $a = Get-SgHostPolicy 'powershell'
        $env:PSExecutionPolicyPreference = 'Bypass'; $b2 = Get-SgHostPolicy 'powershell'
    } finally { Remove-Item env:PSExecutionPolicyPreference -ErrorAction SilentlyContinue }
    Assert-That ($a -eq $b2) "the policy follows the parent: AllSigned parent gave '$a', Bypass parent gave '$b2'"
}

Invoke-Scenario '3.11i1' {
    # I-1: -ClearOverrides, then a failure after S5: the user variables must come back.
    [void](New-Item -ItemType Directory -Force -Path $B.SYNC_GATE_INSTALL_DIR)
    $L = Get-TestLayout
    $vars = Set-SyncGateUserVars -Key $L.EnvKey -Vars $L.Overrides
    Write-SyncGateLauncher -Layout $L
    Save-SgState -Layout $L -Version '0.0.1' -PathPlaced @() -Vars $vars -ProfileEntries @()
    $L = Get-TestLayout
    $want = Read-SgUserVar $L.EnvKey 'SYNC_GATE_SOCKET'
    Assert-That ($want -eq $B.SYNC_GATE_SOCKET) 'setup: the socket variable is not in the key'
    Save-SyncGateRollback -Layout $L -Fresh $false -Stamp 's1' -FirstStep 'S1'
    $L2 = Get-SyncGateLayout -ClearOverrides
    Set-SgStep $L2 'S5'
    [void](Invoke-SgConfigure -Layout $L2 -Shims (Join-Path $tmp 'shims') -Version '0.0.1' -Old $L.State)
    Assert-That ($null -eq (Read-SgUserVar $L2.EnvKey 'SYNC_GATE_SOCKET')) 'setup: -ClearOverrides did not remove the variable'
    Set-SgStep $L2 'S6'
    $problems = @(Restore-SyncGateRollback -Layout $L2)
    Assert-That ($problems.Count -eq 0) "restore problems: $($problems -join '; ')"
    foreach ($n in 'SYNC_GATE_SOCKET', 'SYNC_GATE_DATA_DIR', 'SYNC_GATE_CONFIG') {
        Assert-That ((Read-SgUserVar $L2.EnvKey $n) -ceq $B[$n]) "$n in the key after the restore: '$(Read-SgUserVar $L2.EnvKey $n)'"
    }
    Assert-That ([IO.File]::ReadAllText($L2.Launcher).Contains('set "SYNC_GATE_SOCKET=')) 'the restored launcher lost the socket'
}

Invoke-Scenario '3.11i2' {
    # I-2: a failure INSIDE S5 (second profile read-only, after the first was written) must leave nothing behind.
    [void](New-Item -ItemType Directory -Force -Path $B.SYNC_GATE_INSTALL_DIR)
    $L = Get-TestLayout
    $p1 = $L.Profiles[0].Path; $p2 = $L.Profiles[1].Path
    [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p2))
    $orig = [Text.Encoding]::UTF8.GetBytes("# managed`r`n")
    [IO.File]::WriteAllBytes($p2, $orig)
    Set-ItemProperty -LiteralPath $p2 -Name IsReadOnly -Value $true
    try {
        $pathBefore = Read-SgPathRaw $L.EnvKey
        Save-SyncGateRollback -Layout $L -Fresh $true -Stamp 's2' -FirstStep 'S1'
        Set-SgStep $L 'S5'
        $threw = $false
        try { [void](Invoke-SgConfigure -Layout $L -Shims (Join-Path $tmp 'shims') -Version '0.0.1' -Old $null) } catch { $threw = $true }
        Assert-That $threw 'setup: the read-only profile did not make S5 fail'
        Assert-That (Test-Path -LiteralPath $p1) 'setup: the first profile was not written before the failure'
        $problems = @(Restore-SyncGateRollback -Layout $L)
        Assert-That ($problems.Count -eq 0) "restore problems: $($problems -join '; ')"
        Assert-That (-not (Test-Path -LiteralPath $p1)) 'the profile created by the failed run is still there'
        Assert-That ((Get-SgHash ([IO.File]::ReadAllBytes($p2))) -eq (Get-SgHash $orig)) 'the read-only profile changed'
        $pathAfter = Read-SgPathRaw $L.EnvKey
        Assert-That ($pathAfter.Present -eq $pathBefore.Present -and $pathAfter.Raw -ceq $pathBefore.Raw) 'PATH is not as before'
        foreach ($n in $script:SgOwnNames) { Assert-That ($null -eq (Read-SgUserVar $L.EnvKey $n)) "variable $n left" }
        Assert-That (-not (Test-Path -LiteralPath $L.Launcher) -and -not (Test-Path -LiteralPath $L.StatePath)) 'launcher or state left'
    } finally { Set-ItemProperty -LiteralPath $p2 -Name IsReadOnly -Value $false }
}

Invoke-Scenario '3.11m' {
    # I-2 through the whole flow: a read-only second profile makes S5 fail; the run must end restored.
    $L0 = Get-TestLayout
    $p2 = $L0.Profiles[1].Path
    [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p2))
    [IO.File]::WriteAllBytes($p2, [Text.Encoding]::UTF8.GetBytes("# managed`r`n"))
    Set-ItemProperty -LiteralPath $p2 -Name IsReadOnly -Value $true
    try {
        $s = Get-Snap
        $r = Invoke-Inst -From $FromNew
        Assert-That ($r.Code -eq 1 -and $r.Text -match 'previous version restored') "exit $($r.Code): $($r.Text)"
        Assert-That ((Get-Snap) -ceq $s) 'the state after the failed run differs from before'
    } finally { Set-ItemProperty -LiteralPath $p2 -Name IsReadOnly -Value $false }
}

Invoke-Scenario '3.7bom' {
    # A UTF-16 profile that holds only its BOM comes back byte for byte after install plus uninstall.
    $dir = Join-Path $tmp 'prof\bom'; [void](New-Item -ItemType Directory -Force -Path $dir)
    $f = Join-Path $dir 'profile.ps1'
    $orig = [byte[]](0xFF, 0xFE)
    [IO.File]::WriteAllBytes($f, $orig)
    $ent = Set-SyncGateProfileBlock -Profiles @(@{ Path = $f; Host = 'powershell' }) -Shims 'C:\s'
    [void](Set-SyncGateProfileBlock -Profiles @() -Remove -Previous $ent)
    $after = [BitConverter]::ToString([IO.File]::ReadAllBytes($f))
    Assert-That ($after -eq 'FF-FE') "BOM-only profile became $after"
}

Invoke-Scenario '3.14r' {
    # A root with '%' on a volume with no 8.3 name is refused by the pre-check, which leaves no folder behind.
    $root = Join-Path $tmp 'r %X% r\inst'
    function Get-SgShortPath { param([string]$Path) $null }   # stand-in: "8.3 not generated"
    $msg = ''
    try { Test-SgTaskRoot $root } catch { $msg = $_.Exception.Message }
    Assert-That ($msg -like "*has no 8.3 name*") "got '$msg'"
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $tmp 'r %X% r'))) 'the pre-check left its folder behind'
}

Invoke-Scenario 'zip' {
    # The release zip may come from `tar -a` (entries with a "./" prefix and a "./" directory entry); anything outside the list is refused.
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    function New-Zip([string]$Dir, [string[]]$Entries) {
        [void](New-Item -ItemType Directory -Force -Path $Dir)
        $zp = Join-Path $Dir $zipName
        if (Test-Path -LiteralPath $zp) { Remove-Item -LiteralPath $zp -Force }
        $za = [IO.Compression.ZipFile]::Open($zp, 'Create')
        try {
            foreach ($e in $Entries) {
                $en = $za.CreateEntry($e)
                if (-not $e.EndsWith('/')) { $s = $en.Open(); try { $s.Write([byte[]](65, 66), 0, 2) } finally { $s.Dispose() } }
            }
        } finally { $za.Dispose() }
        $h = (Get-FileHash -LiteralPath $zp -Algorithm SHA256).Hash.ToLower()
        Set-Content -LiteralPath (Join-Path $Dir 'SHA256SUMS') -Value "$h  $zipName" -Encoding ASCII
    }
    $exes = $script:SgExes + @('LICENSE-MIT', 'LICENSE-APACHE')
    $good = Join-Path $assets 'zip-good'; New-Zip $good (@('./') + @($exes | ForEach-Object { "./$_" }))
    $env:SYNC_GATE_INSTALL_FROM = $good
    try {
        $r = Get-SyncGateAssets -Dest (Join-Path $tmp 'dl-good')
        foreach ($n in $script:SgExes) { Assert-That (Test-Path -LiteralPath (Join-Path $r.Dir $n)) "$n not extracted from a ./-prefixed zip" }
        $bad = Join-Path $assets 'zip-bad'; New-Zip $bad (@($exes) + @('../evil.exe'))
        $env:SYNC_GATE_INSTALL_FROM = $bad
        $msg = ''; try { [void](Get-SyncGateAssets -Dest (Join-Path $tmp 'dl-bad')) } catch { $msg = $_.Exception.Message }
        Assert-That ($msg -like 'unexpected entry*') "a foreign entry was not refused: '$msg'"
        $bad2 = Join-Path $assets 'zip-bad2'; New-Zip $bad2 (@($exes) + @('sub/'))
        $env:SYNC_GATE_INSTALL_FROM = $bad2
        $msg = ''; try { [void](Get-SyncGateAssets -Dest (Join-Path $tmp 'dl-bad2')) } catch { $msg = $_.Exception.Message }
        Assert-That ($msg -like 'unexpected entry*') "a foreign directory entry was not refused: '$msg'"
    } finally { Remove-Item env:SYNC_GATE_INSTALL_FROM -ErrorAction SilentlyContinue }
}

Invoke-Scenario 'checksum' {
    $bad = Join-Path $assets 'bad'
    if (Test-Path -LiteralPath $bad) { Remove-Item -LiteralPath $bad -Recurse -Force }
    Copy-Item -LiteralPath $FromNew -Destination $bad -Recurse
    $z = Join-Path $bad $zipName
    $b = [IO.File]::ReadAllBytes($z); $b[$b.Length - 30] = $b[$b.Length - 30] -bxor 1; [IO.File]::WriteAllBytes($z, $b)
    $threw = ''
    $env:SYNC_GATE_INSTALL_FROM = $bad
    try { [void](Get-SyncGateAssets -Dest (Join-Path $tmp 'dl')) } catch { $threw = $_.Exception.Message } finally { Remove-Item env:SYNC_GATE_INSTALL_FROM }
    Assert-That ($threw -like 'checksum mismatch*') "got '$threw'"
}

# ---------------------------------------------------------------- scenarios with the real binaries

Invoke-Scenario '3.1' {
    $first = Install-Ok $FromNew
    $L = Get-TestLayout
    $dirs = Get-SyncGatePaths -Bin (Join-Path $L.Bin 'sync_gate.exe') -Env (Get-InstEnv)
    $xml = [xml](Export-ScheduledTask -TaskName $L.Task)
    $ns = New-Object Xml.XmlNamespaceManager $xml.NameTable; $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    Assert-That ($xml.SelectSingleNode('//t:ExecutionTimeLimit', $ns).InnerText -eq 'PT0S') 'ExecutionTimeLimit is not PT0S'
    Assert-That ($xml.SelectSingleNode('//t:MultipleInstancesPolicy', $ns).InnerText -eq 'IgnoreNew') 'MultipleInstancesPolicy is not IgnoreNew'
    Assert-That ($null -ne $xml.SelectSingleNode('//t:LogonTrigger', $ns)) 'no logon trigger'
    Assert-That ($xml.SelectSingleNode('//t:LogonTrigger/t:Repetition/t:Interval', $ns).InnerText -eq 'PT5M') 'repetition is not PT5M'
    Assert-That ((Read-SgPathRaw $L.EnvKey).Raw.StartsWith("$($dirs.shims);$($L.Bin)")) 'Path does not start with <shims>;<bin>'
    foreach ($p in $L.Profiles) { Assert-That ([IO.File]::ReadAllText($p.Path).TrimEnd().EndsWith($script:SgBlockEnd)) "profile $($p.Path) does not end with the block" }
    Assert-That (Test-Path -LiteralPath (Join-Path $dirs.shims 'npm.exe')) 'npm.exe shim missing'
    Test-SyncGateHealth -Layout $L
    $d = @(Get-BinDaemon); Assert-That ($d.Count -eq 1) "expected one sync_gated, found $($d.Count)"
    $chain = Get-ParentChain $d[0].Pid
    Assert-That ($chain.Count -ge 3 -and $chain[0] -eq 'cmd.exe' -and $chain[1] -eq 'conhost.exe' -and $chain[2] -eq 'svchost.exe') "parent chain: $($chain -join ' > ')"
    Assert-That (-not ($chain | Where-Object { $_ -match '^(powershell|pwsh|bash)\.exe$' })) "shell in the chain: $($chain -join ' > ')"
    # 3.15 (account): the first output line is the integrity line.
    Assert-That (($first.Text -split "\r?\n")[0] -eq 'integrity: Medium Mandatory Level') "first line: $(($first.Text -split "\r?\n")[0])"
}

Invoke-Scenario '3.1p' {
    # `shims install` decides "only a PowerShell script exists" from PATH: it must see what a new terminal sees
    # (machine + the key), not this process's PATH, which may predate the user's latest change. gradle is on neither here.
    $d = Join-Path $tmp 'prof\ps1only'; [void](New-Item -ItemType Directory -Force -Path $d)
    Set-Content -LiteralPath (Join-Path $d 'gradle.ps1') -Value 'exit 0'
    Set-TestPath $d 'String'
    [void](Install-Ok $FromNew)
    $dirs = Get-SyncGatePaths -Bin (Join-Path (Get-TestLayout).Bin 'sync_gate.exe') -Env (Get-InstEnv)
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $dirs.shims 'gradle.exe'))) 'gradle.exe shim created: it would hide the gradle.ps1 a new terminal finds on PATH'
    Assert-That (Test-Path -LiteralPath (Join-Path $dirs.shims 'npm.exe')) 'npm.exe shim missing'
}

Invoke-Scenario '3.2' {
    [void](Install-Ok $FromNew)
    $L = Get-TestLayout
    $snap1 = Get-Snap; $state1 = [IO.File]::ReadAllText($L.StatePath)
    [void](Install-Ok $FromNew)
    $raw = (Read-SgPathRaw $L.EnvKey).Raw -split ';'
    foreach ($d in @($raw | Select-Object -Unique)) { if ($d) { Assert-That (@($raw | Where-Object { $_ -ieq $d }).Count -eq 1) "'$d' appears more than once on Path" } }
    foreach ($p in $L.Profiles) { Assert-That (([regex]::Matches([IO.File]::ReadAllText($p.Path), [regex]::Escape($script:SgBlockStart))).Count -eq 1) "more than one block in $($p.Path)" }
    $a = $snap1 | ConvertFrom-Json; $b = Get-Snap | ConvertFrom-Json
    Assert-That ($a.task -eq $b.task) 'task definition changed on the second run'
    Assert-That ($state1 -ceq [IO.File]::ReadAllText($L.StatePath)) 'state changed on the second run'
}

Invoke-Scenario '3.3' {
    Set-Content -LiteralPath $B.SYNC_GATE_CONFIG -Value "reserve_fraction = 0.99`naging_secs = 86400"
    [void](Install-Ok $FromOld)
    $L = Get-TestLayout
    $bin = Join-Path $L.Bin 'sync_gate.exe'
    $pidBefore = @(Get-BinDaemon)[0].Pid
    $mark = Join-Path $tmp 'mark.txt'
    $env1 = Get-InstEnv
    $mcp = Start-Bg -File $bin -Arguments @('mcp', 'serve') -Env $env1 -Stdin
    $t0 = Get-Date
    $ping = Start-Bg -File $bin -Arguments @('run', '--', 'ping', '-n', '300', '127.0.0.1') -Env $env1   # outlives the upgrade (43 s measured with debug exes); killed below
    $e2 = Get-InstEnv; $e2['SYNC_GATE_FORCE_HEAVY'] = '1'; $e2['MARK'] = $mark
    $queued = Start-Bg -File $bin -Arguments @('run', '--max-wait', '600', '--', 'cmd', '/d', '/c', 'echo x>>%MARK%') -Env $e2
    $pending = { @(Get-ChildItem -LiteralPath $B.SYNC_GATE_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'pending' -and -not $_.PSIsContainer }).Count }
    Assert-That (Wait-Until { (& $pending) -gt 0 } 30) 'the heavy command never reached the queue (no pending file)'
    $r = Invoke-Inst -From $FromNew
    Assert-That ($r.Code -eq 0) "upgrade exited $($r.Code): $($r.Text)"
    Assert-That ($r.Text -notmatch 'Access is denied') 'Access is denied in the output'
    Assert-That (-not $mcp.HasExited) 'mcp serve died'
    Assert-That (-not $ping.HasExited) "the ping run died (exit $(if ($ping.HasExited) { $ping.ExitCode }) at $(if ($ping.HasExited) { [int]($ping.ExitTime - $t0).TotalSeconds }) s, checked at $([int]((Get-Date) - $t0).TotalSeconds) s)"
    Assert-That (@(Get-ChildItem -LiteralPath $L.Bin -Filter 'sync_gate.exe.old-*').Count -ge 1) 'no sync_gate.exe.old-* after upgrading in use'
    Assert-That (@(Get-BinDaemon)[0].Pid -ne $pidBefore) 'daemon pid did not change'
    Assert-That ($queued.WaitForExit(180000)) 'the queued command never finished'
    $lines = @(Get-Content -LiteralPath $mark -ErrorAction SilentlyContinue).Count
    Assert-That ($lines -eq 1) "queued command ran $lines times (want exactly 1)"
    Assert-That ((& $pending) -eq 0) 'a pending file is left'
    $mcp.StandardInput.Close(); [void]$mcp.WaitForExit(15000); if (-not $ping.HasExited) { $ping.Kill() }
    [void](Wait-Until { -not (Get-Process -Id $mcp.Id -ErrorAction SilentlyContinue) -and -not (Get-Process -Id $ping.Id -ErrorAction SilentlyContinue) } 20)
    [void](Install-Ok $FromNew)
    Assert-That (@(Get-ChildItem -LiteralPath $L.Bin -Filter '*.old-*').Count -eq 0) '.old-* files left after the next run'
}

Invoke-Scenario '3.4' {
    [void](Install-Ok $FromOld)
    $L = Get-TestLayout
    $job = Start-Job -ArgumentList $L.Task -ScriptBlock {
        param($n)
        $errs = @()
        $end = (Get-Date).AddSeconds(240)
        while ((Get-Date) -lt $end -and -not (Test-Path "$env:TEMP\sync_gate-t34-stop-$n")) {
            try { Start-ScheduledTask -TaskName $n -ErrorAction Stop } catch { $errs += $_.Exception.Message }
            Start-Sleep -Milliseconds 200
        }
        $errs
    }
    try { $r = Invoke-Inst -From $FromNew } finally { Set-Content -LiteralPath (Join-Path $env:TEMP "sync_gate-t34-stop-$($L.Task)") -Value 1 }
    $errs = @(Receive-Job -Job $job -Wait); Remove-Job -Job $job -Force
    Remove-Item -LiteralPath (Join-Path $env:TEMP "sync_gate-t34-stop-$($L.Task)") -Force -ErrorAction SilentlyContinue
    Assert-That ($r.Code -eq 0) "upgrade exited $($r.Code): $($r.Text)"
    Assert-That (-not ($errs | Where-Object { $_ -match 'denied|acesso' }) -and $r.Text -notmatch 'Access is denied') "access error: $($errs -join '; ')"
    Assert-That ((Get-ScheduledTask -TaskName $L.Task).State -ne 'Disabled') 'task left disabled'
    Assert-That (@(Get-BinDaemon).Count -eq 1) "found $(@(Get-BinDaemon).Count) sync_gated of the test folder"
}

Invoke-Scenario '3.5' {
    $sd = Join-Path $tmp 'stranger'; [void](New-Item -ItemType Directory -Force -Path $sd)
    Copy-Item -LiteralPath (Join-Path $BinDir 'sync_gated.exe') -Destination $sd
    $stranger = Start-Bg -File (Join-Path $sd 'sync_gated.exe') -Arguments @() -Env (Get-InstEnv)
    try {
        Assert-That (Wait-Until { (Invoke-SgNative -File (Join-Path $BinDir 'sync_gate.exe') -Arguments @('status') -Env (Get-InstEnv)).ExitCode -eq 0 } 20) 'the stranger daemon did not come up'
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue).Count
        $r = Invoke-Inst -From $FromNew
        Assert-That ($r.Code -eq 1) "exit $($r.Code), want 1"
        Assert-That ($r.Text -match [regex]::Escape("another sync_gated is serving $($B.SYNC_GATE_SOCKET)")) "message: $($r.Text)"
        Assert-That (-not (Test-Path -LiteralPath $B.SYNC_GATE_INSTALL_DIR)) 'the install folder was created'
        Assert-That (@(Get-ScheduledTask -ErrorAction SilentlyContinue).Count -eq $tasks) 'the task count changed'
        Assert-That (-not (Get-Process -Id $stranger.Id -ErrorAction SilentlyContinue).HasExited) 'the stranger was killed'
    } finally { if (-not $stranger.HasExited) { Stop-Process -Id $stranger.Id -Force } }
    # With a real daemon up on the default name, scenarios 3.1 and the final pid check show it is untouched.
}

Invoke-Scenario '3.6' {
    [void](New-Item -ItemType Directory -Force -Path (Join-Path $B.SYNC_GATE_INSTALL_DIR 'bin'))
    $bin = Join-Path $B.SYNC_GATE_INSTALL_DIR 'bin'
    $seed = "%USERPROFILE%\x;$bin;C:\y"
    Set-TestPath $seed 'ExpandString'
    [void](Install-Ok $FromNew)
    $L = Get-TestLayout
    $dirs = Get-SyncGatePaths -Bin (Join-Path $L.Bin 'sync_gate.exe') -Env (Get-InstEnv)
    $p = Read-SgPathRaw $L.EnvKey
    Assert-That ($p.Kind -eq 'ExpandString' -and $p.Raw -ceq "$($dirs.shims);$bin;$seed") "after install: $($p.Raw) ($($p.Kind))"
    $r = Invoke-Inst -Uninstall; Assert-That ($r.Code -eq 0) "uninstall exited $($r.Code): $($r.Text)"
    $p = Read-SgPathRaw $L.EnvKey
    Assert-That ($p.Raw -ceq $seed) "after uninstall: $($p.Raw)"
}

Invoke-Scenario '3.7b' {
    $L0 = Get-TestLayout
    $pf = $L0.Profiles[0].Path
    [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $pf))
    $orig = [Text.Encoding]::UTF8.GetBytes("# mine`r`nSet-Alias x Get-Item`r`n")
    [IO.File]::WriteAllBytes($pf, $orig)
    [void](Install-Ok $FromNew)
    Assert-That ([IO.File]::ReadAllText($pf).Contains($script:SgBlockStart)) 'block not written under RemoteSigned'
    $r = Invoke-Inst -Uninstall -Extra @{ SYNC_GATE_TEST_POLICY = 'Restricted' }
    Assert-That ($r.Code -eq 0) "uninstall exited $($r.Code): $($r.Text)"
    Assert-That ((Get-SgHash ([IO.File]::ReadAllBytes($pf))) -eq (Get-SgHash $orig)) 'profile is not byte for byte as before'
}

function New-Adopted {
    # Installs, writes a Claude config with one server and adopts it; returns the original bytes.
    [void](Install-Ok $FromNew)
    $cfg = $B.SYNC_GATE_CLAUDE_CONFIG
    Set-Content -LiteralPath $cfg -Encoding ASCII -Value '{"mcpServers":{"demo":{"command":"cmd","args":["/c","echo"]}}}'
    $orig = [IO.File]::ReadAllBytes($cfg)
    $r = Invoke-Bin @('mcp', 'adopt', '--claude-config', $cfg, 'demo')
    Assert-That ($r.ExitCode -eq 0) "adopt exited $($r.ExitCode): $($r.Err)"
    , $orig
}

Invoke-Scenario '3.8' {
    $orig = New-Adopted
    $r = Invoke-Inst -Uninstall; Assert-That ($r.Code -eq 0) "uninstall exited $($r.Code): $($r.Text)"
    Assert-That ((Get-SgHash ([IO.File]::ReadAllBytes($B.SYNC_GATE_CLAUDE_CONFIG))) -eq (Get-SgHash $orig)) 'config is not byte for byte as before'
}

Invoke-Scenario '3.8b' {
    [void](New-Adopted)
    Set-ItemProperty -LiteralPath $B.SYNC_GATE_CLAUDE_CONFIG -Name IsReadOnly -Value $true
    $s = Get-Snap
    $r = Invoke-Inst -Uninstall
    Set-ItemProperty -LiteralPath $B.SYNC_GATE_CLAUDE_CONFIG -Name IsReadOnly -Value $false
    Assert-That ($r.Code -eq 1) "exit $($r.Code), want 1"
    Assert-That ((Get-Snap) -ceq $s) 'something changed'
}

Invoke-Scenario '3.8c' {
    [void](New-Adopted)
    $cfg = $B.SYNC_GATE_CLAUDE_CONFIG
    $bin = ((Get-TestLayout).Bin).Replace('\', '\\')
    $t = [IO.File]::ReadAllText($cfg)
    $swapped = [regex]::Replace($t, [regex]::Escape($bin), { param($m) $m.Value.ToUpper() }, 'IgnoreCase')
    Assert-That ($swapped -cne $t) 'the adopted file does not hold the exe path in the expected spelling'
    [IO.File]::WriteAllText($cfg, $swapped)
    $s = Get-Snap
    $r = Invoke-Inst -Uninstall
    # Task 1b prints the agent label ("still adopted: Claude Code demo in <file> ..."), accepted in its review.
    Assert-That ($r.Code -eq 1 -and $r.Text -match 'still adopted: Claude Code demo in ') "exit $($r.Code): $($r.Text)"
    Assert-That ((Get-Snap) -ceq $s) 'something changed'
}

Invoke-Scenario '3.8d' {
    [void](Install-Ok $FromNew)
    $bin = (Get-TestLayout).Bin
    $cfg = $B.SYNC_GATE_CODEX_CONFIG
    Set-Content -LiteralPath $cfg -Value "[mcp_servers.hand]`ncommand = '$bin\sync_gate.exe'"
    $s = Get-Snap
    $r = Invoke-Inst -Uninstall
    Assert-That ($r.Code -eq 1 -and $r.Text.Contains("${cfg}:2")) "exit $($r.Code): $($r.Text)"
    Assert-That ((Get-Snap) -ceq $s) 'something changed'
}

Invoke-Scenario '3.8e' {
    [void](Install-Ok $FromNew)
    $bin = (Get-TestLayout).Bin
    $cfg = $B.SYNC_GATE_CODEX_CONFIG
    $fwd = $bin.Replace('\', '/')
    $short = Get-SgShortPath $bin
    $spell = [ordered]@{
        'forward slash' = "$fwd/sync_gate.exe"
        'double slash'  = ($bin.Substring(0, 2) + '//' + $bin.Substring(3).Replace('\', '/') + '/sync_gate.exe')
        'mixed separators' = "$fwd\sync_gate.exe"
        'MCP launcher' = "$bin\sync_gate_mcp.exe"
        'swapped case' = ($bin.ToUpper() + '\SYNC_GATE.EXE')
    }
    if ($short -and $short -ne $bin) { $spell['8.3'] = "$short\sync_gate.exe" } else { Write-Host '  3.8e: 8.3 not generated here' }
    $s = Get-Snap
    foreach ($name in $spell.Keys) {
        Set-Content -LiteralPath $cfg -Value "[mcp_servers.hand]`ncommand = '$($spell[$name])'"
        $r = Invoke-Inst -Uninstall
        Assert-That ($r.Code -eq 1 -and $r.Text.Contains("${cfg}:2")) "spelling '$name': exit $($r.Code): $($r.Text)"
        Assert-That ((Get-Snap) -ceq $s) "spelling '$name': something changed"
    }
    Set-Content -LiteralPath $cfg -Value "[mcp_servers.other]`ncommand = 'C:\Tools\other.exe'"
    $r = Invoke-Inst -Uninstall
    Assert-That ($r.Code -eq 0) "an unrelated config blocked the uninstall: $($r.Text)"
}

Invoke-Scenario '3.9' {
    $L0 = Get-TestLayout
    $seed = 'C:\keep1;%USERPROFILE%\keep2'
    Set-TestPath $seed 'ExpandString'
    $pf = $L0.Profiles[1].Path
    [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $pf))
    $orig = [Text.Encoding]::UTF8.GetBytes("# keep`r`n")
    [IO.File]::WriteAllBytes($pf, $orig)
    [void][IO.Directory]::CreateDirectory($B.SYNC_GATE_DATA_DIR)
    Set-Content -LiteralPath $B.SYNC_GATE_CONFIG -Value '# test'
    [void](Install-Ok $FromNew)
    $dirs = Get-SyncGatePaths -Bin (Join-Path $L0.Bin 'sync_gate.exe') -Env (Get-InstEnv)
    $strange = Join-Path $dirs.shims 'strange.txt'; Set-Content -LiteralPath $strange -Value 'mine'
    $r = Invoke-Inst -Uninstall; Assert-That ($r.Code -eq 0) "uninstall exited $($r.Code): $($r.Text)"
    Assert-That (-not (Get-ScheduledTask -TaskName $L0.Task -ErrorAction SilentlyContinue)) 'task still there'
    Assert-That ((Read-SgPathRaw $L0.EnvKey).Raw -ceq $seed) 'Path is not as seeded'
    foreach ($n in $script:SgOwnNames) { Assert-That ($null -eq (Read-SgUserVar $L0.EnvKey $n)) "user variable $n left" }
    Assert-That ((Get-SgHash ([IO.File]::ReadAllBytes($pf))) -eq (Get-SgHash $orig)) 'seeded profile changed'
    Assert-That (-not (Test-Path -LiteralPath $L0.Profiles[0].Path)) 'created profile left'
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $dirs.shims 'npm.exe'))) 'npm.exe shim left'
    Assert-That (Test-Path -LiteralPath $strange) 'the foreign file in the shims folder is gone'
    foreach ($f in $L0.Bin, $L0.Launcher, $L0.StatePath) { Assert-That (-not (Test-Path -LiteralPath $f)) "$f left" }
    Assert-That ((Test-Path -LiteralPath $dirs.data) -and (Test-Path -LiteralPath $B.SYNC_GATE_CONFIG)) 'data or config deleted'
    Assert-That (@(Get-BinDaemon).Count -eq 0) 'a sync_gated of the test folder is still running'
}

Invoke-Scenario '3.10' {
    $bash = 'C:\Program Files\Git\bin\bash.exe'
    if (-not (Test-Path -LiteralPath $bash)) { Write-Host '  3.10: Git Bash not found here, skipped'; return }
    $e = Get-InstEnv; $e['SYNC_GATE_INSTALL_FROM'] = $FromNew
    $ps1 = $script:Installer.Replace('\', '/')
    $r = Invoke-SgNative -File $bash -Arguments @('-c', "powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$ps1'") -Env $e -TimeoutSec 400
    Assert-That ($r.ExitCode -eq 0) "install from bash exited $($r.ExitCode): $($r.Out)$($r.Err)"
    $d = @(Get-BinDaemon); Assert-That ($d.Count -eq 1) 'no daemon of the test folder'
    $chain = Get-ParentChain $d[0].Pid
    Assert-That (-not ($chain | Where-Object { $_ -match '^bash\.exe$' })) "bash.exe in the chain: $($chain -join ' > ')"
}

Invoke-Scenario '3.11' {
    foreach ($step in 'S2', 'S3', 'S4', 'S5', 'S6', 'S7') {
        Reset-Area
        $L0 = Get-TestLayout
        $pf = $L0.Profiles[0].Path; [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $pf))
        [IO.File]::WriteAllBytes($pf, [Text.Encoding]::UTF8.GetBytes("# keep`r`n"))
        Set-TestPath 'C:\keep1;%USERPROFILE%\keep2' 'ExpandString'
        [void](Install-Ok $FromOld)
        $s = Get-Snap
        $r = Invoke-Inst -From $FromNew -Extra @{ SYNC_GATE_INSTALL_FAIL_AT = $step }
        Assert-That ($r.Code -eq 1 -and $r.Text -match 'previous version restored') "$step`: exit $($r.Code): $($r.Text)"
        Assert-That ((Get-Snap) -ceq $s) "$step`: the state after the rollback differs from before"
        Assert-That ((Get-ScheduledTask -TaskName $L0.Task).State -ne 'Disabled') "$step`: task left disabled"
        Test-SyncGateHealth -Layout (Get-TestLayout)
    }
    foreach ($step in 'U5', 'U6', 'U7') {
        Reset-Area
        [void](Install-Ok $FromNew)
        $s = Get-Snap
        $r = Invoke-Inst -Uninstall -Extra @{ SYNC_GATE_INSTALL_FAIL_AT = $step }
        Assert-That ($r.Code -eq 1) "$step`: exit $($r.Code): $($r.Text)"
        Assert-That ((Get-Snap) -ceq $s) "$step`: the installation changed"
        Test-SyncGateHealth -Layout (Get-TestLayout)
    }
    foreach ($step in 'S3', 'S5', 'S6') {
        Reset-Area
        [void](Install-Ok $FromOld)
        $r = Invoke-Inst -From $FromNew -Extra @{ SYNC_GATE_INSTALL_FAIL_AT = "${step}:crash" }
        Assert-That ($r.Code -ne 0) "$step`:crash exited 0"
        $r2 = Invoke-Inst -From $FromNew
        Assert-That ($r2.Code -eq 0 -and $r2.Text -match 'restoring it first') "$step`:crash next run: exit $($r2.Code): $($r2.Text)"
        $L = Get-TestLayout
        Assert-That ((Get-FileHash -LiteralPath (Join-Path $L.Bin 'sync_gate.exe')).Hash -eq $HashNew['sync_gate.exe']) "$step`:crash: the new exe is not installed"
        Test-SyncGateHealth -Layout $L
    }
    Reset-Area
    $bad = Join-Path $assets 'bad2'
    if (Test-Path -LiteralPath $bad) { Remove-Item -LiteralPath $bad -Recurse -Force }
    Copy-Item -LiteralPath $FromNew -Destination $bad -Recurse
    $z = Join-Path $bad $zipName; $bytes = [IO.File]::ReadAllBytes($z); $bytes[$bytes.Length - 30] = $bytes[$bytes.Length - 30] -bxor 1; [IO.File]::WriteAllBytes($z, $bytes)
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue).Count
    $r = Invoke-Inst -From $bad
    Assert-That ($r.Code -eq 1 -and $r.Text -match 'checksum mismatch') "tampered zip: exit $($r.Code): $($r.Text)"
    Assert-That (-not (Test-Path -LiteralPath $B.SYNC_GATE_INSTALL_DIR) -and @(Get-ScheduledTask -ErrorAction SilentlyContinue).Count -eq $tasks) 'the tampered run changed something'
}

Invoke-Scenario '3.12' {
    $e = Get-InstEnv; $e['SYNC_GATE_INSTALL_FROM'] = $FromNew
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $q = $script:Installer.Replace("'", "''")
    [void](Invoke-SgNative -File $ps -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', "Get-Content -Raw '$q' | iex") -Env $e -TimeoutSec 400)
    $L = Get-TestLayout
    Assert-That (Test-Path -LiteralPath $L.StatePath) 'Get-Content -Raw install.ps1 | iex did not install'
    $u = Invoke-SgNative -File $ps -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', "& ([scriptblock]::Create((Get-Content -Raw '$q'))) -Uninstall") -Env $e -TimeoutSec 400
    Assert-That (-not (Test-Path -LiteralPath $L.StatePath) -and -not (Get-ScheduledTask -TaskName $L.Task -ErrorAction SilentlyContinue)) "the scriptblock form did not uninstall: $($u.Out)$($u.Err)"
}

Invoke-Scenario '3.13' {
    [void](Install-Ok $FromNew)
    $L = Get-TestLayout
    $st = Read-SgState $L.StatePath
    foreach ($n in 'SYNC_GATE_SOCKET', 'SYNC_GATE_DATA_DIR', 'SYNC_GATE_CONFIG') {
        Assert-That ($null -ne (Read-SgUserVar $L.EnvKey $n)) "$n not in the key"
        Assert-That ($null -ne $st.overrides.$n) "$n not in the state"
    }
    $fresh = Get-SgFreshEnv $L $st
    $exe = Join-Path $L.Bin 'sync_gate.exe'
    $p = Invoke-SgNative -File $exe -Arguments @('paths') -Env $fresh -CleanEnv
    $s = Invoke-SgNative -File $exe -Arguments @('status') -Env $fresh -CleanEnv
    Assert-That ($p.ExitCode -eq 0 -and $s.ExitCode -eq 0 -and $p.Out -match [regex]::Escape($B.SYNC_GATE_SOCKET)) 'a new terminal does not find the same daemon'
    $r = Invoke-Inst -From $FromNew -Without 'SYNC_GATE_SOCKET', 'SYNC_GATE_DATA_DIR', 'SYNC_GATE_CONFIG'
    Assert-That ($r.Code -eq 0) "run without the values exited $($r.Code): $($r.Text)"
    foreach ($n in 'SYNC_GATE_SOCKET', 'SYNC_GATE_DATA_DIR', 'SYNC_GATE_CONFIG') {
        Assert-That ([IO.File]::ReadAllText($L.Launcher).Contains("set `"$n=")) "$n lost from the launcher"
        Assert-That ($r.Text.Contains("own value in use: $n=")) "$n not listed in the output"
    }
    # -ClearOverrides is covered by 3.13u: running it here would start a daemon on the real pipe and data folder.
}

Invoke-Scenario '3.14' {
    $odd = Join-Path $tmp "Sync Gate O'Brien %TEMP% & ^!"
    $x = @{ SYNC_GATE_INSTALL_DIR = Join-Path $odd 'inst'; SYNC_GATE_DATA_DIR = Join-Path $odd 'data' }
    foreach ($k in $x.Keys) { Set-Item -Path "env:$k" -Value $x[$k] }
    try {
        # Does this volume give the odd folder an 8.3 name? (Task Scheduler needs one for a '%' in the path.)
        [void](New-Item -ItemType Directory -Force -Path $x.SYNC_GATE_INSTALL_DIR)
        $short = Get-SgShortPath $x.SYNC_GATE_INSTALL_DIR
        Remove-Item -LiteralPath $odd -Recurse -Force
        if (-not $short -or $short.Contains('%')) {
            Write-Host '  3.14: 8.3 not generated here (a root with % must be refused before any change)'
            Set-TestPath 'C:\keep' 'String'
            $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue).Count
            $r = Invoke-Inst -From $FromNew -Extra $x
            Assert-That ($r.Code -eq 1 -and $r.Text.Contains('has no 8.3 name')) "root with % and no 8.3 name: exit $($r.Code): $($r.Text)"
            Assert-That (-not (Test-Path -LiteralPath $odd)) 'the refused run left the folder'
            Assert-That (@(Get-ScheduledTask -ErrorAction SilentlyContinue).Count -eq $tasks -and (Read-SgPathRaw $B.SYNC_GATE_ENV_KEY).Raw -ceq 'C:\keep') 'the refused run changed something'
            return
        }
        Set-TestPath 'C:\keep' 'String'
        $r = Invoke-Inst -From $FromNew -Extra $x
        Assert-That ($r.Code -eq 0) "install exited $($r.Code): $($r.Text)"
        $L = Get-TestLayout
        $dirs = Get-SyncGatePaths -Bin (Join-Path $L.Bin 'sync_gate.exe') -Env $x
        $block = [IO.File]::ReadAllText($L.Profiles[0].Path)
        $err = $null; [void][Management.Automation.Language.Parser]::ParseInput($block, [ref]$null, [ref]$err)
        Assert-That ($err.Count -eq 0) 'the profile does not parse'
        $apply = Join-Path $tmp 'apply.ps1'; Set-Content -LiteralPath $apply -Value 'param($p) . $p; ($env:Path -split '';'')[0]'
        $a = Invoke-SgNative -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $apply, $L.Profiles[0].Path)
        Assert-That ($a.Out.Trim() -ceq $dirs.shims) "child Path starts with '$($a.Out.Trim())', want '$($dirs.shims)'"
        Assert-That (Test-Path -LiteralPath (Join-Path $dirs.data 'sync_gated.lock')) 'sync_gated.lock not in the odd data folder (P37)'
        $u = Invoke-Inst -Uninstall -Extra $x
        Assert-That ($u.Code -eq 0 -and (Read-SgPathRaw $L.EnvKey).Raw -ceq 'C:\keep') "uninstall: exit $($u.Code): $($u.Text)"
        # refusals: nothing may change
        $semi = @{ SYNC_GATE_INSTALL_DIR = Join-Path $tmp 'a;b\inst' }
        $r = Invoke-Inst -From $FromNew -Extra $semi
        Assert-That ($r.Code -eq 1 -and $r.Text.Contains("contains ';'")) "root with ';': exit $($r.Code): $($r.Text)"
        Assert-That (-not (Test-Path -LiteralPath (Join-Path $tmp 'a;b'))) "root with ';' was created"
        Set-TestPath 'C:\keep' 'ExpandString'
        $r = Invoke-Inst -From $FromNew -Extra $x
        Assert-That ($r.Code -eq 1 -and $r.Text.Contains("contains '%'")) "root with % and an expanding PATH: exit $($r.Code): $($r.Text)"
        Assert-That ((Read-SgPathRaw $L.EnvKey).Raw -ceq 'C:\keep') 'Path changed by a refused run'
    } finally { foreach ($k in $x.Keys) { Set-Item -Path "env:$k" -Value $B[$k] } }
}

# N9: SYNC_GATE_DATA_DIR as a user variable reaches the elevated sandbox guest; say so at the end when guests are configured.
$script:SgGuestWarn = 'warning: you set SYNC_GATE_DATA_DIR and your config lists guests. An elevated sandbox guest would try to keep its pending commands in that folder, where it can only read. If you use guests, do not set your own SYNC_GATE_DATA_DIR.'
Invoke-Scenario '3.16' {
    Set-Content -LiteralPath $B.SYNC_GATE_CONFIG -Value 'guests = ["CodexSandboxOffline", "@restricted"]' -Encoding ASCII
    $r = Install-Ok $FromNew
    $lines = @($r.Text -split "\r?\n" | Where-Object { $_ })
    Assert-That ($lines -contains $script:SgGuestWarn) "guest warning missing: $($r.Text)"
    Assert-That ($lines[-1] -like 'Uninstall:*') "warning is not before the closing commands: $($lines[-1])"
}
Invoke-Scenario '3.16n' {
    Set-Content -LiteralPath $B.SYNC_GATE_CONFIG -Value 'guests = []' -Encoding ASCII
    $r = Install-Ok $FromNew
    Assert-That (-not $r.Text.Contains('your config lists guests')) "warning with no guests: $($r.Text)"
}

# ---------------------------------------------------------------- end: clean up and compare

Reset-Area
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
$tmpGone = -not (Test-Path -LiteralPath $tmp)
$keyGone = $null -eq (Open-SgEnvKey $B.SYNC_GATE_ENV_KEY)
$after = @{
    Tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue).Count
    Key = Get-RealKeyDump; Pids = (Get-RealDaemonPids) -join ','; Data = Get-RealDataListing
}
if ($after.Key -ne $before.Key) { $script:Fails++; Write-Host 'FAIL: the real user variables key changed' }
$dataSame = $after.Data -ceq $before.Data
Write-Host ("tasks before=$($before.Tasks) after=$($after.Tasks); test key $(if ($keyGone) { 'removed' } else { 'LEFT' }); " +
    "temp root $(if ($tmpGone) { 'removed' } else { 'LEFT' }); real daemon pid before=$($before.Pids) after=$($after.Pids); " +
    "real data listing $(if ($dataSame) { 'unchanged' } else { 'CHANGED' })")
if ($before.Tasks -ne $after.Tasks -or -not $keyGone -or -not $tmpGone -or $before.Pids -ne $after.Pids -or -not $dataSame) { $script:Fails++ }
Write-Host "$($script:Ran) scenario(s) run, $($script:Fails) failure(s)"
if ($script:Fails -gt 0) { exit 1 }
