<#
.SYNOPSIS
  sync_gate installer for Windows: installs or updates the three programs, registers the daemon as a
  scheduled task of your own account, and can undo all of it.
.DESCRIPTION
  Install or update:  irm https://gate.synclabs.team/install.ps1 | iex
  Uninstall:          & ([scriptblock]::Create((irm https://gate.synclabs.team/install.ps1))) -Uninstall
  Pin a version:      the same scriptblock form with -Version 0.1.0
  Forget own values:  the same scriptblock form with -ClearOverrides
  Never asks for administrator; writes only to your install folder, your data folder, HKCU\Environment,
  your PowerShell profiles and one scheduled task of your account. Files come from the GitHub release,
  over HTTPS, checked against SHA256SUMS. Details: docs/install.md.
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [string]$Version,
    [switch]$ClearOverrides
)

# The domain appears only in the commands printed at the end; files are always fetched from GitHub.
$script:SgCommandUrl = 'https://gate.synclabs.team/install.ps1'
$script:SgRepo = 'sync-labs-team/sync_gate'
$script:SgTarget = 'x86_64-pc-windows-msvc'
$script:SgExes = @('sync_gate.exe', 'sync_gated.exe', 'sync_gate_mcp.exe')   # the sync_gate_shim crate builds sync_gate_mcp.exe; sync_gate_shim.exe is only the shims folder's copy of sync_gate.exe
$script:SgOwnNames = @('SYNC_GATE_SOCKET', 'SYNC_GATE_DATA_DIR', 'SYNC_GATE_CONFIG', 'SYNC_GATE_INSTALL_DIR')
$script:SgTestNames = @('SYNC_GATE_TASK_NAME', 'SYNC_GATE_ENV_KEY', 'SYNC_GATE_PROFILE_PATHS', 'SYNC_GATE_CLAUDE_CONFIG', 'SYNC_GATE_CODEX_CONFIG')
$script:SgBlockStart = '# >>> sync_gate >>>'
$script:SgBlockEnd = '# <<< sync_gate <<<'
$script:SgLatin1 = [Text.Encoding]::GetEncoding(28591)

# ---------------------------------------------------------------- small helpers

function Write-SgLine { param([string]$Text) Write-Host $Text }

function ConvertTo-SgHashtable {
    param($Object)
    $h = [ordered]@{}
    if ($null -ne $Object) { foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    $h
}

function Assert-SgPlainValue {
    param([string]$Name, [string]$Value)
    if ($Value -match "[\r\n]") { throw "$Name must not contain a line break" }
    if ($Value.Contains('"')) { throw "$Name must not contain a double quote" }
}

function Write-SgTextFile {
    # UTF-8 without BOM (state, JSON); `-Encoding utf8` in Windows PowerShell 5.1 would add a BOM.
    param([string]$Path, [string]$Text)
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Get-SgHash {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes) { return 'absent' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($Bytes)) } finally { $sha.Dispose() }
}

function ConvertTo-SgQuotedArg {
    param([string]$Arg)
    if ($Arg -ne '' -and $Arg -notmatch '[\s"]') { return $Arg }
    '"' + (($Arg -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-SgNative {
    # Runs a program with an exact environment: -Env strips every SYNC_GATE_* variable of this process
    # and sets the given ones; -CleanEnv starts from nothing (a "new terminal").
    param(
        [Parameter(Mandatory)][string]$File,
        [string[]]$Arguments = @(),
        [hashtable]$Env,
        [string[]]$Unset = @(),
        [switch]$CleanEnv,
        [int]$TimeoutSec = 60,
        [string]$WorkDir
    )
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = (($Arguments | ForEach-Object { ConvertTo-SgQuotedArg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    if ($WorkDir) { $psi.WorkingDirectory = $WorkDir }
    $e = $psi.EnvironmentVariables
    if ($CleanEnv) { foreach ($k in @($e.Keys)) { $e.Remove($k) } }
    elseif ($PSBoundParameters.ContainsKey('Env')) {
        foreach ($k in @($e.Keys)) { if ($k -match '^SYNC_GATE_') { $e.Remove($k) } }
    }
    foreach ($k in $Unset) { $e.Remove($k) }
    if ($Env) { foreach ($k in $Env.Keys) { $e[$k] = [string]$Env[$k] } }
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        return [pscustomobject]@{ ExitCode = -1; Out = ''; Err = "timed out after $TimeoutSec s: $File" }
    }
    $p.WaitForExit()
    [pscustomobject]@{ ExitCode = $p.ExitCode; Out = $out.Result; Err = $err.Result }
}

function Get-SgIntegrity {
    $sidNames = @{ 'S-1-16-4096' = 'Low Mandatory Level'; 'S-1-16-8192' = 'Medium Mandatory Level'; 'S-1-16-12288' = 'High Mandatory Level'; 'S-1-16-16384' = 'System Mandatory Level' }
    $rows = & (Join-Path $env:SystemRoot 'System32\whoami.exe') /groups /fo csv | ConvertFrom-Csv
    foreach ($r in $rows) { if ($sidNames.ContainsKey($r.SID)) { return $sidNames[$r.SID] } }
    'unknown'
}

function Get-SgWin32 {
    if (-not ('SyncGate.Win' -as [type])) {
        Add-Type -Namespace SyncGate -Name Win -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessageTimeout(System.IntPtr hWnd, uint Msg, System.UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out System.UIntPtr lpdwResult);
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto)]
public static extern uint GetShortPathName(string longPath, System.Text.StringBuilder shortPath, uint bufferSize);
'@
    }
}

function Send-SyncGateEnvChange {
    # P11: tell running programs (Explorer, new terminals) that HKCU\Environment changed.
    Get-SgWin32
    $res = [UIntPtr]::Zero
    [void][SyncGate.Win]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$res)
}

function Get-SgDaemonProcesses {
    # All sync_gated processes of this machine with their executable path (CIM sees paths Get-Process may not).
    @(Get-CimInstance Win32_Process -Filter "Name='sync_gated.exe'" -ErrorAction SilentlyContinue |
        ForEach-Object { [pscustomobject]@{ Pid = [int]$_.ProcessId; Path = $_.ExecutablePath } })
}

function Test-SgSamePath {
    param([string]$A, [string]$B)
    if (-not $A -or -not $B) { return $false }
    [string]::Equals([IO.Path]::GetFullPath($A).TrimEnd('\'), [IO.Path]::GetFullPath($B).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
}

# ---------------------------------------------------------------- layout and state

function Read-SgState {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Get-SgInstallRoot {
    $root = $env:SYNC_GATE_INSTALL_DIR
    if ([string]::IsNullOrEmpty($root)) { $root = Join-Path $env:LOCALAPPDATA 'sync_labs\sync_gate' }
    Assert-SgPlainValue 'the install folder' $root
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($root)
}

function Get-SyncGateLayout {
    param([switch]$ClearOverrides)
    $root = Get-SgInstallRoot
    $statePath = Join-Path $root 'install-state.json'
    $rollback = Join-Path $root 'rollback'
    $active = Test-Path -LiteralPath (Join-Path $rollback 'in-progress')
    $state = if ($active) { Read-SgState (Join-Path $rollback 'install-state.json') } else { Read-SgState $statePath }

    $overrides = [ordered]@{}
    if ($state -and -not $ClearOverrides) { $overrides = ConvertTo-SgHashtable $state.overrides }
    if (-not $ClearOverrides) {
        foreach ($n in $script:SgOwnNames) {
            $v = [Environment]::GetEnvironmentVariable($n)
            if (-not [string]::IsNullOrEmpty($v)) {
                Assert-SgPlainValue $n $v
                if ($overrides.Contains($n) -and $overrides[$n] -ne $v) { Write-SgLine "override changed: $n" }
                $overrides[$n] = $v
            }
        }
    }

    $journal = if ($active) { Read-SgState (Join-Path $rollback 'meta.json') }
    if ($journal -and $journal.PSObject.Properties['test']) {
        $test = ConvertTo-SgHashtable $journal.test
    } else {
        $test = [ordered]@{}
        if ($state -and $state.test) { $test = ConvertTo-SgHashtable $state.test }
        foreach ($n in $script:SgTestNames) {
            if ($active -and $test.Contains($n)) { continue }
            $v = [Environment]::GetEnvironmentVariable($n)
            if (-not [string]::IsNullOrEmpty($v)) { Assert-SgPlainValue $n $v; $test[$n] = $v }
        }
    }

    $docs = [Environment]::GetFolderPath('MyDocuments')
    if ($test.Contains('SYNC_GATE_PROFILE_PATHS')) {
        # Test paths are positional: first the Windows PowerShell 5.1 profile, then the PowerShell 7 one.
        $given = @($test['SYNC_GATE_PROFILE_PATHS'] -split ';' | Where-Object { $_ })
        $hosts = @('powershell', 'pwsh')
        $profiles = @(for ($i = 0; $i -lt $given.Count; $i++) { @{ Path = $given[$i]; Host = $hosts[[Math]::Min($i, 1)] } })
    } else {
        $profiles = @(
            @{ Path = Join-Path $docs 'WindowsPowerShell\profile.ps1'; Host = 'powershell' },
            @{ Path = Join-Path $docs 'PowerShell\profile.ps1'; Host = 'pwsh' }
        )
    }

    $task = 'sync_gate'; if ($test.Contains('SYNC_GATE_TASK_NAME')) { $task = $test['SYNC_GATE_TASK_NAME'] }
    $envKey = 'HKCU:\Environment'; if ($test.Contains('SYNC_GATE_ENV_KEY')) { $envKey = $test['SYNC_GATE_ENV_KEY'] }
    $claude = $null; if ($test.Contains('SYNC_GATE_CLAUDE_CONFIG')) { $claude = $test['SYNC_GATE_CLAUDE_CONFIG'] }
    $codex = $null; if ($test.Contains('SYNC_GATE_CODEX_CONFIG')) { $codex = $test['SYNC_GATE_CODEX_CONFIG'] }
    @{
        Root = $root; Bin = Join-Path $root 'bin'; Launcher = Join-Path $root 'launcher.cmd'
        Log = Join-Path $root 'daemon.log'; StatePath = $statePath; Rollback = $rollback
        State = $state; Overrides = $overrides; Test = $test; Profiles = $profiles
        Task = $task; EnvKey = $envKey; ClaudeConfig = $claude; CodexConfig = $codex
    }
}

function Save-SgState {
    param($Layout, [string]$Version, [string[]]$PathPlaced, $Vars, $ProfileEntries, $Original = ([ordered]@{}))
    $s = [ordered]@{
        version = $Version; root = $Layout.Root; overrides = $Layout.Overrides; test = $Layout.Test
        path_placed = @($PathPlaced); vars = $Vars; vars_original = $Original; profiles = @($ProfileEntries)
    }
    Write-SgTextFile $Layout.StatePath ($s | ConvertTo-Json -Depth 6)
}

# ---------------------------------------------------------------- the binary's own paths (P37)

function Get-SyncGatePaths {
    param([Parameter(Mandatory)][string]$Bin, [hashtable]$Env)
    $r = Invoke-SgNative -File $Bin -Arguments @('paths') -Env $Env
    if ($r.ExitCode -ne 0) { throw "sync_gate paths failed: $($r.Err.Trim())" }
    $h = @{}
    foreach ($line in ($r.Out -split "\r?\n")) {
        $i = $line.IndexOf('=')
        if ($i -gt 0) { $h[$line.Substring(0, $i)] = $line.Substring($i + 1) }
    }
    foreach ($k in 'config', 'data', 'shims', 'adopted', 'socket', 'hub') {
        if (-not $h.ContainsKey($k) -or $h[$k] -eq '') { throw "sync_gate paths: line '$k' is missing" }
    }
    $h
}

# ---------------------------------------------------------------- release files

function Get-SgRemoteFile {
    param([string]$Url, [string]$Dest)
    if (-not $Url.StartsWith('https://')) { throw "refusing a download that is not HTTPS: $Url" }
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
}

function Get-SyncGateAssets {
    param([string]$Version, [Parameter(Mandatory)][string]$Dest)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ($Version -and $Version -notmatch '^\d+\.\d+\.\d+$') { throw "-Version must look like 0.1.0, not '$Version'" }
    [void](New-Item -ItemType Directory -Force -Path $Dest)
    $sums = Join-Path $Dest 'SHA256SUMS'
    $from = $env:SYNC_GATE_INSTALL_FROM
    $base = "https://github.com/$script:SgRepo/releases/latest/download"
    if ($Version) { $base = "https://github.com/$script:SgRepo/releases/download/v$Version" }
    if ($from) { Copy-Item -LiteralPath (Join-Path $from 'SHA256SUMS') -Destination $sums }
    else { Get-SgRemoteFile "$base/SHA256SUMS" $sums }

    $hashes = @{}
    foreach ($line in (Get-Content -LiteralPath $sums)) {
        if ($line -match '^([0-9a-fA-F]{64})\s+\*?(\S+)$') { $hashes[$Matches[2]] = $Matches[1] }
    }
    $zipName = $null; $ver = $null
    foreach ($n in $hashes.Keys) {
        if ($n -match "^sync_gate-(\d+\.\d+\.\d+)-$([regex]::Escape($script:SgTarget))\.zip$") {
            if (-not $Version -or $Matches[1] -eq $Version) { $zipName = $n; $ver = $Matches[1] }
        }
    }
    if (-not $zipName) { throw "SHA256SUMS lists no $script:SgTarget zip$(if ($Version) { " for version $Version" })" }
    $zip = Join-Path $Dest $zipName
    if ($from) { Copy-Item -LiteralPath (Join-Path $from $zipName) -Destination $zip }
    else { Get-SgRemoteFile "$base/$zipName" $zip }
    $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    if ($actual -ne $hashes[$zipName]) { throw "checksum mismatch for $zipName" }

    # Only the expected names may leave the archive (no path tricks), then extract.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $allowed = $script:SgExes + @('LICENSE-MIT', 'LICENSE-APACHE')
    $za = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($entry in $za.Entries) {
            $name = $entry.FullName
            while ($name.StartsWith('./')) { $name = $name.Substring(2) }
            if ($name -eq '' -and $entry.FullName.EndsWith('/')) { continue }   # the "./" directory entry
            if ($allowed -notcontains $name) { throw "unexpected entry in $zipName`: $($entry.FullName)" }
        }
    } finally { $za.Dispose() }
    $files = Join-Path $Dest 'files'
    Expand-Archive -LiteralPath $zip -DestinationPath $files -Force
    foreach ($n in $script:SgExes) {
        if (-not (Test-Path -LiteralPath (Join-Path $files $n))) { throw "$zipName does not contain $n" }
    }
    @{ Version = $ver; Dir = $files }
}

# ---------------------------------------------------------------- PATH and user variables

function Open-SgEnvKey {
    param([string]$Key, [switch]$Write)
    $sub = $Key -replace '^HKCU:\\?', ''
    if ($Write) { [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($sub) }
    else { [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($sub) }
}

function Read-SgPathRaw {
    # Raw text, not expanded; absent value = empty ExpandString.
    param([string]$Key)
    $k = Open-SgEnvKey $Key
    if ($null -eq $k) { return @{ Present = $false; Raw = ''; Kind = 'ExpandString' } }
    try {
        if (@($k.GetValueNames()) -inotcontains 'Path') { return @{ Present = $false; Raw = ''; Kind = 'ExpandString' } }
        $kind = $k.GetValueKind('Path').ToString()
        if ($kind -ne 'String') { $kind = 'ExpandString' }
        @{ Present = $true; Raw = [string]$k.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); Kind = $kind }
    } finally { $k.Dispose() }
}

function Test-SgPathEntries {
    # No escape exists for ';' in PATH, nor for '%' in an expanding value: refuse before any change.
    param([string]$Key, [string[]]$Entries)
    $kind = (Read-SgPathRaw $Key).Kind
    foreach ($e in $Entries) {
        if ($e.Contains(';')) { throw "'$e' contains ';' and cannot go on PATH (PATH has no escape for it); choose another folder" }
        if ($e.Contains('%') -and $kind -eq 'ExpandString') { throw "'$e' contains '%' and your PATH is an expanding value (no escape exists); choose another folder" }
    }
}

function Set-SyncGatePath {
    # Install: drop the first copy of each entry we placed before, put -Front first. Remove: drop ours only.
    # shortcut: a copy of ours that the user moved is not told apart from an older identical entry; fine until
    # the installer keeps a position per entry.
    param([string]$Key, [string[]]$Front = @(), [string[]]$Placed = @(), [switch]$Remove, [switch]$Plan)
    $cur = Read-SgPathRaw $Key
    $entries = New-Object 'Collections.Generic.List[string]'
    if ($cur.Raw -ne '') { foreach ($p in ($cur.Raw -split ';')) { $entries.Add($p) } }
    foreach ($p in $Placed) {
        $n = $p.TrimEnd('\')
        for ($i = 0; $i -lt $entries.Count; $i++) {
            if ($entries[$i].TrimEnd('\') -ieq $n) { $entries.RemoveAt($i); break }
        }
    }
    if (-not $Remove) {
        Test-SgPathEntries $Key $Front
        $entries.InsertRange(0, [string[]]$Front)
    }
    $new = ($entries -join ';')
    if ($Plan) { return @{ Present = ($new -ne ''); Raw = $new; Kind = $cur.Kind } }
    $k = Open-SgEnvKey $Key -Write
    try {
        if ($new -eq '') { if ($cur.Present) { $k.DeleteValue('Path') } }
        else { $k.SetValue('Path', $new, [Microsoft.Win32.RegistryValueKind]$cur.Kind) }
    } finally { $k.Dispose() }
    if ($Key -eq 'HKCU:\Environment') { Send-SyncGateEnvChange }
    @{ Present = ($new -ne ''); Raw = $new; Kind = $cur.Kind }
}

function Read-SgUserVar {
    param([string]$Key, [string]$Name)
    $k = Open-SgEnvKey $Key
    if ($null -eq $k) { return $null }
    try { $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $k.Dispose() }
}

function Read-SgUserVarOriginal {
    # What was in the user variable before sync_gate: @{ value; kind } (raw text), or $null when absent.
    # Only text values (REG_SZ, REG_EXPAND_SZ) can be given back as they were; any other type is refused.
    param([string]$Key, [string]$Name)
    $k = Open-SgEnvKey $Key
    if ($null -eq $k) { return $null }
    try {
        if (@($k.GetValueNames()) -inotcontains $Name) { return $null }
        $kind = $k.GetValueKind($Name).ToString()
        if ($kind -ne 'String' -and $kind -ne 'ExpandString') {
            throw "user variable $Name is of type $kind and sync_gate keeps only text values; remove or change it, then run again (nothing was changed)"
        }
        @{ value = [string]$k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); kind = $kind }
    } finally { $k.Dispose() }
}

function Get-SgOriginals {
    # vars_original of a state; a state written by 0.1.0 or 0.1.1 has none (those originals are lost).
    param($State)
    if ($State -and $State.PSObject.Properties['vars_original']) { $State.vars_original }
}

function Set-SyncGateUserVars {
    # Writes -Vars; first drops the names of -Previous that are not in -Vars (only if still our value) and gives
    # back the -Original ({ value; kind } by name) that was there before sync_gate.
    param([string]$Key, [System.Collections.IDictionary]$Vars = @{}, $Previous, $Original, [switch]$Remove)
    if ($Remove) { $Vars = @{} }
    $prev = ConvertTo-SgHashtable $Previous
    $orig = if ($Original -is [System.Collections.IDictionary]) { $Original } else { ConvertTo-SgHashtable $Original }
    $k = Open-SgEnvKey $Key -Write
    try {
        foreach ($n in $prev.Keys) {
            if ($Vars.Contains($n)) { continue }
            $cur = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -ne $cur -and $cur -is [string] -and $cur -ceq $prev[$n]) {
                $o = $orig[$n]
                if ($null -ne $o) { $k.SetValue($n, [string]$o.value, [Microsoft.Win32.RegistryValueKind]$o.kind) } else { $k.DeleteValue($n) }
            }
            elseif ($null -ne $cur) { Write-SgLine "user variable $n changed by someone else; left as it is" }
        }
        foreach ($n in $Vars.Keys) { $k.SetValue($n, [string]$Vars[$n], [Microsoft.Win32.RegistryValueKind]::String) }
    } finally { $k.Dispose() }
    if ($Key -eq 'HKCU:\Environment') { Send-SyncGateEnvChange }
    $out = [ordered]@{}; foreach ($n in $Vars.Keys) { $out[$n] = [string]$Vars[$n] }
    $out
}

# ---------------------------------------------------------------- PowerShell profiles

function Test-SyncGateProfileAllowed {
    param([string]$Policy)
    if ($env:SYNC_GATE_TEST_POLICY) { $Policy = $env:SYNC_GATE_TEST_POLICY }
    $Policy -in @('RemoteSigned', 'Unrestricted', 'Bypass')
}

function Get-SgHostPolicy {
    param([string]$HostName)
    if ($env:SYNC_GATE_TEST_POLICY) { return $env:SYNC_GATE_TEST_POLICY }
    if ($HostName -eq 'pwsh') {
        $c = Get-Command pwsh -ErrorAction SilentlyContinue
        # PowerShell 7 not installed: its Windows default is RemoteSigned; the file is inert until it is.
        if (-not $c) { return 'RemoteSigned' }
        $exe = $c.Source
    } else { $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
    # `powershell -ExecutionPolicy X` puts X in PSExecutionPolicyPreference and every child inherits it; the
    # policy a NEW terminal would have is the one without it.
    $r = Invoke-SgNative -File $exe -Arguments @('-NoProfile', '-Command', 'Get-ExecutionPolicy') -Unset @('PSExecutionPolicyPreference')
    $r.Out.Trim()
}

function Get-SyncGateBlockText {
    param([string]$Shims)
    $q = $Shims.Replace("'", "''")
    $line = '$env:Path = ''{0};'' + (($env:Path -split '';'' | ? {{ $_ -and $_.TrimEnd(''\'') -ne ''{0}'' }}) -join '';'')' -f $q
    $err = $null
    [void][Management.Automation.Language.Parser]::ParseInput($line, [ref]$null, [ref]$err)
    if ($err.Count -gt 0) { throw "profile block does not parse: $($err[0].Message)" }
    "$script:SgBlockStart`r`n$line`r`n$script:SgBlockEnd"
}

function Read-SgProfile {
    # Text view that round-trips bytes: UTF-16 files by their BOM, everything else as Latin-1 (1 byte = 1 char).
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $b = [IO.File]::ReadAllBytes($Path)
    if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { $enc = [Text.Encoding]::Unicode; $bom = $b[0..1]; $body = @(if ($b.Length -gt 2) { $b[2..($b.Length - 1)] }) }
    elseif ($b.Length -ge 2 -and $b[0] -eq 0xFE -and $b[1] -eq 0xFF) { $enc = [Text.Encoding]::BigEndianUnicode; $bom = $b[0..1]; $body = @(if ($b.Length -gt 2) { $b[2..($b.Length - 1)] }) }
    elseif ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $enc = $script:SgLatin1; $bom = $b[0..2]; $body = @(if ($b.Length -gt 3) { $b[3..($b.Length - 1)] }) }
    else { $enc = $script:SgLatin1; $bom = @(); $body = $b }
    @{ Bytes = $b; Enc = $enc; Bom = [byte[]]$bom; Text = $enc.GetString([byte[]]$body) }
}

function ConvertTo-SgProfileBytes {
    param($Profile, [string]$Text)
    [byte[]]($Profile.Bom + $Profile.Enc.GetBytes($Text))
}

function Remove-SgBlockText {
    param([string]$Text)
    $re = '(?s)(?:\r\n)?' + [regex]::Escape($script:SgBlockStart) + '.*?' + [regex]::Escape($script:SgBlockEnd) + '(?:\r\n)?'
    [regex]::Replace($Text, $re, '')
}

function Set-SyncGateProfileBlock {
    # Install: -Profiles @{Path;Host}. Remove: -Remove with the paths of -Previous and of -Profiles, policy ignored.
    # Returns the state entries (path, created). shortcut: a no-BOM profile gets the block as UTF-8 bytes;
    # a non-ASCII shims path then reads wrongly in Windows PowerShell 5.1 until the file has a BOM.
    param($Profiles = @(), [string]$Shims, $Previous = @(), [switch]$Remove, [scriptblock]$Ahead)
    $entries = @()
    $prevCreated = @{}
    foreach ($p in @($Previous)) { if ($p) { $prevCreated[[string]$p.path] = [bool]$p.created } }
    if ($Remove) {
        $paths = @($prevCreated.Keys) + @($Profiles | ForEach-Object { $_.Path })
        foreach ($path in ($paths | Select-Object -Unique)) {
            $pf = Read-SgProfile $path
            if (-not $pf) { continue }
            $new = Remove-SgBlockText $pf.Text
            if ($new -eq $pf.Text) { continue }
            if ($prevCreated[$path] -and $new -eq '') {
                if ($Ahead) { & $Ahead $path 'absent' }
                Remove-Item -LiteralPath $path -Force
            } else {
                $bytes = ConvertTo-SgProfileBytes $pf $new
                if ($Ahead) { & $Ahead $path (Get-SgHash $bytes) }
                [IO.File]::WriteAllBytes($path, $bytes)
            }
        }
        return
    }
    $block = Get-SyncGateBlockText $Shims
    foreach ($pr in $Profiles) {
        $path = $pr.Path
        $policy = Get-SgHostPolicy $pr.Host
        if (-not (Test-SyncGateProfileAllowed -Policy $policy)) {
            Write-SgLine "profile $path left alone: the $($pr.Host) execution policy is $policy, so it would not run the profile"
            continue
        }
        $pf = Read-SgProfile $path
        $created = $false
        if (-not $pf) {
            $dir = Split-Path -Parent $path
            if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Force -Path $dir) }
            $bytes = [byte[]](@(0xEF, 0xBB, 0xBF) + [Text.Encoding]::UTF8.GetBytes("$block`r`n"))
            if ($Ahead) { & $Ahead $path (Get-SgHash $bytes) }
            [IO.File]::WriteAllBytes($path, $bytes)
            $created = $true
        } else {
            $created = [bool]$prevCreated[$path]
            $text = Remove-SgBlockText $pf.Text
            $appended = $block
            if ($pf.Enc -eq $script:SgLatin1) { $appended = $script:SgLatin1.GetString([Text.Encoding]::UTF8.GetBytes($block)) }
            $sep = ''; if ($text -ne '') { $sep = "`r`n" }
            $bytes = ConvertTo-SgProfileBytes $pf ($text + $sep + $appended + "`r`n")
            if ($Ahead) { & $Ahead $path (Get-SgHash $bytes) }
            [IO.File]::WriteAllBytes($path, $bytes)
        }
        $entries += , ([ordered]@{ path = $path; created = $created })
    }
    $entries
}

# ---------------------------------------------------------------- launcher and task

function ConvertTo-SgBatValue {
    param([string]$Value)
    Assert-SgPlainValue 'a launcher value' $Value
    $Value.Replace('%', '%%')
}

function Write-SyncGateLauncher {
    param($Layout)
    $n = ConvertTo-SgBatValue
    $lines = @('@echo off', 'setlocal DisableDelayedExpansion',
        "rem Written by the sync_gate installer; started by the scheduled task $(ConvertTo-SgBatValue $Layout.Task).")
    foreach ($k in $Layout.Overrides.Keys) { $lines += "set `"$k=$(ConvertTo-SgBatValue ([string]$Layout.Overrides[$k]))`"" }
    $log = ConvertTo-SgBatValue $Layout.Log
    $lines += "if exist `"$log`" move /y `"$log`" `"$log.1`" >nul"
    $lines += "`"$(ConvertTo-SgBatValue (Join-Path $Layout.Bin 'sync_gated.exe'))`" 2> `"$log`""
    $text = ($lines -join "`r`n") + "`r`n"
    # cmd reads the file in the OEM code page; refuse text that would not survive it.
    $oem = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
    $bytes = $oem.GetBytes($text)
    if ($oem.GetString($bytes) -ne $text) { throw 'a path in the launcher has characters the console code page cannot hold' }
    [IO.File]::WriteAllBytes($Layout.Launcher, $bytes)
}

function Test-SgTaskRoot {
    # Task Scheduler expands %NAME% in the working directory (error 0x8007010B); there is no escape, so a root with
    # '%' needs an 8.3 short name. GetShortPathName needs the folder to exist: it is created here and removed
    # again if the install is refused (this runs before any other change).
    param([string]$Root)
    if (-not $Root.Contains('%')) { return }
    $first = $null; $p = $Root
    while ($p -and -not (Test-Path -LiteralPath $p)) { $first = $p; $p = Split-Path -Parent $p }
    [void](New-Item -ItemType Directory -Force -Path $Root)
    $short = Get-SgShortPath $Root
    if (-not $short -or $short.Contains('%')) {
        if ($first) { Remove-Item -LiteralPath $first -Recurse -Force -ErrorAction SilentlyContinue }
        throw "the install folder contains '%', Task Scheduler cannot start a program there, and this volume has no 8.3 name for it; choose another folder"
    }
}

function Register-SyncGateTask {
    param($Layout)
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $conhost = Join-Path $env:SystemRoot 'System32\conhost.exe'
    # Task Scheduler expands %NAME% in the working directory (error 0x8007010B on a folder named %TEMP%);
    # there is no escape, so a root with '%' goes in by its 8.3 name or the install stops.
    $work = $Layout.Root
    if ($work.Contains('%')) {
        $work = Get-SgShortPath $work
        if (-not $work -or $work.Contains('%')) { throw "the install folder contains '%', Task Scheduler cannot start a program there, and this volume has no 8.3 name for it; choose another folder" }
    }
    $action = New-ScheduledTaskAction -Execute $conhost -Argument '--headless cmd.exe /d /v:off /c launcher.cmd' -WorkingDirectory $work
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    # Repetition every 5 min with no end: while the daemon runs IgnoreNew drops the repeat; if it dies, the next one restarts it.
    $rep = New-ScheduledTaskTrigger -Once -At '00:00' -RepetitionInterval (New-TimeSpan -Minutes 5)
    $trigger.Repetition = $rep.Repetition
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    [void](Register-ScheduledTask -TaskName $Layout.Task -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force)
}

# ---------------------------------------------------------------- daemon control and health

function Get-SgInstallEnv {
    param($Layout)
    $e = @{}
    foreach ($k in $Layout.Overrides.Keys) { $e[$k] = [string]$Layout.Overrides[$k] }
    $e
}

function Stop-SyncGateDaemon {
    param($Layout, [string]$StatusExe)
    $t = Get-ScheduledTask -TaskName $Layout.Task -ErrorAction SilentlyContinue
    if ($t) {
        [void](Disable-ScheduledTask -TaskName $Layout.Task)
        Stop-ScheduledTask -TaskName $Layout.Task -ErrorAction SilentlyContinue
    }
    $ours = Join-Path $Layout.Bin 'sync_gated.exe'
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $mine = @(Get-SgDaemonProcesses | Where-Object { Test-SgSamePath $_.Path $ours })
        foreach ($p in $mine) { Stop-Process -Id $p.Pid -Force -ErrorAction SilentlyContinue }
        if ($mine.Count -eq 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($StatusExe -and (Test-Path -LiteralPath $StatusExe)) {
        $r = Invoke-SgNative -File $StatusExe -Arguments @('status') -Env (Get-SgInstallEnv $Layout) -TimeoutSec 15
        if ($r.ExitCode -eq 0) {
            $sock = '(see sync_gate paths)'
            try { $sock = (Get-SyncGatePaths -Bin $StatusExe -Env (Get-SgInstallEnv $Layout)).socket } catch { }
            $others = @(Get-SgDaemonProcesses | Where-Object { -not (Test-SgSamePath $_.Path $ours) } |
                ForEach-Object { "  pid $($_.Pid): $($_.Path)" })
            $hint = ''; if ($others.Count) { $hint = "`nsync_gated processes from other folders (not touched):`n" + ($others -join "`n") }
            throw "another sync_gated is serving $sock$hint"
        }
    }
}

function Install-SyncGateBinaries {
    param([Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string]$Bin, [Parameter(Mandatory)][string]$Stamp)
    [void](New-Item -ItemType Directory -Force -Path $Bin)
    foreach ($n in $script:SgExes) {
        $dst = Join-Path $Bin $n
        # A running program can be renamed on Windows but not overwritten (P16); the .old-* files are removed later.
        if (Test-Path -LiteralPath $dst) { Rename-Item -LiteralPath $dst -NewName "$n.old-$Stamp" }
        Copy-Item -LiteralPath (Join-Path $From $n) -Destination $dst
    }
}

function Start-SyncGateDaemon {
    param($Layout)
    [void](Enable-ScheduledTask -TaskName $Layout.Task)
    Start-ScheduledTask -TaskName $Layout.Task
    $exe = Join-Path $Layout.Bin 'sync_gate.exe'
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $r = Invoke-SgNative -File $exe -Arguments @('status') -Env (Get-SgInstallEnv $Layout) -TimeoutSec 15
        if ($r.ExitCode -eq 0) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "the daemon did not answer within 15 s (see $($Layout.Log))"
}

function Get-SgFreshEnv {
    # What a new terminal would have: the user variables of the key, never this process's SYNC_GATE_*.
    param($Layout, $State)
    $e = @{}
    foreach ($n in 'SystemRoot', 'windir', 'ComSpec', 'USERNAME', 'USERPROFILE', 'USERDOMAIN', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP', 'PATHEXT', 'OS', 'ProgramData', 'ProgramFiles', 'COMPUTERNAME') {
        $v = [Environment]::GetEnvironmentVariable($n); if ($v) { $e[$n] = $v }
    }
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userRaw = (Read-SgPathRaw $Layout.EnvKey).Raw
    $e['Path'] = [Environment]::ExpandEnvironmentVariables("$userRaw;$machine")
    if ($State -and $State.vars) {
        foreach ($p in $State.vars.PSObject.Properties) {
            $v = Read-SgUserVar $Layout.EnvKey $p.Name
            if ($null -ne $v) { $e[$p.Name] = [string]$v }
        }
    }
    $e
}

function Test-SyncGateHealth {
    param($Layout)
    $state = Read-SgState $Layout.StatePath
    $exe = Join-Path $Layout.Bin 'sync_gate.exe'
    $fresh = Get-SgFreshEnv $Layout $state
    $r = Invoke-SgNative -File $exe -Arguments @('paths') -Env $fresh -CleanEnv
    if ($r.ExitCode -ne 0) { throw "health: sync_gate paths failed in a clean environment: $($r.Err.Trim())" }
    $seen = @{}
    foreach ($line in ($r.Out -split "\r?\n")) { $i = $line.IndexOf('='); if ($i -gt 0) { $seen[$line.Substring(0, $i)] = $line.Substring($i + 1) } }
    $want = Get-SyncGatePaths -Bin $exe -Env (Get-SgInstallEnv $Layout)
    foreach ($k in 'socket', 'data', 'config') {
        if ($seen[$k] -ne $want[$k]) { throw "health: a new terminal would use $k=$($seen[$k]) but the install uses $($want[$k])" }
    }
    $s = Invoke-SgNative -File $exe -Arguments @('status') -Env $fresh -CleanEnv -TimeoutSec 15
    if ($s.ExitCode -ne 0) { throw "health: sync_gate status exited $($s.ExitCode) in a clean environment: $($s.Err.Trim())" }
    $ours = Join-Path $Layout.Bin 'sync_gated.exe'
    $procs = @(Get-SgDaemonProcesses)
    $mine = @($procs | Where-Object { Test-SgSamePath $_.Path $ours })
    if ($mine.Count -eq 0) { throw "health: no sync_gated of $($Layout.Bin) is running" }
    # shortcut: the pid in `status` is matched only if the text has one ("pid ... N"); else the process check above stands.
    if ($s.Out -match '(?i)pid\D{0,5}(\d+)') {
        $pidSeen = [int]$Matches[1]
        if (-not ($mine | Where-Object { $_.Pid -eq $pidSeen })) { throw "health: the daemon that answers (pid $pidSeen) is not the one in $($Layout.Bin)" }
    }
}

function Complete-SyncGateJournal {
    param($Layout)
    # A later run only rolls back while this marker exists. Remove it before discarding any backups.
    Remove-Item -LiteralPath (Join-Path $Layout.Rollback 'in-progress') -Force -ErrorAction Stop
    try { Remove-Item -LiteralPath $Layout.Rollback -Recurse -Force -ErrorAction Stop }
    catch { Write-SgLine "warning: could not clear the completed journal in $($Layout.Rollback): $($_.Exception.Message)" }
}

function Get-SgOldBinaries {
    param([string]$Bin)
    if (-not (Test-Path -LiteralPath $Bin)) { return }
    Get-ChildItem -LiteralPath $Bin -Filter '*.old-*' -File -Force | Where-Object {
        $_.Name -match '^(?<exe>[^.]+\.exe)\.old-(?:new-)?(?:[0-9]{14}|[0-9a-f]{32})$' -and $script:SgExes -contains $Matches.exe
    }
}

function Complete-SyncGateRun {
    param($Layout)
    Complete-SyncGateJournal $Layout
    $left = @()
    foreach ($f in @(Get-SgOldBinaries $Layout.Bin)) {
        try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop } catch { $left += $f.Name }
    }
    $left
}

# ---------------------------------------------------------------- rollback

function Save-SyncGateRollback {
    param($Layout, [bool]$Fresh, [string]$Stamp, [string]$FirstStep)
    $rb = $Layout.Rollback
    if (Test-Path -LiteralPath $rb) { Remove-Item -LiteralPath $rb -Recurse -Force }
    [void](New-Item -ItemType Directory -Force -Path (Join-Path $rb 'bin'), (Join-Path $rb 'profiles'))
    foreach ($n in $script:SgExes) {
        $f = Join-Path $Layout.Bin $n
        if (Test-Path -LiteralPath $f) { Copy-Item -LiteralPath $f -Destination (Join-Path $rb "bin\$n") }
    }
    foreach ($f in @($Layout.Launcher, $Layout.StatePath)) {
        if (Test-Path -LiteralPath $f) { Copy-Item -LiteralPath $f -Destination (Join-Path $rb (Split-Path -Leaf $f)) }
    }
    $task = Get-ScheduledTask -TaskName $Layout.Task -ErrorAction SilentlyContinue
    if ($task) { Write-SgTextFile (Join-Path $rb 'task.xml') ([string](Export-ScheduledTask -TaskName $Layout.Task)) }
    Write-SgTextFile (Join-Path $rb 'path.json') ((Read-SgPathRaw $Layout.EnvKey) | ConvertTo-Json)
    $names = @($script:SgOwnNames)
    if ($Layout.State -and $Layout.State.vars) { $names += @($Layout.State.vars.PSObject.Properties.Name) }
    $vars = [ordered]@{}
    foreach ($n in ($names | Select-Object -Unique)) { $vars[$n] = Read-SgUserVar $Layout.EnvKey $n }
    Write-SgTextFile (Join-Path $rb 'vars.json') ($vars | ConvertTo-Json)
    # The kind of a value that expands (a journal of 0.1.1 has no such file: everything was written as text).
    $kinds = [ordered]@{}
    foreach ($n in $vars.Keys) { if ($vars[$n] -is [string]) { if ((Read-SgUserVarOriginal $Layout.EnvKey $n).kind -eq 'ExpandString') { $kinds[$n] = 'ExpandString' } } }
    Write-SgTextFile (Join-Path $rb 'vars-kinds.json') ($kinds | ConvertTo-Json)
    $paths = @($Layout.Profiles | ForEach-Object { $_.Path })
    if ($Layout.State -and $Layout.State.profiles) { $paths += @($Layout.State.profiles | ForEach-Object { $_.path }) }
    $meta = @()
    $i = 0
    foreach ($p in ($paths | Select-Object -Unique)) {
        $i++
        $exists = Test-Path -LiteralPath $p
        if ($exists) { Copy-Item -LiteralPath $p -Destination (Join-Path $rb "profiles\p$i.bin") }
        $meta += , ([ordered]@{ path = $p; exists = $exists; file = "p$i.bin" })
    }
    Write-SgTextFile (Join-Path $rb 'profiles.json') (ConvertTo-Json -InputObject $meta -Depth 4)
    Write-SgTextFile (Join-Path $rb 'meta.json') (([ordered]@{ fresh = $Fresh; stamp = $Stamp; test = $Layout.Test }) | ConvertTo-Json)
    Write-SgTextFile (Join-Path $rb 'wrote.json') '{}'
    Set-SgStep $Layout $FirstStep
}

function Set-SgStep {
    param($Layout, [string]$Step)
    $marker = Join-Path $Layout.Rollback 'in-progress'
    $next = "$marker.next"
    # Publish only a complete step, leaving the previous one active if writing is interrupted.
    Write-SgTextFile $next $Step
    if ([IO.File]::Exists($marker)) { [IO.File]::Replace($next, $marker, [NullString]::Value) }
    else { [IO.File]::Move($next, $marker) }
}

function Set-SgWrote {
    # Records what the installer left, so a rollback only overwrites values that are still ours.
    param($Layout, [string]$Kind, $Value, [string]$Name)
    $f = Join-Path $Layout.Rollback 'wrote.json'
    $w = ConvertTo-SgHashtable (Get-Content -LiteralPath $f -Raw | ConvertFrom-Json)
    if ($Kind -eq 'path') { $w['path'] = $Value }
    else {
        $sub = ConvertTo-SgHashtable $w[$Kind]
        $sub[$Name] = $Value
        $w[$Kind] = $sub
    }
    Write-SgTextFile $f ($w | ConvertTo-Json -Depth 5)
}

function Restore-SyncGateRollback {
    # Undoes the steps up to the recorded one, newest first. Returns the items it could not restore.
    param($Layout)
    $rb = $Layout.Rollback
    $step = [IO.File]::ReadAllText((Join-Path $rb 'in-progress')).Trim()
    $acts = @{
        S1 = @(); S2 = @('stop'); S3 = @('stop', 'bin'); S4 = @('stop', 'bin', 'shims'); S5 = @('stop', 'bin', 'shims', 'regs')
        S6 = @('stop', 'bin', 'shims', 'regs', 'task'); S7 = @('stop', 'bin', 'shims', 'regs', 'task', 'daemon')
        U3 = @(); U4 = @('stop'); U5 = @('stop', 'shims'); U6 = @('stop', 'shims', 'regs', 'task'); U7 = @('stop', 'bin', 'shims', 'regs', 'task')
    }[$step]
    if ($null -eq $acts) { throw "unknown rollback step '$step'" }
    $meta = Get-Content -LiteralPath (Join-Path $rb 'meta.json') -Raw | ConvertFrom-Json
    $wrote = Get-Content -LiteralPath (Join-Path $rb 'wrote.json') -Raw | ConvertFrom-Json
    $problems = @()
    $oldEnv = $null
    $oldStateFile = Join-Path $rb 'install-state.json'
    if (Test-Path -LiteralPath $oldStateFile) {
        $o = Read-SgState $oldStateFile
        $oldEnv = @{}; foreach ($k in (ConvertTo-SgHashtable $o.overrides).Keys) { $oldEnv[$k] = [string]$o.overrides.$k }
    } else { $oldEnv = Get-SgInstallEnv $Layout }
    $exe = Join-Path $Layout.Bin 'sync_gate.exe'
    $hadTask = Test-Path -LiteralPath (Join-Path $rb 'task.xml')

    if ($acts -contains 'daemon') {
        try { Stop-SyncGateDaemon -Layout $Layout } catch { $problems += "stop of the new daemon ($($_.Exception.Message))" }
    }
    if ($acts -contains 'regs') {
        # PATH
        $origPath = Get-Content -LiteralPath (Join-Path $rb 'path.json') -Raw | ConvertFrom-Json
        $cur = Read-SgPathRaw $Layout.EnvKey
        if ($wrote.PSObject.Properties['path']) {
            $w = $wrote.path
            if (($cur.Present -eq $w.Present -and $cur.Raw -ceq $w.Raw) -or ($cur.Present -eq $origPath.Present -and $cur.Raw -ceq $origPath.Raw)) {
                $k = Open-SgEnvKey $Layout.EnvKey -Write
                try {
                    if ($origPath.Present) { $k.SetValue('Path', [string]$origPath.Raw, [Microsoft.Win32.RegistryValueKind]$origPath.Kind) }
                    elseif ($cur.Present) { $k.DeleteValue('Path') }
                } finally { $k.Dispose() }
            } else { $problems += 'PATH (changed by someone else; left as it is)' }
        }
        # user variables
        $origVars = ConvertTo-SgHashtable (Get-Content -LiteralPath (Join-Path $rb 'vars.json') -Raw | ConvertFrom-Json)
        $wv = @{}; if ($wrote.PSObject.Properties['vars']) { $wv = ConvertTo-SgHashtable $wrote.vars }
        $kf = Join-Path $rb 'vars-kinds.json'
        $origKinds = @{}; if (Test-Path -LiteralPath $kf) { $origKinds = ConvertTo-SgHashtable (Get-Content -LiteralPath $kf -Raw | ConvertFrom-Json) }
        $k = Open-SgEnvKey $Layout.EnvKey -Write
        try {
            foreach ($n in $origVars.Keys) {
                if (-not $wv.Contains($n)) { continue }
                $c = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $o = $origVars[$n]; $wn = $wv[$n]
                if (($c -ceq $wn) -or ($c -ceq $o) -or ($null -eq $c -and $null -eq $wn) -or ($null -eq $c -and $null -eq $o)) {
                    if ($null -eq $o) { if ($null -ne $c) { $k.DeleteValue($n) } } else {
                        $kind = 'String'; if ($origKinds.Contains($n)) { $kind = $origKinds[$n] }
                        $k.SetValue($n, [string]$o, [Microsoft.Win32.RegistryValueKind]$kind)
                    }
                } else { $problems += "user variable $n (changed by someone else; left as it is)" }
            }
        } finally { $k.Dispose() }
        if ($Layout.EnvKey -eq 'HKCU:\Environment') { Send-SyncGateEnvChange }
        # profiles
        $wp = @{}; if ($wrote.PSObject.Properties['profiles']) { $wp = ConvertTo-SgHashtable $wrote.profiles }
        # No @(...) here: Windows PowerShell 5.1 emits a JSON array as one object, and @() would nest it.
        foreach ($m in (Get-Content -LiteralPath (Join-Path $rb 'profiles.json') -Raw | ConvertFrom-Json)) {
            if (-not $wp.Contains($m.path)) { continue }
            $curBytes = $null; if (Test-Path -LiteralPath $m.path) { $curBytes = [IO.File]::ReadAllBytes($m.path) }
            $orig = $null; if ($m.exists) { $orig = [IO.File]::ReadAllBytes((Join-Path $rb "profiles\$($m.file)")) }
            $hc = Get-SgHash $curBytes
            if ($hc -eq (Get-SgHash $orig)) { continue }
            if ($hc -eq $wp[$m.path]) {
                try {
                    if ($m.exists) { [IO.File]::WriteAllBytes($m.path, $orig) }
                    elseif (Test-Path -LiteralPath $m.path) { Remove-Item -LiteralPath $m.path -Force }
                } catch { $problems += "profile $($m.path) ($($_.Exception.Message))" }
            } else { $problems += "profile $($m.path) (changed by someone else; left as it is)" }
        }
        # launcher and state
        foreach ($f in @($Layout.Launcher, $Layout.StatePath)) {
            $copy = Join-Path $rb (Split-Path -Leaf $f)
            try {
                if (Test-Path -LiteralPath $copy) { Copy-Item -LiteralPath $copy -Destination $f -Force }
                elseif (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
            } catch { $problems += "$f ($($_.Exception.Message))" }
        }
    }
    if ($step -ne 'U7' -and $acts -contains 'shims' -and $meta.fresh -and (Test-Path -LiteralPath $exe)) {
        $r = Invoke-SgNative -File $exe -Arguments @('shims', 'remove') -Env $oldEnv
        if ($r.ExitCode -ne 0) { $problems += "shims ($($r.Err.Trim()))" }
    }
    $binaryProblems = @()
    if ($acts -contains 'bin') {
        foreach ($n in $script:SgExes) {
            $dst = Join-Path $Layout.Bin $n
            $old = Join-Path $Layout.Bin "$n.old-$($meta.stamp)"
            $copy = Join-Path $rb "bin\$n"
            try {
                $hasDst = Test-Path -LiteralPath $dst
                $hasOld = Test-Path -LiteralPath $old
                $hasCopy = Test-Path -LiteralPath $copy
                if ($step -eq 'U7' -and -not ($hasOld -or $hasCopy) -and ($n -eq 'sync_gate.exe' -or ($hadTask -and $n -eq 'sync_gated.exe'))) {
                    throw 'previous binary is missing from the rollback journal'
                }
                if ($step -eq 'U7' -and $hasDst) {
                    # U7 only renames executables out of the way, so a replacement might belong to the user.
                    $previous = if ($hasOld) { $old } elseif ($hasCopy) { $copy }
                    if ($previous -and (Get-FileHash -LiteralPath $dst).Hash -ne (Get-FileHash -LiteralPath $previous).Hash) {
                        throw 'changed by someone else; left as it is'
                    }
                } elseif ($hasOld) {
                    if ($hasDst) { Rename-Item -LiteralPath $dst -NewName "$n.old-new-$($meta.stamp)" }
                    Rename-Item -LiteralPath $old -NewName $n
                } elseif ($hasCopy -and -not $hasDst) {
                    [void][IO.Directory]::CreateDirectory($Layout.Bin)
                    [IO.File]::Copy($copy, $dst)
                } elseif ($meta.fresh -and $hasDst -and -not $hasCopy) {
                    Rename-Item -LiteralPath $dst -NewName "$n.old-new-$($meta.stamp)"
                }
            } catch { $binaryProblems += "$n ($($_.Exception.Message))" }
        }
        foreach ($f in @(Get-SgOldBinaries $Layout.Bin | Where-Object { $_.Name.EndsWith(".old-new-$($meta.stamp)") })) {
            try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop } catch { }
        }
    }
    if ($binaryProblems.Count) { return ($problems + $binaryProblems) }
    if ($acts -contains 'shims' -and -not $meta.fresh -and (Test-Path -LiteralPath $exe)) {
        $se = @{} + $oldEnv; $se['Path'] = (Get-SgFreshEnv $Layout $null)['Path']   # as in S4
        $r = Invoke-SgNative -File $exe -Arguments @('shims', 'install') -Env $se
        if ($r.ExitCode -ne 0) { $problems += "shims ($($r.Err.Trim()))" }
    }
    if ($acts -contains 'task') {
        try {
            if ($hadTask) { [void](Register-ScheduledTask -TaskName $Layout.Task -Xml ([IO.File]::ReadAllText((Join-Path $rb 'task.xml'))) -Force) }
            else { Unregister-ScheduledTask -TaskName $Layout.Task -Confirm:$false -ErrorAction SilentlyContinue }
        } catch { $problems += "scheduled task ($($_.Exception.Message))" }
    }
    if ($acts -contains 'stop' -and $hadTask) {
        # Waits until the old daemon answers: the health check right after would otherwise race its start.
        try { Start-SyncGateDaemon -Layout $Layout } catch { $problems += "task start ($($_.Exception.Message))" }
    }
    $problems
}

# ---------------------------------------------------------------- uninstall helpers

function Get-SgShortPath {
    param([string]$Path)
    Get-SgWin32
    $sb = New-Object Text.StringBuilder 520
    if ([SyncGate.Win]::GetShortPathName($Path, $sb, 520) -gt 0) { $sb.ToString() } else { $null }
}

function ConvertTo-SgReferencePath {
    param([string]$Path)
    $normalized = $Path -replace '[\\/]+', '\'
    if ($normalized -match '^\\[?.]\\UNC\\') { $normalized = $normalized -replace '^\\[?.]\\UNC\\', '\\' }
    elseif ($normalized -match '^\\[?.]\\[a-z]:\\') { $normalized = $normalized.Substring(3) }
    elseif ($Path -match '^[\\/]{2}') { $normalized = '\' + $normalized }
    try { [IO.Path]::GetFullPath($normalized) }
    catch [ArgumentException], [NotSupportedException] { }
}

function Get-SgAgentConfigs {
    param($Layout)
    $claude = $Layout.ClaudeConfig
    if (-not $claude) {
        $claudeDir = $env:CLAUDE_CONFIG_DIR
        if (-not $claudeDir) { $claudeDir = $env:USERPROFILE }
        $claude = Join-Path $claudeDir '.claude.json'
    }
    $codex = $Layout.CodexConfig
    if (-not $codex) {
        $codexDir = $env:CODEX_HOME
        if (-not $codexDir) { $codexDir = Join-Path $env:USERPROFILE '.codex' }
        $codex = Join-Path $codexDir 'config.toml'
    }
    @{
        Claude = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($claude)
        Codex = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($codex)
    }
}

function Find-SgConfigReferences {
    # shortcut: matches executable paths in config text, until agent config readers expose command paths.
    param([string]$Bin, [string[]]$Files)
    $dirs = foreach ($dir in $Bin, (Get-SgShortPath $Bin)) {
        if ($dir) { ConvertTo-SgReferencePath $dir }
    }
    $names = foreach ($exe in $script:SgExes) {
        [IO.Path]::GetFileNameWithoutExtension($exe)
        $short = Get-SgShortPath (Join-Path $Bin $exe)
        if ($short) { [IO.Path]::GetFileNameWithoutExtension($short) }
    }
    $escapedNames = $names | Select-Object -Unique | ForEach-Object { [regex]::Escape($_) }
    $heads = '%LOCALAPPDATA%', '$env:LOCALAPPDATA', '${env:LOCALAPPDATA}', '%USERPROFILE%\AppData\Local', '$env:USERPROFILE\AppData\Local', '$HOME\AppData\Local', '~\AppData\Local'
    $aliases = '(?:' + (($heads | ForEach-Object { [regex]::Escape($_) -replace '\\\\', '[\\/]+' }) -join '|') + ')(?=[\\/])'
    $root = '(?:[a-z]:[\\/]|[\\/]{2}|' + $aliases + ')'
    $path = '(?i)(?<![^\s"''=])(?=(?<file>' + $root + '[^"\r\n]*\z))'
    $end = '(?i)[\\/](?:{0})(?:\.exe)?(?=$|[\s"''\],}}]|\\+")' -f ($escapedNames -join '|')
    $jsonString = '"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
    foreach ($f in $files) {
        try { $lines = [IO.File]::ReadAllLines($f) }
        catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] { continue }
        $n = 0
        :line foreach ($line in $lines) {
            $n++
            # Read escape sequences without requiring a particular config shape or losing line numbers.
            $texts = @(
                $line
                foreach ($token in [regex]::Matches($line, $jsonString)) {
                    if ($token.Value.Contains('\')) { ConvertFrom-Json -InputObject $token.Value -ErrorAction Stop }
                }
            )
            foreach ($text in $texts) {
                foreach ($ending in [regex]::Matches($text, $end)) {
                    foreach ($match in [regex]::Matches($text.Substring(0, $ending.Index + $ending.Length), $path)) {
                        $candidate = $match.Groups['file'].Value
                        if ($candidate -match "^$aliases") {
                            if (-not $env:LOCALAPPDATA) { continue }
                            $candidate = $env:LOCALAPPDATA.TrimEnd('\', '/') + $candidate.Substring($Matches[0].Length)
                        }
                        $full = ConvertTo-SgReferencePath $candidate
                        if ($full -and $dirs -contains [IO.Path]::GetDirectoryName($full) -and $names -contains [IO.Path]::GetFileNameWithoutExtension($full)) {
                            "${f}:$n"
                            continue line
                        }
                    }
                }
            }
        }
    }
}

# ---------------------------------------------------------------- run control

function Test-SgFailAt {
    param([string]$Step)
    $f = $env:SYNC_GATE_INSTALL_FAIL_AT
    if ($f -eq "${Step}:crash") { [Environment]::Exit(1) }
    if ($f -eq $Step) { throw "injected failure at $Step" }
}

function Invoke-SgStep {
    param($Layout, [string]$Step, [scriptblock]$Body)
    $script:SgStepNow = $Step
    Set-SgStep $Layout $Step
    & $Body
    Test-SgFailAt $Step
}

function Exit-SgRun {
    param([int]$Code)
    if ($Code -eq 0) { return }
    if ($PSCommandPath) { exit $Code }
    $global:LASTEXITCODE = $Code
}

function Write-SgGuestHint {
    # N9: a user-level SYNC_GATE_DATA_DIR reaches every process of the account, an elevated sandbox guest included.
    # shortcut: scans literal keys without TOML table or multiline string context, until supported releases expose a config reader.
    param($Layout, [string]$ConfigPath)
    if (-not $Layout.Overrides.Contains('SYNC_GATE_DATA_DIR')) { return }
    try { $config = [IO.File]::ReadAllText($ConfigPath) }
    catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] { return }
    catch {
        Write-SgLine "warning: could not check the config for guests ($ConfigPath): $($_.Exception.Message)"
        return
    }
    if ($config -cmatch '(?m)^[ \t]*(?:guests|"guests"|''guests'')[ \t]*=[ \t]*\[(?:[ \t\r\n]|#[^\r\n]*(?:\r?\n|\z))*["'']') {
        Write-SgLine 'warning: you set SYNC_GATE_DATA_DIR and your config lists guests. An elevated sandbox guest would try to keep its pending commands in that folder, where it can only read. If you use guests, do not set your own SYNC_GATE_DATA_DIR.'
    }
}

function Write-SgPluginHints {
    Write-SgLine 'Agent plugin (the installer does not install it):'
    Write-SgLine '  claude plugin marketplace add sync-labs-team/sync_gate'
    Write-SgLine '  claude plugin install sync-gate@sync_gate'
    Write-SgLine '  codex plugin marketplace add sync-labs-team/sync_gate'
    Write-SgLine '  codex plugin add sync-gate@sync_gate'
}

function Resolve-SgFailure {
    # Undo to the previous state, bring the old daemon back, say exactly what is left.
    param($Layout, [string]$What, [string]$Step, [string]$Cause, [bool]$Fresh)
    Write-SgLine "error: $Cause"
    $problems = @()
    try { $problems = @(Restore-SyncGateRollback -Layout $Layout) } catch { $problems = @("rollback ($($_.Exception.Message))") }
    if ($problems.Count -eq 0 -and -not $Fresh) {
        try { Test-SyncGateHealth -Layout $Layout } catch { $problems += "health of the previous version ($($_.Exception.Message))" }
    }
    if ($problems.Count -eq 0) {
        Complete-SyncGateJournal $Layout
        Write-SgLine "$What failed at $Step; previous version restored"
    } else {
        Write-SgLine "$What failed at $Step; could not restore $($problems -join ', '); files kept in $($Layout.Rollback) (see docs/install.md#recover)"
    }
}

function Invoke-SgConfigure {
    # S5: PATH, user variables, profile blocks, launcher, state. Returns what the state recorded.
    param($Layout, [string]$Shims, [string]$Version, $Old)
    $L = $Layout
    $oldPlaced = @(); $oldVars = $null; $oldProfiles = @()
    if ($Old) { $oldPlaced = @($Old.path_placed); $oldVars = $Old.vars; $oldProfiles = @($Old.profiles) }
    # What the user had in a variable before we first wrote it. A name that is already ours keeps the original of
    # the first time (the registry holds our value now); a new name is read from the registry, before anything changes.
    $oldOrig = Get-SgOriginals $Old
    $oldOrigH = ConvertTo-SgHashtable $oldOrig
    $oldVarsH = ConvertTo-SgHashtable $oldVars
    $orig = [ordered]@{}
    foreach ($n in $L.Overrides.Keys) {
        if ($oldVarsH.Contains($n)) { if ($oldOrigH.Contains($n)) { $orig[$n] = $oldOrigH[$n] } }
        else { $o = Read-SgUserVarOriginal $L.EnvKey $n; if ($null -ne $o) { $orig[$n] = $o } }
    }
    # Write-ahead: what a mutation will leave is recorded in wrote.json BEFORE it happens, so a failure or a
    # crash inside the step is still undone (a name to be deleted is recorded with a null value).
    $plan = Set-SyncGatePath -Key $L.EnvKey -Front @($Shims, $L.Bin) -Placed $oldPlaced -Plan
    Set-SgWrote $L 'path' @{ Present = $plan.Present; Raw = $plan.Raw }
    [void](Set-SyncGatePath -Key $L.EnvKey -Front @($Shims, $L.Bin) -Placed $oldPlaced)
    $placed = @($Shims, $L.Bin)
    foreach ($n in $oldVarsH.Keys) {
        if ($L.Overrides.Contains($n)) { continue }
        $w = $null; if ($oldOrigH.Contains($n)) { $w = [string]$oldOrigH[$n].value }   # a removed name goes back to its original
        Set-SgWrote $L 'vars' $w $n
    }
    foreach ($n in $L.Overrides.Keys) { Set-SgWrote $L 'vars' ([string]$L.Overrides[$n]) $n }
    $vars = Set-SyncGateUserVars -Key $L.EnvKey -Vars $L.Overrides -Previous $oldVars -Original $oldOrig
    $profiles = @(Set-SyncGateProfileBlock -Profiles $L.Profiles -Shims $Shims -Previous $oldProfiles -Ahead { param($ap, $ah) Set-SgWrote $L 'profiles' $ah $ap })
    Write-SyncGateLauncher -Layout $L
    Save-SgState -Layout $L -Version $Version -PathPlaced $placed -Vars $vars -ProfileEntries $profiles -Original $orig
    @{ Placed = $placed; Vars = $vars; Profiles = $profiles }
}

function Invoke-SyncGateInstall {
    param([string]$Version, [switch]$ClearOverrides)
    $L = Get-SyncGateLayout -ClearOverrides:$ClearOverrides
    if (Test-Path -LiteralPath (Join-Path $L.Rollback 'in-progress')) {
        $was = [IO.File]::ReadAllText((Join-Path $L.Rollback 'in-progress')).Trim()
        Write-SgLine "a previous run stopped at $was; restoring it first"
        $pr = @(Restore-SyncGateRollback -Layout $L)
        if ($pr.Count) { throw "could not restore $($pr -join ', '); files kept in $($L.Rollback) (see docs/install.md#recover)" }
        Complete-SyncGateJournal $L
        $L = Get-SyncGateLayout -ClearOverrides:$ClearOverrides
    }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('sync_gate-install-' + [Guid]::NewGuid().ToString('N'))
    try {
        $assets = Get-SyncGateAssets -Version $Version -Dest $tmp
        $staged = Join-Path $assets.Dir 'sync_gate.exe'
        $dirs = Get-SyncGatePaths -Bin $staged -Env (Get-SgInstallEnv $L)
        foreach ($v in $dirs.Values) { Assert-SgPlainValue 'a path from sync_gate paths' $v }
        Test-SgPathEntries $L.EnvKey @($dirs.shims, $L.Bin)
        Test-SgTaskRoot $L.Root
        $hadTask = [bool](Get-ScheduledTask -TaskName $L.Task -ErrorAction SilentlyContinue)
        if (-not $hadTask) {
            $r = Invoke-SgNative -File $staged -Arguments @('status') -Env (Get-SgInstallEnv $L) -TimeoutSec 15
            if ($r.ExitCode -eq 0) { throw "another sync_gated is serving $($dirs.socket); nothing was changed" }
        }
        $fresh = (-not $hadTask) -and -not (Test-Path -LiteralPath (Join-Path $L.Bin 'sync_gate.exe'))
        $old = $L.State
        $oldVersion = 'nothing'; if ($old) { $oldVersion = [string]$old.version }
        $stamp = [Guid]::NewGuid().ToString('N')
        $ctx = @{}

        [void](New-Item -ItemType Directory -Force -Path $L.Root)
        Save-SyncGateRollback -Layout $L -Fresh $fresh -Stamp $stamp -FirstStep 'S1'
        try {
            Invoke-SgStep $L 'S2' { Stop-SyncGateDaemon -Layout $L -StatusExe $(if (Test-Path -LiteralPath (Join-Path $L.Bin 'sync_gate.exe')) { Join-Path $L.Bin 'sync_gate.exe' } else { $staged }) }
            Invoke-SgStep $L 'S3' { Install-SyncGateBinaries -From $assets.Dir -Bin $L.Bin -Stamp $stamp }
            Invoke-SgStep $L 'S4' {
                # PATH of a new terminal (machine + the key), not this process's: it decides which shims would hide a .ps1.
                $se = Get-SgInstallEnv $L; $se['Path'] = (Get-SgFreshEnv $L $null)['Path']
                $r = Invoke-SgNative -File (Join-Path $L.Bin 'sync_gate.exe') -Arguments @('shims', 'install') -Env $se
                if ($r.ExitCode -ne 0) { throw "sync_gate shims install failed: $($r.Err.Trim())" }
            }
            Invoke-SgStep $L 'S5' { $s5 = Invoke-SgConfigure -Layout $L -Shims $dirs.shims -Version $assets.Version -Old $old; $ctx.Profiles = $s5.Profiles }
            Invoke-SgStep $L 'S6' { Register-SyncGateTask -Layout $L }
            Invoke-SgStep $L 'S7' { Start-SyncGateDaemon -Layout $L; Test-SyncGateHealth -Layout $L }
        } catch {
            Resolve-SgFailure -Layout $L -What 'upgrade' -Step $script:SgStepNow -Cause $_.Exception.Message -Fresh $fresh
            Exit-SgRun 1
            return
        }
        $left = @(Complete-SyncGateRun -Layout $L)
        Write-SgLine "sync_gate $($assets.Version) installed in $($L.Root) (was: $oldVersion)"
        Write-SgLine "  on PATH (new terminals): $($dirs.shims) ; $($L.Bin)"
        Write-SgLine "  data: $($dirs.data)   config: $($dirs.config)"
        foreach ($k in $L.Overrides.Keys) { Write-SgLine "  own value in use: $k=$($L.Overrides[$k])" }
        foreach ($p in @($ctx.Profiles)) { Write-SgLine "  profile updated: $($p.path)" }
        foreach ($f in $left) { Write-SgLine "  old file still in use, removed on the next run: $f" }
        Write-SgGuestHint -Layout $L -ConfigPath $dirs.config
        Write-SgPluginHints
        Write-SgLine "Update:    irm $script:SgCommandUrl | iex"
        Write-SgLine "Uninstall: & ([scriptblock]::Create((irm $script:SgCommandUrl))) -Uninstall"
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-SyncGateUninstall {
    $L = Get-SyncGateLayout
    if (Test-Path -LiteralPath (Join-Path $L.Rollback 'in-progress')) {
        $was = [IO.File]::ReadAllText((Join-Path $L.Rollback 'in-progress')).Trim()
        Write-SgLine "a previous run stopped at $was; restoring it first"
        $pr = @(Restore-SyncGateRollback -Layout $L)
        if ($pr.Count) { throw "could not restore $($pr -join ', '); files kept in $($L.Rollback) (see docs/install.md#recover)" }
        Complete-SyncGateJournal $L
        $L = Get-SyncGateLayout
    }
    $exe = Join-Path $L.Bin 'sync_gate.exe'
    if (-not $L.State -and -not (Test-Path -LiteralPath $exe)) { Write-SgLine "sync_gate is not installed in $($L.Root); nothing to do"; return }
    if (-not (Test-Path -LiteralPath $exe)) { throw "$exe is missing; reinstall first, then uninstall" }
    $env1 = Get-SgInstallEnv $L
    $dirs = Get-SyncGatePaths -Bin $exe -Env $env1

    # U1: hand every adopted MCP server back; anything but success stops here.
    $a = @('mcp', 'restore', '--strict')
    if ($L.ClaudeConfig) { $a += @('--claude-config', $L.ClaudeConfig) }
    if ($L.CodexConfig) { $a += @('--codex-config', $L.CodexConfig) }
    $r = Invoke-SgNative -File $exe -Arguments $a -Env $env1
    if ($r.ExitCode -ne 0) {
        Write-SgLine ($r.Out + $r.Err).Trim()
        throw 'sync_gate mcp restore --strict failed; nothing was removed'
    }
    # U2: no config may still name our programs, adopted or typed by hand.
    $configs = Get-SgAgentConfigs $L
    $refs = @(Find-SgConfigReferences -Bin $L.Bin -Files @($configs.Claude, $configs.Codex))
    if ($refs.Count) {
        Write-SgLine 'Agent configs still point at the sync_gate programs:'
        foreach ($h in $refs) { Write-SgLine "  $h" }
        throw 'remove those lines (or run `sync_gate mcp restore`) and uninstall again; nothing was removed'
    }
    $stamp = [Guid]::NewGuid().ToString('N')
    $old = $L.State
    Save-SyncGateRollback -Layout $L -Fresh $false -Stamp $stamp -FirstStep 'U3'
    try {
        Invoke-SgStep $L 'U4' { Stop-SyncGateDaemon -Layout $L }
        Invoke-SgStep $L 'U5' {
            $r = Invoke-SgNative -File $exe -Arguments @('shims', 'remove') -Env $env1
            if ($r.ExitCode -ne 0) {
                $names = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($dirs.shims, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { $_.ProcessName } | Select-Object -Unique)
                $list = if ($names.Count) { $names -join ', ' } else { 'the programs listed above' }
                throw "close $list and run uninstall again ($($r.Err.Trim()))"
            }
        }
        Invoke-SgStep $L 'U6' {
            $placed = @(); $vars = $null; $profs = @()
            if ($old) { $placed = @($old.path_placed); $vars = $old.vars; $profs = @($old.profiles) }
            $origH = ConvertTo-SgHashtable (Get-SgOriginals $old)
            $plan = Set-SyncGatePath -Key $L.EnvKey -Placed $placed -Remove -Plan
            Set-SgWrote $L 'path' @{ Present = $plan.Present; Raw = $plan.Raw }
            [void](Set-SyncGatePath -Key $L.EnvKey -Placed $placed -Remove)
            foreach ($n in (ConvertTo-SgHashtable $vars).Keys) { $w = $null; if ($origH.Contains($n)) { $w = [string]$origH[$n].value }; Set-SgWrote $L 'vars' $w $n }
            [void](Set-SyncGateUserVars -Key $L.EnvKey -Previous $vars -Original $origH -Remove)
            [void](Set-SyncGateProfileBlock -Profiles $L.Profiles -Previous $profs -Remove -Ahead { param($ap, $ah) Set-SgWrote $L 'profiles' $ah $ap })
            Unregister-ScheduledTask -TaskName $L.Task -Confirm:$false -ErrorAction SilentlyContinue
            foreach ($f in @($L.Launcher, $L.StatePath)) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
        }
        Invoke-SgStep $L 'U7' {
            foreach ($n in $script:SgExes) {
                $f = Join-Path $L.Bin $n
                if (Test-Path -LiteralPath $f) { Rename-Item -LiteralPath $f -NewName "$n.old-$stamp" }
            }
        }
    } catch {
        Resolve-SgFailure -Layout $L -What 'uninstall' -Step $script:SgStepNow -Cause $_.Exception.Message -Fresh $false
        Exit-SgRun 1
        return
    }
    # Deleting is not undoable: it runs only after every undoable step succeeded.
    Complete-SyncGateJournal $L
    $busy = @()
    foreach ($f in @(Get-SgOldBinaries $L.Bin)) {
        try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop }
        catch {
            $base = $f.Name -replace '\.old-.*$', ''
            $pids = @(Get-CimInstance Win32_Process -Filter "Name='$base'" -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and (Test-SgSamePath (Split-Path -Parent $_.ExecutablePath) $L.Bin) } | ForEach-Object { $_.ProcessId })
            $busy += "$($f.FullName) (delete after closing pid $($pids -join ', '))"
        }
    }
    foreach ($f in @($L.Log, "$($L.Log).1")) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
    foreach ($d in @($L.Bin, $L.Root)) {
        if ((Test-Path -LiteralPath $d) -and -not (Get-ChildItem -LiteralPath $d -Force)) { Remove-Item -LiteralPath $d -Force }
    }
    Write-SgLine "sync_gate removed from $($L.Root)."
    foreach ($b in $busy) { Write-SgLine "  still in use: $b" }
    Write-SgLine "Kept (not deleted): config $($dirs.config) and data $($dirs.data)"
    Write-SgLine 'Remove the agent plugin yourself if you installed it:'
    Write-SgLine '  claude plugin uninstall sync-gate@sync_gate ; claude plugin marketplace remove sync_gate'
    Write-SgLine '  codex plugin remove sync-gate@sync_gate ; codex plugin marketplace remove sync_gate'
}

function Invoke-SyncGateMain {
    param([switch]$Uninstall, [string]$Version, [switch]$ClearOverrides)
    $ErrorActionPreference = 'Stop'
    try {
        if ($env:OS -ne 'Windows_NT') { throw 'this installer is for Windows; on Linux and macOS use install.sh' }
        $level = Get-SgIntegrity
        Write-SgLine "integrity: $level"
        if ($level -notin @('Medium Mandatory Level', 'Low Mandatory Level')) {
            throw 'run this from a normal (non-administrator) PowerShell window: the installer never needs administrator rights'
        }
        # The scheduled task and user settings are shared even when two invocations use different roots.
        $busy = 'another install or uninstall is running; wait for it to finish and retry'
        try { $mutex = [Threading.Mutex]::new($false, 'Global\SyncGate-Installer') }
        catch [UnauthorizedAccessException] { throw $busy }
        $locked = $false
        try {
            try { $locked = $mutex.WaitOne(0) }
            catch [Threading.AbandonedMutexException] { $locked = $true }
            if (-not $locked) { throw $busy }
            if ($Uninstall) { Invoke-SyncGateUninstall } else { Invoke-SyncGateInstall -Version $Version -ClearOverrides:$ClearOverrides }
        } finally {
            if ($locked) { $mutex.ReleaseMutex() }
            $mutex.Dispose()
        }
    } catch {
        Write-SgLine "error: $($_.Exception.Message)"
        Exit-SgRun 1
    }
}

if ($env:SYNC_GATE_INSTALL_NO_MAIN -ne '1') {
    Invoke-SyncGateMain -Uninstall:$Uninstall -Version $Version -ClearOverrides:$ClearOverrides
}
