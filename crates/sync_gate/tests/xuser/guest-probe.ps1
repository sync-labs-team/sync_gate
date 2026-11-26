# Raw client of the sync_gate guest protocol, run INSIDE a Codex sandbox by tests/xuser_windows.rs.
# Opens the pipes with TokenImpersonationLevel.Identification, as the guest CLI does (the daemon
# reads the caller's identity from each message, F47). Prints one `label = value` line per check.
# With -Serve <name> it is instead the pipe occupant of scenario X9: it creates that pipe with
# default security, waits up to 30 s for ONE client and reports how many bytes it received.
param(
  [string]$Main = '',          # the owner's pipe name
  [string]$Guest = '',         # the guest pipe this sandbox is meant to use
  [uint64]$OwnerTicket = 0,    # a ticket of the owner: every request on it must be refused
  [uint32]$ForgedPid = 0,      # a process of the owner (full token): `Started` for it must be refused
  [string]$Cwd = '',           # sent as the cwd of the probe's own `Acquire`
  [string]$Sync = '',          # base path: after its Acquire the probe writes <Sync>.acquired, then waits for <Sync>.go (20 s at most)
  [string]$Serve = '',
  [string]$Out = ''
)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)

if ($Serve) {
  $p = New-Object System.IO.Pipes.NamedPipeServerStream($Serve, [System.IO.Pipes.PipeDirection]::InOut, 1)
  Set-Content -Encoding ascii "$Out.ready" "$PID"
  $bytes = 0; $connected = $false
  if ($p.WaitForConnectionAsync().Wait(30000)) {
    $connected = $true
    $buf = New-Object byte[] 4096
    $t = $p.ReadAsync($buf, 0, 4096)
    if ($t.Wait(4000)) { $bytes = $t.Result }
  }
  Set-Content -Encoding ascii $Out "connected=$connected bytes=$bytes"
  $p.Dispose()
  "serve done connected=$connected bytes=$bytes"
  return
}

function Open-Narrow([string]$name) {
  New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, [System.IO.Pipes.PipeAccessRights]0x120083, 'None', 'Identification', 'None')
}

# A pipe the other end closed: ERROR_BROKEN_PIPE (109) or ERROR_NO_DATA (232).
function Is-Closed($e) { $h = $e.HResult -band 0xFFFF; return ($h -eq 109 -or $h -eq 232) }

# One request on a fresh connection; the reply line, or a word saying why there is none.
# CLOSED-WITHOUT-REPLY only when the connection WAS made and the daemon then dropped it (EOF or a
# broken pipe); a failure to connect (access, timeout) or another write/read error is FAILED(stage).
function Exchange([string]$name, $request) {
  $c = Open-Narrow $name
  $stage = 'connect'
  try {
    $c.Connect(3000)
    $stage = 'write'
    $line = if ($request -is [string] -and $request -eq 'Status') { '"Status"' } else { ConvertTo-Json -Compress -Depth 6 $request }
    $bytes = $utf8.GetBytes($line + "`n")
    $c.Write($bytes, 0, $bytes.Length); $c.Flush()
    $stage = 'read'
    $buf = New-Object byte[] 65536
    $t = $c.ReadAsync($buf, 0, $buf.Length)
    if (-not $t.Wait(6000)) { return 'NO-REPLY' }
    if ($t.Result -eq 0) { return 'CLOSED-WITHOUT-REPLY' }
    return $utf8.GetString($buf, 0, $t.Result).TrimEnd("`r", "`n")
  } catch {
    $e = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
    if ($stage -ne 'connect' -and (Is-Closed $e)) { return 'CLOSED-WITHOUT-REPLY' }
    return "FAILED($stage): " + $e.Message
  }
  finally { $c.Dispose() }
}

function Try-Generic([string]$name) {
  $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, [System.IO.Pipes.PipeDirection]::InOut, 'None', 'Identification')
  try { $c.Connect(2000); return 'OPEN' }
  catch [System.UnauthorizedAccessException] { return 'DENIED' }
  catch { return 'FAILED: ' + $_.Exception.Message }
  finally { $c.Dispose() }
}

function Try-Create([string]$name) {
  try { $s = New-Object System.IO.Pipes.NamedPipeServerStream($name, [System.IO.Pipes.PipeDirection]::InOut, 4); $s.Dispose(); return 'CREATED' }
  catch [System.UnauthorizedAccessException] { return 'DENIED' }
  catch { return 'FAILED: ' + $_.Exception.Message }
}

"identity = $(whoami)"
"main GR|GW = $(Try-Generic $Main)"
"guest GR|GW = $(Try-Generic $Guest)"

$c = Open-Narrow $Guest
try {
  $c.Connect(3000)
  "guest narrow = OK"
  $owner = try { $c.GetAccessControl().GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { 'unreadable: ' + $_.Exception.Message }
  "owner = $owner"
} catch { "guest narrow = FAILED: " + $_.Exception.Message } finally { $c.Dispose() }

# The probe's own ticket first: `Started` and the cwd check need one.
$acq = Exchange $Guest @{ Acquire = @{ argv = [string[]]@('cmd', '/d', '/c', 'echo', 'probe'); cwd = $Cwd; session = 'guest-probe'; heavy = $true } }
"Acquire = $acq"
$mine = 0
if ($acq -match '"id":(\d+)') { $mine = [uint64]$Matches[1] }
if ($Sync) {
  Set-Content -Encoding ascii "$Sync.acquired" "$mine"
  for ($i = 0; $i -lt 200 -and -not (Test-Path "$Sync.go"); $i++) { Start-Sleep -Milliseconds 100 }
}

if ($OwnerTicket -ne 0) { "Cancel owner = $(Exchange $Guest @{ Cancel = @{ id = $OwnerTicket } })" }
"Lease = $(Exchange $Guest @{ Lease = @{ service = 'postgres'; project = $Cwd; holder = @{ pid = $PID; start = $null }; request = 'abc' } })"
if ($ForgedPid -ne 0) { "Started forged = $(Exchange $Guest @{ Started = @{ id = $mine; pid = $ForgedPid } })" }
"create instance main = $(Try-Create $Main)"
"create instance guest = $(Try-Create $Guest)"
if ($mine -ne 0) { "Cancel mine = $(Exchange $Guest @{ Cancel = @{ id = $mine } })" }
"probe done pid=$PID"
