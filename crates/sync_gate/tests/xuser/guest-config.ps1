# Run INSIDE a Codex sandbox by tests/xuser_windows.rs (X13a): the sandbox account's own sync_gate config,
# at its default place (%APPDATA%\sync_labs\sync_gate\config\config.toml of that account).
#   -Action create   the file must not exist (exit 3 if it does, nothing touched); missing folders are made and
#                    listed in <List>; the file gets `max_wait_secs = <Value>` and the line `# <Marker>`.
#   -Action rewrite  only a file that holds `# <Marker>`: `max_wait_secs = <Value>` again.
#   -Action clean    removes the file only if it holds `# <Marker>`, then the folders listed in <List> (deepest
#                    first, only when empty). Prints `left: <folder>` for each listed folder still there, then
#                    `gone` (last line) when the file is absent afterwards.
param(
  [Parameter(Mandatory)][string]$Action,
  [string]$Value = '0',
  [Parameter(Mandatory)][string]$Marker,
  [Parameter(Mandatory)][string]$List
)
$ErrorActionPreference = 'Stop'
$dir = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'sync_labs\sync_gate\config'
$file = Join-Path $dir 'config.toml'
$text = "max_wait_secs = $Value`n# $Marker`n"
$ours = { (Test-Path -LiteralPath $file) -and ([IO.File]::ReadAllText($file).Contains("# $Marker")) }
switch ($Action) {
  'create' {
    if (Test-Path -LiteralPath $file) { 'skipped: guest config exists'; exit 3 }
    $made = @()
    $d = $dir
    $missing = @()
    while (-not (Test-Path -LiteralPath $d)) { $missing += $d; $d = Split-Path -Parent $d }
    [array]::Reverse($missing)
    foreach ($m in $missing) { [void][IO.Directory]::CreateDirectory($m); $made += $m }
    Set-Content -LiteralPath $List -Value $made -Encoding UTF8
    $fs = [IO.File]::Open($file, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $b = [Text.Encoding]::ASCII.GetBytes($text); $fs.Write($b, 0, $b.Length) } finally { $fs.Dispose() }
    "created $file"
  }
  'rewrite' {
    if (-not (& $ours)) { 'not ours'; exit 4 }
    [IO.File]::WriteAllText($file, $text)
    "rewritten $file"
  }
  'clean' {
    if (& $ours) { Remove-Item -LiteralPath $file -Force }
    if (Test-Path -LiteralPath $List) {
      $made = @(Get-Content -LiteralPath $List | Where-Object { $_ })
      [array]::Reverse($made)
      foreach ($m in $made) {
        if ((Test-Path -LiteralPath $m) -and -not (Get-ChildItem -LiteralPath $m -Force)) { Remove-Item -LiteralPath $m -Force }
      }
      foreach ($m in $made) { if (Test-Path -LiteralPath $m) { "left: $m" } }
    }
    if (Test-Path -LiteralPath $file) { 'still there' } else { 'gone' }
  }
}
