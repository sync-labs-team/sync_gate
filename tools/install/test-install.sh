#!/bin/sh
# Tests for tools/install/install.sh (macOS and Linux). POSIX sh.
#
#   sh tools/install/test-install.sh <dir with the Linux sync_gate, sync_gated and sync_gate_mcp>
#
# Run it as an ordinary user (uid != 0) in a throwaway container or account: the container is started
# with `--user 1000:1000`. Every scenario gets its own HOME under mktemp -d, a fake systemctl, launchctl,
# uname and cargo in front of PATH (they log to $HOME/calls.log) and its own SYNC_GATE_SOCKET.
# Prints "PASS 4.n" per scenario. SYNC_GATE_TEST_ONLY="4.6 4.14" runs a subset.
set -eu
umask 022

BINS=${1:-}
if [ -z "$BINS" ] || [ ! -x "$BINS/sync_gate" ] || [ ! -x "$BINS/sync_gated" ] || [ ! -x "$BINS/sync_gate_mcp" ]; then
  echo "usage: sh test-install.sh <dir with sync_gate, sync_gated and sync_gate_mcp (Linux)>" >&2
  exit 2
fi
BINS=$(cd "$BINS" && pwd)
SELF=$(cd "$(dirname "$0")" && pwd)
INSTALL=$SELF/install.sh
if [ ! -f "$INSTALL" ]; then
  echo "FAIL: $INSTALL not found" >&2
  exit 1
fi

UID_NOW=$(id -u)
if [ "$UID_NOW" -eq 0 ]; then
  echo "refusing to run as root (the container must start with --user 1000:1000)" >&2
  exit 1
fi
REAL_HOME=${HOME:-}
ONLY=${SYNC_GATE_TEST_ONLY:-}
for v in $(env | sed -n 's/^\(SYNC_GATE_[A-Za-z_]*\)=.*/\1/p'); do unset "$v"; done

T=$(mktemp -d "${TMPDIR:-/tmp}/sgi.XXXXXX")
case $T in "$REAL_HOME" | "$REAL_HOME"/) echo "refusing to run: temp root is the real HOME" >&2; exit 1 ;; esac

# The real data folder must not change while we run (P37). Skipped when `paths` does not run here.
REAL_DATA=$(env -i HOME="$REAL_HOME" PATH=/usr/bin:/bin "$BINS/sync_gate" paths 2>/dev/null | sed -n 's/^data=//p') || REAL_DATA=
real_listing() { if [ -n "$REAL_DATA" ] && [ -d "$REAL_DATA" ]; then ls -lA "$REAL_DATA"; else echo none; fi; }
REAL_BEFORE=$(real_listing)

cleanup() {
  for d in "$T"/h*; do
    [ -d "$d/pids" ] || continue
    for f in "$d"/pids/*.pid; do
      [ -f "$f" ] || continue
      p=$(cat "$f"); kill "$p" 2>/dev/null || true
      i=0; while alive "$p" && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done # a daemon still writing breaks rm -rf
    done
  done
  chmod -R u+rwx "$T" 2>/dev/null || true
  rm -rf "$T"
}
trap cleanup EXIT INT TERM

pass() { echo "PASS $1"; }
fail() {
  echo "FAIL $1: $2" >&2
  [ -f "${HOME:-/nonexistent}/out.txt" ] && { echo "--- last install output ---" >&2; tail -n 25 "$HOME/out.txt" >&2; }
  exit 1
}
want() {
  [ -z "$ONLY" ] && return 0
  case " $ONLY " in *" $1 "*) return 0 ;; esac
  return 1
}
has() { grep -F -- "$2" "$1" >/dev/null 2>&1; }          # has <file> <text>
hasx() { grep -Fx -- "$2" "$1" >/dev/null 2>&1; }        # has a whole line
alive() {
  kill -0 "$1" 2>/dev/null || return 1
  s=$(awk '/^State:/{print $2}' "/proc/$1/status" 2>/dev/null) || s=
  [ "$s" != Z ]
}

# ---- assets: the "new" release (0.1.0) and the "old" one (0.0.9 = same binaries plus 16 bytes, P59) ----
TARGET=
case $(uname -m) in
  x86_64 | amd64) TARGET=x86_64-unknown-linux-musl ;;
  aarch64 | arm64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "unsupported test machine: $(uname -m)" >&2; exit 2 ;;
esac
OLDBINS=$T/oldbins
mkdir -p "$OLDBINS"
for n in sync_gate sync_gated sync_gate_mcp; do
  cp "$BINS/$n" "$OLDBINS/$n"
  head -c 16 /dev/zero >> "$OLDBINS/$n"
done
make_assets() { # make_assets <dir> <version> <bin dir>
  mkdir -p "$1"
  tar -C "$3" -czf "$1/sync_gate-$2-$TARGET.tar.gz" sync_gate sync_gated sync_gate_mcp
  (cd "$1" && sha256sum "sync_gate-$2-$TARGET.tar.gz" > SHA256SUMS)
}
NEW=$T/assets-new; OLD=$T/assets-old; BAD=$T/assets-bad
make_assets "$NEW" 0.1.0 "$BINS"
make_assets "$OLD" 0.0.9 "$OLDBINS"
mkdir -p "$BAD"
cp "$NEW/SHA256SUMS" "$BAD/"
cp "$NEW/sync_gate-0.1.0-$TARGET.tar.gz" "$BAD/"
printf '\377\377\377\377' | dd of="$BAD/sync_gate-0.1.0-$TARGET.tar.gz" bs=1 seek=64 conv=notrunc 2>/dev/null

# ---- test doubles (P56: the systemctl double implements only the unescape rules of the table) ----
FAKE=$T/fake
mkdir -p "$FAKE"
FAKE_REAL_PATH=/usr/bin:/bin
export FAKE_REAL_PATH FAKE_BINS="$BINS"

cat > "$FAKE/common.sh" <<'EOF'
alive() {
  kill -0 "$1" 2>/dev/null || return 1
  s=$(awk '/^State:/{print $2}' "/proc/$1/status" 2>/dev/null) || s=
  [ "$s" != Z ]
}
# stop_pid <name>: kill the daemon this double started under <name>
stop_pid() {
  [ -f "$HOME/pids/$1.pid" ] || return 0
  p=$(cat "$HOME/pids/$1.pid")
  kill "$p" 2>/dev/null || true
  i=0
  while alive "$p" && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
  rm -f "$HOME/pids/$1.pid"
}
# start_pid <name> <exe> [NAME=value ...]: the real sync_gated, with only the given environment (like a manager does)
start_pid() {
  name=$1; exe=$2; shift 2
  mkdir -p "$HOME/pids"
  # A real service manager does not pass the installer's lock fd to its daemon.
  nohup env -i HOME="$HOME" PATH="$FAKE_REAL_PATH" USER="${USER:-x}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}" "$@" "$exe" >/dev/null 2>>"$HOME/daemon.err" </dev/null 9>&- &
  echo $! > "$HOME/pids/$name.pid"
}
EOF

cat > "$FAKE/systemctl" <<'EOF'
#!/bin/sh
. "$(dirname "$0")/common.sh"
echo "systemctl $*" >> "$HOME/calls.log"
[ "${1:-}" = "--user" ] || exit 1
shift
cmd=${1:-}
name=${2:-}
unit=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$name
# systemd.syntax(7): \\ and \" inside quotes; systemd.unit(5): %% is %. The executable path of ExecStart keeps $ as
# written ($$ stays $$) and systemd 255 refuses ', " and \ in it (Task 4 Step 3), so both lines unescape alike.
unesc() {
  awk '{
    out = ""; n = length($0); i = 1
    while (i <= n) {
      c = substr($0, i, 1); d = substr($0, i + 1, 1)
      if (c == "\\" && (d == "\\" || d == "\"")) { out = out d; i += 2 }
      else if (c == "%" && d == "%") { out = out "%"; i += 2 }
      else { out = out c; i++ }
    }
    print out }'
}
case $cmd in
  show-environment) [ -z "${FAKE_NO_SYSTEMD:-}" ] ;;
  daemon-reload | enable | disable) ;;
  stop) stop_pid "$name" ;;
  restart)
    stop_pid "$name"
    exe=
    set --
    while IFS= read -r l; do
      case $l in
        'ExecStart="'*) v=${l#'ExecStart="'}; v=${v%'"'}; exe=$(printf '%s\n' "$v" | unesc) ;;
        'Environment="'*) v=${l#'Environment="'}; v=${v%'"'}; set -- "$@" "$(printf '%s\n' "$v" | unesc)" ;;
      esac
    done < "$unit"
    [ -n "$exe" ] || exit 1
    start_pid "$name" "$exe" "$@"
    ;;
  *) exit 1 ;;
esac
EOF

cat > "$FAKE/launchctl" <<'EOF'
#!/bin/sh
. "$(dirname "$0")/common.sh"
echo "launchctl $*" >> "$HOME/calls.log"
unx() { sed -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e "s/&apos;/'/g" -e 's/&amp;/\&/g'; }
case ${1:-} in
  bootout) stop_pid "${2##*/}" ;;
  bootstrap)
    plist=$3
    name=$(basename "$plist" .plist)
    exe=; key=; inenv=0; inargs=0
    set --
    while IFS= read -r l; do
      l=${l#"${l%%[![:space:]]*}"}
      case $l in
        '<key>ProgramArguments</key>') inargs=1 ;;
        '<key>EnvironmentVariables</key>') inenv=1 ;;
        '<key>'*'</key>') k=${l#'<key>'}; key=$(printf '%s\n' "${k%'</key>'}" | unx) ;;
        '<string>'*'</string>')
          s=${l#'<string>'}; s=$(printf '%s\n' "${s%'</string>'}" | unx)
          if [ "$inenv" = 1 ]; then set -- "$@" "$key=$s"
          elif [ "$inargs" = 1 ] && [ -z "$exe" ]; then exe=$s; fi ;;
      esac
    done < "$plist"
    [ -n "$exe" ] || exit 1
    start_pid "$name" "$exe" "$@"
    ;;
  *) exit 1 ;;
esac
EOF

cat > "$FAKE/uname" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-s" ] && [ -n "${FAKE_UNAME_S:-}" ]; then echo "$FAKE_UNAME_S"; exit 0; fi
PATH=$FAKE_REAL_PATH exec uname "$@"
EOF

cat > "$FAKE/cargo" <<'EOF'
#!/bin/sh
echo "cargo $*" >> "$HOME/calls.log"
root=
while [ $# -gt 0 ]; do
  [ "$1" = "--root" ] && root=$2
  shift
done
mkdir -p "$root/bin"
cp "$FAKE_BINS/sync_gate" "$FAKE_BINS/sync_gated" "$FAKE_BINS/sync_gate_mcp" "$root/bin/"
EOF
chmod +x "$FAKE"/systemctl "$FAKE"/launchctl "$FAKE"/uname "$FAKE"/cargo

# ---- stub release (scenarios 4.15 onward run with scripts in place of the binaries: no daemon, no /proc) ----
# The stub `sync_gate` answers like the real one for what install.sh calls: `paths` (6 lines, fails while
# $HOME/stub-paths-fail exists), `status` (succeeds only while $HOME/stub-daemon exists), `shims`, and `mcp`
# (records its arguments; fails like adopt.rs when CLAUDE_CONFIG_DIR is set and --claude-config is missing).
make_stub() { # make_stub <dir> <tag>
  mkdir -p "$1"
  cat > "$1/sync_gate" <<STUB
#!/bin/sh
# stub $2
H=\${HOME:?}
d=\${SYNC_GATE_DATA_DIR:-\$H/stub-data}
shim_home=\${SYNC_GATE_DATA_DIR:-\${XDG_DATA_HOME:-\$H}}
case \${1:-} in
  paths)
    [ ! -e "\$H/stub-paths-fail" ] || exit 1
    printf 'config=%s\ndata=%s\nshims=%s\nadopted=%s\nsocket=%s\nhub=%s\n' "\$H/stub-cfg" "\$d" "\$shim_home/stub-shims" "\$H/stub-adopted" "\$H/stub.sock" "\$H/stub-hub" ;;
  status) [ -e "\$H/stub-daemon" ] || exit 1 ;;
  shims)
    [ ! -e "\$H/stub-shims-\$2-fail" ] && [ ! -e "\$H/stub-shims-\$2-$2-fail" ] || exit 1
    echo "\$2" >> "\$H/shims.log"
    if [ "\$2" = install ]; then
      mkdir -p "\$shim_home/stub-shims" && printf '%s\n' '$2' > "\$shim_home/stub-shims/sync_gate_shims.json" || exit 1
    else
      rm -f "\$shim_home/stub-shims/sync_gate_shims.json" || exit 1
    fi ;;
  mcp)
    echo "\$*" > "\$H/mcp.args"
    if [ -n "\${CLAUDE_CONFIG_DIR:-}" ]; then
      case " \$* " in *" --claude-config "*) ;; *) echo "CLAUDE_CONFIG_DIR is set: pass --claude-config" >&2; exit 2 ;; esac
    fi ;;
esac
exit 0
STUB
  printf '#!/bin/sh\n# stub %s\nexit 0\n' "$2" > "$1/sync_gated"
  printf '#!/bin/sh\n# stub %s\nexit 0\n' "$2" > "$1/sync_gate_mcp"
  chmod +x "$1/sync_gate" "$1/sync_gated" "$1/sync_gate_mcp"
}
STUBNEW=$T/stub-new; STUBOLD=$T/stub-old
make_stub "$T/stubbin-new" new; make_stub "$T/stubbin-old" old
make_assets "$STUBNEW" 0.1.0 "$T/stubbin-new"
make_assets "$STUBOLD" 0.0.9 "$T/stubbin-old"

# ---- per-scenario environment ----
HN=0
mk_home() { # mk_home [linux|mac] [suffix of the HOME folder name]; sets HOME and the paths the scenarios compare
  HN=$((HN + 1))
  HOME=$T/h$HN${2:-}
  [ "$HOME" != "$REAL_HOME" ] || { echo "refusing: HOME is the real HOME" >&2; exit 1; }
  mkdir -p "$HOME" "$HOME/run"
  chmod 700 "$HOME/run"
  USER=fgt4x$$n$HN
  XDG_RUNTIME_DIR=$HOME/run
  SYNC_GATE_SOCKET=$HOME/s.sock
  SYNC_GATE_CLAUDE_CONFIG=$HOME/claude.json
  SYNC_GATE_CODEX_CONFIG=$HOME/codex.toml
  export HOME USER XDG_RUNTIME_DIR SYNC_GATE_SOCKET SYNC_GATE_CLAUDE_CONFIG SYNC_GATE_CODEX_CONFIG
  unset XDG_CONFIG_HOME XDG_STATE_HOME XDG_DATA_HOME XDG_CACHE_HOME CLAUDE_CONFIG_DIR SYNC_GATE_DATA_DIR SYNC_GATE_CONFIG SYNC_GATE_INSTALL_DIR SYNC_GATE_SERVICE_NAME SYNC_GATE_INSTALL_FAIL_AT || true
  : > "$HOME/calls.log"
  case ${1:-linux} in
    mac) FAKE_UNAME_S=Darwin; SVC=dev.sync_labs.sync_gated; PIDNAME=$SVC ;;
    *) FAKE_UNAME_S=Linux; SVC=sync_gated; PIDNAME=$SVC.service ;;
  esac
  export FAKE_UNAME_S
  unset FAKE_NO_SYSTEMD || true
  FAKE_BINS=$BINS; export FAKE_BINS
  FROM=$NEW
  BIN=$HOME/.local/bin
  STATE=$HOME/.local/state/sync_gate
  UNIT=$HOME/.config/systemd/user/$SVC.service
  PLIST=$HOME/Library/LaunchAgents/$SVC.plist
  SCRIPT=$INSTALL
  SH=sh
  RUN_CWD=$HOME
}
run_install() { # run_install [args]: output in $HOME/out.txt, status in $RC
  RC=0
  ( cd "$RUN_CWD" && PATH="$FAKE:$FAKE_REAL_PATH" SYNC_GATE_INSTALL_FROM="$FROM" "$SH" "$SCRIPT" "$@" ) > "$HOME/out.txt" 2>&1 < /dev/null || RC=$?
}
install_old() { FROM=$OLD; FAKE_BINS=$OLDBINS; run_install; [ "$RC" -eq 0 ] || fail "$1" "old install failed ($RC)"; FROM=$NEW; FAKE_BINS=$BINS; }
newsh() { # newsh '<snippet>': a shell that only read nothing but what we pass (env -i), like a new terminal
  env -i HOME="$HOME" PATH=/usr/bin:/bin sh -c "$1" sh
}
status_ok() { newsh ". \"\$HOME/.profile\"; sync_gate status" > /dev/null 2>&1; }
shims_dir() { newsh ". \"\$HOME/.profile\"; sync_gate paths" | sed -n 's/^shims=//p'; }
block_text() { printf '%s\n' "# >>> sync_gate >>>" "[ -f '$STATE/env' ] && . '$STATE/env'" "# <<< sync_gate <<<"; }
count_blocks() { grep -c '^# >>> sync_gate >>>$' "$1" || true; }
snap_files() { # the files every rollback scenario compares byte by byte
  for f in "$BIN/sync_gate" "$BIN/sync_gated" "$BIN/sync_gate_mcp" "$UNIT" "$PLIST" "$HOME/.profile" "$HOME/.bashrc" \
    "$HOME/.bash_profile" "$HOME/.zprofile" "$HOME/.zshrc" "$STATE/env" "$STATE/install-state"; do
    if [ -e "$f" ]; then printf '%s %s\n' "$(cksum < "$f")" "$f"; else echo "absent $f"; fi
  done
  if [ -d "$STATE/rollback" ]; then echo "rollback present"; else echo "rollback absent"; fi
}
pid_of() { cat "$HOME/pids/$PIDNAME.pid" 2>/dev/null || echo none; } # the doubles name it after their argument (<name>.service, <label>)
seed_profiles() {
  printf '# my profile\nexport FOO=1\n' > "$HOME/.profile"
  printf '# my bashrc\nalias ll="ls -l"\n' > "$HOME/.bashrc"
}

# ---------------------------------------------------------------------------------------------
s41() {
  mk_home linux
  seed_profiles
  mkdir -p "$T/x"
  printf '#!/bin/sh\necho fake cargo\n' > "$T/x/cargo"; chmod +x "$T/x/cargo"
  printf 'PATH=%s:$PATH\n' "$T/x" >> "$HOME/.profile"
  run_install
  [ "$RC" -eq 0 ] || fail 4.1 "install exited $RC"
  exp=$HOME/unit.expected
  {
    printf '%s\n' '[Unit]' 'Description=sync_gate daemon' '' '[Service]'
    printf 'ExecStart="%s/sync_gated"\n' "$BIN"
    printf 'Environment="SYNC_GATE_SOCKET=%s"\n' "$SYNC_GATE_SOCKET"
    printf '%s\n' 'Restart=on-failure' 'RestartPreventExitStatus=2' '' '[Install]' 'WantedBy=default.target'
  } > "$exp"
  cmp -s "$exp" "$UNIT" || { diff "$exp" "$UNIT" >&2 || true; fail 4.1 "unit text differs"; }
  for l in "systemctl --user daemon-reload" "systemctl --user enable $SVC.service" "systemctl --user restart $SVC.service"; do
    hasx "$HOME/calls.log" "$l" || fail 4.1 "calls.log lacks: $l"
  done
  status_ok || fail 4.1 "sync_gate status does not answer"
  for f in .profile .bashrc; do
    tail -n 3 "$HOME/$f" > "$HOME/tail.txt"
    block_text > "$HOME/block.txt"
    cmp -s "$HOME/tail.txt" "$HOME/block.txt" || fail 4.1 "block is not at the end of $f"
  done
  sh=$(shims_dir)
  [ -n "$sh" ] || fail 4.1 "no shims dir"
  got=$(env -i HOME="$HOME" PATH=/usr/bin:/bin sh -c '. "$HOME/.bashrc"; command -v cargo')
  [ "$got" = "$sh/cargo" ] || fail 4.1 "bashrc: command -v cargo = $got, want $sh/cargo"
  got=$(env -i HOME="$HOME" PATH=/usr/bin:/bin sh -c '. "$HOME/.profile"; command -v cargo')
  [ "$got" = "$sh/cargo" ] || fail 4.1 "profile with a PATH line before the block: command -v cargo = $got"
  pass 4.1
}

s42() {
  mk_home mac
  run_install
  [ "$RC" -eq 0 ] || fail 4.2 "install exited $RC"
  exp=$HOME/plist.expected
  cat > "$exp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$SVC</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN/sync_gated</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardErrorPath</key>
  <string>$HOME/Library/Logs/sync_gate/daemon.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SYNC_GATE_SOCKET</key>
    <string>$SYNC_GATE_SOCKET</string>
  </dict>
</dict>
</plist>
EOF
  cmp -s "$exp" "$PLIST" || { diff "$exp" "$PLIST" >&2 || true; fail 4.2 "plist text differs"; }
  hasx "$HOME/calls.log" "launchctl bootout gui/$UID_NOW/$SVC" || fail 4.2 "calls.log lacks bootout"
  hasx "$HOME/calls.log" "launchctl bootstrap gui/$UID_NOW $PLIST" || fail 4.2 "calls.log lacks bootstrap"
  for f in .zprofile .zshrc; do
    [ -f "$HOME/$f" ] || fail 4.2 "$f missing"
    block_text > "$HOME/block.txt"
    tail -n 3 "$HOME/$f" | cmp -s - "$HOME/block.txt" || fail 4.2 "block is not at the end of $f"
  done
  status_ok || fail 4.2 "sync_gate status does not answer"
  pass 4.2
}

s43() {
  mk_home linux
  seed_profiles
  run_install
  [ "$RC" -eq 0 ] || fail 4.3 "first install exited $RC"
  cp "$UNIT" "$HOME/unit.1"; cp "$STATE/env" "$HOME/env.1"; cp "$STATE/install-state" "$HOME/state.1"
  echo "# user line after the block" >> "$HOME/.profile"
  run_install
  [ "$RC" -eq 0 ] || fail 4.3 "second install exited $RC"
  [ "$(count_blocks "$HOME/.profile")" = 1 ] || fail 4.3 "more than one block in .profile"
  [ "$(count_blocks "$HOME/.bashrc")" = 1 ] || fail 4.3 "more than one block in .bashrc"
  { printf '# my profile\nexport FOO=1\n# user line after the block\n'; block_text; } > "$HOME/profile.expected"
  cmp -s "$HOME/profile.expected" "$HOME/.profile" || fail 4.3 "block did not move to the end"
  cmp -s "$HOME/unit.1" "$UNIT" || fail 4.3 "unit changed"
  cmp -s "$HOME/env.1" "$STATE/env" || fail 4.3 "env changed"
  cmp -s "$HOME/state.1" "$STATE/install-state" || fail 4.3 "install-state changed"
  pass 4.3
}

s44() {
  mk_home linux
  install_old 4.4
  ino_before=$(ls -i "$BIN/sync_gate" | awk '{print $1}')
  pid_before=$(pid_of)
  [ "$pid_before" != none ] || fail 4.4 "no daemon pid recorded for the old install"
  mkfifo "$HOME/fifo"
  sleep 120 > "$HOME/fifo" &
  holder=$!
  newsh ". \"\$HOME/.profile\"; exec sync_gate mcp serve < \"\$HOME/fifo\" > /dev/null 2>&1" &
  serve=$!
  sleep 1
  alive "$serve" || { kill "$holder" 2>/dev/null || true; fail 4.4 "mcp serve did not stay up on the old binary"; }
  run_install
  rc=$RC
  alive "$serve" && still=yes || still=no
  kill "$serve" "$holder" 2>/dev/null || true
  [ "$rc" -eq 0 ] || fail 4.4 "update exited $rc"
  [ "$still" = yes ] || fail 4.4 "the old mcp serve process died"
  ino_after=$(ls -i "$BIN/sync_gate" | awk '{print $1}')
  [ "$ino_before" != "$ino_after" ] || fail 4.4 "inode of sync_gate did not change"
  [ "$pid_before" != "$(pid_of)" ] || fail 4.4 "daemon pid did not change"
  status_ok || fail 4.4 "status does not answer after the update"
  pass 4.4
}

s45() {
  mk_home linux
  FAKE_NO_SYSTEMD=1; export FAKE_NO_SYSTEMD
  run_install
  unset FAKE_NO_SYSTEMD
  [ "$RC" -eq 0 ] || fail 4.5 "install exited $RC"
  hasx "$HOME/out.txt" "systemd --user is not available here; start sync_gated yourself, see docs/install.md" || fail 4.5 "warning line missing"
  [ ! -e "$UNIT" ] || fail 4.5 "a unit was written"
  [ ! -e "$HOME/pids" ] || [ -z "$(ls "$HOME/pids" 2>/dev/null)" ] || fail 4.5 "a sync_gated was started"
  for w in daemon-reload enable restart; do has "$HOME/calls.log" "$w" && fail 4.5 "systemctl $w was called"; done
  pass 4.5
}

s46() {
  mk_home linux
  seed_profiles
  before=$(find "$HOME" ! -name out.txt ! -name calls.log ! -name .sync_gate-install.lock -print | sort | tr '\n' ' ')
  FROM=$BAD
  run_install
  [ "$RC" -eq 1 ] || fail 4.6 "expected exit 1, got $RC"
  has "$HOME/out.txt" "checksum mismatch" || fail 4.6 "no checksum mismatch message"
  after=$(find "$HOME" ! -name out.txt ! -name calls.log ! -name .sync_gate-install.lock -print | sort | tr '\n' ' ')
  [ "$before" = "$after" ] || fail 4.6 "files changed"
  [ ! -e "$BIN" ] && [ ! -e "$STATE" ] && [ ! -e "$UNIT" ] || fail 4.6 "something was created"
  pass 4.6
}

adopt_setup() { # install, then adopt a server in the test Claude config
  printf '{"mcpServers":{"demo":{"command":"/usr/bin/true","args":[]}}}\n' > "$SYNC_GATE_CLAUDE_CONFIG"
  : > "$SYNC_GATE_CODEX_CONFIG"
  cp "$SYNC_GATE_CLAUDE_CONFIG" "$HOME/claude.orig"
  newsh ". \"\$HOME/.profile\"; sync_gate mcp adopt --claude-config \"$SYNC_GATE_CLAUDE_CONFIG\" demo" > "$HOME/adopt.txt" 2>&1 \
    || fail "$1" "adopt failed: $(cat "$HOME/adopt.txt")"
}

s47() {
  mk_home linux
  seed_profiles
  cp "$HOME/.profile" "$HOME/profile.orig"; cp "$HOME/.bashrc" "$HOME/bashrc.orig"
  run_install
  [ "$RC" -eq 0 ] || fail 4.7 "install exited $RC"
  adopt_setup 4.7
  data=$(newsh '. "$HOME/.profile"; sync_gate paths' | sed -n 's/^data=//p')
  pid=$(pid_of)
  run_install --uninstall
  [ "$RC" -eq 0 ] || fail 4.7 "uninstall exited $RC"
  cmp -s "$HOME/claude.orig" "$SYNC_GATE_CLAUDE_CONFIG" || fail 4.7 "agent config is not the original"
  [ ! -e "$UNIT" ] || fail 4.7 "unit left"
  cmp -s "$HOME/profile.orig" "$HOME/.profile" || fail 4.7 ".profile is not byte for byte the original"
  cmp -s "$HOME/bashrc.orig" "$HOME/.bashrc" || fail 4.7 ".bashrc is not byte for byte the original"
  [ ! -e "$STATE/env" ] && [ ! -e "$STATE/install-state" ] || fail 4.7 "env or state left"
  for n in sync_gate sync_gated sync_gate_mcp; do [ ! -e "$BIN/$n" ] || fail 4.7 "$n left in bin"; done
  [ -d "$data" ] || fail 4.7 "data folder was removed"
  [ -f "$SYNC_GATE_CLAUDE_CONFIG" ] || fail 4.7 "agent config was removed"
  [ "$pid" != none ] || fail 4.7 "no daemon pid recorded before uninstall"
  ! alive "$pid" || fail 4.7 "daemon still alive"
  pass 4.7
}

s47b() {
  mk_home linux
  run_install
  [ "$RC" -eq 0 ] || fail 4.7b "install exited $RC"
  adopt_setup 4.7b
  # the adopted command rewritten by hand: other text, same exe (restore compares command and args as text)
  awk -v a="\"$BIN/sync_gate\"" -v b="\"$BIN/./sync_gate\"" '{ i = index($0, a); if (i) $0 = substr($0, 1, i - 1) b substr($0, i + length(a)); print }' \
    "$SYNC_GATE_CLAUDE_CONFIG" > "$HOME/claude.edit"
  cmp -s "$HOME/claude.edit" "$SYNC_GATE_CLAUDE_CONFIG" && fail 4.7b "the hand edit changed nothing"
  cp "$HOME/claude.edit" "$SYNC_GATE_CLAUDE_CONFIG"
  snap_files > "$HOME/snap.1"
  run_install --uninstall
  [ "$RC" -eq 1 ] || fail 4.7b "reworded adoption: expected exit 1, got $RC"
  has "$HOME/out.txt" "still adopted: " || fail 4.7b "reworded adoption: not refused by restore --strict (U1)"
  snap_files > "$HOME/snap.2"
  cmp -s "$HOME/snap.1" "$HOME/snap.2" || fail 4.7b "reworded adoption: something changed"
  status_ok || fail 4.7b "daemon not answering after the refused uninstall"
  # a hand-written reference in the Codex test config: file:line
  cp "$HOME/claude.orig" "$SYNC_GATE_CLAUDE_CONFIG"
  printf '[mcp_servers.x]\ncommand = "%s/sync_gate"\n' "$BIN" > "$SYNC_GATE_CODEX_CONFIG"
  snap_files > "$HOME/snap.1"
  run_install --uninstall
  [ "$RC" -eq 1 ] || fail 4.7b "hand-written reference: expected exit 1, got $RC"
  has "$HOME/out.txt" "codex.toml:2" || fail 4.7b "no file:line in the message"
  snap_files > "$HOME/snap.2"
  cmp -s "$HOME/snap.1" "$HOME/snap.2" || fail 4.7b "hand-written reference: something changed"
  pass 4.7b
}

s47c() {
  mk_home linux
  run_install
  [ "$RC" -eq 0 ] || fail 4.7c "install exited $RC"
  : > "$SYNC_GATE_CLAUDE_CONFIG"
  snap_files > "$HOME/snap.1"
  n=0
  for ref in '$HOME/.local/bin/sync_gate' '~/.local/bin/sync_gate' '${HOME}/.local/bin/sync_gate' \
    "$HOME/.local//bin/sync_gate" "$HOME/.local/./bin/sync_gate" "$HOME//.local/bin//sync_gate"; do
    n=$((n + 1))
    printf 'command = "%s"\n' "$ref" > "$SYNC_GATE_CODEX_CONFIG"
    run_install --uninstall
    [ "$RC" -eq 1 ] || fail 4.7c "spelling [$ref]: expected exit 1, got $RC"
    has "$HOME/out.txt" "codex.toml:1" || fail 4.7c "spelling [$ref]: no file:line"
    snap_files > "$HOME/snap.2"
    cmp -s "$HOME/snap.1" "$HOME/snap.2" || fail 4.7c "spelling [$ref]: something changed"
  done
  : > "$SYNC_GATE_CODEX_CONFIG"
  run_install --uninstall
  [ "$RC" -eq 0 ] || fail 4.7c "a config without the path should let the uninstall run (got $RC)"
  pass 4.7c
}

s48() {
  mk_home linux
  mkdir -p "$HOME/cfgdir"
  SYNC_GATE_CLAUDE_CONFIG=$HOME/cfgdir/claude.json; export SYNC_GATE_CLAUDE_CONFIG
  run_install
  [ "$RC" -eq 0 ] || fail 4.8 "install exited $RC"
  adopt_setup 4.8
  chmod 555 "$HOME/cfgdir"; chmod 444 "$SYNC_GATE_CLAUDE_CONFIG"
  snap_files > "$HOME/snap.1"
  run_install --uninstall
  rc=$RC
  chmod 755 "$HOME/cfgdir"; chmod 644 "$SYNC_GATE_CLAUDE_CONFIG"
  [ "$rc" -eq 1 ] || fail 4.8 "expected exit 1, got $rc"
  snap_files > "$HOME/snap.2"
  cmp -s "$HOME/snap.1" "$HOME/snap.2" || fail 4.8 "something was removed"
  status_ok || fail 4.8 "daemon not answering"
  pass 4.8
}

s49() {
  for shell in dash bash; do
    command -v "$shell" > /dev/null 2>&1 || fail 4.9 "$shell is not installed in this image"
    mk_home linux
    RC=0
    ( cd "$HOME" && PATH="$FAKE:$FAKE_REAL_PATH" SYNC_GATE_INSTALL_FROM="$NEW" "$shell" < "$INSTALL" ) > "$HOME/out.txt" 2>&1 || RC=$?
    [ "$RC" -eq 0 ] || fail 4.9 "$shell < install.sh exited $RC"
    [ -x "$BIN/sync_gate" ] || fail 4.9 "$shell: not installed"
    RC=0
    ( cd "$HOME" && PATH="$FAKE:$FAKE_REAL_PATH" SYNC_GATE_INSTALL_FROM="$NEW" "$shell" -s -- --uninstall < "$INSTALL" ) > "$HOME/out.txt" 2>&1 || RC=$?
    [ "$RC" -eq 0 ] || fail 4.9 "$shell -s -- --uninstall exited $RC"
    [ ! -e "$BIN/sync_gate" ] || fail 4.9 "$shell: not uninstalled"
  done
  pass 4.9
}

s410() {
  mk_home mac
  case $(uname -m) in aarch64 | arm64) apple=aarch64-apple-darwin ;; *) apple=x86_64-apple-darwin ;; esac
  run_install
  [ "$RC" -eq 0 ] || fail 4.10 "install with cargo exited $RC"
  grep -E "^cargo install --locked --git https://github.com/sync-labs-team/sync_gate --tag v0.1.0 --root .+ sync_gate sync_gated sync_gate_shim\$" "$HOME/calls.log" > /dev/null \
    || fail 4.10 "cargo install call not found in calls.log"
  mk_home mac
  mv "$FAKE/cargo" "$FAKE/cargo.off"
  run_install
  mv "$FAKE/cargo.off" "$FAKE/cargo"
  [ "$RC" -eq 1 ] || fail 4.10 "without cargo: expected exit 1, got $RC"
  hasx "$HOME/out.txt" "no prebuilt binary for $apple in this release; install Rust from https://rustup.rs and run this again" \
    || fail 4.10 "rustup message missing"
  [ ! -e "$BIN" ] || fail 4.10 "without cargo: bin was created"
  pass 4.10
}

s411() {
  for plat in linux mac; do
    for step in S2 S3 S4 S5 S6 S7; do
      mk_home "$plat"
      seed_profiles
      install_old 4.11
      oldpid=$(pid_of)
      snap_files > "$HOME/snap.1"
      : > "$HOME/calls.log"
      SYNC_GATE_INSTALL_FAIL_AT=$step run_install
      [ "$RC" -eq 1 ] || fail 4.11 "$plat $step: expected exit 1, got $RC"
      hasx "$HOME/out.txt" "upgrade failed at $step; previous version restored" || fail 4.11 "$plat $step: message missing"
      snap_files > "$HOME/snap.2"
      cmp -s "$HOME/snap.1" "$HOME/snap.2" || { diff "$HOME/snap.1" "$HOME/snap.2" >&2 || true; fail 4.11 "$plat $step: files differ from the old install"; }
      if [ "$plat" = linux ]; then has "$HOME/calls.log" "systemctl --user daemon-reload" || fail 4.11 "$plat $step: no daemon-reload of the old unit"
      else has "$HOME/calls.log" "launchctl bootstrap gui/$UID_NOW $PLIST" || fail 4.11 "$plat $step: no bootstrap of the old plist"; fi
      status_ok || fail 4.11 "$plat $step: old daemon not answering"
      # the daemon that answers is the old binary: its file is the old one
      [ "$(cksum < "$BIN/sync_gated")" = "$(cksum < "$OLDBINS/sync_gated")" ] || fail 4.11 "$plat $step: sync_gated is not the old one"
      [ "$oldpid" != none ] || fail 4.11 "$plat $step: no old pid recorded"
    done
    for step in U5 U6 U7; do
      mk_home "$plat"
      seed_profiles
      run_install
      [ "$RC" -eq 0 ] || fail 4.11 "$plat $step: install exited $RC"
      snap_files > "$HOME/snap.1"
      SYNC_GATE_INSTALL_FAIL_AT=$step run_install --uninstall
      [ "$RC" -eq 1 ] || fail 4.11 "$plat $step: uninstall expected exit 1, got $RC"
      snap_files > "$HOME/snap.2"
      cmp -s "$HOME/snap.1" "$HOME/snap.2" || { diff "$HOME/snap.1" "$HOME/snap.2" >&2 || true; fail 4.11 "$plat $step: files differ"; }
      status_ok || fail 4.11 "$plat $step: daemon not answering"
    done
    for step in S3 S5 S6; do
      mk_home "$plat"
      seed_profiles
      install_old 4.11
      SYNC_GATE_INSTALL_FAIL_AT=$step:crash run_install
      [ "$RC" -ne 0 ] || fail 4.11 "$plat $step:crash: expected a non-zero exit"
      run_install
      [ "$RC" -eq 0 ] || fail 4.11 "$plat $step:crash: the next run exited $RC"
      has "$HOME/out.txt" "restoring it first" || fail 4.11 "$plat $step:crash: 'restoring it first' missing"
      [ "$(cksum < "$BIN/sync_gated")" = "$(cksum < "$BINS/sync_gated")" ] || fail 4.11 "$plat $step:crash: new version not installed"
      status_ok || fail 4.11 "$plat $step:crash: daemon not answering"
      [ ! -e "$STATE/rollback" ] || fail 4.11 "$plat $step:crash: rollback left"
    done
  done
  pass 4.11
}

s412() {
  mk_home linux
  SYNC_GATE_DATA_DIR=$HOME/mydata; SYNC_GATE_CONFIG=$HOME/myconfig.toml
  export SYNC_GATE_DATA_DIR SYNC_GATE_CONFIG
  run_install
  [ "$RC" -eq 0 ] || fail 4.12 "install exited $RC"
  out=$(newsh '. "$HOME/.profile"; sync_gate paths; sync_gate status' 2>&1) || fail 4.12 "new shell: paths/status failed: $out"
  printf '%s\n' "$out" | grep -Fx "data=$SYNC_GATE_DATA_DIR" > /dev/null || fail 4.12 "paths does not show the custom data dir"
  printf '%s\n' "$out" | grep -Fx "socket=$SYNC_GATE_SOCKET" > /dev/null || fail 4.12 "paths does not show the custom socket"
  # reinstall from an environment without the three
  unset SYNC_GATE_DATA_DIR SYNC_GATE_CONFIG
  SOCK=$SYNC_GATE_SOCKET; unset SYNC_GATE_SOCKET
  run_install
  [ "$RC" -eq 0 ] || fail 4.12 "reinstall exited $RC"
  for k in SYNC_GATE_SOCKET SYNC_GATE_DATA_DIR SYNC_GATE_CONFIG; do
    has "$UNIT" "Environment=\"$k=" || fail 4.12 "the unit lost $k"
    has "$HOME/out.txt" "$k" || fail 4.12 "the output does not list $k"
  done
  status_ok || fail 4.12 "the daemon is not the same after the reinstall"
  run_install --clear-overrides
  [ "$RC" -eq 0 ] || fail 4.12 "--clear-overrides exited $RC"
  for f in "$UNIT" "$STATE/env" "$STATE/install-state"; do
    for k in SYNC_GATE_SOCKET SYNC_GATE_DATA_DIR SYNC_GATE_CONFIG; do
      has "$f" "$k" && fail 4.12 "$k is still in $f"
    done
  done
  SYNC_GATE_SOCKET=$SOCK; export SYNC_GATE_SOCKET
  pass 4.12
}

# ---- 4.13: hand-written fixtures from the systemd documentation (P56). Never produced by the installer's escaper. ----
# install.sh ships UNIT_SPECIALS_PROVEN=1 (systemd 255 parsed the unit for real, Task 4 Step 3); 4.26 runs a copy switched
# back to 0 so the fail-closed gate stays tested.
GATED=$T/install-gated.sh
sed 's/^UNIT_SPECIALS_PROVEN=1$/UNIT_SPECIALS_PROVEN=0/' "$INSTALL" > "$GATED"
if cmp -s "$INSTALL" "$GATED"; then echo "FAIL: install.sh has no UNIT_SPECIALS_PROVEN=1 line to switch" >&2; exit 1; fi

env_row() { # env_row <DATA_DIR tail> <expected full line, @H@ = this row's HOME (it exists only after mk_home)>
  mk_home linux
  set -- "$1" "${2%%@H@*}$HOME${2#*@H@}"
  SYNC_GATE_DATA_DIR=$HOME$1; export SYNC_GATE_DATA_DIR
  run_install
  [ "$RC" -eq 0 ] || fail 4.13 "Environment row [$1]: install exited $RC"
  hasx "$UNIT" "$2" || { grep Environment= "$UNIT" >&2 || true; fail 4.13 "Environment row [$1]: expected line not in the unit: $2"; }
}
exec_row() { # exec_row <INSTALL_DIR tail> <expected full line, @H@ = this row's HOME>
  mk_home linux
  set -- "$1" "${2%%@H@*}$HOME${2#*@H@}"
  SYNC_GATE_INSTALL_DIR=$HOME$1; export SYNC_GATE_INSTALL_DIR
  run_install
  [ "$RC" -eq 0 ] || fail 4.13 "ExecStart row [$1]: install exited $RC"
  hasx "$UNIT" "$2" || { grep ExecStart= "$UNIT" >&2 || true; fail 4.13 "ExecStart row [$1]: expected line not in the unit: $2"; }
}
s413() {
  env_row '/Sync Gate' 'Environment="SYNC_GATE_DATA_DIR=@H@/Sync Gate"'
  env_row '/$HOME/x' 'Environment="SYNC_GATE_DATA_DIR=@H@/$HOME/x"'
  env_row '/50%h' 'Environment="SYNC_GATE_DATA_DIR=@H@/50%%h"'
  env_row '/a"b\c' 'Environment="SYNC_GATE_DATA_DIR=@H@/a\"b\\c"'
  # ExecStart rows measured on systemd 255 (Step 3): $ stays as written, %% is %; ', " and \ are refused by systemd
  exec_row '/Sync Gate $x %h' 'ExecStart="@H@/Sync Gate $x %%h/sync_gated"'
  for bad in '/a"b' "/O'Brien" '/a\b'; do
    mk_home linux
    SYNC_GATE_INSTALL_DIR=$HOME$bad; export SYNC_GATE_INSTALL_DIR
    run_install
    [ "$RC" -eq 1 ] || fail 4.13 "install dir [$bad]: expected exit 1, got $RC"
    has "$HOME/out.txt" "systemd refuses" || fail 4.13 "install dir [$bad]: no message"
    [ ! -e "$UNIT" ] && [ ! -e "$STATE" ] && [ ! -e "$HOME/.profile" ] || fail 4.13 "install dir [$bad]: something was created"
  done

  # the scenario folder: install dir and data dir named $HOME/Sync Gate O'Brien %h $HOME & <x> "q" \b
  mk_home linux
  seed_profiles
  W=$HOME/'Sync Gate O'\''Brien %h $HOME & <x> "q" \b'
  WI=$HOME/'Sync Gate %h $HOME & <x>'
  # the unit comes out as the table says. The install dir drops ', " and \ (systemd refuses them in ExecStart).
  SYNC_GATE_INSTALL_DIR=$WI; SYNC_GATE_DATA_DIR=$W; export SYNC_GATE_INSTALL_DIR SYNC_GATE_DATA_DIR
  run_install
  [ "$RC" -eq 0 ] || fail 4.13 "scenario folder: install exited $RC"
  hasx "$UNIT" 'ExecStart="'"$HOME"'/Sync Gate %%h $HOME & <x>/sync_gated"' || fail 4.13 "scenario folder: ExecStart line"
  hasx "$UNIT" 'Environment="SYNC_GATE_DATA_DIR='"$HOME"'/Sync Gate O'\''Brien %%h $HOME & <x> \"q\" \\b"' || fail 4.13 "scenario folder: DATA_DIR line"
  hasx "$UNIT" 'Environment="SYNC_GATE_INSTALL_DIR='"$HOME"'/Sync Gate %%h $HOME & <x>"' || fail 4.13 "scenario folder: INSTALL_DIR line"
  got=$(STATE_ENV=$STATE/env env -i HOME="$HOME" PATH=/usr/bin:/bin STATE_ENV="$STATE/env" sh -c '. "$STATE_ENV"; command -v sync_gate')
  [ "$got" = "$WI/sync_gate" ] || fail 4.13 "sh: command -v sync_gate = [$got]"
  if command -v dash > /dev/null 2>&1; then
    got=$(env -i HOME="$HOME" PATH=/usr/bin:/bin STATE_ENV="$STATE/env" dash -c '. "$STATE_ENV"; command -v sync_gate')
    [ "$got" = "$WI/sync_gate" ] || fail 4.13 "dash: command -v sync_gate = [$got]"
  fi
  # daemon and CLI use the same data folder (literal $ and % in its name)
  data=$(env -i HOME="$HOME" PATH=/usr/bin:/bin STATE_ENV="$STATE/env" sh -c '. "$STATE_ENV"; sync_gate paths' | sed -n 's/^data=//p')
  [ "$data" = "$W" ] || fail 4.13 "paths data=[$data], want [$W]"
  i=0
  while [ ! -e "$W/sync_gated.lock" ] && [ "$i" -lt 50 ]; do sleep 0.2; i=$((i + 1)); done
  [ -e "$W/sync_gated.lock" ] || fail 4.13 "sync_gated.lock is not in the data folder the CLI prints"
  # a value with a line break is refused
  mk_home linux
  SYNC_GATE_DATA_DIR=$(printf '%s\n%s' "$HOME/a" b); export SYNC_GATE_DATA_DIR
  run_install
  [ "$RC" -eq 1 ] || fail 4.13 "newline value: expected exit 1, got $RC"
  [ ! -e "$BIN" ] || fail 4.13 "newline value: something was installed"
  # the same folder on the macOS side: XML entities
  mk_home mac
  SYNC_GATE_INSTALL_DIR=$HOME/'Sync Gate O'\''Brien %h $HOME & <x> "q" \b'; SYNC_GATE_DATA_DIR=$SYNC_GATE_INSTALL_DIR
  export SYNC_GATE_INSTALL_DIR SYNC_GATE_DATA_DIR
  run_install
  [ "$RC" -eq 0 ] || fail 4.13 "mac scenario folder: install exited $RC"
  hasx "$PLIST" "    <string>$HOME/Sync Gate O&apos;Brien %h \$HOME &amp; &lt;x&gt; &quot;q&quot; \\b/sync_gated</string>" || fail 4.13 "mac scenario folder: plist ProgramArguments"
  hasx "$PLIST" "    <string>$HOME/Sync Gate O&apos;Brien %h \$HOME &amp; &lt;x&gt; &quot;q&quot; \\b</string>" || fail 4.13 "mac scenario folder: plist env value"
  run_install --uninstall
  [ "$RC" -eq 0 ] || fail 4.13 "mac scenario folder: uninstall exited $RC"
  [ ! -e "$PLIST" ] || fail 4.13 "mac scenario folder: plist left"
  pass 4.13
}

s414() {
  echo "id -u = $UID_NOW"
  [ "$UID_NOW" -ne 0 ] || fail 4.14 "uid is 0"
  pass 4.14
}

# ---- 4.15 onward: the first review's findings (stub binaries) ----
mk_stub_home() { mk_home linux "${1:-}"; FROM=$STUBNEW; FAKE_NO_SYSTEMD=1; export FAKE_NO_SYSTEMD; }

s415() { # I1: a start marker without its end marker is never allowed to eat the rest of the file
  mk_stub_home
  printf 'export KEEP1=1\n# >>> sync_gate >>>\nexport KEEP2=2\nalias gs=x\nexport KEEP3=3\n' > "$HOME/.bashrc"
  cp "$HOME/.bashrc" "$HOME/bashrc.orig"
  run_install
  [ "$RC" -ne 0 ] || fail 4.15 "install over an unbalanced block exited 0"
  cmp -s "$HOME/bashrc.orig" "$HOME/.bashrc" || fail 4.15 "install changed a file with a start marker and no end marker"
  has "$HOME/out.txt" "end marker" || fail 4.15 "install did not say what is wrong"
  [ ! -e "$BIN/sync_gate" ] || fail 4.15 "install put binaries in place before refusing"
  # uninstall: the end line removed by hand after a good install
  mk_stub_home
  run_install
  [ "$RC" -eq 0 ] || fail 4.15 "clean install exited $RC"
  grep -v '^# <<< sync_gate <<<$' "$HOME/.bashrc" > "$HOME/bashrc.cut"
  printf 'export AFTER=1\n' >> "$HOME/bashrc.cut"
  cp "$HOME/bashrc.cut" "$HOME/.bashrc"
  run_install --uninstall
  [ "$RC" -ne 0 ] || fail 4.15 "uninstall over an unbalanced block exited 0"
  cmp -s "$HOME/bashrc.cut" "$HOME/.bashrc" || fail 4.15 "uninstall changed a file with a start marker and no end marker"
  [ -x "$BIN/sync_gate" ] || fail 4.15 "uninstall removed binaries before refusing"
  pass 4.15
}

s416() { # I2: HOME with a space (and the shell file list is never word-split)
  for shl in sh dash bash; do
    command -v "$shl" > /dev/null 2>&1 || continue
    mk_stub_home ' sp'
    SH=$shl
    seed_profiles
    cp "$HOME/.profile" "$HOME/profile.orig"
    run_install
    [ "$RC" -eq 0 ] || fail 4.16 "$shl: install with a space in HOME exited $RC"
    [ ! -e "$T/h$HN" ] || fail 4.16 "$shl: a stray file was created where HOME was split"
    for f in .profile .bashrc; do
      tail -n 3 "$HOME/$f" > "$HOME/tail.txt"
      block_text > "$HOME/block.txt"
      cmp -s "$HOME/tail.txt" "$HOME/block.txt" || fail 4.16 "$shl: block is not at the end of $f"
    done
    run_install --uninstall
    [ "$RC" -eq 0 ] || fail 4.16 "$shl: uninstall exited $RC"
    cmp -s "$HOME/profile.orig" "$HOME/.profile" || fail 4.16 "$shl: .profile is not back byte for byte"
    [ ! -e "$BIN/sync_gate" ] || fail 4.16 "$shl: binaries left"
  done
  pass 4.16
}

s417() { # I3: `sync_gate paths` failing in S5 of an update is undone like any other step
  mk_stub_home
  FROM=$STUBOLD
  run_install
  [ "$RC" -eq 0 ] || fail 4.17 "old install exited $RC"
  FROM=$STUBNEW
  before=$(snap_files)
  : > "$HOME/stub-paths-fail"
  run_install
  [ "$RC" -eq 1 ] || fail 4.17 "update with failing paths: expected 1, got $RC"
  has "$HOME/out.txt" "upgrade failed at S5; previous version restored" || fail 4.17 "no rollback message"
  after=$(snap_files)
  [ "$before" = "$after" ] || fail 4.17 "files differ after the failed update"
  pass 4.17
}

s418() { # I4: a failure injected in U7 puts the binaries back (the folder was removed by u_bins)
  mk_stub_home
  run_install
  [ "$RC" -eq 0 ] || fail 4.18 "install exited $RC"
  before=$(snap_files)
  SYNC_GATE_INSTALL_FAIL_AT=U7; export SYNC_GATE_INSTALL_FAIL_AT
  run_install --uninstall
  unset SYNC_GATE_INSTALL_FAIL_AT
  [ "$RC" -eq 1 ] || fail 4.18 "expected 1, got $RC"
  has "$HOME/out.txt" "previous version restored" || fail 4.18 "binaries were not restored"
  after=$(snap_files)
  [ "$before" = "$after" ] || fail 4.18 "files differ after the failed uninstall"
  pass 4.18
}

s419() { # I5: CLAUDE_CONFIG_DIR: restore gets --claude-config and U2 looks at that file
  mk_stub_home
  unset SYNC_GATE_CLAUDE_CONFIG
  CLAUDE_CONFIG_DIR=$HOME/cdir; export CLAUDE_CONFIG_DIR
  mkdir -p "$CLAUDE_CONFIG_DIR"
  run_install
  [ "$RC" -eq 0 ] || fail 4.19 "install exited $RC"
  printf '{"x":{"command":"%s/sync_gate"}}\n' "$BIN" > "$CLAUDE_CONFIG_DIR/.claude.json"
  run_install --uninstall
  [ "$RC" -eq 1 ] || fail 4.19 "a hand-written reference in CLAUDE_CONFIG_DIR/.claude.json: expected 1, got $RC"
  has "$HOME/out.txt" "cdir/.claude.json:1" || fail 4.19 "U2 did not name the file in CLAUDE_CONFIG_DIR"
  rm -f "$CLAUDE_CONFIG_DIR/.claude.json"
  run_install --uninstall
  [ "$RC" -eq 0 ] || fail 4.19 "uninstall with CLAUDE_CONFIG_DIR exited $RC"
  has "$HOME/mcp.args" "--claude-config $CLAUDE_CONFIG_DIR/.claude.json" || fail 4.19 "restore did not get --claude-config"
  unset CLAUDE_CONFIG_DIR
  pass 4.19
}

s420() { # I6: a hit in an agent config prints file:line, never the line (it can hold a secret)
  mk_stub_home
  run_install
  [ "$RC" -eq 0 ] || fail 4.20 "install exited $RC"
  printf '{"mcpServers":{"x":{"command":"%s/sync_gate","env":{"API_KEY":"sk-REAL-LOOKING-SECRET"}}}}\n' "$BIN" > "$SYNC_GATE_CLAUDE_CONFIG"
  run_install --uninstall
  [ "$RC" -eq 1 ] || fail 4.20 "expected 1, got $RC"
  has "$HOME/out.txt" "claude.json:1" || fail 4.20 "no file:line in the output"
  ! has "$HOME/out.txt" "sk-REAL" || fail 4.20 "the secret is in the output"
  pass 4.20
}

s421() { # I7 and Minor 14: the env file moves shims to the front without word splitting and keeps noglob
  mk_stub_home
  run_install
  [ "$RC" -eq 0 ] || fail 4.21 "install exited $RC"
  ! grep -q 'IFS' "$STATE/env" || fail 4.21 "env relies on IFS word splitting (zsh does not split \$PATH)"
  shm=$HOME/stub-shims
  want_path=$shm:$BIN:/a:/b:/usr/bin:/bin
  for shl in sh dash bash zsh; do
    command -v "$shl" > /dev/null 2>&1 || continue
    got=$(env -i HOME="$HOME" PATH=/usr/bin:/bin "$shl" -c 'PATH="/a:$2:/b:/usr/bin:/bin"; . "$1"; . "$1"; printf "%s\n" "$PATH"' sh "$STATE/env" "$shm")
    [ "$got" = "$want_path" ] || fail 4.21 "$shl: PATH = [$got], want [$want_path]"
    got=$(env -i HOME="$HOME" PATH=/usr/bin:/bin "$shl" -c 'set -f; . "$1"; case $- in *f*) echo kept ;; *) echo lost ;; esac' sh "$STATE/env")
    [ "$got" = kept ] || fail 4.21 "$shl: the env file turned noglob off"
  done
  pass 4.21
}

s422() { # Minor 8: a shell file that cannot be written fails the install (and the undo leaves it alone)
  mk_stub_home
  seed_profiles
  cp "$HOME/.profile" "$HOME/profile.orig"
  chmod 444 "$HOME/.bashrc"
  run_install
  [ "$RC" -eq 1 ] || fail 4.22 "install over a read-only .bashrc: expected 1, got $RC"
  has "$HOME/out.txt" "previous version restored" || fail 4.22 "no clean rollback message"
  cmp -s "$HOME/profile.orig" "$HOME/.profile" || fail 4.22 ".profile was not put back"
  [ ! -e "$BIN/sync_gate" ] || fail 4.22 "binaries were left"
  pass 4.22
}

s423() { # Minor 10: SHA256SUMS without a final newline and with upper-case hashes (Get-FileHash style)
  mk_stub_home
  rm -rf "$HOME/assets"; mkdir -p "$HOME/assets"
  cp "$STUBNEW/sync_gate-0.1.0-$TARGET.tar.gz" "$HOME/assets/"
  awk '{ printf "%s  %s", toupper($1), $2 }' "$STUBNEW/SHA256SUMS" > "$HOME/assets/SHA256SUMS"
  FROM=$HOME/assets
  run_install
  [ "$RC" -eq 0 ] || fail 4.23 "install exited $RC"
  has "$HOME/out.txt" "sync_gate 0.1.0 installed" || fail 4.23 "no success line"
  pass 4.23
}

s424() { # R1: an unbalanced block is refused before uninstall touches the agent configs (mcp restore)
  mk_stub_home
  run_install
  [ "$RC" -eq 0 ] || fail 4.24 "clean install exited $RC"
  grep -v '^# <<< sync_gate <<<$' "$HOME/.bashrc" > "$HOME/bashrc.cut"
  cp "$HOME/bashrc.cut" "$HOME/.bashrc"
  rm -f "$HOME/mcp.args"
  run_install --uninstall
  [ "$RC" -ne 0 ] || fail 4.24 "uninstall over an unbalanced block exited 0"
  [ ! -e "$HOME/mcp.args" ] || fail 4.24 "mcp restore ran before the unbalanced block was refused"
  pass 4.24
}

s425() { # the release ships sync_gate_mcp, the [[bin]] of the sync_gate_shim package (T5 dist): prebuilt and cargo paths
  mk_stub_home
  run_install
  [ "$RC" -eq 0 ] || fail 4.25 "install of a release named like the real package exited $RC"
  [ -x "$BIN/sync_gate_mcp" ] || fail 4.25 "sync_gate_mcp not installed"
  [ ! -e "$BIN/sync_gate_shim" ] || fail 4.25 "a sync_gate_shim binary appeared"
  run_install --uninstall
  [ "$RC" -eq 0 ] || fail 4.25 "uninstall exited $RC"
  [ ! -e "$BIN/sync_gate_mcp" ] || fail 4.25 "sync_gate_mcp left in bin"
  # no prebuilt for this target: cargo installs the sync_gate_shim package, which builds sync_gate_mcp
  mk_stub_home
  case $TARGET in x86_64-*) other=aarch64-unknown-linux-musl ;; *) other=x86_64-unknown-linux-musl ;; esac
  mkdir -p "$HOME/assets"
  printf '%s  sync_gate-0.1.0-%s.tar.gz\n' 0000000000000000000000000000000000000000000000000000000000000000 "$other" > "$HOME/assets/SHA256SUMS"
  FROM=$HOME/assets; FAKE_BINS=$T/stubbin-new
  run_install
  FAKE_BINS=$BINS
  [ "$RC" -eq 0 ] || fail 4.25 "install through cargo exited $RC"
  has "$HOME/calls.log" " sync_gate sync_gated sync_gate_shim" || fail 4.25 "cargo was not asked for the sync_gate_shim package"
  [ -x "$BIN/sync_gate_mcp" ] || fail 4.25 "cargo path: sync_gate_mcp not installed"
  pass 4.25
}

s426() { # I-1: the UNIT_SPECIALS_PROVEN=0 gate, on a copy switched back to 0 (clean install folder; the special sits in another field)
  for tail in '/50%h' '/$HOME/x' '/a\b'; do
    mk_home linux
    FROM=$STUBNEW
    SCRIPT=$GATED
    SYNC_GATE_DATA_DIR=$HOME$tail; export SYNC_GATE_DATA_DIR
    run_install
    [ "$RC" -eq 1 ] || fail 4.26 "data dir [$tail]: expected exit 1, got $RC"
    has "$HOME/out.txt" "not supported yet" || fail 4.26 "data dir [$tail]: not the PROVEN=0 refusal"
    [ ! -e "$UNIT" ] && [ ! -e "$STATE" ] && [ ! -e "$BIN" ] || fail 4.26 "data dir [$tail]: something was created"
  done
  pass 4.26
}

s427() { # Minor M-4: ', " and \ in the install folder are refused, and the message says how to pick another folder
  for bad in '/a"b' "/O'Brien" '/a\b'; do
    mk_home linux
    FROM=$STUBNEW
    SYNC_GATE_INSTALL_DIR=$HOME$bad; export SYNC_GATE_INSTALL_DIR
    run_install
    [ "$RC" -eq 1 ] || fail 4.27 "install dir [$bad]: expected exit 1, got $RC"
    has "$HOME/out.txt" "systemd refuses" || fail 4.27 "install dir [$bad]: no refusal"
    has "$HOME/out.txt" "SYNC_GATE_INSTALL_DIR" || fail 4.27 "install dir [$bad]: the message does not name SYNC_GATE_INSTALL_DIR"
    [ ! -e "$UNIT" ] && [ ! -e "$STATE" ] || fail 4.27 "install dir [$bad]: something was created"
  done
  pass 4.27
}

s428() { # Minor M-5: U2 also catches <bin>/sync_gate_mcp (and still lets <bin>/sync_gate-other through)
  mk_stub_home
  run_install
  [ "$RC" -eq 0 ] || fail 4.28 "install exited $RC"
  printf '{"x":{"command":"%s/sync_gate-other"}}\n' "$BIN" > "$SYNC_GATE_CLAUDE_CONFIG"
  printf '{"x":{"command":"%s/sync_gate_mcp"}}\n' "$BIN" > "$SYNC_GATE_CODEX_CONFIG"
  run_install --uninstall
  [ "$RC" -eq 1 ] || fail 4.28 "sync_gate_mcp reference in the Codex config: expected 1, got $RC"
  has "$HOME/out.txt" "codex.toml:1" || fail 4.28 "U2 did not name the file"
  printf '{"x":{"command":"%s/sync_gate_mcp"}}\n' "$BIN" > "$SYNC_GATE_CLAUDE_CONFIG"
  : > "$SYNC_GATE_CODEX_CONFIG"
  run_install --uninstall
  [ "$RC" -eq 1 ] || fail 4.28 "sync_gate_mcp reference in the Claude config: expected 1, got $RC"
  has "$HOME/out.txt" "claude.json:1" || fail 4.28 "U2 did not name the Claude file"
  printf '{"x":{"command":"%s/sync_gate-other"}}\n' "$BIN" > "$SYNC_GATE_CLAUDE_CONFIG"
  run_install --uninstall
  [ "$RC" -eq 0 ] || fail 4.28 "a sync_gate-other path is not ours: expected 0, got $RC"
  pass 4.28
}
s429() {
  mk_stub_home
  cat > "$FAKE/cp" <<'EOF'
#!/bin/sh
case $* in
  *"/rollback/files/"*".bytes")
    if [ -f "$HOME/.local/state/sync_gate/rollback/in-progress" ]; then
      rm "$HOME/.local/state/sync_gate/rollback/in-progress"
      mkdir "$HOME/.local/state/sync_gate/rollback/in-progress"
    fi ;;
  *"/x/sync_gate "*) : > "$HOME/copied-new-bin" ;;
esac
exec /bin/cp "$@"
EOF
  chmod +x "$FAKE/cp"
  seed_profiles
  run_install
  rm "$FAKE/cp"
  [ ! -e "$HOME/copied-new-bin" ] || fail 4.29 "copied a new binary after losing the step marker"
  [ "$RC" -eq 1 ] || fail 4.29 "expected failure writing the step marker, got $RC"
  [ ! -e "$BIN/sync_gate" ] || fail 4.29 "installed binary survived"
  pass 4.29
}

s430() {
  mk_stub_home
  cat > "$FAKE/cp" <<'EOF'
#!/bin/sh
case $* in
  *"/x/sync_gate "*)
    : > "$HOME/copy-started"
    i=0
    while [ ! -e "$HOME/copy-release" ] && [ "$i" -lt 200 ]; do sleep 0.05; i=$((i + 1)); done ;;
esac
exec /bin/cp "$@"
EOF
  chmod +x "$FAKE/cp"
  (run_install; exit "$RC") &
  installer_pid=$!
  i=0
  while [ ! -e "$HOME/copy-started" ] && [ "$i" -lt 100 ]; do sleep 0.05; i=$((i + 1)); done
  second_rc=0
  XDG_STATE_HOME="$HOME/custom-state" PATH="$FAKE:$FAKE_REAL_PATH" sh "$INSTALL" --uninstall > "$HOME/second.txt" 2>&1 || second_rc=$?
  same_rc=0
  PATH="$FAKE:$FAKE_REAL_PATH" sh "$INSTALL" --uninstall > "$HOME/same.txt" 2>&1 || same_rc=$?
  cp "$STATE/rollback/in-progress" "$HOME/active-step" || true
  : > "$HOME/copy-release"
  first_rc=0
  wait "$installer_pid" || first_rc=$?
  rm "$FAKE/cp"
  [ "$second_rc" -eq 1 ] || fail 4.30 "concurrent uninstall exited $second_rc"
  has "$HOME/second.txt" "another sync_gate installer is running" || fail 4.30 "concurrent uninstall did not fail at the lock"
  [ "$same_rc" -eq 1 ] && has "$HOME/same.txt" "another sync_gate installer is running" \
    || fail 4.30 "concurrent uninstall with the same state folder did not fail at the lock"
  hasx "$HOME/active-step" S3 || fail 4.30 "concurrent uninstall disturbed the active snapshot"
  [ "$first_rc" -eq 0 ] || fail 4.30 "first install exited $first_rc"
  SYNC_GATE_INSTALL_FAIL_AT=S3:crash run_install
  [ "$RC" -eq 1 ] || fail 4.30 "injected crash exited $RC"
  [ -f "$STATE/rollback/ready" ] || fail 4.30 "injected crash left no snapshot"
  run_install
  [ "$RC" -eq 0 ] || fail 4.30 "new install after crash exited $RC"
  has "$HOME/out.txt" "a previous run stopped at S3" || fail 4.30 "new install did not recover the earlier run"
  pass 4.30
}

s431() {
  mk_stub_home
  run_install
  [ "$RC" -eq 0 ] || fail 4.31 "install exited $RC"
  : > "$SYNC_GATE_CLAUDE_CONFIG"
  cat > "$FAKE/grep" <<'EOF'
#!/bin/sh
if [ "$1" = -nE ]; then exit 2; fi
exec /bin/grep "$@"
EOF
  chmod +x "$FAKE/grep"
  run_install --uninstall
  rm "$FAKE/grep"
  [ "$RC" -eq 1 ] || fail 4.31 "uninstall accepted a config read failure: got $RC"
  has "$HOME/out.txt" "cannot search $SYNC_GATE_CLAUDE_CONFIG" || fail 4.31 "uninstall did not identify the affected config"
  [ -x "$BIN/sync_gate" ] || fail 4.31 "uninstall removed the binary despite the config read failure"
  run_install --uninstall
  [ "$RC" -eq 0 ] || fail 4.31 "uninstall with a readable config exited $RC"
  pass 4.31
}

s432() {
  mk_stub_home
  FROM=$HOME/archive
  mkdir "$FROM"
  cp -R "$T/stubbin-new" "$HOME/fixture"
  arch_file=sync_gate-0.1.0-$TARGET.tar.gz
  printf 'placeholder\n' > "$HOME/fixture/LICENSE-MIT"
  printf 'placeholder\n' > "$HOME/fixture/LICENSE-APACHE"
  for kind in duplicate extra link hardlink directory valid; do
    set -- sync_gate sync_gated sync_gate_mcp LICENSE-MIT LICENSE-APACHE
    case $kind in
      duplicate) set -- "$@" sync_gate ;;
      extra) : > "$HOME/fixture/extra"; set -- "$@" extra ;;
      link) rm "$HOME/fixture/LICENSE-MIT"; ln -s LICENSE-APACHE "$HOME/fixture/LICENSE-MIT" ;;
      hardlink) rm "$HOME/fixture/LICENSE-MIT"; ln "$HOME/fixture/LICENSE-APACHE" "$HOME/fixture/LICENSE-MIT" ;;
      directory) rm "$HOME/fixture/LICENSE-MIT"; mkdir "$HOME/fixture/LICENSE-MIT" ;;
      valid) rmdir "$HOME/fixture/LICENSE-MIT"; printf 'placeholder\n' > "$HOME/fixture/LICENSE-MIT" ;;
    esac
    tar -C "$HOME/fixture" -czf "$FROM/$arch_file" "$@"
    (cd "$FROM" && sha256sum "$arch_file" > SHA256SUMS)
    run_install --version 0.1.0
    if [ "$kind" = valid ]; then
      [ "$RC" -eq 0 ] || fail 4.32 "release archive exited $RC"
    else
      [ "$RC" -eq 1 ] || fail 4.32 "$kind archive: expected 1, got $RC"
      has "$HOME/out.txt" "invalid archive members" || fail 4.32 "$kind archive: missing rejection diagnostic"
      [ ! -e "$BIN/sync_gate" ] || fail 4.32 "$kind archive installed binaries"
    fi
  done
  pass 4.32
}

s433() {
  mk_stub_home
  cat > "$FAKE/rm" <<'EOF'
#!/bin/sh
if [ "$*" = "-f $HOME/.local/bin/sync_gate" ]; then exit 1; fi
exec /bin/rm "$@"
EOF
  chmod +x "$FAKE/rm"
  SYNC_GATE_INSTALL_FAIL_AT=S3 run_install
  rm "$FAKE/rm"
  [ "$RC" -eq 1 ] || fail 4.33 "injected failure exited $RC"
  has "$HOME/out.txt" "could not restore sync_gate" || fail 4.33 "rollback did not report the failed removal"
  [ -f "$STATE/rollback/ready" ] || fail 4.33 "rollback lost its backup"
  run_install
  [ "$RC" -eq 0 ] || fail 4.33 "new install after rollback failure exited $RC"
  has "$HOME/out.txt" "a previous run stopped at S3" || fail 4.33 "new install did not finish the earlier rollback"
  pass 4.33
}

s434() {
  mk_home linux
  FAKE_NO_SYSTEMD=1; export FAKE_NO_SYSTEMD
  run_install
  [ "$RC" -eq 0 ] || fail 4.34 "install exited $RC"
  SYNC_GATE_CLAUDE_CONFIG=$HOME/private/sub/config.json
  mkdir -p "$HOME/private/sub"
  printf '{}\n' > "$SYNC_GATE_CLAUDE_CONFIG"
  chmod 600 "$HOME/private"
  run_install --uninstall
  chmod 700 "$HOME/private"
  [ "$RC" -eq 1 ] || fail 4.34 "uninstall accepted an inaccessible parent: got $RC"
  has "$HOME/out.txt" "cannot search $SYNC_GATE_CLAUDE_CONFIG" || fail 4.34 "missing config diagnostic"
  [ -x "$BIN/sync_gate" ] || fail 4.34 "uninstall removed the binary despite the config lookup failure"
  SYNC_GATE_CLAUDE_CONFIG=$HOME/private/missing/sub/config.json
  run_install --uninstall
  [ "$RC" -eq 0 ] || fail 4.34 "uninstall with a missing config tree exited $RC"
  pass 4.34
}

s435() {
  mk_stub_home
  seed_profiles
  cat > "$FAKE/cp" <<'EOF'
#!/bin/sh
case $* in
  *"/rollback/files/1.bytes") mkdir "${3%/*}/2.path" || exit 1 ;;
esac
exec /bin/cp "$@"
EOF
  chmod +x "$FAKE/cp"
  run_install
  rm "$FAKE/cp"
  [ "$RC" -eq 1 ] || fail 4.35 "install accepted an unwritable snapshot index: got $RC"
  [ ! -e "$STATE/rollback/ready" ] || fail 4.35 "marked an incomplete snapshot ready"
  [ ! -e "$BIN/sync_gate" ] || fail 4.35 "installed binaries after failing to take a snapshot"
  run_install
  [ "$RC" -eq 0 ] || fail 4.35 "install after discarding the incomplete snapshot exited $RC"
  pass 4.35
}

s436() {
  mk_stub_home
  : > "$HOME/stub-shims-remove-fail"
  SYNC_GATE_INSTALL_FAIL_AT=S4 run_install
  [ "$RC" -eq 1 ] || fail 4.36 "failed fresh install exited $RC"
  has "$HOME/out.txt" "could not restore shims" || fail 4.36 "failed shim removal was reported as restored"
  [ -f "$STATE/rollback/ready" ] && [ -x "$BIN/sync_gate" ] || fail 4.36 "lost the snapshot or the binary needed to remove shims"
  rm "$HOME/stub-shims-remove-fail"
  run_install
  [ "$RC" -eq 0 ] || fail 4.36 "install after retrying shim removal exited $RC"
  hasx "$HOME/shims.log" remove || fail 4.36 "recovery did not retry shim removal"

  : > "$HOME/stub-shims-install-fail"
  SYNC_GATE_INSTALL_FAIL_AT=U5 run_install --uninstall
  [ "$RC" -eq 1 ] || fail 4.36 "failed uninstall exited $RC"
  has "$HOME/out.txt" "could not restore shims" || fail 4.36 "failed shim installation was reported as restored"
  [ -f "$STATE/rollback/ready" ] || fail 4.36 "lost the snapshot needed to reinstall shims"
  rm "$HOME/stub-shims-install-fail"
  run_install
  [ "$RC" -eq 0 ] || fail 4.36 "install after retrying shim installation exited $RC"
  has "$HOME/out.txt" "a previous run stopped at U5" || fail 4.36 "did not resume uninstall rollback"
  pass 4.36
}

s437() {
  cat > "$FAKE/rm" <<'EOF'
#!/bin/sh
rb=$HOME/.local/state/sync_gate/rollback
case "${1:-} ${2:-}" in
  "-f $rb/ready") [ ! -f "$HOME/disarm-fail" ] || exit 1 ;;
  "-rf $rb")
    if [ -f "$rb/meta" ] && [ ! -f "$HOME/cleanup-interrupted" ]; then
      : > "$HOME/cleanup-interrupted"
      /bin/rm -f "$rb/meta"
      exit 1
    fi ;;
esac
exec /bin/rm "$@"
EOF
  chmod +x "$FAKE/rm"
  for point in S3 S3:crash; do
    mk_stub_home
    : > "$HOME/disarm-fail"
    SYNC_GATE_INSTALL_FAIL_AT=$point run_install
    [ "$RC" -eq 1 ] || fail 4.37 "$point: failed install exited $RC"
    if [ "$point" = S3:crash ]; then
      run_install
      [ "$RC" -eq 1 ] || fail 4.37 "recovery with a failed disarm exited $RC"
    fi
    has "$HOME/out.txt" "cannot disarm rollback" || fail 4.37 "$point: missing disarm failure diagnostic"
    [ -f "$STATE/rollback/ready" ] && [ -f "$STATE/rollback/meta" ] || fail 4.37 "$point: cleanup began before disarm"
    rm "$HOME/disarm-fail"
    run_install
    [ "$RC" -eq 1 ] || fail 4.37 "$point: failed cleanup exited $RC"
    [ -d "$STATE/rollback" ] && [ ! -e "$STATE/rollback/ready" ] || fail 4.37 "$point: partially removed snapshot is still armed"
    run_install
    [ "$RC" -eq 0 ] || fail 4.37 "$point: install after discarding an unarmed snapshot exited $RC"
    if has "$HOME/out.txt" "restoring it first"; then fail 4.37 "$point: attempted to restore a partially removed snapshot"; fi
  done
  rm "$FAKE/rm"
  pass 4.37
}

s438() {
  for prior in manual manual-no-shims managed; do
    mk_stub_home
    manifest=$HOME/stub-shims/sync_gate_shims.json
    if [ "$prior" = managed ]; then
      FROM=$STUBOLD
      run_install
      [ "$RC" -eq 0 ] || fail 4.38 "managed seed install exited $RC"
      cp "$STATE/env" "$HOME/env.before"
      tag=old
    else
      make_stub "$BIN" manual
      tag=manual
      [ "$prior" = manual-no-shims ] || "$BIN/sync_gate" shims install
    fi
    FROM=$STUBNEW
    SYNC_GATE_INSTALL_FAIL_AT=S4 run_install
    [ "$RC" -eq 1 ] || fail 4.38 "$prior: injected failure exited $RC"
    has "$HOME/out.txt" "previous version restored" || fail 4.38 "$prior: failed to restore after S4"
    [ ! -e "$STATE/rollback/ready" ] || fail 4.38 "$prior: left an armed rollback"
    hasx "$BIN/sync_gate" "# stub $tag" || fail 4.38 "$prior: did not restore the binary"
    case $prior in
      managed) cmp -s "$HOME/env.before" "$STATE/env" || fail 4.38 "managed env changed" ;;
      *) [ ! -e "$STATE/env" ] || fail 4.38 "$prior: wrote a managed env" ;;
    esac
    if [ "$prior" = manual-no-shims ]; then
      [ ! -e "$manifest" ] || fail 4.38 "introduced shims to the manual install"
    else
      hasx "$manifest" "$tag" || fail 4.38 "$prior: did not restore the shims"
    fi
    run_install
    [ "$RC" -eq 0 ] || fail 4.38 "$prior: next install exited $RC"
  done

  for override in SYNC_GATE_DATA_DIR XDG_DATA_HOME; do
    mk_stub_home
    make_stub "$BIN" manual
    export "$override=$HOME/manual-data"
    "$BIN/sync_gate" shims install
    : > "$HOME/stub-shims-install-manual-fail"
    SYNC_GATE_INSTALL_FAIL_AT=S4 run_install
    [ "$RC" -eq 1 ] && [ -f "$STATE/rollback/ready" ] || fail 4.38 "$override: lost the snapshot after failed manual shims restore"
    has "$HOME/out.txt" "could not restore shims install" || fail 4.38 "$override: missing manual shims error"
    rm "$HOME/stub-shims-install-manual-fail"
    unset "$override"
    run_install
    [ "$RC" -eq 0 ] && has "$HOME/out.txt" "a previous run stopped at S4" || fail 4.38 "$override: failed to retry manual shims restore"
    hasx "$HOME/manual-data/stub-shims/sync_gate_shims.json" manual || fail 4.38 "$override: retry did not restore the original manual shims directory"
  done
  pass 4.38
}

s439() {
  mk_stub_home
  make_stub "$BIN" manual
  before=$(snap_files)
  : > "$HOME/stub-paths-fail"
  run_install
  [ "$RC" -eq 1 ] || fail 4.39 "manual install with failing paths exited $RC"
  [ ! -e "$HOME/stub-shims/sync_gate_shims.json" ] || fail 4.39 "manual install created shims without a snapshot"
  [ ! -e "$HOME/shims.log" ] || fail 4.39 "shims command ran despite the paths error"
  [ "$before" = "$(snap_files)" ] || fail 4.39 "manual install changed before snapshot validation"
  has "$HOME/out.txt" "sync_gate paths failed" || fail 4.39 "missing paths diagnostic"
  pass 4.39
}

s440() {
  for override in SYNC_GATE_DATA_DIR XDG_DATA_HOME; do
    mk_stub_home
    make_stub "$BIN" manual
    mkdir -p "$HOME/original" "$HOME/other/relative data/stub-shims"
    ln -s "$HOME/original" "$HOME/original-link"
    RUN_CWD=$HOME/original-link
    export "$override=relative data"
    ( cd "$RUN_CWD" && "$BIN/sync_gate" shims install )
    manifest="$HOME/original/relative data/stub-shims/sync_gate_shims.json"
    other="$HOME/other/relative data/stub-shims/sync_gate_shims.json"
    printf 'other\n' > "$other"
    : > "$HOME/stub-shims-install-manual-fail"
    SYNC_GATE_INSTALL_FAIL_AT=S4 run_install
    [ "$RC" -eq 1 ] && [ -f "$STATE/rollback/ready" ] || fail 4.40 "$override: lost the snapshot"
    has "$HOME/out.txt" "could not restore shims install" || fail 4.40 "$override: missing manual shims error"
    hasx "$manifest" new || fail 4.40 "$override: upgrade did not reach relative shims"
    rm "$HOME/stub-shims-install-manual-fail" "$RUN_CWD"
    RUN_CWD=$HOME/other
    export "$override=$HOME/retry-data"
    run_install
    [ "$RC" -eq 0 ] && has "$HOME/out.txt" "a previous run stopped at S4" || fail 4.40 "$override: failed to retry manual shims restore"
    hasx "$manifest" manual || fail 4.40 "$override: retry did not restore the original manual shims directory"
    hasx "$other" other || fail 4.40 "$override: retry modified the other workspace's shims"
    hasx "$HOME/retry-data/stub-shims/sync_gate_shims.json" new || fail 4.40 "$override: retry did not install to the new override"
  done
  pass 4.40
}

for n in 4.1:s41 4.2:s42 4.3:s43 4.4:s44 4.5:s45 4.6:s46 4.7:s47 4.7b:s47b 4.7c:s47c 4.8:s48 4.9:s49 4.10:s410 4.11:s411 4.12:s412 4.13:s413 4.14:s414 4.15:s415 4.16:s416 4.17:s417 4.18:s418 4.19:s419 4.20:s420 4.21:s421 4.22:s422 4.23:s423 4.24:s424 4.25:s425 4.26:s426 4.27:s427 4.28:s428 4.29:s429 4.30:s430 4.31:s431 4.32:s432 4.33:s433 4.34:s434 4.35:s435 4.36:s436 4.37:s437 4.38:s438 4.39:s439 4.40:s440; do
  id=${n%%:*}
  fn=${n#*:}
  if want "$id"; then "$fn"; fi
done

REAL_AFTER=$(real_listing)
[ "$REAL_BEFORE" = "$REAL_AFTER" ] || { echo "FAIL: the real data folder changed" >&2; exit 1; }
echo "real data listing unchanged"
