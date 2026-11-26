#!/bin/sh
# sync_gate installer for macOS and Linux. POSIX sh (runs under dash).
#
#   install or update: curl -fsSL https://gate.synclabs.team/install.sh | sh
#   uninstall:         curl -fsSL https://gate.synclabs.team/install.sh | sh -s -- --uninstall
#   options:           --version 0.1.0   --clear-overrides   --uninstall
#
# Never asks for administrator rights; writes only to the user's own folders. Starts the daemon only through
# the service manager (systemd --user or launchd). Everything is inside main(), called on the last line, so a
# truncated download runs nothing.
set -eu

COMMAND_URL=https://gate.synclabs.team/install.sh
REPO_URL=https://github.com/sync-labs-team/sync_gate
# 1: values with $, % or \ go into the systemd unit escaped as esc_env/esc_exec say. Proven on a real systemd 255
# (Task 4 Step 3: the daemon's environ held the raw text). 0 refuses them (fail closed).
# shortcut: proven only on systemd 255.4, set to 0 if another version reads the unit differently.
UNIT_SPECIALS_PROVEN=1
NL='
'

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

# shq <text>: POSIX single-quoted form, ' becomes '\''
shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
# systemd: Environment="NAME=..." gets \ -> \\, " -> \" and % -> %% (P56). The executable path of ExecStart="..." gets
# % -> %% only: systemd 255 keeps $ as written there ($$ stays $$) and refuses ', " and \ (measured, Task 4 Step 3).
esc_exec() { printf '%s' "$1" | sed -e 's/%/%%/g'; }
esc_env() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/%/%%/g'; }
esc_xml() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&apos;/g"; }
# rx_lit <text>: ERE-escaped text
rx_lit() { printf '%s' "$1" | sed 's/[].[\*^$+?(){}|]/\\&/g'; }

check_value() { # check_value <what> <value>: no control characters (line breaks included)
  case $2 in
    *[[:cntrl:]]*) die "$1 contains a line break or control character; refusing" ;;
  esac
}

hash_of() {
  if command -v sha256sum > /dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum > /dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "neither sha256sum nor shasum found"; fi
}

fetch() { # fetch <https url> <dest>
  case $1 in https://*) ;; *) die "refusing a non-HTTPS url: $1" ;; esac
  if command -v curl > /dev/null 2>&1; then curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1" || die "download failed: $1"
  elif command -v wget > /dev/null 2>&1; then wget -q --https-only -O "$2" "$1" || die "download failed: $1"
  else die "neither curl nor wget found"; fi
}

# ---------------------------------------------------------------------------------------------
# state

read_state() { # fills ST_* from install-state (key=value lines, split at the first =; never sourced)
  ST_VERSION=; ST_BIN=; ST_SOCKET=; ST_DATA_DIR=; ST_CONFIG=; ST_INSTALL_DIR=; ST_BLOCKS=; ST_CREATED=; ST_NONL=
  [ -f "$STATE" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    k=${line%%=*}; v=${line#*=}
    case $k in
      version) ST_VERSION=$v ;;
      bin) ST_BIN=$v ;;
      SYNC_GATE_SOCKET) ST_SOCKET=$v ;;
      SYNC_GATE_DATA_DIR) ST_DATA_DIR=$v ;;
      SYNC_GATE_CONFIG) ST_CONFIG=$v ;;
      SYNC_GATE_INSTALL_DIR) ST_INSTALL_DIR=$v ;;
      shell_block) ST_BLOCKS=$ST_BLOCKS$v$NL ;;
      shell_created) ST_CREATED=$ST_CREATED$v$NL ;;
      shell_nonl) ST_NONL=$ST_NONL$v$NL ;;
    esac
  done < "$STATE"
}

# each_shellfile <command...>: run the command with each file of $SHELLFILES (one per line) as the last argument.
# Never `for f in $SHELLFILES`: a HOME with a space or a glob character would be split (review 1, I2).
each_shellfile() {
  while IFS= read -r __sf; do
    [ -z "$__sf" ] || "$@" "$__sf" || return 1
  done <<EOF
$SHELLFILES
EOF
}

in_list() { case "$NL$2" in *"$NL$1$NL"*) return 0 ;; esac; return 1; } # in_list <item> <newline list>

write_state() {
  { printf 'version=%s\nbin=%s\n' "$VER" "$BIN"
    [ -z "$V_SOCKET" ] || printf 'SYNC_GATE_SOCKET=%s\n' "$V_SOCKET"
    [ -z "$V_DATA_DIR" ] || printf 'SYNC_GATE_DATA_DIR=%s\n' "$V_DATA_DIR"
    [ -z "$V_CONFIG" ] || printf 'SYNC_GATE_CONFIG=%s\n' "$V_CONFIG"
    [ -z "$V_INSTALL_DIR" ] || printf 'SYNC_GATE_INSTALL_DIR=%s\n' "$V_INSTALL_DIR"
    printf '%s' "$NEW_BLOCKS" | while IFS= read -r p; do [ -z "$p" ] || printf 'shell_block=%s\n' "$p"; done
    printf '%s' "$NEW_CREATED" | while IFS= read -r p; do [ -z "$p" ] || printf 'shell_created=%s\n' "$p"; done
    printf '%s' "$NEW_NONL" | while IFS= read -r p; do [ -z "$p" ] || printf 'shell_nonl=%s\n' "$p"; done
  } > "$STATE.tmp.$$" && mv -f "$STATE.tmp.$$" "$STATE"
}

# ---------------------------------------------------------------------------------------------
# layout

setup_layout() {
  [ -n "${HOME:-}" ] || die "HOME is not set"
  case $HOME in /*) ;; *) die "HOME is not an absolute path" ;; esac
  check_value HOME "$HOME"
  SYS=$(uname -s)
  case $SYS in
    Linux) OS=linux ;;
    Darwin) OS=mac ;;
    *) die "unsupported system: $SYS (Linux and macOS only; Windows has install.ps1)" ;;
  esac
  STATEDIR=${XDG_STATE_HOME:-$HOME/.local/state}/sync_gate
  STATE=$STATEDIR/install-state
  ENVF=$STATEDIR/env
  RB=$STATEDIR/rollback
  SAFE_PATH=/usr/bin:/bin:/usr/sbin:/sbin
}

setup_target() {
  case $(uname -m) in
    x86_64 | amd64) ARCH=x86_64 ;;
    aarch64 | arm64) ARCH=aarch64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  if [ "$OS" = linux ]; then TARGET=$ARCH-unknown-linux-musl; else TARGET=$ARCH-apple-darwin; fi
}

lock_install() {
  # Even different XDG_STATE_HOME values can modify the same programs and shell files.
  # Keep this inode: unlinking a lock file lets another run lock a different inode.
  exec 9>> "$HOME/.sync_gate-install.lock"
  if command -v flock > /dev/null 2>&1; then
    flock -n 9 && return 0
  elif command -v perl > /dev/null 2>&1; then
    # macOS has Perl's flock but no flock command. The shell keeps fd 9 open after Perl exits.
    perl -MFcntl=:flock -e 'open my $lock, ">&=9" or die "$!\n"; exit !flock($lock, LOCK_EX | LOCK_NB)' && return 0
  else
    die "install or uninstall requires flock or Perl with flock support"
  fi
  die "another sync_gate installer is running, or the installer lock is unavailable"
}

# merge_overrides: the stored values, replaced by what the environment has now (and said so); --clear-overrides drops them.
merge_overrides() {
  V_SOCKET=; V_DATA_DIR=; V_CONFIG=; V_INSTALL_DIR=
  if [ "$CLEAR" = 1 ]; then
    say "clearing the stored values of SYNC_GATE_SOCKET, SYNC_GATE_DATA_DIR, SYNC_GATE_CONFIG and SYNC_GATE_INSTALL_DIR"
    # shortcut: with a cleared SYNC_GATE_INSTALL_DIR the default folder is used and the old binaries stay where they were; say so.
    [ -z "$ST_INSTALL_DIR" ] || say "note: binaries installed in $ST_INSTALL_DIR are not moved or removed"
    return 0
  fi
  for k in SOCKET DATA_DIR CONFIG INSTALL_DIR; do
    eval "stored=\$ST_$k; cur=\${SYNC_GATE_$k:-}"
    new=$stored
    if [ -n "$cur" ]; then
      new=$cur
      if [ -n "$stored" ] && [ "$stored" != "$cur" ]; then say "override changed: SYNC_GATE_$k"; fi
    fi
    [ -z "$new" ] || check_value "SYNC_GATE_$k" "$new"
    eval "V_$k=\$new"
  done
}

export_overrides() { # the effective values for every binary this run starts
  for k in SOCKET DATA_DIR CONFIG INSTALL_DIR; do
    eval "val=\$V_$k"
    if [ -n "$val" ]; then eval "SYNC_GATE_$k=\$val; export SYNC_GATE_$k"; else eval "unset SYNC_GATE_$k" || true; fi
  done
}

setup_bin() {
  if [ -n "$V_INSTALL_DIR" ]; then BIN=$V_INSTALL_DIR; else BIN=$HOME/.local/bin; fi
  case $BIN in /*) ;; *) die "the install folder must be an absolute path: $BIN" ;; esac
  case $BIN in *:*) die "the install folder cannot contain ':' (it goes into PATH): $BIN" ;; esac
  SVCNAME=${SYNC_GATE_SERVICE_NAME:-}
  check_value SYNC_GATE_SERVICE_NAME "$SVCNAME"
  if [ "$OS" = linux ]; then
    SVC=${SVCNAME:-sync_gated}
    SVCFILE=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$SVC.service
  else
    SVC=${SVCNAME:-dev.sync_labs.sync_gated}
    SVCFILE=$HOME/Library/LaunchAgents/$SVC.plist
  fi
  case $SVC in */* | *[[:space:]]*) die "invalid service name: $SVC" ;; esac
  LOGFILE=$HOME/Library/Logs/sync_gate/daemon.log
}

# service kind for this machine: systemd | launchd | none
detect_kind() {
  KIND=none
  if [ "$OS" = linux ]; then
    if command -v systemctl > /dev/null 2>&1 && systemctl --user show-environment > /dev/null 2>&1 < /dev/null; then KIND=systemd; fi
  else
    if command -v launchctl > /dev/null 2>&1; then KIND=launchd; fi
  fi
}

load_paths() { # load_paths <bin dir>: P_config P_data P_shims P_adopted P_socket P_hub from `sync_gate paths` (no recalculation here, P37)
  out=$("$1/sync_gate" paths 2> /dev/null < /dev/null) || { say "$1/sync_gate paths failed" >&2; return 1; }
  P_config=; P_data=; P_shims=; P_adopted=; P_socket=; P_hub=
  while IFS= read -r line; do
    case $line in *=*) ;; *) continue ;; esac
    k=${line%%=*}; v=${line#*=}
    case $k in
      config) P_config=$v ;; data) P_data=$v ;; shims) P_shims=$v ;;
      adopted) P_adopted=$v ;; socket) P_socket=$v ;; hub) P_hub=$v ;;
    esac
  done <<EOF
$out
EOF
  for k in config data shims adopted socket hub; do
    eval "val=\$P_$k"
    [ -n "$val" ] || { say "sync_gate paths printed no $k line" >&2; return 1; }
  done
}

# ---------------------------------------------------------------------------------------------
# release files

check_archive() {
  LC_ALL=C tar -tzf "$1" > "$TMP/names" &&
    LC_ALL=C tar -tvzf "$1" > "$TMP/types" &&
    awk '
      FILENAME == ARGV[1] {
        if ($0 !~ /^(sync_gate|sync_gated|sync_gate_mcp|LICENSE-MIT|LICENSE-APACHE)$/ || seen[$0]++) bad = 1
        names++
        next
      }
      { if (substr($0, 1, 1) != "-") bad = 1; types++ }
      END { exit (bad || names != types || !seen["sync_gate"] || !seen["sync_gated"] || !seen["sync_gate_mcp"]) }
    ' "$TMP/names" "$TMP/types"
}

get_assets() { # fills NEWBIN and VER; no mutation outside TMP
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/sync_gate-install.XXXXXX") || die "cannot create a temporary folder"
  trap 'rm -rf "$TMP"' EXIT
  if [ -n "${SYNC_GATE_INSTALL_FROM:-}" ]; then
    [ -f "$SYNC_GATE_INSTALL_FROM/SHA256SUMS" ] || die "no SHA256SUMS in $SYNC_GATE_INSTALL_FROM"
    cp "$SYNC_GATE_INSTALL_FROM/SHA256SUMS" "$TMP/SHA256SUMS"
    BASE=
  else
    if [ -n "$WANT_VER" ]; then BASE=$REPO_URL/releases/download/v$WANT_VER; else BASE=$REPO_URL/releases/latest/download; fi
    fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS"
  fi
  FILE=; WANT=; VER=$WANT_VER; ANYVER=
  while read -r h f || [ -n "$h" ]; do
    f=${f#\*}
    case $f in
      sync_gate-*.tar.gz)
        if [ -z "$ANYVER" ]; then
          v=${f#sync_gate-}
          for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-apple-darwin aarch64-apple-darwin; do v=${v%-"$t".tar.gz}; done
          v=${v%.tar.gz}
          ANYVER=$v
        fi ;;
    esac
    if [ -z "$FILE" ]; then
      if [ -n "$WANT_VER" ]; then
        [ "$f" = "sync_gate-$WANT_VER-$TARGET.tar.gz" ] && { FILE=$f; WANT=$h; }
      else
        case $f in sync_gate-*-"$TARGET".tar.gz) FILE=$f; WANT=$h; v=${f#sync_gate-}; VER=${v%-"$TARGET".tar.gz} ;; esac
      fi
    fi
  done < "$TMP/SHA256SUMS"
  [ -n "$VER" ] || VER=$ANYVER
  case $VER in *[!0-9A-Za-z.+-]*) die "odd version string: $VER" ;; esac
  if [ -n "$FILE" ]; then
    if [ -n "$BASE" ]; then fetch "$BASE/$FILE" "$TMP/$FILE"; else cp "$SYNC_GATE_INSTALL_FROM/$FILE" "$TMP/$FILE" || die "missing $FILE in $SYNC_GATE_INSTALL_FROM"; fi
    got=$(hash_of "$TMP/$FILE" | tr 'A-F' 'a-f'); WANT=$(printf '%s' "$WANT" | tr 'A-F' 'a-f')
    [ "$got" = "$WANT" ] || die "checksum mismatch for $FILE (nothing was changed)"
    check_archive "$TMP/$FILE" || die "$FILE has invalid archive members"
    mkdir "$TMP/x"
    tar -xzf "$TMP/$FILE" -C "$TMP/x" -- sync_gate sync_gated sync_gate_mcp || die "cannot unpack $FILE"
    for n in sync_gate sync_gated sync_gate_mcp; do [ -f "$TMP/x/$n" ] || die "$FILE has no $n"; done
    NEWBIN=$TMP/x
  else
    [ -n "$VER" ] || die "cannot tell the version of this release"
    command -v cargo > /dev/null 2>&1 \
      || die "no prebuilt binary for $TARGET in this release; install Rust from https://rustup.rs and run this again"
    say "no prebuilt binary for $TARGET; building v$VER with cargo (this takes a while)"
    # package names: the sync_gate_shim package builds the sync_gate_mcp binary
    cargo install --locked --git "$REPO_URL" --tag "v$VER" --root "$TMP/cargo" sync_gate sync_gated sync_gate_shim < /dev/null \
      || die "cargo install failed (nothing was changed)"
    NEWBIN=$TMP/cargo/bin
    for n in sync_gate sync_gated sync_gate_mcp; do [ -f "$NEWBIN/$n" ] || die "cargo did not build $n"; done
  fi
}

# ---------------------------------------------------------------------------------------------
# daemon probes and service control

# Env only from the persisted files: what a brand new terminal sees (plus the account and runtime-dir variables a login gives).
run_stored() {
  env -i HOME="$HOME" PATH="$SAFE_PATH" ${USER:+USER="$USER"} ${LOGNAME:+LOGNAME="$LOGNAME"} \
    ${XDG_RUNTIME_DIR:+XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR"} ${TMPDIR:+TMPDIR="$TMPDIR"} \
    sh -c '. "$1"; shift; exec "$@"' sh "$ENVF" "$@" < /dev/null
}
health() { run_stored sync_gate paths > /dev/null 2>&1 && run_stored sync_gate status > /dev/null 2>&1; }
wait_health() { i=0; while [ "$i" -lt 15 ]; do health && return 0; sleep 1; i=$((i + 1)); done; return 1; }
responds() { "$1/sync_gate" status > /dev/null 2>&1 < /dev/null; } # with the effective SYNC_GATE_* exported

svc_stop() {
  case $KIND in
    systemd) systemctl --user stop "$SVC.service" < /dev/null > /dev/null 2>&1 || true ;;
    launchd) launchctl bootout "gui/$(id -u)/$SVC" < /dev/null > /dev/null 2>&1 || true ;;
  esac
  return 0
}
svc_restart() {
  case $KIND in
    systemd) systemctl --user restart "$SVC.service" < /dev/null || return 1 ;;
    launchd)
      launchctl bootout "gui/$(id -u)/$SVC" < /dev/null > /dev/null 2>&1 || true
      launchctl bootstrap "gui/$(id -u)" "$SVCFILE" < /dev/null || return 1 ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# rollback (same design on every path: S1 saves, a run left in progress is undone by the next one)

step() {
  [ ! -d "$RB/in-progress" ] &&
    printf '%s\n' "$1" > "$RB/in-progress.new" &&
    mv -f "$RB/in-progress.new" "$RB/in-progress"
}
inject() { # inject <step>: SYNC_GATE_INSTALL_FAIL_AT=<step> fails after the step ran, <step>:crash leaves without undoing
  case ${SYNC_GATE_INSTALL_FAIL_AT:-} in
    "$1") say "injected failure at $1" >&2; return 1 ;;
    "$1:crash") say "injected crash at $1" >&2; exit 1 ;;
  esac
  return 0
}
run_step() { # run_step <name> <function>
  step "$1" || return 1
  "$2" || return 1
  inject "$1"
}

rb_file() { # save the bytes of a file (or the fact that it is absent)
  RBN=$((RBN + 1))
  printf '%s\n' "$1" > "$RB/files/$RBN.path" || return 1
  if [ -e "$1" ]; then cp -p "$1" "$RB/files/$RBN.bytes"; else true > "$RB/files/$RBN.absent"; fi
}

prepare_manual_shims() { # after load_paths, before changing installed files
  case $P_shims in
    /*) manual_shims=$P_shims ;;
    *)
      cwd=$(pwd -P && printf .) || die "cannot resolve the working directory for manual shims"
      cwd=${cwd%"$NL."}
      manual_shims=${cwd%/}/$P_shims ;;
  esac
  case $manual_shims in
    *"$NL"* | */ | */. | */..) die "invalid shims path from sync_gate paths" ;;
  esac
  # The CLI joins "shims" onto SYNC_GATE_DATA_DIR. Pin its effective parent across retries.
  MANUAL_SHIMS_DATA_DIR=${manual_shims%/*}/
  MANUAL_SHIMS_ABSENT=0
  manifest=$manual_shims/sync_gate_shims.json
  if config_absent "$manifest"; then
    MANUAL_SHIMS_ABSENT=1
  elif [ ! -f "$manifest" ] || [ ! -r "$manifest" ]; then
    die "cannot inspect the manual shims manifest: $manifest"
  fi
}

run_manual_shims() (
  if [ -f "$RB/manual-shims-env" ]; then
    { IFS= read -r data_dir && IFS= read -r xdg_data_home; } < "$RB/manual-shims-env" || return 1
    if [ -n "$data_dir" ]; then export SYNC_GATE_DATA_DIR="$data_dir"; else unset SYNC_GATE_DATA_DIR; fi
    if [ -n "$xdg_data_home" ]; then export XDG_DATA_HOME="$xdg_data_home"; else unset XDG_DATA_HOME; fi
  fi
  "$BIN/sync_gate" shims "$1" < /dev/null
)

rb_save() { # rb_save <mode: install|uninstall>
  rm -rf "$RB" || return 1
  mkdir -p "$RB/bin" "$RB/files" || return 1
  step S1 || return 1
  RBN=0
  for n in sync_gate sync_gated sync_gate_mcp; do
    if [ -e "$BIN/$n" ]; then
      cp -p "$BIN/$n" "$RB/bin/$n" || return 1
    else
      true > "$RB/bin/$n.absent" || return 1
    fi
  done
  each_shellfile rb_file && rb_file "$ENVF" && rb_file "$STATE" && rb_file "$SVCFILE" || return 1
  if [ -n "$MANUAL_SHIMS_DATA_DIR" ]; then
    printf '%s\n' "$MANUAL_SHIMS_DATA_DIR" '' > "$RB/manual-shims-env" || return 1
    if [ "$MANUAL_SHIMS_ABSENT" = 1 ]; then
      true > "$RB/manual-shims-absent" || return 1
    fi
  fi
  svc_existed=0
  [ ! -e "$SVCFILE" ] || svc_existed=1
  printf 'mode=%s\nbin=%s\nkind=%s\nsvc=%s\nsvcfile=%s\nstep=\nsvc_existed=%s\n' \
    "$1" "$BIN" "$KIND" "$SVC" "$SVCFILE" "$svc_existed" > "$RB/meta" || return 1
  true > "$RB/ready"
}

load_meta() {
  M_mode=; M_bin=; M_kind=; M_svc=; M_svcfile=; M_existed=0
  while IFS= read -r line; do
    k=${line%%=*}; v=${line#*=}
    case $k in
      mode) M_mode=$v ;; bin) M_bin=$v ;; kind) M_kind=$v ;; svc) M_svc=$v ;; svcfile) M_svcfile=$v ;; svc_existed) M_existed=$v ;;
    esac
  done < "$RB/meta"
}

# undo_run: put everything saved in rollback/ back and bring the old daemon up. Returns 1 if some item could not be restored.
undo_run() {
  UNDO_ERR=
  load_meta || { UNDO_ERR=" rollback metadata"; return 1; }
  cur=$(cat "$RB/in-progress") || { UNDO_ERR=" rollback step"; return 1; }
  num=${cur%%:*}; num=${num#?}
  KIND=$M_kind; SVC=$M_svc; SVCFILE=$M_svcfile; BIN=$M_bin
  svc_stop
  # Remove shims introduced at S4 before the new binary goes away.
  if [ "$M_mode" = install ] && [ "$num" -ge 4 ] && [ -x "$BIN/sync_gate" ]; then
    if [ -f "$RB/bin/sync_gate.absent" ] || [ -f "$RB/manual-shims-absent" ]; then
      run_manual_shims remove > /dev/null 2>&1 || { UNDO_ERR=" shims removal"; return 1; }
    fi
  fi
  for n in sync_gate sync_gated sync_gate_mcp; do
    if [ -f "$RB/bin/$n.absent" ]; then rm -f "$BIN/$n" || UNDO_ERR="$UNDO_ERR $n"
    elif [ -f "$RB/bin/$n" ]; then
      if mkdir -p "$BIN" && cp -p "$RB/bin/$n" "$BIN/.$n.undo.$$" && mv -f "$BIN/.$n.undo.$$" "$BIN/$n"; then :; else UNDO_ERR="$UNDO_ERR $n"; fi
    fi
  done
  old_env_absent=0
  for pf in "$RB"/files/*.path; do
    [ -f "$pf" ] || continue
    b=${pf%.path}
    IFS= read -r p < "$pf"
    if [ -f "$b.absent" ]; then
      [ "$p" != "$ENVF" ] || old_env_absent=1
      rm -f "$p" || UNDO_ERR="$UNDO_ERR $p"
    elif [ -f "$p" ] && cmp -s "$b.bytes" "$p"; then :
    else
      mkdir -p "$(dirname "$p")"
      cat "$b.bytes" > "$p" || UNDO_ERR="$UNDO_ERR $p"
    fi
  done
  # old shims back (install S4+ / uninstall U5+)
  if [ -f "$RB/bin/sync_gate" ] && [ ! -f "$RB/manual-shims-absent" ]; then
    if { [ "$M_mode" = install ] && [ "$num" -ge 4 ]; } || { [ "$M_mode" = uninstall ] && [ "$num" -ge 5 ]; }; then
      if [ "$old_env_absent" = 1 ]; then
        run_manual_shims install > /dev/null 2>&1 || UNDO_ERR="$UNDO_ERR shims install"
      else
        run_stored sync_gate shims install > /dev/null 2>&1 || UNDO_ERR="$UNDO_ERR shims install"
      fi
    fi
  fi
  case $KIND in
    systemd)
      systemctl --user daemon-reload < /dev/null > /dev/null 2>&1 || true
      if [ "$M_existed" = 1 ]; then systemctl --user restart "$SVC.service" < /dev/null > /dev/null 2>&1 || UNDO_ERR="$UNDO_ERR service"
      else systemctl --user disable "$SVC.service" < /dev/null > /dev/null 2>&1 || true; fi ;;
    launchd)
      if [ "$M_existed" = 1 ]; then
        launchctl bootout "gui/$(id -u)/$SVC" < /dev/null > /dev/null 2>&1 || true
        launchctl bootstrap "gui/$(id -u)" "$SVCFILE" < /dev/null > /dev/null 2>&1 || UNDO_ERR="$UNDO_ERR service"
      fi ;;
  esac
  if [ "$M_existed" = 1 ] && [ -f "$RB/bin/sync_gate" ]; then wait_health || UNDO_ERR="$UNDO_ERR health"; fi
  [ -z "$UNDO_ERR" ]
}

clear_undo() {
  # Keep the complete snapshot if we cannot disarm it. Cleanup may stop partway.
  rm -f "$RB/ready" || die "cannot disarm rollback; files kept in $RB (see docs/install.md#recover)"
  rm -rf "$RB" || die "previous version restored; cannot remove rollback files in $RB"
}

fail_with_undo() { # fail_with_undo <word: upgrade|uninstall> <step>
  say "$1 failed at $2" >&2
  if undo_run; then
    clear_undo
    die "$1 failed at $2; previous version restored"
  else
    die "$1 failed at $2; could not restore${UNDO_ERR}; files kept in $RB (see docs/install.md#recover)"
  fi
}

recover_pending() {
  [ -d "$RB" ] || return 0
  if [ ! -f "$RB/ready" ]; then rm -rf "$RB" || die "cannot remove rollback files in $RB"; return 0; fi
  [ -f "$RB/in-progress" ] || die "missing rollback step; files kept in $RB (see docs/install.md#recover)"
  say "a previous run stopped at $(cat "$RB/in-progress"); restoring it first"
  if undo_run; then clear_undo; else die "could not restore${UNDO_ERR}; files kept in $RB (see docs/install.md#recover)"; fi
}

commit_run() {
  # Disarm rollback before deleting its files, so an interruption during cleanup cannot undo a committed run.
  rm -f "$RB/ready" || fail_with_undo "$1" "$2"
  rm -rf "$RB"
}

# ---------------------------------------------------------------------------------------------
# shell files

shell_files() { # the files that get the block on this machine
  printf '%s\n' "$HOME/.profile" "$HOME/.bashrc"
  [ ! -e "$HOME/.bash_profile" ] || printf '%s\n' "$HOME/.bash_profile"
  if [ "$OS" = mac ] || command -v zsh > /dev/null 2>&1; then printf '%s\n' "$HOME/.zprofile" "$HOME/.zshrc"; fi
}

BLOCK_BEGIN='# >>> sync_gate >>>'
BLOCK_END='# <<< sync_gate <<<'

# block_ok <file>: no start marker without its end marker (stripping such a file would eat everything after it)
block_ok() { [ ! -f "$1" ] || awk -v b="$BLOCK_BEGIN" -v e="$BLOCK_END" '$0 == b { s = 1; next } s && $0 == e { s = 0 } END { exit s }' "$1"; }
check_blocks() { # refuse before changing anything
  while IFS= read -r __sf; do
    [ -z "$__sf" ] || block_ok "$__sf" \
      || die "$__sf has the sync_gate start marker ($BLOCK_BEGIN) but not the end marker ($BLOCK_END); fix it by hand and run this again (nothing was changed)"
  done <<EOF
$SHELLFILES
EOF
}

strip_block() { awk -v b="$BLOCK_BEGIN" -v e="$BLOCK_END" '$0 == b { s = 1; next } s && $0 == e { s = 0; next } !s { print }' "$1"; }

# add_block <file>: tail of the file, only inside our markers (the rest stays byte for byte)
add_block() {
  f=$1
  if [ ! -e "$f" ]; then : > "$f"; NEW_CREATED=$NEW_CREATED$f$NL
  elif [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then in_list "$f" "$NEW_NONL" || NEW_NONL=$NEW_NONL$f$NL; fi
  in_list "$f" "$ST_NONL" && { in_list "$f" "$NEW_NONL" || NEW_NONL=$NEW_NONL$f$NL; }
  in_list "$f" "$ST_CREATED" && { in_list "$f" "$NEW_CREATED" || NEW_CREATED=$NEW_CREATED$f$NL; }
  { strip_block "$f"; printf '%s\n' "$BLOCK_BEGIN" "[ -f $(shq "$ENVF") ] && . $(shq "$ENVF")" "$BLOCK_END"; } > "$TMP/blk.$$"
  cat "$TMP/blk.$$" > "$f" || return 1
  NEW_BLOCKS=$NEW_BLOCKS$f$NL
}

# remove_block <file>
remove_block() {
  f=$1
  [ -f "$f" ] || return 0
  strip_block "$f" > "$TMP/rm.$$"
  if in_list "$f" "$ST_NONL"; then # we added the missing final newline: take that one back
    printf '%s' "$(cat "$TMP/rm.$$")" > "$f" || return 1
  elif in_list "$f" "$ST_CREATED" && [ ! -s "$TMP/rm.$$" ]; then
    rm -f "$f" || return 1
  else
    cat "$TMP/rm.$$" > "$f" || return 1
  fi
  if in_list "$f" "$ST_CREATED" && [ -f "$f" ] && [ ! -s "$f" ]; then rm -f "$f" || return 1; fi
}

write_env() { # the file every shell reads
  sq_shims=$(shq "$P_shims"); sq_bin=$(shq "$BIN")
  {
    echo "# Written by the sync_gate installer. Do not edit; run the installer again instead."
    for k in SOCKET DATA_DIR CONFIG INSTALL_DIR; do
      eval "val=\$V_$k"
      [ -z "$val" ] || printf 'export SYNC_GATE_%s=%s\n' "$k" "$(shq "$val")"
    done
    cat <<EOF
__sg_shims=$sq_shims
__sg_bin=$sq_bin
__sg_has_bin=0
__sg_p=:\$PATH:
while :; do
  case \$__sg_p in
    *":\$__sg_shims:"*) __sg_p=\${__sg_p%%":\$__sg_shims:"*}:\${__sg_p#*":\$__sg_shims:"} ;;
    *) break ;;
  esac
done
case \$__sg_p in *":\$__sg_bin:"*) __sg_has_bin=1 ;; esac
__sg_p=\${__sg_p#:}
__sg_p=\${__sg_p%:}
if [ "\$__sg_has_bin" = 1 ]; then PATH=\$__sg_shims\${__sg_p:+:\$__sg_p}; else PATH=\$__sg_shims:\$__sg_bin\${__sg_p:+:\$__sg_p}; fi
export PATH
unset __sg_shims __sg_bin __sg_p __sg_has_bin
EOF
  } > "$ENVF.tmp.$$" && mv -f "$ENVF.tmp.$$" "$ENVF"
}

# ---------------------------------------------------------------------------------------------
# service files

unit_check_specials() {
  case $BIN in
    *"'"* | *'"'* | *'\'*) die "systemd refuses ', \" and \\ in the path of the program it starts ($BIN); set SYNC_GATE_INSTALL_DIR to another folder and run the installer again (nothing was changed)" ;;
  esac
  [ "$UNIT_SPECIALS_PROVEN" = 1 ] && return 0
  for v in "$BIN" "$V_SOCKET" "$V_DATA_DIR" "$V_CONFIG" "$V_INSTALL_DIR"; do
    case $v in
      *'$'* | *'%'* | *'\'*) die "a value going into the systemd unit has \$, % or \\ ($v): not supported yet; use another folder (nothing was changed)" ;;
    esac
  done
}

write_service() {
  mkdir -p "$(dirname "$SVCFILE")"
  if [ "$KIND" = systemd ]; then
    {
      printf '%s\n' '[Unit]' 'Description=sync_gate daemon' '' '[Service]'
      printf 'ExecStart="%s"\n' "$(esc_exec "$BIN/sync_gated")"
      for k in SOCKET DATA_DIR CONFIG INSTALL_DIR; do
        eval "val=\$V_$k"
        [ -z "$val" ] || printf 'Environment="SYNC_GATE_%s=%s"\n' "$k" "$(esc_env "$val")"
      done
      printf '%s\n' 'Restart=on-failure' 'RestartPreventExitStatus=2' '' '[Install]' 'WantedBy=default.target'
    } > "$SVCFILE.tmp.$$" && mv -f "$SVCFILE.tmp.$$" "$SVCFILE"
  else
    mkdir -p "$(dirname "$LOGFILE")"
    {
      printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
        '<plist version="1.0">' '<dict>' '  <key>Label</key>'
      printf '  <string>%s</string>\n' "$(esc_xml "$SVC")"
      printf '%s\n' '  <key>ProgramArguments</key>' '  <array>'
      printf '    <string>%s</string>\n' "$(esc_xml "$BIN/sync_gated")"
      printf '%s\n' '  </array>' '  <key>RunAtLoad</key>' '  <true/>' '  <key>KeepAlive</key>' '  <dict>' \
        '    <key>SuccessfulExit</key>' '    <false/>' '  </dict>' '  <key>StandardErrorPath</key>'
      printf '  <string>%s</string>\n' "$(esc_xml "$LOGFILE")"
      if [ -n "$V_SOCKET$V_DATA_DIR$V_CONFIG$V_INSTALL_DIR" ]; then
        printf '%s\n' '  <key>EnvironmentVariables</key>' '  <dict>'
        for k in SOCKET DATA_DIR CONFIG INSTALL_DIR; do
          eval "val=\$V_$k"
          [ -z "$val" ] || printf '    <key>SYNC_GATE_%s</key>\n    <string>%s</string>\n' "$k" "$(esc_xml "$val")"
        done
        printf '%s\n' '  </dict>'
      fi
      printf '%s\n' '</dict>' '</plist>'
    } > "$SVCFILE.tmp.$$" && mv -f "$SVCFILE.tmp.$$" "$SVCFILE"
  fi
}

# ---------------------------------------------------------------------------------------------
# install steps (each returns non-zero on failure)

s_stop() {
  svc_stop || return 1
  if [ -x "$BIN/sync_gate" ] && responds "$BIN"; then
    say "another sync_gated is still serving ${SYNC_GATE_SOCKET:-the default socket}; it is not touched" >&2
    return 1
  fi
  return 0
}

s_binaries() {
  mkdir -p "$BIN" || return 1
  for n in sync_gate sync_gated sync_gate_mcp; do
    cp "$NEWBIN/$n" "$BIN/.$n.new.$$" || return 1
    chmod 755 "$BIN/.$n.new.$$" || return 1
    mv -f "$BIN/.$n.new.$$" "$BIN/$n" || return 1
  done
}

s_shims() { "$BIN/sync_gate" shims install < /dev/null > /dev/null || return 1; }

s_env() {
  load_paths "$BIN" || return 1
  mkdir -p "$STATEDIR" || return 1
  NEW_BLOCKS=; NEW_CREATED=; NEW_NONL=
  write_env || return 1
  each_shellfile add_block || return 1
  write_state || return 1
}

s_unit() {
  [ "$KIND" != none ] || return 0
  write_service || return 1
  if [ "$KIND" = systemd ]; then
    systemctl --user daemon-reload < /dev/null || return 1
    systemctl --user enable "$SVC.service" < /dev/null > /dev/null 2>&1 || return 1
  fi
}

s_start() {
  [ "$KIND" != none ] || return 0
  svc_restart || return 1
  wait_health || { say "the daemon did not answer within 15 s" >&2; return 1; }
}

do_install() {
  recover_pending
  read_state
  merge_overrides
  export_overrides
  setup_bin
  get_assets
  detect_kind
  SHELLFILES=$({ shell_files; printf '%s' "$ST_BLOCKS"; } | awk 'NF && !seen[$0]++')
  OLDVER=$ST_VERSION
  [ "$KIND" != systemd ] || unit_check_specials
  # a sync_gated we do not own serving this socket: stop here, nothing changed
  if [ ! -e "$SVCFILE" ] && responds "$NEWBIN"; then
    die "another sync_gated is serving this socket (not installed by this script); stop it and run this again. Nothing was changed."
  fi
  check_blocks
  if [ ! -e "$ENVF" ] && [ -x "$BIN/sync_gate" ]; then
    load_paths "$BIN" || die "cannot locate the manual shims; installation stopped"
    prepare_manual_shims
  fi
  mkdir -p "$STATEDIR"
  rb_save install || die "cannot save rollback files in $RB; installation stopped"
  for pair in S2:s_stop S3:s_binaries S4:s_shims S5:s_env S6:s_unit S7:s_start; do
    st=${pair%%:*}; fn=${pair#*:}
    if ! run_step "$st" "$fn"; then fail_with_undo upgrade "$st"; fi
  done
  step S8 || fail_with_undo upgrade S8
  commit_run upgrade S8
  if [ "$KIND" = none ]; then
    if [ "$OS" = linux ]; then say "systemd --user is not available here; start sync_gated yourself, see docs/install.md"
    else say "launchctl is not available here; start sync_gated yourself, see docs/install.md"; fi
  fi
  say "sync_gate $VER installed in $BIN${OLDVER:+ (was $OLDVER)}"
  say "data=$P_data"; say "config=$P_config"; say "shims=$P_shims"
  for k in SOCKET DATA_DIR CONFIG INSTALL_DIR; do
    eval "val=\$V_$k"
    [ -z "$val" ] || say "own value in use: SYNC_GATE_$k=$val"
  done
  say "Open a new terminal, or run: . $(shq "$ENVF")"
  say "COMMAND_URL=$COMMAND_URL"
  say "update:    curl -fsSL $COMMAND_URL | sh"
  say "uninstall: curl -fsSL $COMMAND_URL | sh -s -- --uninstall"
}

# ---------------------------------------------------------------------------------------------
# uninstall

# u_refs: U2, search the agent configs for the install path in every spelling (N8). Prints file:line on a hit.
rx_path() { # rx_path <absolute path>: ERE matching it with // and /./ and the $HOME, ${HOME} and ~ spellings
  p=$1
  sep='/+(\./+)*'
  rest=$p
  pre=
  case $p in
    "$HOME"/*) rest=${p#"$HOME"/}; pre="($(rx_path_abs "$HOME")|\\\$HOME|\\\$\\{HOME\\}|~)" ;;
  esac
  body=
  old_ifs=$IFS; IFS=/; set -f
  for c in $rest; do
    [ -z "$c" ] || [ "$c" = . ] || body=$body$sep$(rx_lit "$c")
  done
  set +f; IFS=$old_ifs
  if [ -n "$pre" ]; then printf '%s%s' "$pre" "$body"; else printf '%s' "$body"; fi
}
rx_path_abs() {
  sep='/+(\./+)*'; body=
  old_ifs=$IFS; IFS=/; set -f
  for c in $1; do [ -z "$c" ] || body=$body$sep$(rx_lit "$c"); done
  set +f; IFS=$old_ifs
  printf '%s' "$body"
}

# The Claude config the agent uses: SYNC_GATE_CLAUDE_CONFIG, else $CLAUDE_CONFIG_DIR/.claude.json (adopt.rs refuses to
# guess when CLAUDE_CONFIG_DIR is set), else ~/.claude.json.
claude_config_path() {
  if [ -n "${SYNC_GATE_CLAUDE_CONFIG:-}" ]; then printf '%s' "$SYNC_GATE_CLAUDE_CONFIG"
  elif [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then printf '%s/.claude.json' "$CLAUDE_CONFIG_DIR"
  else printf '%s/.claude.json' "$HOME"; fi
}

# A failed file test also covers lookup errors. Confirm absence in a searchable ancestor.
config_absent() (
  case $1 in /*) path=$1 ;; *) path=./$1 ;; esac
  while [ ! -e "$path" ] && [ ! -L "$path" ]; do
    dir=${path%/*}; dir=${dir:-/}
    if [ -d "$dir" ]; then
      [ -r "$dir" ] && [ -x "$dir" ] || return 1
      name=$(printf '%sx\n' "${path##*/}" | sed 's/[][?*\\]/\\&/g') || return 1
      entry=$(find "${dir%/}/." ! -name . -prune -name "${name%x}" -print) || return 1
      [ -z "$entry" ]
      return
    fi
    path=$dir
  done
  return 1
)

u_refs() {
  claude=$(claude_config_path)
  codex=${SYNC_GATE_CODEX_CONFIG:-${CODEX_HOME:-$HOME/.codex}/config.toml}
  pat_bin="$(rx_path "$BIN/sync_gate")(_mcp)?([^A-Za-z0-9_.-]|\$)"
  pat_state="$(rx_path "$STATEDIR")/"
  hit=0
  for f in "$claude" "$codex"; do
    if [ ! -f "$f" ]; then
      config_absent "$f" && continue
      die "cannot search $f for sync_gate references; nothing was removed. Check the file and run uninstall again"
    fi
    for pat in "$pat_bin" "$pat_state"; do
      if grep -nE -- "$pat" "$f" > "$TMP/refs.$$" 2> /dev/null; then
        while IFS= read -r l; do say "$f:${l%%:*}" >&2; done < "$TMP/refs.$$"
        hit=1
      elif [ "$?" -ne 1 ]; then
        die "cannot search $f for sync_gate references; nothing was removed. Check the file and run uninstall again"
      fi
    done
  done
  [ "$hit" = 0 ]
}

do_uninstall() {
  recover_pending
  read_state
  [ -n "$ST_BIN" ] || [ -e "$STATE" ] || say "no install state found at $STATE; looking at the default folders"
  V_SOCKET=$ST_SOCKET; V_DATA_DIR=$ST_DATA_DIR; V_CONFIG=$ST_CONFIG; V_INSTALL_DIR=$ST_INSTALL_DIR
  export_overrides
  setup_bin
  [ -z "$ST_BIN" ] || BIN=$ST_BIN
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/sync_gate-install.XXXXXX") || die "cannot create a temporary folder"
  trap 'rm -rf "$TMP"' EXIT
  [ -x "$BIN/sync_gate" ] || die "no sync_gate in $BIN; nothing to uninstall"
  detect_kind
  load_paths "$BIN" || die "cannot read the paths from $BIN/sync_gate; nothing was removed"
  [ -e "$ENVF" ] || prepare_manual_shims
  SHELLFILES=$({ shell_files; printf '%s' "$ST_BLOCKS"; } | awk 'NF && !seen[$0]++')
  check_blocks # before U1: mcp restore changes the agent configs
  # U1
  CLAUDE_CFG=
  if [ -n "${SYNC_GATE_CLAUDE_CONFIG:-}${CLAUDE_CONFIG_DIR:-}" ]; then CLAUDE_CFG=$(claude_config_path); fi
  # shellcheck disable=SC2086
  if ! "$BIN/sync_gate" mcp restore --strict ${CLAUDE_CFG:+--claude-config "$CLAUDE_CFG"} ${SYNC_GATE_CODEX_CONFIG:+--codex-config "$SYNC_GATE_CODEX_CONFIG"} < /dev/null; then
    die "mcp restore --strict failed; nothing was removed. Fix what it reports (SYNC_GATE_CLAUDE_CONFIG and SYNC_GATE_CODEX_CONFIG point it at another config file) and run uninstall again"
  fi
  # U2
  u_refs || die "the agent configs above still point at $BIN/sync_gate (or at the sync_gate state folder); nothing was removed. Remove those lines and run uninstall again"
  mkdir -p "$STATEDIR"
  rb_save uninstall || die "cannot save rollback files in $RB; uninstall stopped" # U3
  step U4 || fail_with_undo uninstall U4
  svc_stop
  if responds "$BIN"; then
    fail_with_undo uninstall U4
  fi
  step U5 || fail_with_undo uninstall U5
  if ! "$BIN/sync_gate" shims remove < /dev/null; then
    say "close the programs that run sync_gate shortcuts and run uninstall again" >&2
    fail_with_undo uninstall U5
  fi
  inject U5 || fail_with_undo uninstall U5
  if ! run_step U6 u_state; then fail_with_undo uninstall U6; fi
  if ! run_step U7 u_bins; then fail_with_undo uninstall U7; fi
  commit_run uninstall U7
  rmdir "$STATEDIR" 2> /dev/null || true
  say "sync_gate uninstalled."
  say "kept (yours): config $P_config"
  say "kept (yours): data   $P_data"
}

u_state() {
  each_shellfile remove_block || return 1
  rm -f "$ENVF" "$STATE" || return 1
  case $KIND in
    systemd)
      systemctl --user disable "$SVC.service" < /dev/null > /dev/null 2>&1 || true
      rm -f "$SVCFILE" || return 1
      systemctl --user daemon-reload < /dev/null > /dev/null 2>&1 || true ;;
    *) rm -f "$SVCFILE" || return 1 ;;
  esac
}

u_bins() {
  for n in sync_gate sync_gated sync_gate_mcp; do rm -f "$BIN/$n" || return 1; done
  rmdir "$BIN" 2> /dev/null || true
}

# ---------------------------------------------------------------------------------------------

main() {
  exec < /dev/null # nothing below may read the script when it comes in through `sh < install.sh`
  UNINSTALL=0; CLEAR=0; WANT_VER=
  MANUAL_SHIMS_DATA_DIR=
  while [ $# -gt 0 ]; do
    case $1 in
      --uninstall) UNINSTALL=1 ;;
      --clear-overrides) CLEAR=1 ;;
      --version) [ $# -ge 2 ] || die "--version needs a value"; WANT_VER=$2; shift ;;
      --version=*) WANT_VER=${1#--version=} ;;
      *) die "unknown option: $1 (use --uninstall, --version <x.y.z> or --clear-overrides)" ;;
    esac
    shift
  done
  case $WANT_VER in *[!0-9A-Za-z.+-]*) die "odd version string: $WANT_VER" ;; esac
  setup_layout
  setup_target
  lock_install
  if [ "$UNINSTALL" = 1 ]; then do_uninstall; else do_install; fi
}
main "$@"
