//! The Claude Code / Codex plugin in `plugin/` and the two marketplace catalogs at the repo root.

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn json(path: PathBuf) -> Value {
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The SessionStart command hook.
fn hook_entry(hooks: &Value) -> &Value {
    &hooks["hooks"]["SessionStart"][0]["hooks"][0]
}

#[test]
fn the_plugin_manifests_agree() {
    let plugin = root().join("plugin");
    let claude = json(plugin.join(".claude-plugin/plugin.json"));
    let codex = json(plugin.join(".codex-plugin/plugin.json"));
    for m in [&claude, &codex] {
        assert_eq!(m["name"], "sync-gate");
        assert_eq!(m["version"], env!("CARGO_PKG_VERSION"));
    }
    let declared = |key: &str| -> PathBuf {
        let rel = codex[key].as_str().unwrap_or_else(|| panic!("codex {key}"));
        assert!(plugin.join(rel).exists(), "codex {key}: {rel} is missing");
        plugin.join(rel)
    };
    assert!(declared("skills").join("sync_gate/SKILL.md").is_file());
    assert_eq!(codex["hooks"], "./hooks/hooks.json");
    assert_eq!(codex["mcpServers"], "./.mcp.json");
    let hooks = json(declared("hooks"));
    let hook = hook_entry(&hooks);
    assert_eq!(hook["type"], "command");
    let mcp = json(declared("mcpServers"));
    assert_eq!(mcp["mcpServers"]["sync_gate"]["command"], "sync_gate");
    assert_eq!(
        mcp["mcpServers"]["sync_gate"]["args"],
        serde_json::json!(["mcp", "serve"])
    );
    let claude_cat = json(root().join(".claude-plugin/marketplace.json"));
    assert_eq!(claude_cat["plugins"][0]["name"], "sync-gate");
    assert_eq!(claude_cat["plugins"][0]["source"], "./plugin");
    let codex_cat = json(root().join(".agents/plugins/marketplace.json"));
    assert_eq!(codex_cat["plugins"][0]["name"], "sync-gate");
    assert_eq!(codex_cat["plugins"][0]["source"]["source"], "local");
    assert_eq!(codex_cat["plugins"][0]["source"]["path"], "./plugin");
}

#[test]
fn the_hook_command_is_a_real_subcommand() {
    let codex = json(root().join("plugin/.codex-plugin/plugin.json"));
    let hooks = json(root().join("plugin").join(codex["hooks"].as_str().unwrap()));
    let command = hook_entry(&hooks)["command"].as_str().unwrap();
    let args = command
        .strip_prefix("sync_gate ")
        .expect("starts with sync_gate");
    // A data folder of its own (no real shims) and no session env file to append to.
    let data = std::env::temp_dir().join(format!("sync_gate-plugin-hook-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_sync_gate"))
        .args(args.split_whitespace())
        .env("SYNC_GATE_DATA_DIR", &data)
        .env_remove("CLAUDE_ENV_FILE")
        .env_remove("SYNC_GATE_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    use std::io::{Read, Write};
    child.stdin.take().unwrap().write_all(b"{}").unwrap();
    let mut pipe = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = pipe.read_to_end(&mut b);
        b
    });
    let start = std::time::Instant::now();
    let code = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s.code();
        }
        if start.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the hook did not exit within 30 s");
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    let stdout = reader.join().unwrap();
    let _ = std::fs::remove_dir_all(&data);
    assert_eq!(code, Some(0));
    let v: Value = serde_json::from_slice(&stdout).expect("the hook prints JSON");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "SessionStart");
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(ctx.contains("sync_gate"), "context: {ctx}");
    // The Windows note is only added on Windows.
    assert_eq!(
        ctx.contains(WINDOWS_SANDBOX_NOTE),
        cfg!(windows),
        "context: {ctx}"
    );
}

/// What the session context says about Codex's Windows sandbox (plan 3-S).
const WINDOWS_SANDBOX_NOTE: &str = "Inside Codex's Windows sandbox the queue works only when the owner lists the sandbox in \"guests\" (see docs/sandbox.md); otherwise commands run directly and sync_gate prints one line saying so.";

#[test]
fn the_skill_names_the_exit_code_and_the_resume() {
    let skill = std::fs::read_to_string(root().join("plugin/skills/sync_gate/SKILL.md")).unwrap();
    assert!(skill.starts_with("---\nname: sync_gate\n"));
    for needle in ["75", "sync_gate wait", "PowerShell"] {
        assert!(skill.contains(needle), "SKILL.md lacks {needle}");
    }
    assert!(
        skill.contains("takes the slot AND runs the stored command"),
        "SKILL.md must say wait runs the stored command"
    );
    assert!(skill.contains("never run the original command again"));
    assert!(skill.contains("environment of the shell that calls it"));
    assert!(!skill.contains("then run the same command again"));
    assert!(skill.contains("could not be started"));
    assert!(skill.contains(".ps1"));
    // The Windows sandbox paragraph (plan 3-S): guests, the two own-account modes, exit 75 = rerun.
    for needle in [
        "`guests`",
        "`mxc`",
        "`unelevated`",
        "exits 75 and nothing is kept",
        "run the same command again",
    ] {
        assert!(
            skill.contains(needle),
            "SKILL.md sandbox paragraph lacks {needle}"
        );
    }
}

/// New installs go through the `sync-labs` catalog; the old `sync_gate` catalog stays only as a documented fallback.
#[test]
fn the_install_texts_use_the_sync_labs_catalog() {
    for file in [
        "README.md",
        "README.pt-BR.md",
        "README.es.md",
        "plugin/README.md",
        "tools/install/install.ps1",
    ] {
        let text = std::fs::read_to_string(root().join(file)).unwrap();
        assert!(
            text.contains("claude plugin marketplace add sync-labs-team/plugins"),
            "{file}"
        );
        assert!(
            text.contains("claude plugin install sync-gate@sync-labs"),
            "{file}"
        );
        assert!(
            !text.contains("claude plugin install sync-gate@sync_gate"),
            "{file}"
        );
    }
    let install = std::fs::read_to_string(root().join("docs/install.md")).unwrap();
    assert!(install.contains("sync-gate@sync-labs"));
}
