//! `sync_gate_mcp <server>`: stands in for an MCP server; see the library for what it does.

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [server] = args.as_slice() else {
        eprintln!("usage: sync_gate_mcp <server>");
        std::process::exit(2);
    };
    sync_gate_shim::exit_on_signal();
    std::process::exit(sync_gate_shim::run_process(server));
}
