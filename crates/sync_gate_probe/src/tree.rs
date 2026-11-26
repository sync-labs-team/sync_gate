//! Resident memory of a process and all its descendants.
use crate::Probe;
use std::collections::{HashMap, HashSet};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate};

/// `root` and all its descendants, parents before children. `ppids`: pid -> parent pid.
/// Each pid is visited once, so parent cycles (pid reuse, pid 0 parenting itself) terminate.
/// Empty if `root` is not in the table.
pub(crate) fn descendants(root: u32, ppids: &HashMap<u32, u32>) -> Vec<u32> {
    walk(root, ppids, |_| true)
}

/// [`descendants`] limited to the pids `keep` accepts; never walks below a refused one.
pub(crate) fn walk(
    root: u32,
    ppids: &HashMap<u32, u32>,
    mut keep: impl FnMut(u32) -> bool,
) -> Vec<u32> {
    if !ppids.contains_key(&root) {
        return Vec::new();
    }
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&pid, &ppid) in ppids {
        children.entry(ppid).or_default().push(pid);
    }
    for kids in children.values_mut() {
        kids.sort_unstable_by(|a, b| b.cmp(a)); // popped ascending: deterministic order
    }
    let (mut order, mut seen, mut stack) = (Vec::new(), HashSet::new(), vec![root]);
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) || !keep(pid) {
            continue;
        }
        order.push(pid);
        stack.extend(children.get(&pid).into_iter().flatten().copied());
    }
    order
}

/// pid -> parent pid from `(pid, ppid, start_time)` rows. A link is dropped (parent becomes
/// `u32::MAX`) when the child started before its parent: the parent pid was reused after the
/// real parent died (Windows never updates ppid). Start time 0 means unknown: keep the link.
pub(crate) fn links_from(rows: &[(u32, u32, u64)]) -> HashMap<u32, u32> {
    let start: HashMap<u32, u64> = rows.iter().map(|&(pid, _, st)| (pid, st)).collect();
    rows.iter()
        .map(|&(pid, ppid, st)| {
            let stale = match start.get(&ppid) {
                Some(&pst) => st != 0 && pst != 0 && st < pst,
                None => false,
            };
            (pid, if stale { u32::MAX } else { ppid })
        })
        .collect()
}

/// pid -> parent pid for every live process (`u32::MAX` when the parent is unknown or stale).
pub(crate) fn ppid_table() -> std::io::Result<HashMap<u32, u32>> {
    let mut sys = sysinfo::System::new().map_err(std::io::Error::other)?;
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let rows: Vec<_> = sys
        .processes()
        .iter()
        .map(|(pid, p)| {
            let ppid = p.parent().map_or(u32::MAX, Pid::as_u32);
            (pid.as_u32(), ppid, p.start_time())
        })
        .collect();
    Ok(links_from(&rows))
}

/// Sum RSS of `root` and descendants. `table`: pid -> (parent pid, rss).
pub(crate) fn sum_tree(root: u32, table: &HashMap<u32, (u32, u64)>) -> u64 {
    let ppids = table.iter().map(|(&pid, &(ppid, _))| (pid, ppid)).collect();
    descendants(root, &ppids)
        .iter()
        .map(|pid| table[pid].1)
        .sum()
}

impl Probe {
    /// Sum of RSS of `root_pid` and every descendant; 0 if the pid is unknown.
    pub fn tree_rss(&mut self, root_pid: u32) -> u64 {
        let Some(sys) = self.sys.as_mut() else {
            return 0;
        };
        // Memory only: no cpu, disk, environ or cmdline reads.
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_memory(),
        );
        let table: HashMap<u32, (u32, u64)> = sys
            .processes()
            .iter()
            .map(|(pid, p)| {
                let ppid = p.parent().map_or(u32::MAX, Pid::as_u32);
                (pid.as_u32(), (ppid, p.memory()))
            })
            .collect();
        sum_tree(root_pid, &table)
    }
}
