# Shared PostgreSQL

The daemon (`sync_gated`) can own one PostgreSQL server for the machine. Each `sync_gate run` of a
declared project gets a database and a role of its own for as long as the command runs (a
"lease"); the database is dropped when the command ends. The server is a separate cluster
created with your own PostgreSQL binaries; sync_gate never uses or changes a server of yours.

## Configuration

In the sync_gate configuration file (`SYNC_GATE_CONFIG`, or `config.toml` in the per-user
sync_gate configuration folder):

```toml
[postgres]
bin_dir = "/usr/lib/postgresql/17/bin"   # absolute path of the PostgreSQL `bin` folder
port = 28543                             # default; TCP, 127.0.0.1 only
max_leases = 8                           # default; 1 to 64 databases at once
connections_per_lease = 25               # default; 1 to 1000
idle_stop_secs = 600                     # default; stop the server after this long without a lease (0 = never)
lease_wait_secs = 30                     # default; 1 to 300, see below

[[postgres.project]]
dir = "/home/me/src/shop"                # absolute; matches commands run in this folder or below
commands = ["npm test", "cargo test"]    # command prefixes; empty or absent = every command
url_vars = ["DATABASE_URL"]              # default; variables that receive the connection URL
```

sync_gate first keeps the projects whose `dir` contains the working folder and whose `commands`
match the command, and then uses the deepest of those. So a command that the deepest project's
`commands` do not match falls back to a matching project higher up, if there is one. A command
that matches no project runs exactly as without sync_gate. The daemon reads the configuration when
it starts.

## What the command receives

A command that gets a lease runs with:

| Variable | Value |
|---|---|
| `PGHOST` | `127.0.0.1` |
| `PGPORT` | the configured port |
| `PGUSER`, `PGDATABASE` | the lease's role and database (same name, `fg_l_` and 16 hex digits) |
| `PGPASSWORD` | the lease's password |
| `PGSSLMODE` | `disable` |
| each name in `url_vars` | `postgresql://<role>:<password>@127.0.0.1:<port>/<database>` |

These replace values of the same name. `PGSERVICE`, `PGSERVICEFILE`, `PGPASSFILE`, `PGHOSTADDR`
and `PGOPTIONS` are removed, so your own PostgreSQL settings cannot redirect the command. Names
in `url_vars` must match `[A-Za-z_][A-Za-z0-9_]{0,63}` and must not start with `PG`.

When no lease can be had, the command runs with its environment unchanged (nothing added, nothing
removed) and sync_gate prints one line on stderr:

```
sync_gate: no shared database (<reason>); running with the project's own settings
```

The command always runs once, with its own exit code. `sync_gate status` shows the service as
`postgres: <state>, <n> lease(s), rss <n> MiB, restarts <n>`, followed by `, <n> with unknown owner`
and `, <n> cleanup pending` when those are not zero.

## What is guaranteed, and for whom

The guarantee holds between programs that use the credentials they received, and it covers
access to content: a lease's role cannot connect to another lease's database, nor to `postgres`,
`template0` or `template1`; it cannot create databases or roles and cannot switch to another
role; no lease reads, writes, pre-populates or drops the database of another lease.

Not guaranteed:

- Availability and resource quotas inside the shared server. One program can degrade the server
  for the others: advisory locks that exhaust the shared lock memory, a burst of connection
  attempts, or grants that keep another lease's role from being dropped. Affected commands fail
  open on their next lease. See "Resetting the cluster" below.
- Metadata. Each lease can see role and database names, owners, database ACLs, role comments,
  that other sessions exist, aggregate statistics of other databases and global lock
  information, from which activity can be inferred. "Cannot see the data" means it cannot read
  the content of other leases' tables.
- The role comment `sync_gate:lease:<token>` is public by design. The token marks which roles
  sync_gate created; it is not a credential.
- sync_gate is not a sandbox. Every agent runs as the same operating system user as the daemon.
  A process of that user that looks for the administrator socket or the cluster's files, or that
  changes the file system while the daemon runs, is outside the guarantee. Protection against a
  hostile agent needs an operating system boundary per agent (another user, a container or a
  virtual machine); this version does not provide one.

## `lease_wait_secs`

The longest time the CLI waits for one answer from the daemon about its database: server start,
queue and creating the role and database together. Default 30, from 1 to 300. When it runs out,
the command starts at once without a shared database, with its original environment and one of
two reasons on stderr, which mean the same thing: `timed out after <n> s` (the CLI's own deadline)
or `postgres is still starting` (the daemon answered first that the server is not ready yet).

It is a limit per step, not a total. A project without `migrate`, or a run whose template is
ready, waits for one step. The first run of a new template key (see "A template database from the
migrations") waits for the candidate, then for `migrate` itself up to `migrate_timeout_secs`, then
for the promotion, then for the copy, each step with its own `lease_wait_secs`: up to three times
`lease_wait_secs` plus `migrate_timeout_secs` before the command starts. When a run falls back
after the daemon gave it a database (for example `migrate` failed, could not start or passed its
deadline, a watched file changed, or the daemon is older), the CLI's last messages about that
database (the failure, the give-back) share one more `lease_wait_secs` before the command starts
with its original environment.

The CLI then tells the daemon it gave up, so that no role or database is kept for that request.
That message is best effort. If it is lost, or the daemon is stopped while the database is being
created, the leftover is dropped later by the daemon's own rules (see "When the daemon drops a
database on its own") or when the daemon next starts. A drop that fails is retried (see "Pending
cleanups and resetting the cluster").

The first command after the daemon starts may run without a shared database while the server is
still being created and started. Later commands get one once the server is ready, so on a slow
machine the first few commands may run without one; there, raise the number.

## Pending cleanups and resetting the cluster

A database or role that could not be dropped yet stays as a pending cleanup and is retried (after
1 s, 2 s, 4 s and so on, at most every 30 s). With 32 pending cleanups (`MAX_PENDING_RELEASES`,
fixed in the code) no new lease is granted: commands run without a shared database, with the
reason `32 postgres cleanups are pending; no new database until they finish or the cluster is
reset`, until the count goes down or you reset the cluster.

To reset a degraded server, delete the cluster as described in "Deleting the cluster by hand"
below. The next lease creates a new cluster. Until then, the affected commands fail open.

## One database per run, no databases created by the command

Each lease has exactly one database, and its role cannot create others. Tools that create their
own databases do not work with sync_gate in this version: the Django test runner (`test_<NAME>`),
the shadow database of `prisma migrate dev`, and Rails parallel tests. Leave those commands out of
`commands`; they then run as they do today. Without `migrate` (next section), each run starts
from an empty database and runs its own migrations.

## Extensions

A project's own database image often creates extensions before any migration runs, for example
an `init-extensions.sql` among the compose init scripts. A database from sync_gate starts without
them, and a migration that expects one then fails (`operator class "gin_trgm_ops" does not exist`
is pg_trgm missing). Declare them and every database sync_gate lends has them:

```toml
[[postgres.project]]
dir = "/home/me/src/shop"
extensions = ["pg_trgm", "unaccent"]   # names matching [a-z_][a-z0-9_-]{0,62}, at most 16, no repeats
```

- sync_gate creates them only in an empty database, before any of the project's code ran in it:
  a lease of a project without `migrate`, and the template's candidate before `migrate` runs.
  They are created in this order, after the database exists and before the command (or
  `migrate`) gets it, as `CREATE EXTENSION IF NOT EXISTS ... SCHEMA public`, in the `public`
  schema whatever the database's search path says.
- They are created as the lease's role, so the lease owns them. Only extensions that a database
  owner may create work: PostgreSQL's trusted extensions (`pg_trgm`, `unaccent`, `pgcrypto`,
  `uuid-ossp`, `citext`, `hstore` and others; `trusted = true` in the extension's control file).
  An untrusted one (`file_fdw`, `dblink`, `pg_stat_statements`, ...) fails with `permission denied
  to create extension`, and the command runs with its own settings.
- With `migrate`, the list is part of the template key (see "The template key"), so the template
  has them and every copy inherits them, owned by the copy's lease. A copy is never given an
  extension: it already holds the migration's objects, among which an extension script would run
  with more rights than the lease has. sync_gate only checks that the copy has every declared
  extension; when one is missing (the migration dropped it), the run fails open with `the template
  lacks extension(s) <names>; a new template is made when a watched file or the extensions list
  changes`.
- The CLI sends the list it read with every request, and the daemon, which reads its
  configuration only when it starts, refuses a list other than its own, order included, before
  it creates anything, with or without `migrate`: `the daemon's configuration is older than this
  command's (extensions differ); restart the daemon`. After changing `extensions`, restart the
  daemon.
- A failure to create them fails open like any other: the reason names the extensions and quotes
  the server's first error line.

## A template database from the migrations

A project can let sync_gate run its migrations once per version of its migration files. Every later
run then gets a copy of the migrated database instead of an empty one.

```toml
[[postgres.project]]
dir = "/home/me/src/shop"
migrate = ["npx", "prisma", "migrate", "deploy"]   # program and arguments, no shell
watch = ["prisma/migrations", "prisma/schema.prisma"]
migrate_timeout_secs = 300                          # default; 1 to 3600
```

- `migrate` is a program and its arguments, run without a shell, in the project's `dir`.
- `watch` lists files or folders, relative to `dir`, at most 64 entries, without empty, `.` or
  `..` parts. A folder counts with everything below it.
- `migrate` and `watch` must be set together.
- `migrate_timeout_secs` is how long a run waits for `migrate`, from 1 to 3600 (default 300).
- The watched paths may hold at most 10 000 files and folders together (each watched folder
  included) and 64 MiB in total.

### The template key

The template is identified by a key, a 64-bit hash (FNV-1a, not cryptographic) of:

- the project folder (its full path);
- the `migrate` program and its arguments;
- the `extensions` list, in the order written (the order they are created in);
- the relative name and the content of every watched file.

Changing a watched file (content, size or name), adding or removing one, changing `migrate`, or
changing `extensions` (including its order) gives a new key. Keys made before `extensions` existed
are never reused: the first run after the upgrade migrates once more and its template replaces
the old one. A link to a file is read; a link to a folder, a missing entry, an unreadable file
or anything that is neither a file nor a folder makes the run fall back (see below). The template
database is `fg_t_<key>` and the role that owns its objects is `fg_o_<key>` (`NOLOGIN`, with the
comment `sync_gate:owner:<key>`). The database belongs to the administrator and accepts no
connections.

### The first run and the next ones

The first run with a new key:

1. The CLI hashes the watched files and asks for a database with that key.
2. The daemon gives it an empty database and role, the "candidate", like a lease.
3. The CLI runs `migrate` on the candidate. `migrate` gets the same variables a command gets
   (`PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSWORD`, `PGSSLMODE` and each name in
   `url_vars`). Its standard input is closed, and its standard output and error go to sync_gate's
   stderr, so the command's own output stays clean. `migrate` runs within the lease the command
   was already admitted for; it does not queue on its own.
4. When `migrate` exits with 0 and the watched files still give the same key, the daemon turns the
   candidate into the template:
   - the role can no longer log in;
   - the database's own settings are removed;
   - every session of the role or in the database is ended (each gets 5 s; one that is still
     there makes the key fail), so a pool or a background `psql` left by `migrate` does not
     block the template;
   - the arrangement is checked (see "What `migrate` must not do");
   - the database passes to the administrator, closed to connections;
   - role and database are renamed to `fg_o_<key>` and `fg_t_<key>`.
5. The CLI asks again and the command runs on a copy of the template.

Every next run with the same key gets a copy at once (`CREATE DATABASE ... TEMPLATE`), without
running `migrate`. In the copy:

- every object the migration made belongs to the run's own role: tables, sequences, functions,
  schemas, large objects and extensions;
- the objects inside a trusted extension (for example `pgcrypto`) stay owned by the bootstrap
  superuser, and the schema `public` stays owned by `pg_database_owner`, as in any new database;
- default privileges the migration set for its own role (`ALTER DEFAULT PRIVILEGES` without
  `FOR ROLE`) apply to the run's role;
- object grants to predefined roles (for example `pg_read_all_data`) are kept.

Copies are independent databases: what one run writes, no other copy sees. A run never waits for
another run's migration: while a key is being prepared, other runs with the same key fall back at
once.

There is one template per project. When a new key becomes the template, the project's previous
template is dropped, and copies still in use are not affected. So switching between two branches
whose migrations differ runs `migrate` again at every switch.

### When the command runs with its original environment

A project with `migrate` never gets an empty database: when no copy of the right template can be
had, the command runs once with its environment unchanged, and the CLI prints the usual line:

```
sync_gate: no shared database (<reason>); running with the project's own settings
```

| When | `<reason>` |
|---|---|
| A watched path cannot be read (missing, a link to a folder, unreadable) | ``cannot read the watched path `<relative path>` `` |
| The watched files are too many or too large | `the watched files are over the limit (10000 files and folders, 64 MiB)` |
| Another run is migrating this key | `a migration for this project is running` |
| This key failed before | `the migration for these files failed before` |
| The template registry is missing, unreadable or of an unknown version | `the template registry is unknown; delete the cluster directory to reset it` |
| The template registry is full | `the template registry is full; delete the cluster directory to reset it` |
| `migrate` cannot be started (for example a typo in the program) | `the migration could not start` |
| `migrate` exits with another code | `the migration failed (exit <n>)` |
| `migrate` is still running at `migrate_timeout_secs` | `the migration is still running after <n> s` |
| A watched file changed while `migrate` ran | `the watched files changed during the migration` |
| A watched file changed while the copy was made | `the watched files changed while the database was being made` |
| The daemon refused the template (see "What `migrate` must not do") | `the template could not be made: postgres template failed: <why>` |
| The daemon was started with another configuration for this project | `the daemon and the CLI disagree about migrate for this project` |
| The daemon was started with another `extensions` list (or order) for this project | `the daemon's configuration is older than this command's (extensions differ); restart the daemon` |
| The template lacks a declared extension | `the template lacks extension(s) <names>; a new template is made when a watched file or the extensions list changes` |
| The daemon does not know template keys | `the daemon is older than this command` |

The reasons of a project without `migrate` (`daemon not running`, `timed out after <n> s` and the
others) apply too. When the daemon refuses a template, `sync_gate status` also lists the reason
among its decisions.

`migrate` that fails, cannot start or passes its deadline marks its key as failed. A key that
failed is not migrated again while it is among the 16 most recent failures of the project; change
a watched file or the `migrate` command to try again, or delete the cluster folder to start over.
Some consequences:

- A typo in the `migrate` program marks the key failed; fixing the command changes the key.
- Ctrl+C while `migrate` runs is not a failure: an interrupted migration is not remembered, the
  key is free again and the next run migrates again.
- The CLI never ends a `migrate` that passes its deadline. The key is marked failed (and
  remembered as above): later runs use the project's own settings until a watched file or the
  `migrate` command changes. The `migrate` keeps its candidate until it exits, and then the daemon
  drops the candidate.
- The CLI registers `migrate` as the holder of its candidate, as it does for a command. If the
  daemon does not confirm it within `lease_wait_secs`, the CLI says so (`... and could not be
  registered as the holder of its database, which may be dropped under it`) and goes on. If the
  registration was indeed not recorded, and that `migrate` is still running after the CLI exits
  and keeps no session open for 10 minutes, its candidate database may be dropped while it still
  runs.
- If the CLI dies before the daemon has recorded `migrate` as the holder, the key is not marked
  failed: once the candidate is dropped, the next run migrates again.

The template registry (`templates.json`, next to `leases.json`) holds at most 1024 keys; when it is
full, runs with a new key fall back. Deleting the cluster folder resets it. A registry that is
missing, unreadable or of an unknown version in an existing cluster turns templates off, and with
them every drop of a template, until the cluster folder is deleted.

### What `migrate` must not do

The template is refused, the key fails and the command runs with its original environment when the
migrated database holds anything a copy would lose or that `DROP OWNED` would remove in silence:

- a grant to another role on an object (for example `GRANT SELECT ON t TO <another lease>`);
- any row-level security policy, whatever its target, `PUBLIC` included;
- any database-level grant to a role other than the candidate and `PUBLIC`, predefined roles
  included;
- any default privilege (`ALTER DEFAULT PRIVILEGES`) for a role other than the candidate and
  `PUBLIC`, predefined roles included;
- any privilege of the candidate on an object it does not own;
- any role membership of the candidate (`GRANT <its own role> TO ...`; on the PostgreSQL releases
  tested, 15.20, 16 and 17, that grant already fails inside `migrate`).

A project that needs row-level security never gets a template, and runs with its own settings.

The daemon never runs code of the migration as the administrator: each script it runs inside the
candidate or a copy fixes `search_path = pg_catalog, pg_temp` first, and the candidate's database
settings are removed before the administrator enters it.

### What does not reach the copy

- Database settings (`ALTER DATABASE ... SET`) and role settings (`ALTER ROLE ... SET`).
- Database-level permissions (`GRANT ... ON DATABASE`).

### Other notes

- The output of `migrate` goes to sync_gate's stderr and is outside the secret guarantee (see
  "What stays outside the secret"): if `migrate` prints its connection URL, it is there.
- The daemon checks the template registry against the server once each time the daemon starts.
  A restart of the PostgreSQL server alone does not trigger that check; a candidate that goes
  away is checked against the server's catalogue then.
- A cluster created by a sync_gate version without templates has no `templates.json`. Such a
  cluster stays without templates (with the reason `the template registry is unknown; ...`) until
  its folder is deleted; leases of projects without `migrate` go on as before.

## What stays outside the secret

sync_gate writes no password or URL to a file, the status, its notes, its logs, its stderr or the
server log: they live only in the daemon's memory, in the reply on its private socket and in the
command's environment. Outside this, and not controlled by sync_gate: what your application's own
SQL puts in the server log when it fails, the application's own output (and that of its `migrate`,
which goes to sync_gate's stderr), operating system memory dumps, and the SCRAM verifier the server
stores for each role.

## When the daemon drops a database on its own

- The command ended: the CLI gives the database back.
- Every recorded owner is gone (the CLI and the command it registered). A process whose state
  cannot be read counts as alive; an unknown owner never leads to a drop.
- The command was never registered (the CLI died between starting it and registering it) and no
  session was seen in its database for 10 minutes. Such a command loses its database. In the
  other direction, without a registered command, a connection that stays open (a pool, for
  example) keeps the database until it closes. A session sample that fails or is uncertain never
  allows a drop. A lease whose CLI died before starting the command holds a slot for up to about
  10.5 minutes.

## Windows: job objects

Windows can tie a program to a job object, and ending the job ends the program. sync_gate puts the
server's starter outside every job object that sync_gate itself created, so stopping or crashing
the daemon never ends the server.

A job object the daemon was started in (by a terminal, a scheduler, an IDE or a CI runner) is
accepted. What happens when that environment ends its job, for example when you close the terminal
window, depends on the job. If the job does not let processes leave it, the server stays inside it:
the daemon and the server end together, commands that were using a database lose their
connections, and the next daemon start brings the server back and cleans up what was left. If the
job lets processes leave it, the server's starter leaves it (it is created with
`CREATE_BREAKAWAY_FROM_JOB`): the server is outside the job, so ending the job ends only the
daemon, the server keeps running, and the next daemon adopts it.

The status shows `failed: postgres cannot be started outside the daemon's job object` only when
the starter could not be kept out of a job that sync_gate owns. Commands then run without a shared
database.

To keep the server alive when a terminal closes, start the daemon from something that outlives
it: at log-on, or from a scheduled task.

## Limits

- PostgreSQL 15 or newer in `bin_dir` (`failed: PostgreSQL 15 or newer is required; bin_dir has
  <m>` otherwise). Tested with 15, 16 and 17.
- Durability is off (`fsync`, `synchronous_commit` and `full_page_writes`). After a crash of the
  operating system the cluster may be damaged; delete it as described in "Deleting the cluster by
  hand".
- The cluster runs in UTC (`timezone` and `log_timezone`), like the official Docker image, whatever
  the host's time zone. A cluster already running with the old setting is restarted when idle.
- Locale `C`, encoding `UTF8`: text may sort differently than in production.
- Only the extensions installed with the binaries of `bin_dir` are available.
- A lease registry (`leases.json`) that is missing or unreadable in an existing cluster turns off
  the automatic cleanup of leftovers until the cluster folder is deleted; the decisions in
  `sync_gate status` say so.
- A `postgresql.auto.conf` that sets anything (for example after `ALTER SYSTEM`) keeps the service
  off. sync_gate never writes that file. Remove the settings or delete the cluster.
- Templates (see "A template database from the migrations"): at most 10 000 watched files and
  folders and 64 MiB in total, at most 64 entries in `watch`, `migrate_timeout_secs` up to 3600, 16 failed
  keys remembered per project and 1024 rows in the template registry.

## Deleting the cluster by hand

The cluster is the folder `<data_dir>/pg/<major>` (for example `pg/17` under the sync_gate data
folder, `SYNC_GATE_DATA_DIR` or the per-user data folder). It holds the data folder, the server
log, the private socket folder, `cluster.json`, `leases.json` and `templates.json`. Stopping the
daemon is not enough, because the daemon leaves the server running while leases are alive. In this
order:

1. End the commands that use a shared database.
2. Stop the daemon.
3. Make sure the server is not running, and signal nothing before you have checked what it is.
   `pg_ctl stop` signals the process whose id is in `postmaster.pid` without checking it, and
   after a crash of the server or of the machine that id can belong to another program.
   - If `<data_dir>/pg/<major>/data/postmaster.pid` does not exist, the server is not running:
     go to step 4.
   - If it exists, look at the process whose id is on the first line of that file. If the
     machine was restarted since the cluster last ran, or no such process exists, or it is not a
     `postgres` program serving that data folder, the file is stale and the server is not
     running: go to step 4 (the stale file is deleted with the folder). To see the command line
     of a process, on Linux and macOS run `ps -p <pid> -o args=`, and on Windows, in PowerShell,
     `(Get-CimInstance Win32_Process -Filter "ProcessId=<pid>").CommandLine`.
   - Only when that process is a `postgres` program whose command line names that data folder,
     stop it with the `pg_ctl` of `bin_dir`:
     `pg_ctl stop -D "<data_dir>/pg/<major>/data" -m fast`. Check that `postmaster.pid` is gone
     before you go to step 4.
4. Delete `<data_dir>/pg/<major>`.
