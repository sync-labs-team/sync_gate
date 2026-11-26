//! Pure text layer of the shared PostgreSQL service: every SQL statement the administrator runs,
//! `pg_hba.conf`, the server configuration, names, the injected environment and secret redaction.
//! Nothing here starts a process or touches a file.

use std::collections::BTreeMap;
use std::path::Path;
use sync_gate_core::{Secret, is_extension_name, is_template_key};

pub const ADMIN_ROLE: &str = "sync_gate";
pub const LEASE_COMMENT: &str = "sync_gate:lease:";
/// Run first in every administrator script: nothing it says may reach the server log.
pub const ADMIN_PREAMBLE: &str = "SET log_min_messages = panic;\n\
SET log_min_error_statement = panic;\n\
SET log_statement = 'none';\n";

/// A caller-supplied string that cannot be placed safely in SQL or configuration text. The message
/// is static on purpose: it must never carry the rejected input (it may be a secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlError(&'static str);

impl std::fmt::Display for SqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for SqlError {}

type Sql = Result<String, SqlError>;

/// Double-quoted identifier. Rejects NUL (not representable in SQL text) and the empty name.
pub fn quote_ident(s: &str) -> Sql {
    if s.is_empty() || s.contains('\0') {
        return Err(SqlError("invalid SQL identifier"));
    }
    Ok(format!("\"{}\"", s.replace('"', "\"\"")))
}

/// Single-quoted literal for `standard_conforming_strings = on`. Rejects NUL and backslash: only
/// hex, validated names and normalized paths belong here, and a backslash would change meaning
/// under a different server setting.
pub fn quote_literal(s: &str) -> Sql {
    if s.contains(['\0', '\\']) {
        return Err(SqlError("invalid SQL literal"));
    }
    Ok(format!("'{}'", s.replace('\'', "''")))
}

fn is_hex(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `fg_l_<16 hex>`: 64 random bits chosen by the caller.
pub fn lease_name(hex16: &str) -> Sql {
    if hex16.len() != 16 || !is_hex(hex16, 16) {
        return Err(SqlError("lease name needs 16 hex digits"));
    }
    Ok(format!("fg_l_{hex16}"))
}

pub fn is_lease_name(s: &str) -> bool {
    s.strip_prefix("fg_l_")
        .is_some_and(|h| h.len() == 16 && is_hex(h, 16))
}

fn lease_ident(name: &str) -> Sql {
    if !is_lease_name(name) {
        return Err(SqlError("not a lease name"));
    }
    quote_ident(name)
}

fn token_ok(token: &str) -> Result<&str, SqlError> {
    if is_hex(token, 64) {
        Ok(token)
    } else {
        Err(SqlError("invalid creation token"))
    }
}

/// The creation mark as a quoted literal.
fn mark(token: &str) -> Sql {
    quote_literal(&format!("{LEASE_COMMENT}{}", token_ok(token)?))
}

/// Fixed file; the first matching line wins. TCP only matches `sameuser` for lease roles.
pub fn hba_conf() -> &'static str {
    "local all sync_gate trust\n\
     local all all reject\n\
     host  all sync_gate 0.0.0.0/0 reject\n\
     host  all sync_gate ::/0 reject\n\
     host  sameuser all 127.0.0.1/32 scram-sha-256\n\
     host  all all 0.0.0.0/0 reject\n\
     host  all all ::/0 reject\n"
}

/// Value of `unix_socket_directories` for one directory: a double-quoted list element (the
/// setting is a comma-separated list, and only quotes protect commas and surrounding spaces),
/// inside the single-quoted configuration value (apostrophes doubled; `#` is safe in quotes).
/// A double quote is refused: the documentation does not say how one is escaped in a list element.
fn socket_dir_value(dir: &str) -> Sql {
    if dir.is_empty() || dir.contains(['\0', '\n', '\r', '"']) {
        return Err(SqlError("invalid socket directory"));
    }
    let dir = dir.replace('\\', "/").replace('\'', "''");
    Ok(format!("'\"{dir}\"'"))
}

pub fn server_conf(port: u16, sock_dir: &Path, max_connections: u32) -> Sql {
    let dir = socket_dir_value(
        sock_dir
            .to_str()
            .ok_or(SqlError("socket directory is not UTF-8"))?,
    )?;
    Ok(format!(
        "port = {port}\n\
         listen_addresses = '127.0.0.1'\n\
         unix_socket_directories = {dir}\n\
         unix_socket_permissions = 0700\n\
         max_connections = {max_connections}\n\
         max_prepared_transactions = 0\n\
         shared_buffers = '32MB'\n\
         password_encryption = 'scram-sha-256'\n\
         fsync = off\n\
         synchronous_commit = off\n\
         full_page_writes = off\n\
         track_counts = on\n\
         track_activities = on\n\
         log_statement = 'none'\n\
         log_min_error_statement = panic\n\
         log_connections = off\n\
         log_disconnections = off\n\
         timezone = 'UTC'\n\
         log_timezone = 'UTC'\n"
    ))
}

pub fn bootstrap_sql() -> String {
    "REVOKE CONNECT ON DATABASE postgres FROM PUBLIC; \
     REVOKE CONNECT ON DATABASE template1 FROM PUBLIC; \
     DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('postgres','template0','template1')) \
     THEN RAISE EXCEPTION 'unexpected role'; END IF; END $$;"
        .into()
}

pub fn cluster_identity_sql() -> String {
    "SELECT system_identifier, current_setting('data_directory') FROM pg_control_system();".into()
}

/// One statement, run in the same session as a caller's script: it fails with
/// `not the sync_gate cluster` unless the server's system identifier is `system_identifier`
/// (compared as text, so the unsigned value never meets `bigint`).
pub fn identity_guard_sql(system_identifier: u64) -> String {
    format!(
        "DO $$ BEGIN IF (SELECT system_identifier::text FROM pg_control_system()) <> '{system_identifier}' \
         THEN RAISE EXCEPTION 'not the sync_gate cluster'; END IF; END $$;\n"
    )
}

/// Prints `t` or `f`.
pub fn name_taken(name: &str) -> Sql {
    let n = quote_literal(name)?;
    Ok(format!(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {n}) \
         OR EXISTS (SELECT 1 FROM pg_database WHERE datname = {n});"
    ))
}

/// Role and creation mark are born together or not at all. Contains the password: stdin only.
pub fn create_role(name: &str, token: &str, password: &str, conn_limit: u32) -> Sql {
    let (id, mark, pw) = (lease_ident(name)?, mark(token)?, quote_literal(password)?);
    Ok(format!(
        "BEGIN; CREATE ROLE {id} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION \
         NOBYPASSRLS CONNECTION LIMIT {conn_limit} PASSWORD {pw}; \
         COMMENT ON ROLE {id} IS {mark}; COMMIT;"
    ))
}

/// Outside a transaction: `CREATE DATABASE` cannot run in a block.
pub fn create_database(name: &str) -> Sql {
    let id = lease_ident(name)?;
    Ok(format!(
        "CREATE DATABASE {id} OWNER {id} TEMPLATE \"template0\"; \
         REVOKE ALL ON DATABASE {id} FROM PUBLIC;"
    ))
}

/// One database name per line, only those owned by the role that carries this creation mark.
pub fn owned_databases(name: &str, token: &str) -> Sql {
    let (n, mark) = (quote_literal(name)?, mark(token)?);
    Ok(format!(
        "SELECT d.datname FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba \
         WHERE r.rolname = {n} AND shobj_description(r.oid, 'pg_authid') = {mark};"
    ))
}

/// The owner may have marked its own database as a template, which `DROP` refuses.
pub fn drop_database(db: &str) -> Sql {
    let id = quote_ident(db)?;
    Ok(format!(
        "ALTER DATABASE {id} IS_TEMPLATE false; DROP DATABASE IF EXISTS {id} WITH (FORCE);"
    ))
}

/// Checks the mark and drops in one block; a role without the mark is left alone.
pub fn drop_role(name: &str, token: &str) -> Sql {
    let id = lease_ident(name)?;
    let (n, mark) = (quote_literal(name)?, mark(token)?);
    let own = quote_literal(&format!("DROP OWNED BY {id}"))?;
    let role = quote_literal(&format!("DROP ROLE {id}"))?;
    Ok(format!(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = {n} \
         AND shobj_description(r.oid, 'pg_authid') = {mark}) \
         THEN EXECUTE {own}; EXECUTE {role}; END IF; END $$;"
    ))
}

/// Lines `<role>|<token>` for every role carrying a lease mark.
pub fn lease_roles() -> String {
    // the token starts right after the prefix (substr counts from 1)
    format!(
        "SELECT rolname, substr(shobj_description(oid, 'pg_authid'), {}) FROM pg_roles \
         WHERE shobj_description(oid, 'pg_authid') LIKE '{LEASE_COMMENT}%';",
        LEASE_COMMENT.len() + 1
    )
}

/// Prints `<live sessions>|<sessions so far>` (-1 when the database has no statistics row).
pub fn db_activity(name: &str) -> Sql {
    let n = quote_literal(name)?;
    Ok(format!(
        "SELECT (SELECT count(*) FROM pg_stat_activity WHERE datname = {n} \
         AND backend_type = 'client backend'), \
         coalesce((SELECT sessions FROM pg_stat_database WHERE datname = {n}), -1);"
    ))
}

pub const OWNER_COMMENT: &str = "sync_gate:owner:";
/// Right after the preamble in every template script, and again after each `\connect`: only
/// system functions and operators resolve, whatever path a database or its objects set.
pub const SAFE_PATH: &str = "SET search_path = pg_catalog, pg_temp;\n";

fn key_ok(key: &str) -> Result<&str, SqlError> {
    if is_template_key(key) {
        Ok(key)
    } else {
        Err(SqlError("invalid template key"))
    }
}

/// `fg_t_<key>`: the template database of one key.
pub fn template_db(key: &str) -> Sql {
    Ok(format!("fg_t_{}", key_ok(key)?))
}

/// `fg_o_<key>`: the role that owns the objects inside the template database.
pub fn template_owner(key: &str) -> Sql {
    Ok(format!("fg_o_{}", key_ok(key)?))
}

/// The owner mark of `key` as a quoted literal.
fn owner_mark(key: &str) -> Sql {
    quote_literal(&format!("{OWNER_COMMENT}{}", key_ok(key)?))
}

/// An OID as a typed literal; 0 names no object.
fn oid_lit(oid: u32) -> Sql {
    if oid == 0 {
        return Err(SqlError("invalid OID"));
    }
    Ok(format!("'{oid}'::pg_catalog.oid"))
}

/// A `DO` that fails unless the lease role carries the creation mark of `token`, then runs `then`.
fn mark_guard(lease: &str, token: &str, then: &str) -> Sql {
    let (n, mark) = (quote_literal(lease)?, mark(token)?);
    Ok(format!(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = {n} \
         AND pg_catalog.shobj_description(r.oid, 'pg_authid') = {mark}) \
         THEN RAISE EXCEPTION 'the lease role does not carry its mark'; END IF; {then}END $$;\n"
    ))
}

/// `body` run by the administrator inside `db` (a lease or template database), in the same
/// `psql`. The new session gets the preamble and the safe path again, and the script stops
/// before `body` unless the session really is in `db`.
pub fn in_database(db: &str, body: &str) -> Sql {
    if !is_lease_name(db) && !db.strip_prefix("fg_t_").is_some_and(is_template_key) {
        return Err(SqlError("not a lease or template database"));
    }
    let (id, n) = (quote_ident(db)?, quote_literal(db)?);
    Ok(format!(
        "\\connect {id}\n{ADMIN_PREAMBLE}{SAFE_PATH}\
         DO $$ BEGIN IF pg_catalog.current_database() <> {n} \
         THEN RAISE EXCEPTION 'not connected to the expected database'; END IF; END $$;\n{body}"
    ))
}

/// Prints `<role oid>|<database oid>` of the marked lease role and the database of the same name
/// it owns; nothing when either is missing.
pub fn candidate_oids(lease: &str, token: &str) -> Sql {
    lease_ident(lease)?;
    let (n, mark) = (quote_literal(lease)?, mark(token)?);
    Ok(format!(
        "{SAFE_PATH}SELECT r.oid, d.oid FROM pg_catalog.pg_roles r \
         JOIN pg_catalog.pg_database d ON d.datdba = r.oid AND d.datname = r.rolname \
         WHERE r.rolname = {n} AND pg_catalog.shobj_description(r.oid, 'pg_authid') = {mark};"
    ))
}

/// Prints `t` when neither the template database nor its owner role exists.
pub fn template_names_free(key: &str) -> Sql {
    let db = quote_literal(&template_db(key)?)?;
    let owner = quote_literal(&template_owner(key)?)?;
    Ok(format!(
        "{SAFE_PATH}SELECT NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = {db}) \
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {owner});"
    ))
}

/// S1: the marked role can no longer log in, the database's own settings are gone (before the
/// administrator ever enters it), and every other session of the role or in the database is
/// ended. Prints `t` when none is left.
pub fn template_seal(lease: &str, token: &str) -> Sql {
    let (id, n) = (lease_ident(lease)?, quote_literal(lease)?);
    let seal = quote_literal(&format!("ALTER ROLE {id} NOLOGIN PASSWORD NULL"))?;
    let guard = mark_guard(lease, token, &format!("EXECUTE {seal}; "))?;
    Ok(format!(
        "{SAFE_PATH}{guard}ALTER DATABASE {id} RESET ALL;\n\
         SELECT coalesce(bool_and(pg_catalog.pg_terminate_backend(pid, 5000)), true) \
         FROM pg_catalog.pg_stat_activity WHERE (usename = {n} OR datname = {n}) \
         AND pid <> pg_catalog.pg_backend_pid();"
    ))
}

/// S2, inside the candidate database. Prints `t` only when (a) every dependency of this
/// database's objects on a role is ownership by the candidate, (b) no other role appears on the
/// database itself, neither as a dependency nor in its ACL (grants to pinned predefined roles
/// leave no dependency), (c) the candidate is in no role membership, (d) the database has no
/// row security policy (one for PUBLIC leaves no dependency), and (e) every default privilege
/// goes to the candidate or PUBLIC (one for a pinned role leaves no dependency, and a copy cannot
/// recreate it): anything else would be lost by the copy or dropped in silence by `DROP OWNED`.
pub fn template_check(lease: &str) -> Sql {
    lease_ident(lease)?;
    let n = quote_literal(lease)?;
    in_database(
        lease,
        &format!(
            "WITH c AS (SELECT r.oid AS role, d.oid AS db \
             FROM pg_catalog.pg_roles r, pg_catalog.pg_database d \
             WHERE r.rolname = {n} AND d.datname = pg_catalog.current_database()) \
             SELECT EXISTS (SELECT 1 FROM c) \
             AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_shdepend s, c WHERE s.dbid = c.db \
             AND s.refclassid = 'pg_catalog.pg_authid'::regclass \
             AND (s.deptype <> 'o' OR s.refobjid <> c.role)) \
             AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_shdepend s, c WHERE s.dbid = 0 \
             AND s.classid = 'pg_catalog.pg_database'::regclass \
             AND s.refclassid = 'pg_catalog.pg_authid'::regclass \
             AND s.objid = c.db AND s.refobjid <> c.role) \
             AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database d, c, \
             pg_catalog.aclexplode(d.datacl) e WHERE d.oid = c.db \
             AND e.grantee <> c.role AND e.grantee <> 0) \
             AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m, c \
             WHERE m.roleid = c.role OR m.member = c.role) \
             AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy) \
             AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl a, c, \
             pg_catalog.aclexplode(a.defaclacl) e WHERE e.grantee <> c.role AND e.grantee <> 0);"
        ),
    )
}

/// S3: the database passes to the administrator, closed to every connection.
pub fn template_own(lease: &str) -> Sql {
    let (id, admin) = (lease_ident(lease)?, quote_ident(ADMIN_ROLE)?);
    Ok(format!(
        "{SAFE_PATH}ALTER DATABASE {id} OWNER TO {admin};\n\
         ALTER DATABASE {id} IS_TEMPLATE false;\n\
         ALTER DATABASE {id} ALLOW_CONNECTIONS false;\n\
         REVOKE ALL ON DATABASE {id} FROM PUBLIC;"
    ))
}

/// S4a: the marked lease role becomes the template's owner role, with its mark, in one block.
pub fn template_rename_role(lease: &str, token: &str, key: &str) -> Sql {
    let (id, guard) = (lease_ident(lease)?, mark_guard(lease, token, "")?);
    let (owner, comment) = (quote_ident(&template_owner(key)?)?, owner_mark(key)?);
    Ok(format!(
        "{SAFE_PATH}BEGIN;\n{guard}ALTER ROLE {id} RENAME TO {owner};\n\
         COMMENT ON ROLE {owner} IS {comment};\nCOMMIT;"
    ))
}

/// S4b.
pub fn template_rename_db(lease: &str, key: &str) -> Sql {
    let (id, db) = (lease_ident(lease)?, quote_ident(&template_db(key)?)?);
    Ok(format!("{SAFE_PATH}ALTER DATABASE {id} RENAME TO {db};"))
}

/// Prints `t` when the recorded OIDs are a complete template of `key`: the database named, owned
/// by the administrator and closed; the role named, unable to log in and marked.
pub fn template_state(key: &str, db_oid: u32, role_oid: u32) -> Sql {
    let (db, role) = (oid_lit(db_oid)?, oid_lit(role_oid)?);
    let (dn, rn) = (
        quote_literal(&template_db(key)?)?,
        quote_literal(&template_owner(key)?)?,
    );
    let (admin, comment) = (quote_literal(ADMIN_ROLE)?, owner_mark(key)?);
    Ok(format!(
        "{SAFE_PATH}SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database d WHERE d.oid = {db} \
         AND d.datname = {dn} AND pg_catalog.pg_get_userbyid(d.datdba) = {admin} \
         AND NOT d.datallowconn AND NOT d.datistemplate) \
         AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.oid = {role} AND r.rolname = {rn} \
         AND NOT r.rolcanlogin \
         AND pg_catalog.shobj_description(r.oid, 'pg_authid') = {comment});"
    ))
}

/// Prints the name of the database `db_oid` when it is the candidate or the template of `key`
/// and is owned by `role_oid` or the administrator; nothing otherwise. The caller then drops it
/// with [`drop_database`], on the same worker.
pub fn db_by_oid(db_oid: u32, role_oid: u32, lease: &str, key: &str) -> Sql {
    lease_ident(lease)?;
    let (db, role) = (oid_lit(db_oid)?, oid_lit(role_oid)?);
    let (ln, tn) = (quote_literal(lease)?, quote_literal(&template_db(key)?)?);
    let admin = quote_literal(ADMIN_ROLE)?;
    Ok(format!(
        "{SAFE_PATH}SELECT d.datname FROM pg_catalog.pg_database d WHERE d.oid = {db} \
         AND d.datname IN ({ln}, {tn}) \
         AND (d.datdba = {role} OR pg_catalog.pg_get_userbyid(d.datdba) = {admin});"
    ))
}

/// Drops the role `role_oid` only while it is the marked lease role or the marked owner role of
/// `key`; any other role is left alone.
pub fn drop_template_role(role_oid: u32, lease: &str, token: &str, key: &str) -> Sql {
    let role = oid_lit(role_oid)?;
    let owner = template_owner(key)?;
    let is = |name: &str, mark: String| -> Sql {
        Ok(format!(
            "EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.oid = {role} \
             AND r.rolname = {} AND pg_catalog.shobj_description(r.oid, 'pg_authid') = {mark})",
            quote_literal(name)?
        ))
    };
    let drop = |id: String| -> Sql {
        Ok(format!(
            "EXECUTE {}; EXECUTE {};",
            quote_literal(&format!("DROP OWNED BY {id}"))?,
            quote_literal(&format!("DROP ROLE {id}"))?
        ))
    };
    Ok(format!(
        "{SAFE_PATH}DO $$ BEGIN IF {} THEN {} ELSIF {} THEN {} END IF; END $$;",
        is(lease, mark(token)?)?,
        drop(lease_ident(lease)?)?,
        is(&owner, owner_mark(key)?)?,
        drop(quote_ident(&owner)?)?
    ))
}

/// Outside a transaction: `CREATE DATABASE` cannot run in a block.
pub fn create_database_from(lease: &str, key: &str) -> Sql {
    let (id, tpl) = (lease_ident(lease)?, quote_ident(&template_db(key)?)?);
    Ok(format!(
        "{SAFE_PATH}CREATE DATABASE {id} OWNER {id} TEMPLATE {tpl};\n\
         REVOKE ALL ON DATABASE {id} FROM PUBLIC;"
    ))
}

/// Inside a fresh copy: everything the template's owner role owns passes to the lease, its
/// default privileges are recreated for the lease (a global entry replaces the built-in defaults,
/// so those are revoked first), and the owner role's remaining entries here are dropped.
pub fn clone_adopt(lease: &str, key: &str) -> Sql {
    let id = lease_ident(lease)?;
    let owner = template_owner(key)?;
    let (oid_, on) = (quote_ident(&owner)?, quote_literal(&owner)?);
    let adp = quote_literal(&format!("ALTER DEFAULT PRIVILEGES FOR ROLE {id}"))?;
    let me = quote_literal(&id)?;
    in_database(
        lease,
        &format!(
            "REASSIGN OWNED BY {oid_} TO {id};\n\
             DO $$ DECLARE d record; x record; kind text; scope text; who text; BEGIN \
             FOR d IN SELECT a.defaclrole AS owner, a.defaclnamespace AS ns, \
             a.defaclobjtype AS t, a.defaclacl AS acl FROM pg_catalog.pg_default_acl a \
             WHERE a.defaclrole = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = {on}) \
             LOOP \
             kind := CASE d.t WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES' \
             WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' WHEN 'n' THEN 'SCHEMAS' END; \
             IF kind IS NULL THEN RAISE EXCEPTION 'unknown default privilege object type'; END IF; \
             scope := ''; \
             IF d.ns = 0 THEN \
             EXECUTE {adp} || ' REVOKE ALL ON ' || kind || ' FROM PUBLIC'; \
             EXECUTE {adp} || ' REVOKE ALL ON ' || kind || ' FROM ' || {me}; \
             ELSE scope := ' IN SCHEMA ' || pg_catalog.quote_ident((SELECT n.nspname \
             FROM pg_catalog.pg_namespace n WHERE n.oid = d.ns)); END IF; \
             FOR x IN SELECT e.grantee, e.privilege_type, e.is_grantable \
             FROM pg_catalog.aclexplode(d.acl) e LOOP \
             who := CASE x.grantee WHEN 0 THEN 'PUBLIC' WHEN d.owner THEN {me} END; \
             IF who IS NULL THEN RAISE EXCEPTION 'default privilege for another role'; END IF; \
             EXECUTE {adp} || scope || ' GRANT ' || x.privilege_type || ' ON ' || kind \
             || ' TO ' || who || CASE WHEN x.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END; \
             END LOOP; END LOOP; END $$;\n\
             DROP OWNED BY {oid_};"
        ),
    )
}

/// `e` when it is a valid extension name.
fn ext_name(e: &str) -> Result<&str, SqlError> {
    if is_extension_name(e) {
        Ok(e)
    } else {
        Err(SqlError("invalid extension name"))
    }
}

/// Inside a lease database that is still empty (no project code has run in it): the project's
/// extensions, created as the lease role so that the lease owns them (S2 then sees only the
/// candidate's ownership, and a copy's `REASSIGN OWNED` hands them on). Only extensions a
/// database owner may create (trusted ones) succeed. `SCHEMA public` because the safe path puts
/// `pg_catalog` first. Never run in a copy of a template: an extension script would run among
/// the migration's objects.
pub fn create_extensions(lease: &str, extensions: &[String]) -> Sql {
    let id = lease_ident(lease)?;
    let creates = extensions
        .iter()
        .map(|e| {
            let q = quote_ident(ext_name(e)?)?;
            Ok(format!(
                "CREATE EXTENSION IF NOT EXISTS {q} SCHEMA public; "
            ))
        })
        .collect::<Sql>()?;
    in_database(lease, &format!("SET ROLE {id}; {creates}RESET ROLE;"))
}

/// Inside a copy, reading the catalogue only: prints, one per line, each of `extensions` the
/// database does not have.
pub fn missing_extensions(lease: &str, extensions: &[String]) -> Sql {
    lease_ident(lease)?;
    let names = extensions
        .iter()
        .map(|e| quote_literal(ext_name(e)?))
        .collect::<Result<Vec<_>, _>>()?
        .join(", ");
    in_database(
        lease,
        &format!(
            "SELECT x.n FROM pg_catalog.unnest(ARRAY[{names}]::pg_catalog.name[]) AS x(n) \
             WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension e WHERE e.extname = x.n);"
        ),
    )
}

/// Variables injected into the command. The password must be alphanumeric so the URL needs no
/// escaping; the daemon generates hex.
pub fn lease_env(
    name: &str,
    password: &str,
    port: u16,
    url_vars: &[String],
) -> Result<BTreeMap<String, Secret>, SqlError> {
    if !is_lease_name(name) {
        return Err(SqlError("not a lease name"));
    }
    if password.is_empty() || !password.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(SqlError("password must be alphanumeric"));
    }
    let url = format!("postgresql://{name}:{password}@127.0.0.1:{port}/{name}");
    let mut env: BTreeMap<String, Secret> = [
        ("PGHOST", "127.0.0.1".to_string()),
        ("PGPORT", port.to_string()),
        ("PGDATABASE", name.to_string()),
        ("PGUSER", name.to_string()),
        ("PGPASSWORD", password.to_string()),
        ("PGSSLMODE", "disable".to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), Secret::new(v)))
    .collect();
    for v in url_vars {
        env.insert(v.clone(), Secret::new(url.clone()));
    }
    Ok(env)
}

/// Replaces every occurrence of every non-empty secret with `***`. Overlapping or nested matches
/// are merged first, so no tail of a secret survives.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for s in secrets.iter().filter(|s| !s.is_empty()) {
        let mut from = 0;
        while let Some(i) = text[from..].find(s) {
            let start = from + i;
            ranges.push((start, start + s.len()));
            // advance one character so self-overlapping matches are found too
            from = start + text[start..].chars().next().map_or(1, char::len_utf8);
        }
    }
    ranges.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    let mut i = 0;
    while i < ranges.len() {
        let (start, mut end) = ranges[i];
        i += 1;
        while i < ranges.len() && ranges[i].0 < end {
            end = end.max(ranges[i].1);
            i += 1;
        }
        out.push_str(&text[pos..start]);
        out.push_str("***");
        pos = end;
    }
    out.push_str(&text[pos..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    const N: &str = "fg_l_00112233aabbccdd";
    const T: &str = "a1b2c3d4e5f60718";

    fn ok(r: Result<String, SqlError>) -> String {
        r.expect("must be accepted")
    }

    /// A path that is absolute on the platform running the test.
    fn native_abs(rest: &str) -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            format!("C:\\fg\\{rest}")
        } else {
            format!("/fg/{rest}")
        })
    }

    /// The configuration line `server_conf` must write for `p`: one double-quoted list element
    /// inside the single-quoted value, backslashes turned into slashes, apostrophes doubled.
    fn dirs_line(p: &Path) -> String {
        let d = p.to_str().unwrap().replace('\\', "/").replace('\'', "''");
        format!("unix_socket_directories = '\"{d}\"'")
    }

    #[test]
    fn identifiers_and_literals_are_quoted() {
        assert_eq!(ok(quote_ident("a\"b")), "\"a\"\"b\"");
        assert_eq!(ok(quote_literal("o'k")), "'o''k'");
        assert_eq!(ok(quote_literal("ção\n$$")), "'ção\n$$'");
        assert_eq!(ok(quote_ident("é\n")), "\"é\n\"");
        assert_eq!(ok(quote_ident("a\\b")), "\"a\\b\"");
    }

    #[test]
    fn hostile_input_is_rejected_never_a_panic() {
        assert!(quote_literal("a\\b").is_err());
        assert!(quote_literal("a\0b").is_err());
        assert!(quote_ident("a\0b").is_err());
        assert!(quote_ident("").is_err());
        assert!(lease_name("zz").is_err());
        assert!(lease_name("00112233aabbccd").is_err());
        assert!(name_taken("a\\b").is_err());
        assert!(create_role("postgres", T, "00ff", 1).is_err());
        assert!(create_role(N, "x'y", "00ff", 1).is_err());
        assert!(create_role(N, T, "p\\w", 1).is_err());
        assert!(create_database("postgres").is_err());
        assert!(drop_role("postgres", T).is_err());
        assert!(drop_role(N, "").is_err());
        assert!(owned_databases(N, "t\0").is_err());
        assert!(lease_env("postgres", "00ff", 1, &[]).is_err());
        assert!(lease_env(N, "p@ss", 1, &["DATABASE_URL".into()]).is_err());
        assert!(server_conf(1, &native_abs("a\nb"), 1).is_err());
        assert!(server_conf(1, &native_abs("a\rb"), 1).is_err());
        assert!(server_conf(1, &native_abs("a\0b"), 1).is_err());
        assert!(server_conf(1, Path::new(""), 1).is_err());
        let msg = quote_literal("sekret\\").unwrap_err().to_string();
        assert!(!msg.contains("sekret"));
    }

    #[test]
    fn lease_names_carry_64_random_bits() {
        assert_eq!(ok(lease_name("00112233aabbccdd")), N);
        assert!(is_lease_name(N) && !is_lease_name("fg_l_1a2b3c4d") && !is_lease_name("postgres"));
        assert!(!is_lease_name("fg_l_00112233aabbccdd\n"));
        assert!(!is_lease_name("fg_l_00112233aabbccdé"));
    }

    #[test]
    fn hba_admits_only_sameuser_over_tcp() {
        let h = hba_conf();
        assert_eq!(
            h,
            "local all sync_gate trust\nlocal all all reject\n\
             host  all sync_gate 0.0.0.0/0 reject\nhost  all sync_gate ::/0 reject\n\
             host  sameuser all 127.0.0.1/32 scram-sha-256\n\
             host  all all 0.0.0.0/0 reject\nhost  all all ::/0 reject\n"
        );
        assert!(h.find("host  all sync_gate").unwrap() < h.find("sameuser").unwrap());
        assert!(!h.contains("samerole"));
        let scram: Vec<_> = h
            .lines()
            .filter(|l| l.starts_with("host") && l.contains("scram"))
            .collect();
        assert_eq!(scram, ["host  sameuser all 127.0.0.1/32 scram-sha-256"]);
        assert!(h.lines().rev().take(2).all(|l| l.ends_with("reject")));
    }

    #[test]
    fn server_conf_pins_loopback_privacy_counters_and_quiet_logs() {
        let dir = native_abs("s");
        let c = server_conf(28543, &dir, 40).unwrap();
        for line in [
            "port = 28543",
            "listen_addresses = '127.0.0.1'",
            &dirs_line(&dir),
            "unix_socket_permissions = 0700",
            "max_connections = 40",
            "max_prepared_transactions = 0",
            "shared_buffers = '32MB'",
            "password_encryption = 'scram-sha-256'",
            "fsync = off",
            "synchronous_commit = off",
            "full_page_writes = off",
            "track_counts = on",
            "track_activities = on",
            "log_statement = 'none'",
            "log_min_error_statement = panic",
            "log_connections = off",
            "log_disconnections = off",
        ] {
            assert!(c.lines().any(|l| l == line), "{line}");
        }
        for line in ["timezone = 'UTC'", "log_timezone = 'UTC'"] {
            assert_eq!(c.lines().filter(|l| *l == line).count(), 1, "{line}");
        }
    }

    #[test]
    fn socket_directory_is_one_quoted_list_element() {
        // Each case: the exact line, so a comma or space cannot split the list and an
        // apostrophe or `#` cannot end or comment the value.
        for rest in ["a,b", "a b", "a'b", "a#b", " a ", "a,/tmp"] {
            let p = native_abs(rest);
            let c = ok(server_conf(1, &p, 1));
            assert!(c.lines().any(|l| l == dirs_line(&p)), "{rest}");
            assert_eq!(c.matches("unix_socket_directories").count(), 1);
        }
        // The documentation says nothing about a double quote inside a quoted element:
        // ambiguous, so refused.
        assert!(server_conf(1, &native_abs("a\"b"), 1).is_err());
        // Text fixture of the normalisation (Windows separators), not a path of this platform.
        assert_eq!(ok(socket_dir_value("C:\\x\\s")), "'\"C:/x/s\"'");
        assert_eq!(ok(socket_dir_value("/a,b")), "'\"/a,b\"'");
    }

    #[test]
    fn admin_preamble_silences_the_session_log() {
        for s in [
            "log_min_messages = panic",
            "log_min_error_statement = panic",
            "log_statement = 'none'",
        ] {
            assert!(ADMIN_PREAMBLE.contains(s), "{s}");
        }
        assert_eq!(ADMIN_ROLE, "sync_gate");
        assert_eq!(LEASE_COMMENT, "sync_gate:lease:");
    }

    #[test]
    fn lease_role_cannot_create_databases_roles_or_switch() {
        assert_eq!(
            ok(create_role(N, T, "00ff", 25)),
            "BEGIN; CREATE ROLE \"fg_l_00112233aabbccdd\" LOGIN NOSUPERUSER NOCREATEDB \
             NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 25 PASSWORD '00ff'; \
             COMMENT ON ROLE \"fg_l_00112233aabbccdd\" IS 'sync_gate:lease:a1b2c3d4e5f60718'; COMMIT;"
        );
    }

    #[test]
    fn the_database_is_owned_by_the_lease_and_closed_to_public() {
        assert_eq!(
            ok(create_database(N)),
            "CREATE DATABASE \"fg_l_00112233aabbccdd\" OWNER \"fg_l_00112233aabbccdd\" \
             TEMPLATE \"template0\"; \
             REVOKE ALL ON DATABASE \"fg_l_00112233aabbccdd\" FROM PUBLIC;"
        );
    }

    #[test]
    fn cleanup_matches_name_and_token_never_name_alone() {
        assert_eq!(
            ok(owned_databases(N, T)),
            "SELECT d.datname FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba \
             WHERE r.rolname = 'fg_l_00112233aabbccdd' \
             AND shobj_description(r.oid, 'pg_authid') = 'sync_gate:lease:a1b2c3d4e5f60718';"
        );
        assert_eq!(
            ok(drop_role(N, T)),
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = 'fg_l_00112233aabbccdd' \
             AND shobj_description(r.oid, 'pg_authid') = 'sync_gate:lease:a1b2c3d4e5f60718') \
             THEN EXECUTE 'DROP OWNED BY \"fg_l_00112233aabbccdd\"'; \
             EXECUTE 'DROP ROLE \"fg_l_00112233aabbccdd\"'; END IF; END $$;"
        );
        assert_eq!(
            ok(drop_database(N)),
            "ALTER DATABASE \"fg_l_00112233aabbccdd\" IS_TEMPLATE false; \
             DROP DATABASE IF EXISTS \"fg_l_00112233aabbccdd\" WITH (FORCE);"
        );
    }

    #[test]
    fn session_sample_counts_client_backends_and_total_sessions() {
        assert_eq!(
            ok(db_activity(N)),
            "SELECT (SELECT count(*) FROM pg_stat_activity WHERE datname = 'fg_l_00112233aabbccdd' \
             AND backend_type = 'client backend'), \
             coalesce((SELECT sessions FROM pg_stat_database WHERE datname = 'fg_l_00112233aabbccdd'), -1);"
        );
    }

    #[test]
    fn name_taken_lease_roles_and_identity_text() {
        assert_eq!(
            ok(name_taken("my'db")),
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'my''db') \
             OR EXISTS (SELECT 1 FROM pg_database WHERE datname = 'my''db');"
        );
        assert_eq!(
            lease_roles(),
            "SELECT rolname, substr(shobj_description(oid, 'pg_authid'), 17) FROM pg_roles \
             WHERE shobj_description(oid, 'pg_authid') LIKE 'sync_gate:lease:%';"
        );
        // the token starts right after the 16-character prefix
        assert_eq!(LEASE_COMMENT.len() + 1, 17);
        assert_eq!(
            cluster_identity_sql(),
            "SELECT system_identifier, current_setting('data_directory') FROM pg_control_system();"
        );
    }

    #[test]
    fn identity_guard_names_the_identifier_and_the_error() {
        let g = identity_guard_sql(18446744073709551615);
        assert!(g.contains("'18446744073709551615'"), "{g}");
        assert!(g.contains("not the sync_gate cluster"), "{g}");
        assert!(g.ends_with('\n'));
    }

    #[test]
    fn bootstrap_closes_maintenance_databases() {
        assert_eq!(
            bootstrap_sql(),
            "REVOKE CONNECT ON DATABASE postgres FROM PUBLIC; \
             REVOKE CONNECT ON DATABASE template1 FROM PUBLIC; \
             DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('postgres','template0','template1')) \
             THEN RAISE EXCEPTION 'unexpected role'; END IF; END $$;"
        );
    }

    #[test]
    fn lease_env_contract() {
        let urls = ["DATABASE_URL".into(), "TEST_DATABASE_URL".into()];
        let e = lease_env(N, "00ff", 28543, &urls).unwrap();
        assert_eq!(e["PGHOST"].expose(), "127.0.0.1");
        assert_eq!(e["PGPORT"].expose(), "28543");
        assert_eq!(e["PGDATABASE"].expose(), N);
        assert_eq!(e["PGUSER"].expose(), N);
        assert_eq!(e["PGPASSWORD"].expose(), "00ff");
        assert_eq!(e["PGSSLMODE"].expose(), "disable");
        assert_eq!(
            e["DATABASE_URL"].expose(),
            "postgresql://fg_l_00112233aabbccdd:00ff@127.0.0.1:28543/fg_l_00112233aabbccdd"
        );
        assert_eq!(e["TEST_DATABASE_URL"], e["DATABASE_URL"]);
    }

    const K: &str = "00112233aabbccdd";

    /// Where `needle` starts in `hay`; fails the test when it is missing.
    fn at(hay: &str, needle: &str) -> usize {
        hay.find(needle)
            .unwrap_or_else(|| panic!("missing {needle:?} in {hay}"))
    }

    fn has(sql: &str, clauses: &[&str]) {
        for c in clauses {
            assert!(sql.contains(c), "missing {c:?} in {sql}");
        }
    }

    /// The script starts with the `\connect` to the lease database.
    fn connects_to_lease(sql: &str) {
        assert!(
            sql.starts_with("\\connect \"fg_l_00112233aabbccdd\"\n"),
            "{sql}"
        );
    }

    #[test]
    fn template_names_carry_the_key() {
        assert_eq!(ok(template_db(K)), "fg_t_00112233aabbccdd");
        assert_eq!(ok(template_owner(K)), "fg_o_00112233aabbccdd");
        assert_eq!(OWNER_COMMENT, "sync_gate:owner:");
        assert_eq!(SAFE_PATH, "SET search_path = pg_catalog, pg_temp;\n");
    }

    #[test]
    fn in_database_connects_then_pins_the_path_then_checks_the_database() {
        let s = ok(in_database(N, "SELECT 1;"));
        connects_to_lease(&s);
        let line = at(&s, "\n");
        let (pre, path, check) = (at(&s, ADMIN_PREAMBLE), at(&s, SAFE_PATH), at(&s, "DO $$"));
        assert!(line < pre && pre < path && path < check, "{s}");
        has(
            &s,
            &[
                "IF pg_catalog.current_database() <> 'fg_l_00112233aabbccdd'",
                "RAISE EXCEPTION 'not connected to the expected database'",
            ],
        );
        assert!(
            check < at(&s, "SELECT 1;") && s.ends_with("SELECT 1;"),
            "{s}"
        );
        let t = ok(in_database("fg_t_00112233aabbccdd", ""));
        assert!(
            t.starts_with("\\connect \"fg_t_00112233aabbccdd\"\n"),
            "{t}"
        );
    }

    #[test]
    fn candidate_oids_need_the_mark_and_the_owned_database() {
        let s = ok(candidate_oids(N, T));
        assert!(s.starts_with(SAFE_PATH), "{s}");
        has(
            &s,
            &[
                "SELECT r.oid, d.oid FROM pg_catalog.pg_roles r",
                "JOIN pg_catalog.pg_database d ON d.datdba = r.oid AND d.datname = r.rolname",
                "WHERE r.rolname = 'fg_l_00112233aabbccdd'",
                "pg_catalog.shobj_description(r.oid, 'pg_authid') = 'sync_gate:lease:a1b2c3d4e5f60718'",
            ],
        );
    }

    #[test]
    fn template_names_free_checks_both_names() {
        let s = ok(template_names_free(K));
        assert!(s.starts_with(SAFE_PATH), "{s}");
        has(
            &s,
            &[
                "NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = 'fg_t_00112233aabbccdd')",
                "AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'fg_o_00112233aabbccdd')",
            ],
        );
    }

    #[test]
    fn template_seal_checks_the_mark_resets_settings_then_ends_sessions() {
        let s = ok(template_seal(N, T));
        assert!(s.starts_with(SAFE_PATH), "{s}");
        has(
            &s,
            &[
                "pg_catalog.shobj_description(r.oid, 'pg_authid') = 'sync_gate:lease:a1b2c3d4e5f60718'",
                "EXECUTE 'ALTER ROLE \"fg_l_00112233aabbccdd\" NOLOGIN PASSWORD NULL'",
                "ALTER DATABASE \"fg_l_00112233aabbccdd\" RESET ALL;",
                "SELECT coalesce(bool_and(pg_catalog.pg_terminate_backend(pid, 5000)), true) \
                 FROM pg_catalog.pg_stat_activity \
                 WHERE (usename = 'fg_l_00112233aabbccdd' OR datname = 'fg_l_00112233aabbccdd') \
                 AND pid <> pg_catalog.pg_backend_pid();",
            ],
        );
        let (mark, seal) = (at(&s, "shobj_description"), at(&s, "NOLOGIN"));
        let (reset, term) = (at(&s, "RESET ALL"), at(&s, "pg_terminate_backend"));
        assert!(mark < seal && seal < reset && reset < term, "{s}");
    }

    #[test]
    fn template_check_accepts_only_owner_dependencies_of_the_candidate() {
        let s = ok(template_check(N));
        connects_to_lease(&s);
        has(
            &s,
            &[
                "r.rolname = 'fg_l_00112233aabbccdd'",
                "d.datname = pg_catalog.current_database()",
                "pg_catalog.pg_shdepend",
                "s.dbid = c.db",
                "s.refclassid = 'pg_catalog.pg_authid'::regclass",
                "(s.deptype <> 'o' OR s.refobjid <> c.role)",
                "s.dbid = 0",
                "s.classid = 'pg_catalog.pg_database'::regclass",
                "s.objid = c.db AND s.refobjid <> c.role",
                "pg_catalog.pg_auth_members m",
                "m.roleid = c.role OR m.member = c.role",
                "pg_catalog.aclexplode(d.datacl) e WHERE d.oid = c.db",
                "e.grantee <> c.role AND e.grantee <> 0",
                "AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy)",
                "pg_catalog.aclexplode(a.defaclacl) e WHERE e.grantee <> c.role AND e.grantee <> 0",
            ],
        );
        assert!(at(&s, "not connected") < at(&s, "pg_shdepend"), "{s}");
    }

    #[test]
    fn template_own_hands_the_database_to_the_administrator() {
        let s = ok(template_own(N));
        assert!(s.starts_with(SAFE_PATH), "{s}");
        has(
            &s,
            &[
                "ALTER DATABASE \"fg_l_00112233aabbccdd\" OWNER TO \"sync_gate\";",
                "ALTER DATABASE \"fg_l_00112233aabbccdd\" IS_TEMPLATE false;",
                "ALTER DATABASE \"fg_l_00112233aabbccdd\" ALLOW_CONNECTIONS false;",
                "REVOKE ALL ON DATABASE \"fg_l_00112233aabbccdd\" FROM PUBLIC;",
            ],
        );
    }

    #[test]
    fn template_rename_role_checks_the_mark_in_the_same_transaction() {
        let s = ok(template_rename_role(N, T, K));
        assert!(s.starts_with(SAFE_PATH), "{s}");
        has(
            &s,
            &[
                "pg_catalog.shobj_description(r.oid, 'pg_authid') = 'sync_gate:lease:a1b2c3d4e5f60718'",
                "RAISE EXCEPTION",
                "ALTER ROLE \"fg_l_00112233aabbccdd\" RENAME TO \"fg_o_00112233aabbccdd\";",
                "COMMENT ON ROLE \"fg_o_00112233aabbccdd\" IS 'sync_gate:owner:00112233aabbccdd';",
            ],
        );
        let (begin, mark, rename) = (
            at(&s, "BEGIN;"),
            at(&s, "shobj_description"),
            at(&s, "RENAME"),
        );
        let (comment, commit) = (at(&s, "COMMENT ON"), at(&s, "COMMIT;"));
        assert!(
            begin < mark && mark < rename && rename < comment && comment < commit,
            "{s}"
        );
    }

    #[test]
    fn template_rename_db_names_the_template() {
        assert_eq!(
            ok(template_rename_db(N, K)),
            format!(
                "{SAFE_PATH}ALTER DATABASE \"fg_l_00112233aabbccdd\" RENAME TO \"fg_t_00112233aabbccdd\";"
            )
        );
    }

    #[test]
    fn template_state_checks_both_oids_names_owner_flags_and_mark() {
        let s = ok(template_state(K, 16384, 16385));
        assert!(s.starts_with(SAFE_PATH), "{s}");
        has(
            &s,
            &[
                "d.oid = '16384'::pg_catalog.oid",
                "d.datname = 'fg_t_00112233aabbccdd'",
                "pg_catalog.pg_get_userbyid(d.datdba) = 'sync_gate'",
                "NOT d.datallowconn AND NOT d.datistemplate",
                "r.oid = '16385'::pg_catalog.oid",
                "r.rolname = 'fg_o_00112233aabbccdd'",
                "NOT r.rolcanlogin",
                "pg_catalog.shobj_description(r.oid, 'pg_authid') = 'sync_gate:owner:00112233aabbccdd'",
            ],
        );
    }

    #[test]
    fn db_by_oid_needs_the_oid_a_known_name_and_a_known_owner() {
        let s = ok(db_by_oid(16384, 16385, N, K));
        assert!(s.starts_with(SAFE_PATH), "{s}");
        has(
            &s,
            &[
                "SELECT d.datname FROM pg_catalog.pg_database d WHERE d.oid = '16384'::pg_catalog.oid",
                "d.datname IN ('fg_l_00112233aabbccdd', 'fg_t_00112233aabbccdd')",
                "(d.datdba = '16385'::pg_catalog.oid OR pg_catalog.pg_get_userbyid(d.datdba) = 'sync_gate')",
            ],
        );
    }

    #[test]
    fn drop_template_role_acts_only_on_a_proven_identity() {
        let s = ok(drop_template_role(16385, N, T, K));
        assert!(s.starts_with(SAFE_PATH), "{s}");
        has(
            &s,
            &[
                "r.oid = '16385'::pg_catalog.oid AND r.rolname = 'fg_l_00112233aabbccdd' \
                 AND pg_catalog.shobj_description(r.oid, 'pg_authid') = 'sync_gate:lease:a1b2c3d4e5f60718'",
                "THEN EXECUTE 'DROP OWNED BY \"fg_l_00112233aabbccdd\"'; \
                 EXECUTE 'DROP ROLE \"fg_l_00112233aabbccdd\"';",
                "r.oid = '16385'::pg_catalog.oid AND r.rolname = 'fg_o_00112233aabbccdd' \
                 AND pg_catalog.shobj_description(r.oid, 'pg_authid') = 'sync_gate:owner:00112233aabbccdd'",
                "THEN EXECUTE 'DROP OWNED BY \"fg_o_00112233aabbccdd\"'; \
                 EXECUTE 'DROP ROLE \"fg_o_00112233aabbccdd\"';",
            ],
        );
    }

    #[test]
    fn create_database_from_copies_the_template_closed_to_public() {
        assert_eq!(
            ok(create_database_from(N, K)),
            format!(
                "{SAFE_PATH}CREATE DATABASE \"fg_l_00112233aabbccdd\" OWNER \"fg_l_00112233aabbccdd\" \
                 TEMPLATE \"fg_t_00112233aabbccdd\";\n\
                 REVOKE ALL ON DATABASE \"fg_l_00112233aabbccdd\" FROM PUBLIC;"
            )
        );
    }

    #[test]
    fn clone_adopt_reassigns_then_recreates_default_privileges_then_drops() {
        let s = ok(clone_adopt(N, K));
        connects_to_lease(&s);
        has(
            &s,
            &[
                "REASSIGN OWNED BY \"fg_o_00112233aabbccdd\" TO \"fg_l_00112233aabbccdd\";",
                "FROM pg_catalog.pg_default_acl a",
                "r.rolname = 'fg_o_00112233aabbccdd'",
                "pg_catalog.aclexplode(d.acl)",
                "WHEN 'r' THEN 'TABLES'",
                "WHEN 'S' THEN 'SEQUENCES'",
                "WHEN 'f' THEN 'FUNCTIONS'",
                "WHEN 'T' THEN 'TYPES'",
                "WHEN 'n' THEN 'SCHEMAS'",
                "IF d.ns = 0 THEN",
                "'ALTER DEFAULT PRIVILEGES FOR ROLE \"fg_l_00112233aabbccdd\"'",
                "' REVOKE ALL ON ' || kind || ' FROM PUBLIC'",
                "' REVOKE ALL ON ' || kind || ' FROM ' || '\"fg_l_00112233aabbccdd\"'",
                "' IN SCHEMA ' || pg_catalog.quote_ident(",
                "WHEN 0 THEN 'PUBLIC' WHEN d.owner THEN '\"fg_l_00112233aabbccdd\"'",
                "' WITH GRANT OPTION'",
                "DROP OWNED BY \"fg_o_00112233aabbccdd\";",
            ],
        );
        assert_eq!(s.matches("RAISE EXCEPTION").count(), 3, "{s}");
        let (re, adp, drop) = (
            at(&s, "REASSIGN"),
            at(&s, "ALTER DEFAULT PRIVILEGES"),
            at(&s, "DROP OWNED"),
        );
        assert!(
            at(&s, "not connected") < re && re < adp && adp < drop,
            "{s}"
        );
    }

    #[test]
    fn create_extensions_runs_as_the_lease_in_public() {
        let exts = ["pg_trgm".to_string(), "uuid-ossp".to_string()];
        let s = ok(create_extensions(N, &exts));
        connects_to_lease(&s);
        has(
            &s,
            &[
                "SET ROLE \"fg_l_00112233aabbccdd\"; ",
                "CREATE EXTENSION IF NOT EXISTS \"pg_trgm\" SCHEMA public; ",
                "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\" SCHEMA public; ",
            ],
        );
        let (check, role) = (at(&s, "not connected"), at(&s, "SET ROLE"));
        let (a, b) = (at(&s, "\"pg_trgm\""), at(&s, "\"uuid-ossp\""));
        assert!(check < role && role < a && a < b, "{s}");
        assert!(s.ends_with("RESET ROLE;"), "{s}");
        assert_eq!(s.matches("SET ROLE").count(), 2, "{s}");
        let too_long = "a".repeat(64);
        for bad in [
            "", "PG_TRGM", "1x", "a\"b", "a;b", "pg trgm", "\u{e9}", &too_long,
        ] {
            assert!(create_extensions(N, &[bad.to_string()]).is_err(), "{bad}");
            let mixed = [exts[0].clone(), bad.to_string()];
            assert!(create_extensions(N, &mixed).is_err(), "{bad}");
        }
        for name in ["postgres", "fg_t_00112233aabbccdd", "fg_o_00112233aabbccdd"] {
            assert!(create_extensions(name, &exts).is_err(), "{name}");
        }
    }

    #[test]
    fn missing_extensions_only_reads_the_catalogue() {
        let exts = ["pg_trgm".to_string(), "uuid-ossp".to_string()];
        let s = ok(missing_extensions(N, &exts));
        connects_to_lease(&s);
        has(
            &s,
            &[
                "ARRAY['pg_trgm', 'uuid-ossp']::pg_catalog.name[]",
                "FROM pg_catalog.unnest(",
                "NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension e WHERE e.extname = x.n)",
            ],
        );
        assert!(at(&s, "not connected") < at(&s, "pg_catalog.unnest"), "{s}");
        for never in ["CREATE", "SET ROLE", "public"] {
            assert!(!s.contains(never), "{never} in {s}");
        }
        let too_long = "a".repeat(64);
        for bad in ["", "PG_TRGM", "a'b", "a\"b", "a;b", "\u{e9}", &too_long] {
            let mixed = [exts[0].clone(), bad.to_string()];
            assert!(missing_extensions(N, &mixed).is_err(), "{bad}");
        }
        for name in ["postgres", "fg_t_00112233aabbccdd", "fg_o_00112233aabbccdd"] {
            assert!(missing_extensions(name, &exts).is_err(), "{name}");
        }
    }

    #[test]
    fn builders_refuse_bad_names() {
        const UPPER: &str = "00112233AABBCCDD";
        const SHORT: &str = "00112233aabbccd";
        const TPL: &str = "fg_t_00112233aabbccdd";
        for key in [UPPER, SHORT, "", "00112233aabbccdd0"] {
            assert!(template_db(key).is_err(), "{key}");
            assert!(template_owner(key).is_err(), "{key}");
            assert!(template_names_free(key).is_err(), "{key}");
            assert!(template_rename_role(N, T, key).is_err(), "{key}");
            assert!(template_rename_db(N, key).is_err(), "{key}");
            assert!(template_state(key, 1, 2).is_err(), "{key}");
            assert!(db_by_oid(1, 2, N, key).is_err(), "{key}");
            assert!(drop_template_role(2, N, T, key).is_err(), "{key}");
            assert!(create_database_from(N, key).is_err(), "{key}");
            assert!(clone_adopt(N, key).is_err(), "{key}");
            assert!(in_database(&format!("fg_t_{key}"), "").is_err(), "{key}");
        }
        for name in ["postgres", TPL, "fg_o_00112233aabbccdd"] {
            assert!(candidate_oids(name, T).is_err(), "{name}");
            assert!(template_seal(name, T).is_err(), "{name}");
            assert!(template_check(name).is_err(), "{name}");
            assert!(template_own(name).is_err(), "{name}");
            assert!(template_rename_role(name, T, K).is_err(), "{name}");
            assert!(template_rename_db(name, K).is_err(), "{name}");
            assert!(db_by_oid(1, 2, name, K).is_err(), "{name}");
            assert!(drop_template_role(2, name, T, K).is_err(), "{name}");
            assert!(create_database_from(name, K).is_err(), "{name}");
            assert!(clone_adopt(name, K).is_err(), "{name}");
        }
        assert!(in_database("postgres", "").is_err());
        assert!(in_database("fg_o_00112233aabbccdd", "").is_err());
        for bad in ["", "x'y"] {
            assert!(candidate_oids(N, bad).is_err());
            assert!(template_seal(N, bad).is_err());
            assert!(template_rename_role(N, bad, K).is_err());
            assert!(drop_template_role(2, N, bad, K).is_err());
        }
        assert!(template_state(K, 0, 2).is_err());
        assert!(template_state(K, 1, 0).is_err());
        assert!(db_by_oid(0, 2, N, K).is_err());
        assert!(db_by_oid(1, 0, N, K).is_err());
        assert!(drop_template_role(0, N, T, K).is_err());
    }

    #[test]
    fn a_template_name_is_never_a_lease_name() {
        assert!(!is_lease_name(&ok(template_db(K))));
        assert!(!is_lease_name(&ok(template_owner(K))));
    }

    #[test]
    fn redact_replaces_every_occurrence() {
        assert_eq!(redact("x pw y pw", &["pw"]), "x *** y ***");
        assert_eq!(redact("pwpw!pw", &["pw"]), "******!***");
    }

    #[test]
    fn redact_handles_empty_nested_and_overlapping_secrets() {
        assert_eq!(redact("hello", &[""]), "hello");
        assert_eq!(redact("a abc b", &["ab", "abc"]), "a *** b");
        assert_eq!(redact("a abc b", &["abc", "ab"]), "a *** b");
        assert_eq!(redact("abcd", &["abc", "bcd"]), "***");
        assert_eq!(redact("aaa", &["aa"]), "***");
        assert_eq!(redact("é-pw-ç", &["pw"]), "é-***-ç");
        assert_eq!(redact("a*b", &["*"]), "a***b");
    }
}
