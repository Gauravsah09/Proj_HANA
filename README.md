# Proj_HANA

Automation tooling for SAP HANA operations.

This repository currently ships one tool: **`hana_mdc_recovery.py`**, a
single-file Python utility that drives end-to-end recovery of a SAP HANA
**Multitenant Database Container (MDC)** system after the storage team has
restored `/hana/data/<SID>` (and optionally `/hana/log/<SID>`).

---

## Table of contents

1. [What this code does](#what-this-code-does)
2. [When to use it](#when-to-use-it)
3. [Hard safety invariants](#hard-safety-invariants)
4. [Requirements](#requirements)
5. [Inputs you will be asked for](#inputs-you-will-be-asked-for)
6. [Recovery modes](#recovery-modes)
7. [Phases (state machine)](#phases-state-machine)
8. [How to run it](#how-to-run-it)
9. [Dry run](#dry-run)
10. [Resuming after failure](#resuming-after-failure)
11. [Files written](#files-written)
12. [Security model](#security-model)
13. [Troubleshooting](#troubleshooting)
14. [Limitations](#limitations)
15. [Repository layout](#repository-layout)

---

## What this code does

`hana_mdc_recovery.py` performs the post-storage-restore steps that a HANA
DBA would otherwise run by hand:

1. Pre-flight checks of the host, paths, ownership, free space, and
   required HANA binaries (`HDB`, `hdbsql`, `hdbuserstore`, `sapcontrol`,
   `recoverSys.py`, `recoverTenant.py`).
2. Stops HANA cleanly if it is still running.
3. Recovers **SYSTEMDB** by invoking `recoverSys.py` with a SQL command
   built from the chosen recovery mode (snapshot / most-recent /
   point-in-time / file-based).
4. Recovers each **tenant** sequentially via `recoverTenant.py`.
5. Starts the full system and waits for all services to be GREEN.
6. Resets the `SYSTEM` user password on **SYSTEMDB and every tenant**,
   handling the locked / deactivated case automatically.
7. Verifies databases (`M_DATABASES`), services (`M_SERVICES`), and that
   each new password actually logs in.
8. Writes a timestamped log and prints a summary table.

The script is **interactive by design** — every destructive step is
gated behind a typed confirmation.

## When to use it

Use it on a single-host MDC HANA system after:

- Storage has restored `/hana/data/<SID>` from backup or snapshot, **and**
- You need to bring SYSTEMDB + tenants back online and rotate the
  `SYSTEM` passwords as part of the same operation.

Do **not** use it for:

- HANA scale-out clusters (this script targets single-host MDC).
- System Replication failover (separate procedure).
- Recovering a single tenant in isolation while SYSTEMDB is healthy
  (use `recoverTenant.py` directly).

## Hard safety invariants

The script is built around one rule:

> **It NEVER deletes any HANA artifact.**

Concretely:

- No `rm`, `shutil.rmtree`, `os.remove`, or `unlink` is invoked against
  any path under `/hana/data`, `/hana/log`, `/hana/shared`, `/usr/sap`,
  or `/hana/backup`. A defense-in-depth check
  (`assert_not_protected_for_delete`) refuses any deletion target whose
  realpath falls under those prefixes.
- The **only** deletion the script ever performs is removing temporary
  `hdbuserstore` keys it created itself. Those keys are prefix-guarded
  with `RECOV_TMP_<pid>_` and removed only after a typed `YES`
  confirmation.
- `subprocess` is always called with `shell=False` and a list `argv`.
  No string interpolation reaches a shell unvalidated.
- Passwords are read with `getpass`, compared with
  `hmac.compare_digest`, and handed to `hdbuserstore` via stdin
  (`hdbuserstore -i`). They are never on `argv`, never echoed, never
  logged.
- The log file is created with `umask 0o077` → mode `0600`.

## Requirements

- Linux host running SAP HANA (single-host MDC).
- **Python 3.9+**, standard library only — no `pip install` needed.
- Run as `root` (`os.geteuid() == 0` is enforced).
- The HANA `<sid>adm` user must exist and have a working environment
  (`$DIR_INSTANCE`, HANA binaries on PATH).
- `/hana/data/<SID>` must exist (mandatory) and be owned by `<sid>adm`.
- `/hana/log/<SID>` should exist; if missing, the script warns and
  continues (mode A / D may not need it).
- For mode D: backup file and catalog paths reachable by `<sid>adm`.

## Inputs you will be asked for

Collected interactively up front, then echoed for confirmation:

| Input                                | Validation                                   |
| ------------------------------------ | -------------------------------------------- |
| SID                                  | `^[A-Z][A-Z0-9]{2}$`                         |
| Instance number                      | `^\d{2}$` (00–99)                            |
| Tenant DB names                      | comma-separated, each `^[A-Z][A-Z0-9_]{0,15}$` |
| Recovery mode                        | `A` / `B` / `C` / `D`                        |
| PITR timestamp (mode C)              | `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`      |
| Backup file path (mode D)            | `^/[A-Za-z0-9_./\-]+$`                       |
| Backup catalog path (mode D)         | same                                         |
| Current SYSTEMDB `SYSTEM` password   | `getpass`                                    |
| New SYSTEMDB `SYSTEM` password       | entered twice, constant-time compared        |
| New `SYSTEM` password per tenant     | entered twice each                           |
| Final typed-SID confirmation         | must match the SID exactly                   |

## Recovery modes

| Mode | Meaning                | Generated SQL                                                  |
| ---- | ---------------------- | -------------------------------------------------------------- |
| A    | Snapshot / data-only   | `RECOVER DATA FOR <target> USING SNAPSHOT CLEAR LOG`           |
| B    | Most recent state      | `RECOVER <target> UNTIL TIMESTAMP '<now>' CHECK ACCESS USING FILE` |
| C    | Point-in-time (PITR)   | `RECOVER <target> UNTIL TIMESTAMP '<your-ts>' CHECK ACCESS USING FILE` |
| D    | File-based backup      | `RECOVER DATA FOR <target> USING FILE ('<path>') CLEAR LOG`    |

`<target>` is `SYSTEMDB` for the system DB and `DATABASE <name>` for
each tenant. The PITR timestamp must use **24-hour server-local time**;
the script prints the server timezone (`date +%Z`) above the prompt so
there is no ambiguity. Example: `2026-04-18 14:37:05`.

## Phases (state machine)

The script runs eight phases. Each one writes a JSON checkpoint after
it completes; on a re-run the script skips phases already marked done.

| # | Phase              | What it does                                                                |
| - | ------------------ | --------------------------------------------------------------------------- |
| 1 | `preflight`        | uid/path/ownership/disk/binary checks                                       |
| 2 | `stop_hana`        | `HDB stop` after typed `YES`; skips if already down                         |
| 3 | `recover_systemdb` | `python recoverSys.py --command="<SQL>"` then waits for `hdbnameserver` GREEN |
| 4 | `recover_tenants`  | `python recoverTenant.py <T> --command="<SQL>"` per tenant, sequential      |
| 5 | `start_system`     | `HDB start` then waits for all services GREEN                               |
| 6 | `reset_passwords`  | `ALTER USER SYSTEM PASSWORD …` on SYSTEMDB; `ALTER DATABASE <T> SYSTEM USER PASSWORD …` for each tenant |
| 7 | `verify`           | queries `M_DATABASES`, login-tests new tenant passwords                     |
| 8 | `report`           | writes summary to log + stdout                                              |

Each destructive step is gated behind a confirmation:

- Typed **`YES`** for: stop HANA, reset SYSTEM password (each DB), and
  any temporary key cleanup.
- Typed **SID** before SYSTEMDB recovery.
- Typed **tenant name** before each tenant recovery.

## How to run it

```bash
sudo python3 hana_mdc_recovery.py
```

You will be walked through input collection, the mode menu, and the
confirmation ladder. Optional flags:

```
--dry-run          walk through the plan and print SQL; execute nothing
                   destructive
--sid <SID>        pre-fill SID (still validated)
--instance <NN>    pre-fill instance number
--log-dir <dir>    directory for the log file (default /var/tmp)
```

## Dry run

```bash
sudo python3 hana_mdc_recovery.py --dry-run --sid HDB --instance 00
```

In dry-run mode the script:

- still requires root (so the preflight environment is real),
- still asks for all inputs (so you can review the prompts),
- prints the SQL it *would* run for SYSTEMDB and each tenant,
- does **not** stop HANA, does **not** call `recoverSys.py` /
  `recoverTenant.py`, does **not** start HANA, does **not** create
  userstore keys, does **not** change passwords.

## Resuming after failure

If a phase fails mid-recovery, fix the underlying issue and simply
re-run the script with the same SID. It loads
`/var/tmp/hana_recovery_<SID>.state` (mode `0600`, JSON), sees the
phases already completed, and resumes from the next one.

To force a clean run, remove the state file manually before starting.

## Files written

- `/var/tmp/hana_recovery_<SID>_<YYYYMMDD_HHMMSS>.log` — rotating log
  file, mode `0600`. Contains every command (passwords redacted), every
  phase result, and stack traces on failure.
- `/var/tmp/hana_recovery_<SID>.state` — JSON checkpoint, mode `0600`.

The script does not write anywhere else.

## Security model

| Concern                       | How the script handles it                                                       |
| ----------------------------- | ------------------------------------------------------------------------------- |
| Passwords on the command line | Forbidden. Always `getpass` + `hdbuserstore -i` (stdin).                        |
| Passwords in logs             | Forbidden. Commands that carry secrets are logged as `<redacted>`.              |
| Shell injection               | No `shell=True`. Every input is regex-validated before it reaches a subprocess. |
| Privilege                     | Root required; HANA commands run via `su - <sid>adm -c …`.                      |
| Accidental destruction        | Hard-coded refusal to delete anything under HANA paths.                         |
| Signal interruption           | `SIGINT` / `SIGTERM` and `atexit` trigger cleanup of *only* `RECOV_TMP_<pid>_*` keys, with prompt. |

## Troubleshooting

- **"must run as root (uid 0)"** — re-run with `sudo`.
- **"missing /hana/data/<SID>"** — storage restore is incomplete.
- **`hdbnameserver` never goes GREEN** — check
  `/usr/sap/<SID>/HDB<inst>/<host>/trace/nameserver_*.trc`. The script
  times out after 30 minutes.
- **SYSTEM is locked** — the password-reset phase auto-detects "locked"
  / "deactivated" in the error and runs `ALTER USER SYSTEM ACTIVATE
  USER NOW` before retrying.
- **Tenant SQL port not discovered** — the script queries
  `SYS_DATABASES.M_SERVICES` from SYSTEMDB after start. If a tenant is
  not yet up, restart it manually and re-run.
- **Re-run does the same thing twice** — check that
  `/var/tmp/hana_recovery_<SID>.state` exists; if it was deleted, the
  script restarts from `preflight`.

## Limitations

- Single-host MDC only. Scale-out is not supported.
- Tenants are recovered sequentially (by design: HANA does not support
  parallel `recoverTenant.py` against the same SYSTEMDB).
- Tenant `SYSTEM` password reset is performed via SYSTEMDB
  cross-database `ALTER DATABASE … SYSTEM USER PASSWORD`, which
  requires SYSTEMDB `SYSTEM` to have the `DATABASE ADMIN` privilege
  (default on a freshly-recovered system).
- The script does **not** take a backup before recovery, does **not**
  modify `global.ini`, and does **not** touch System Replication
  configuration.

## Repository layout

```
.
├── README.md                # this file
├── .gitignore
└── hana_mdc_recovery.py     # the recovery tool (stdlib only, single file)
```
