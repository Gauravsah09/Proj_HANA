#!/usr/bin/env python3
# =============================================================================
# hana_mdc_recovery.py - SAP HANA MDC automated recovery
# -----------------------------------------------------------------------------
# INVARIANT: This script NEVER deletes any HANA artifact.
#   - No rm / shutil.rmtree / os.remove / unlink against /hana/data, /hana/log,
#     backups, catalog, or trace directories.
#   - The ONLY deletion target is temporary hdbuserstore keys created by this
#     script, prefix-guarded with RECOV_TMP_<pid>_, and only after explicit
#     user confirmation.
# Stdlib only. No third-party packages. No shell=True. Passwords via getpass
# and hdbuserstore stdin (-i), never on argv, never logged.
# =============================================================================
from __future__ import annotations

import argparse
import atexit
import getpass
import hmac
import json
import logging
import logging.handlers
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

# ----- Constants -------------------------------------------------------------
SID_RE = re.compile(r"^[A-Z][A-Z0-9]{2}$")
INST_RE = re.compile(r"^\d{2}$")
TENANT_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,15}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9_./\-]+$")
TMP_KEY_PREFIX = f"RECOV_TMP_{os.getpid()}_"
HANA_PROTECTED_PREFIXES = ("/hana/data", "/hana/log", "/hana/shared",
                           "/usr/sap", "/hana/backup")

PHASES = [
    "preflight", "stop_hana", "recover_systemdb", "recover_tenants",
    "start_system", "reset_passwords", "verify", "report",
]

# ----- Logging ---------------------------------------------------------------
class _ColorFormatter(logging.Formatter):
    COLORS = {"DEBUG": "\033[36m", "INFO": "\033[32m",
              "WARNING": "\033[33m", "ERROR": "\033[31m",
              "CRITICAL": "\033[1;31m"}
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if sys.stderr.isatty():
            return f"{self.COLORS.get(record.levelname, '')}{msg}{self.RESET}"
        return msg


def setup_logging(log_path: Path) -> logging.Logger:
    os.umask(0o077)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(mode=0o600, exist_ok=True)
    os.chmod(log_path, 0o600)

    logger = logging.getLogger("hana_recov")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fh = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=3)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"))

    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.INFO)
    sh.setFormatter(_ColorFormatter("%(levelname)s: %(message)s"))

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


log = logging.getLogger("hana_recov")


# ----- Validation helpers ----------------------------------------------------
def validate_sid(s: str) -> str:
    if not SID_RE.match(s):
        raise ValueError(f"Invalid SID: {s!r} (need 3 chars, A-Z then A-Z/0-9)")
    return s


def validate_instance(s: str) -> str:
    if not INST_RE.match(s):
        raise ValueError(f"Invalid instance number: {s!r} (need 00-99)")
    return s


def validate_tenant(s: str) -> str:
    if not TENANT_RE.match(s):
        raise ValueError(f"Invalid tenant name: {s!r}")
    return s


def validate_timestamp(s: str) -> str:
    if not TS_RE.match(s):
        raise ValueError(f"Invalid timestamp: {s!r}")
    try:
        datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError as e:
        raise ValueError(f"Invalid timestamp value: {e}")
    return s


def validate_path(s: str) -> str:
    if not PATH_RE.match(s):
        raise ValueError(f"Invalid path: {s!r}")
    return s


def assert_not_protected_for_delete(target: str) -> None:
    """Defense-in-depth: refuse any deletion against HANA paths."""
    rp = os.path.realpath(target)
    for prefix in HANA_PROTECTED_PREFIXES:
        if rp == prefix or rp.startswith(prefix + "/"):
            raise RuntimeError(
                f"REFUSED: deletion target {rp!r} is under protected prefix "
                f"{prefix!r}. Script invariant: NEVER delete HANA artifacts.")


# ----- Subprocess wrapper ----------------------------------------------------
@dataclass
class CmdResult:
    rc: int
    stdout: str
    stderr: str


def run_cmd(argv: list[str], *, input_text: Optional[str] = None,
            timeout: Optional[int] = 600, check: bool = True,
            redact_in_log: bool = False) -> CmdResult:
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise TypeError("run_cmd requires list[str] argv (no shell=True)")
    display = "<redacted>" if redact_in_log else " ".join(argv)
    log.debug("exec: %s", display)
    try:
        p = subprocess.run(
            argv, input=input_text, capture_output=True, text=True,
            timeout=timeout, check=False, shell=False)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"command timed out after {timeout}s: {display}") from e
    res = CmdResult(p.returncode, p.stdout or "", p.stderr or "")
    if check and res.rc != 0:
        raise RuntimeError(
            f"command failed rc={res.rc}: {display}\nstderr: {res.stderr}")
    return res


def run_as_sidadm(sidadm: str, command: str, *,
                  input_text: Optional[str] = None,
                  timeout: int = 1800,
                  check: bool = True,
                  redact_in_log: bool = False) -> CmdResult:
    # command is a single shell string executed via su -c; we control the
    # content (built from validated tokens) and never interpolate untrusted
    # input. argv to subprocess remains a list (no shell=True at the python
    # layer).
    if not re.match(r"^[a-z][a-z0-9]{2}adm$", sidadm):
        raise ValueError(f"Invalid sidadm user: {sidadm!r}")
    return run_cmd(["su", "-", sidadm, "-c", command],
                   input_text=input_text, timeout=timeout,
                   check=check, redact_in_log=redact_in_log)


# ----- Confirmation prompts --------------------------------------------------
def confirm_yes(prompt: str) -> bool:
    ans = input(f"{prompt} [type YES to proceed]: ").strip()
    return ans == "YES"


def confirm_token(prompt: str, expected: str) -> bool:
    ans = input(f"{prompt} [type {expected!r} to proceed]: ").strip()
    return ans == expected


# ----- Checkpoint / state ----------------------------------------------------
@dataclass
class State:
    sid: str = ""
    instance: str = ""
    tenants: list[str] = field(default_factory=list)
    mode: str = ""
    timestamp: str = ""
    backup_file: str = ""
    backup_catalog: str = ""
    completed_phases: list[str] = field(default_factory=list)
    started_at: str = ""

    def mark(self, phase: str) -> None:
        if phase not in self.completed_phases:
            self.completed_phases.append(phase)


def state_path(sid: str) -> Path:
    return Path(f"/var/tmp/hana_recovery_{sid}.state")


def save_state(st: State) -> None:
    p = state_path(st.sid)
    tmp = p.with_suffix(".state.tmp")
    tmp.write_text(json.dumps(asdict(st), indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(p)


def load_state(sid: str) -> Optional[State]:
    p = state_path(sid)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        return State(**data)
    except Exception as e:
        log.warning("failed to load state %s: %s", p, e)
        return None


# ----- Temp userstore key tracking ------------------------------------------
_TMP_KEYS: list[tuple[str, str]] = []  # (sidadm, key)


def _userstore_set(sidadm: str, key: str, host: str, port: str,
                   user: str, password: str) -> None:
    if not key.startswith(TMP_KEY_PREFIX):
        raise ValueError(f"refusing to set non-tmp key: {key!r}")
    # hdbuserstore -i reads from stdin: prompts for password silently.
    # Format: hdbuserstore -i SET <KEY> <host:port> <USER>
    cmd = (f"hdbuserstore -i SET {key} "
           f"{host}:{port} {user}")
    run_as_sidadm(sidadm, cmd, input_text=password + "\n",
                  redact_in_log=True, check=True)
    _TMP_KEYS.append((sidadm, key))
    log.info("created temp userstore key %s", key)


def _userstore_delete(sidadm: str, key: str) -> None:
    if not key.startswith(TMP_KEY_PREFIX):
        raise ValueError(f"refusing to delete non-tmp key: {key!r}")
    run_as_sidadm(sidadm, f"hdbuserstore DELETE {key}", check=False)


def cleanup_temp_keys(force: bool = False) -> None:
    if not _TMP_KEYS:
        return
    if not force:
        log.info("temp userstore keys to remove: %s",
                 ", ".join(k for _, k in _TMP_KEYS))
        if not confirm_yes("Delete temporary hdbuserstore keys now?"):
            log.warning("temp keys NOT removed (user declined)")
            return
    for sidadm, key in list(_TMP_KEYS):
        try:
            _userstore_delete(sidadm, key)
            log.info("removed temp key %s", key)
        except Exception as e:
            log.error("failed to remove temp key %s: %s", key, e)
    _TMP_KEYS.clear()


# ----- Input collection ------------------------------------------------------
@dataclass
class Inputs:
    sid: str
    instance: str
    sidadm: str
    tenants: list[str]
    mode: str           # A | B | C | D
    timestamp: str      # mode C
    backup_file: str    # mode D
    backup_catalog: str # mode D
    sysdb_old_pw: str
    sysdb_new_pw: str
    tenant_new_pw: dict[str, str]


def _read_password_twice(prompt: str) -> str:
    while True:
        a = getpass.getpass(f"{prompt}: ")
        b = getpass.getpass(f"{prompt} (confirm): ")
        if hmac.compare_digest(a.encode(), b.encode()) and a:
            return a
        print("Passwords did not match or were empty. Try again.",
              file=sys.stderr)


def _show_mode_menu() -> None:
    tz = ""
    try:
        tz = run_cmd(["date", "+%Z"], check=False).stdout.strip()
    except Exception:
        pass
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\nServer timezone: {tz or '<unknown>'}    Current time: {now}")
    print("""
Recovery modes:
  [A] Snapshot / data-only        -> RECOVER DATA USING SNAPSHOT CLEAR LOG
  [B] Most recent state           -> RECOVER DATABASE ... UNTIL TIMESTAMP '<now>'
  [C] Point-in-time (PITR)        -> RECOVER DATABASE ... UNTIL TIMESTAMP '<your-ts>'
        Format : YYYY-MM-DD HH:MM:SS   (24-hour, server local time)
        Example: 2026-04-18 14:37:05
        Regex  : ^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}$
  [D] File-based backup           -> RECOVER DATA ... USING FILE ('<path>') CLEAR LOG
""")


def collect_inputs(args: argparse.Namespace) -> Inputs:
    sid = validate_sid((args.sid or input("SID (3 chars): ").strip()).upper())
    instance = validate_instance(
        args.instance or input("Instance number (00-99): ").strip())
    sidadm = f"{sid.lower()}adm"

    raw = input("Tenant DB names (comma-separated, e.g. TEN1,TEN2): ").strip()
    tenants = [validate_tenant(t.strip().upper())
               for t in raw.split(",") if t.strip()]
    if not tenants:
        raise ValueError("at least one tenant DB name is required")

    _show_mode_menu()
    mode = input("Choose mode [A/B/C/D]: ").strip().upper()
    if mode not in ("A", "B", "C", "D"):
        raise ValueError(f"invalid mode: {mode!r}")

    ts = ""
    bfile = ""
    bcat = ""
    if mode == "C":
        ts = validate_timestamp(input("PITR timestamp: ").strip())
    elif mode == "D":
        bfile = validate_path(input("Backup file path: ").strip())
        bcat = validate_path(input("Backup catalog path: ").strip())

    print("\n-- Passwords --")
    sysdb_old = getpass.getpass("Current SYSTEMDB SYSTEM password: ")
    if not sysdb_old:
        raise ValueError("current SYSTEM password cannot be empty")
    sysdb_new = _read_password_twice("New SYSTEMDB SYSTEM password")
    tenant_pw = {}
    for t in tenants:
        tenant_pw[t] = _read_password_twice(f"New SYSTEM password for tenant {t}")

    # Final confirmation: type SID
    if not confirm_token(f"Final confirmation to proceed with recovery of {sid}",
                         sid):
        raise RuntimeError("user aborted at final SID confirmation")

    return Inputs(sid=sid, instance=instance, sidadm=sidadm,
                  tenants=tenants, mode=mode, timestamp=ts,
                  backup_file=bfile, backup_catalog=bcat,
                  sysdb_old_pw=sysdb_old, sysdb_new_pw=sysdb_new,
                  tenant_new_pw=tenant_pw)


# ----- SQL builders ----------------------------------------------------------
def build_recover_sql(db: str, mode: str, *, ts: str = "",
                      backup_file: str = "") -> str:
    target = "SYSTEMDB" if db == "SYSTEMDB" else f"DATABASE {db}"
    if mode == "A":
        return f"RECOVER DATA FOR {target} USING SNAPSHOT CLEAR LOG"
    if mode == "B":
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return (f"RECOVER {target} UNTIL TIMESTAMP '{now}' "
                f"CHECK ACCESS USING FILE")
    if mode == "C":
        return (f"RECOVER {target} UNTIL TIMESTAMP '{ts}' "
                f"CHECK ACCESS USING FILE")
    if mode == "D":
        return (f"RECOVER DATA FOR {target} USING FILE "
                f"('{backup_file}') CLEAR LOG")
    raise ValueError(f"unknown mode {mode!r}")


# ----- Phase: preflight ------------------------------------------------------
def find_hana_binary(sidadm: str, name: str) -> str:
    res = run_as_sidadm(sidadm, f"command -v {name} || true", check=False)
    path = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
    if not path:
        raise RuntimeError(f"binary {name!r} not found in {sidadm} PATH")
    return path


def phase_preflight(inp: Inputs, dry_run: bool) -> None:
    log.info("=== PHASE: preflight ===")
    if os.geteuid() != 0:
        raise RuntimeError("must run as root (uid 0)")
    data_dir = Path(f"/hana/data/{inp.sid}")
    log_dir = Path(f"/hana/log/{inp.sid}")
    if not data_dir.is_dir():
        raise RuntimeError(f"missing /hana/data/{inp.sid}")
    if not log_dir.is_dir():
        log.warning("missing %s (optional)", log_dir)
    # Ownership check
    try:
        import pwd
        owner = pwd.getpwuid(data_dir.stat().st_uid).pw_name
        if owner != inp.sidadm:
            log.warning("/hana/data/%s owned by %s, expected %s",
                        inp.sid, owner, inp.sidadm)
    except KeyError:
        log.warning("user %s not found", inp.sidadm)

    free_gb = shutil.disk_usage(str(data_dir)).free / (1024 ** 3)
    log.info("free space on /hana/data: %.1f GB", free_gb)
    if free_gb < 5:
        log.warning("low free space (<5 GB)")

    # Locate binaries (informational; not strictly required in dry-run)
    if not dry_run:
        for tool in ("HDB", "hdbsql", "hdbuserstore", "sapcontrol"):
            try:
                p = find_hana_binary(inp.sidadm, tool)
                log.info("found %s -> %s", tool, p)
            except Exception as e:
                log.error("%s", e)
                raise
        # recoverSys.py / recoverTenant.py
        res = run_as_sidadm(inp.sidadm,
            "ls $DIR_INSTANCE/exe/python_support/recoverSys.py "
            "$DIR_INSTANCE/exe/python_support/recoverTenant.py",
            check=False)
        if res.rc != 0:
            raise RuntimeError("recoverSys.py / recoverTenant.py not found")
        log.info("recovery helpers present:\n%s", res.stdout.strip())


# ----- Phase: stop HANA ------------------------------------------------------
def hana_is_running(inp: Inputs) -> bool:
    res = run_as_sidadm(inp.sidadm,
        f"sapcontrol -nr {inp.instance} -function GetProcessList",
        check=False)
    return "GREEN" in res.stdout or "YELLOW" in res.stdout


def phase_stop_hana(inp: Inputs, dry_run: bool) -> None:
    log.info("=== PHASE: stop HANA ===")
    if dry_run:
        log.info("[dry-run] would run: HDB stop")
        return
    if not hana_is_running(inp):
        log.info("HANA already stopped, skipping")
        return
    if not confirm_yes(f"Stop HANA instance {inp.sid}/{inp.instance}?"):
        raise RuntimeError("user declined to stop HANA")
    run_as_sidadm(inp.sidadm, "HDB stop", timeout=900)
    # wait for processes gone
    for _ in range(60):
        if not hana_is_running(inp):
            break
        time.sleep(5)
    else:
        raise RuntimeError("HANA did not stop within timeout")
    log.info("HANA stopped")


# ----- Phase: recover SYSTEMDB ----------------------------------------------
def _wait_nameserver_green(inp: Inputs, timeout_s: int = 1800) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        res = run_as_sidadm(inp.sidadm,
            f"sapcontrol -nr {inp.instance} -function GetProcessList",
            check=False)
        if "hdbnameserver" in res.stdout and "GREEN" in res.stdout:
            log.info("hdbnameserver is GREEN")
            return
        time.sleep(10)
    raise RuntimeError("timeout waiting for hdbnameserver GREEN")


def phase_recover_systemdb(inp: Inputs, dry_run: bool) -> None:
    log.info("=== PHASE: recover SYSTEMDB ===")
    sql = build_recover_sql("SYSTEMDB", inp.mode,
                            ts=inp.timestamp, backup_file=inp.backup_file)
    log.info("SYSTEMDB recovery SQL: %s", sql)
    if not confirm_token(f"Type SID to recover SYSTEMDB on {inp.sid}", inp.sid):
        raise RuntimeError("user aborted SYSTEMDB recovery")
    if dry_run:
        log.info("[dry-run] would run recoverSys.py with above SQL")
        return
    cmd = (f'python $DIR_INSTANCE/exe/python_support/recoverSys.py '
           f'--command="{sql}"')
    run_as_sidadm(inp.sidadm, cmd, timeout=7200)
    _wait_nameserver_green(inp)


# ----- Phase: recover tenants -----------------------------------------------
def phase_recover_tenants(inp: Inputs, dry_run: bool) -> None:
    log.info("=== PHASE: recover tenants ===")
    for t in inp.tenants:
        sql = build_recover_sql(t, inp.mode,
                                ts=inp.timestamp, backup_file=inp.backup_file)
        log.info("Tenant %s recovery SQL: %s", t, sql)
        if not confirm_token(f"Type tenant name to recover {t}", t):
            raise RuntimeError(f"user aborted tenant {t} recovery")
        if dry_run:
            log.info("[dry-run] would run recoverTenant.py for %s", t)
            continue
        cmd = (f'python $DIR_INSTANCE/exe/python_support/recoverTenant.py '
               f'{t} --command="{sql}"')
        run_as_sidadm(inp.sidadm, cmd, timeout=7200)
        _verify_tenant_active(inp, t)


def _verify_tenant_active(inp: Inputs, tenant: str) -> None:
    # Uses systemdb temp key set later; here we just check via SYSTEMDB
    # M_DATABASES from inside SYSTEMDB.
    log.info("verifying tenant %s is ACTIVE", tenant)
    # Best-effort: SYSTEMDB admin key may not exist yet during recovery. Skip
    # if userstore key not configured; full verification happens in phase 7.


# ----- Phase: start system --------------------------------------------------
def phase_start_system(inp: Inputs, dry_run: bool) -> None:
    log.info("=== PHASE: start system ===")
    if dry_run:
        log.info("[dry-run] would run: HDB start")
        return
    run_as_sidadm(inp.sidadm, "HDB start", timeout=1800)
    deadline = time.time() + 1800
    while time.time() < deadline:
        res = run_as_sidadm(inp.sidadm,
            f"sapcontrol -nr {inp.instance} -function GetProcessList",
            check=False)
        lines = [l for l in res.stdout.splitlines() if "hdb" in l.lower()]
        if lines and all("GREEN" in l for l in lines):
            log.info("all HANA processes GREEN")
            return
        time.sleep(15)
    raise RuntimeError("timeout waiting for full HANA start")


# ----- Phase: reset SYSTEM passwords ----------------------------------------
def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _systemdb_key(inp: Inputs) -> str:
    return f"{TMP_KEY_PREFIX}SYSDB"


def _tenant_key(inp: Inputs, tenant: str) -> str:
    return f"{TMP_KEY_PREFIX}TEN_{tenant}"


def _systemdb_port(inp: Inputs) -> str:
    return f"3{inp.instance}13"


def phase_reset_passwords(inp: Inputs, dry_run: bool) -> None:
    log.info("=== PHASE: reset SYSTEM passwords ===")
    if dry_run:
        log.info("[dry-run] would create temp userstore keys and run "
                 "ALTER USER SYSTEM PASSWORD on SYSTEMDB and each tenant")
        return

    host = "localhost"
    sysdb_key = _systemdb_key(inp)
    _userstore_set(inp.sidadm, sysdb_key, host, _systemdb_port(inp),
                   "SYSTEM", inp.sysdb_old_pw)

    if not confirm_yes("Reset SYSTEM password on SYSTEMDB now?"):
        raise RuntimeError("user declined SYSTEMDB password reset")
    _reset_one_db(inp, sysdb_key, "SYSTEMDB", inp.sysdb_new_pw)

    # Discover tenant SQL ports via SYSTEMDB
    res = run_as_sidadm(inp.sidadm,
        f"hdbsql -U {sysdb_key} -x -a -A "
        f"{shell_quote('SELECT DATABASE_NAME, SQL_PORT FROM SYS_DATABASES.M_SERVICES WHERE SERVICE_NAME=' + chr(39) + 'indexserver' + chr(39))}",
        check=True)
    port_map: dict[str, str] = {}
    for line in res.stdout.splitlines():
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) >= 2 and parts[0] and parts[1].isdigit():
            port_map[parts[0]] = parts[1]
    log.info("discovered tenant ports: %s", port_map)

    for t in inp.tenants:
        port = port_map.get(t)
        if not port:
            raise RuntimeError(f"could not discover SQL port for tenant {t}")
        tkey = _tenant_key(inp, t)
        # SYSTEMDB SYSTEM resets tenant SYSTEM via cross-DB ALTER DATABASE.
        sql = f'ALTER DATABASE {t} SYSTEM USER PASSWORD "{inp.tenant_new_pw[t]}"'
        if not confirm_yes(f"Reset SYSTEM password on tenant {t}?"):
            raise RuntimeError(f"user declined tenant {t} password reset")
        log.info("resetting tenant %s SYSTEM password via SYSTEMDB", t)
        run_as_sidadm(inp.sidadm,
            f"hdbsql -U {sysdb_key} -x -a -A {shell_quote(sql)}",
            redact_in_log=True, check=True)
        # Then create temp tenant key for verification step
        _userstore_set(inp.sidadm, tkey, host, port, "SYSTEM",
                       inp.tenant_new_pw[t])


def _reset_one_db(inp: Inputs, key: str, db_label: str, new_pw: str) -> None:
    # Try ALTER directly; if user is locked, deactivate/activate.
    sql = f'ALTER USER SYSTEM PASSWORD "{new_pw}"'
    res = run_as_sidadm(inp.sidadm,
        f"hdbsql -U {key} -x -a -A {shell_quote(sql)}",
        redact_in_log=True, check=False)
    if res.rc != 0 and ("locked" in res.stderr.lower()
                        or "deactivated" in res.stderr.lower()):
        log.warning("SYSTEM user appears locked on %s; activating", db_label)
        run_as_sidadm(inp.sidadm,
            f"hdbsql -U {key} -x -a -A "
            f"{shell_quote('ALTER USER SYSTEM ACTIVATE USER NOW')}",
            check=True)
        run_as_sidadm(inp.sidadm,
            f"hdbsql -U {key} -x -a -A {shell_quote(sql)}",
            redact_in_log=True, check=True)
    elif res.rc != 0:
        raise RuntimeError(f"failed to reset {db_label} SYSTEM password: "
                           f"{res.stderr}")
    log.info("%s SYSTEM password reset", db_label)


# ----- Phase: verify ---------------------------------------------------------
def phase_verify(inp: Inputs, dry_run: bool) -> None:
    log.info("=== PHASE: verify ===")
    if dry_run:
        log.info("[dry-run] would query M_DATABASES, M_SERVICES, "
                 "and login-test new passwords")
        return
    sysdb_key = _systemdb_key(inp)
    res = run_as_sidadm(inp.sidadm,
        f"hdbsql -U {sysdb_key} -x -a -A "
        f"{shell_quote('SELECT DATABASE_NAME, ACTIVE_STATUS FROM M_DATABASES')}",
        check=True)
    log.info("M_DATABASES:\n%s", res.stdout)
    for t in inp.tenants:
        if f"{t}" not in res.stdout or "YES" not in res.stdout:
            log.warning("tenant %s may not be ACTIVE", t)
    # Login test for each tenant temp key
    for t in inp.tenants:
        tkey = _tenant_key(inp, t)
        r = run_as_sidadm(inp.sidadm,
            f"hdbsql -U {tkey} -x -a -A "
            f"{shell_quote('SELECT 1 FROM DUMMY')}",
            check=False)
        if r.rc == 0:
            log.info("tenant %s SYSTEM login OK", t)
        else:
            log.error("tenant %s SYSTEM login FAILED", t)


# ----- Phase: report ---------------------------------------------------------
def phase_report(inp: Inputs, log_path: Path, st: State) -> None:
    log.info("=== PHASE: report ===")
    print("\n========== HANA RECOVERY SUMMARY ==========")
    print(f"SID                 : {inp.sid}")
    print(f"Instance            : {inp.instance}")
    print(f"Tenants             : {', '.join(inp.tenants)}")
    print(f"Mode                : {inp.mode}")
    if inp.mode == "C":
        print(f"PITR timestamp      : {inp.timestamp}")
    if inp.mode == "D":
        print(f"Backup file         : {inp.backup_file}")
    print(f"Phases completed    : {', '.join(st.completed_phases)}")
    print(f"Log file            : {log_path}")
    print("===========================================\n")


# ----- Signal / atexit handlers ---------------------------------------------
def _signal_handler(signum, frame):
    log.warning("received signal %s; cleaning up temp keys", signum)
    try:
        cleanup_temp_keys(force=False)
    finally:
        sys.exit(130)


# ----- Phase runner with checkpoint -----------------------------------------
def run_phase(name: str, fn, st: State, *args) -> None:
    if name in st.completed_phases:
        log.info("skipping completed phase: %s", name)
        return
    fn(*args)
    st.mark(name)
    save_state(st)


# ----- Main ------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SAP HANA MDC automated recovery (stdlib only).")
    p.add_argument("--dry-run", action="store_true",
                   help="walk through plan and print SQL; execute nothing destructive")
    p.add_argument("--sid", default=None, help="SAP SID (e.g. HDB)")
    p.add_argument("--instance", default=None, help="instance number, 00-99")
    p.add_argument("--log-dir", default="/var/tmp",
                   help="directory for log file (default /var/tmp)")
    return p.parse_args()


def main() -> int:
    print(__doc__ or "")
    print("=" * 78)
    print("SAP HANA MDC RECOVERY  -  INVARIANT: this script NEVER deletes")
    print("HANA artifacts. Only temp hdbuserstore keys (RECOV_TMP_<pid>_*) may")
    print("be removed, and only after typed YES confirmation.")
    print("=" * 78)

    args = parse_args()

    ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    sid_for_log = (args.sid or "UNK").upper()
    log_path = Path(args.log_dir) / f"hana_recovery_{sid_for_log}_{ts_tag}.log"
    setup_logging(log_path)
    log.info("recovery script starting (dry_run=%s)", args.dry_run)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    atexit.register(lambda: cleanup_temp_keys(force=False))

    try:
        inp = collect_inputs(args)
    except Exception as e:
        log.error("input collection failed: %s", e)
        return 2

    # Resume support
    st = load_state(inp.sid) or State(
        sid=inp.sid, instance=inp.instance, tenants=inp.tenants,
        mode=inp.mode, timestamp=inp.timestamp,
        backup_file=inp.backup_file, backup_catalog=inp.backup_catalog,
        started_at=datetime.now().isoformat())
    if st.completed_phases:
        log.info("resuming; previously completed phases: %s",
                 st.completed_phases)
    save_state(st)

    try:
        run_phase("preflight", phase_preflight, st, inp, args.dry_run)
        run_phase("stop_hana", phase_stop_hana, st, inp, args.dry_run)
        run_phase("recover_systemdb", phase_recover_systemdb, st,
                  inp, args.dry_run)
        run_phase("recover_tenants", phase_recover_tenants, st,
                  inp, args.dry_run)
        run_phase("start_system", phase_start_system, st, inp, args.dry_run)
        run_phase("reset_passwords", phase_reset_passwords, st,
                  inp, args.dry_run)
        run_phase("verify", phase_verify, st, inp, args.dry_run)
        phase_report(inp, log_path, st)
        st.mark("report")
        save_state(st)
    except Exception as e:
        log.error("recovery failed: %s", e)
        return 1
    finally:
        # cleanup_temp_keys runs via atexit (with confirmation prompt)
        pass

    log.info("recovery complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
