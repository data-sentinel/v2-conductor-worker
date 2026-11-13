# ds_conductor.py - Data Sentinel Vantage (V2) conductor
#
# The first V2 worker. It connects to the V2 repository database as sentinel_worker and does two
# jobs beside each other, sharing the database link, the lock, the contract check and the heartbeat:
#
#   the check loop   answers every data source availability check the database says is due
#   the run loop     dispatch (package 2026-46-71): begins each run the database says is due, hands
#                    every queue to a worker, watches the leases, takes a lost worker's queue back,
#                    ends each stage and each run with a named ending, and says why a run waits
#
#   settings -> database link -> contract check -> single-instance lock -> check-in
#            -> LISTEN data_source_check, run_request -> heartbeat -> check loop, run loop
#
# The V1 conductor's dispatch code (conduct_runs, eval_scope, insert_partitions, dispatch_agent)
# is NOT in this file: it was written against V1 tables that V2 does not have. The run loop is new.
#
# What it never does: write to a table, read data_source_secrets, call sentinelapi, keep a
# connection object beyond the check that read it, log a connection value other than the host,
# or log a data source's, job's, estate's or person's name. A call to a worker never decides
# anything: the database does, and the conductor learns of every change from the database.
#
#__version__ = '2026.32.2'   # last V1 conductor (runs, partitions and dispatch on the V1 repository)
#__version__ = '2026.47.1'   # VANTAGE (V2) first build: availability checks through ds_connect_lib; check-in and
#                              heartbeat through functions; one instance at a time (advisory lock); /health,
#                              /ready, /status, POST /check. No dispatch yet.
#__version__ = '2026.47.2'   # architect's reply 2026-46-33: every file root that is SET goes to the library, which
#                              looks at it when a path under it is checked - a share mounted after start works with
#                              no restart, and the look at start is for the log, /status and the capabilities only;
#                              POST /check asks sys_get_data_source_check_info for the type when the database has
#                              that function, and reads the table as before when it hasn't.
#                              Addendum 2026-46-35: a health summary goes with every heartbeat when the database's
#                              heartbeat takes one - ready, what stops the worker (problem), what it is doing (work) -
#                              so the app's Workers panel can show the conductor; the heartbeat now carries on while
#                              the contract for checks doesn't hold, saying so.
#__version__ = '2026.47.3'   # package 2026-46-71: dispatch. The run loop beside the check loop: the schedule tick, the
#                              due list, beginning a run with a queue for every worker it has, handing each queue out by
#                              POST /run, the lease watch with the worker's health summary and a direct GET /status only
#                              when its heartbeat is stale too, reclaim, stage and run endings, cancel, stop, the run
#                              window, the run's wait. The run functions are optional: without them dispatch is off and
#                              the checks run as before.
__version__ = '2026.47.4'    # carries ds_connect_lib 2026.47.3 (the discovery walks' additions: handle.call, retries,
#                              token_for, as_user, optional permissions). The conductor's own code is 2026.47.3's.

import os
import sys
import json
import time
import signal
import asyncio
import logging
import logging.handlers
import tempfile
import functools
import collections
import concurrent.futures
import urllib.parse
from datetime import datetime, timezone

import asyncpg
from quart import Quart, jsonify, request

import ds_connect_lib

WORKER_TYPE = "conductor"

# Advisory lock keys in use by Data Sentinel workers (session locks on the repository database).
# The first key is the product's, the second says which lock. Listed in WORKER-STANDARD.md.
LOCK_PRODUCT_KEY = 17491            # "DS"
LOCK_CONDUCTOR_INSTANCE = 1         # one conductor at a time

CONTRACT_FUNCTIONS = ("sys_get_data_source_checks_due", "sys_get_data_source_connection",
                      "sys_post_data_source_check", "sys_post_worker_checkin", "sys_post_worker_heartbeat")
CONTRACT_SQL = """
select p.proname,
       pg_get_function_arguments(p.oid)                        as args,
       has_function_privilege(current_user, p.oid, 'execute')  as may_run,
       current_user::text                                      as login
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'sentinel'
   and p.proname = any($1::text[])
"""
SQL_DUE = "select sentinel.sys_get_data_source_checks_due(v_limit => $1)"
SQL_CONNECTION = ("select now() as started_at, "
                  "sentinel.sys_get_data_source_connection(v_data_source_id => $1) as connection")
SQL_POST = ("select sentinel.sys_post_data_source_check(v_data_source_id => $1, v_status => $2, v_ms => $3, "
            "v_message => $4, v_message_code => $5, v_message_params => $6::jsonb)")
SQL_POST_AT = ("select sentinel.sys_post_data_source_check(v_data_source_id => $1, v_status => $2, v_ms => $3, "
               "v_message => $4, v_message_code => $5, v_message_params => $6::jsonb, v_checked_at => $7)")
SQL_CHECKIN = ("select sentinel.sys_post_worker_checkin(v_worker_type => $1, v_worker_name => $2, "
               "v_worker_version => $3, v_address => $4, v_port => $5, v_capabilities => $6::jsonb)")
SQL_HEARTBEAT = "select sentinel.sys_post_worker_heartbeat(v_worker_id => $1, v_status => $2)"
SQL_HEARTBEAT_PLAIN = "select sentinel.sys_post_worker_heartbeat(v_worker_id => $1)"
SQL_HEARTBEAT_HEALTH = ("select sentinel.sys_post_worker_heartbeat(v_worker_id => $1, v_status => $2, "
                        "v_health => $3::jsonb)")
HEARTBEAT_FUNCTION = "sys_post_worker_heartbeat"

# The health summary that goes with the heartbeat (addendum 2026-46-35). The app's Workers panel
# shows its sentences, and will show them in French and Spanish from the code and the parameters:
# ONE CODE FOR ONE SENTENCE. One sentence, no full stop, no line break, 200 characters at most.
# Never in it: a data source's name, a host, a connection value, the text of a check's message.
HEALTH_MAX_CHARS = 4000
HEALTH_WORK = {
    "idle": "Idle",                                         # nothing is running
    "checking_one": "1 check running",                      # one check is in flight
    "checking": "{n} checks running",                       # n checks are in flight, two or more
    "runs_open_one": "1 run in progress",                   # one run has a claimed queue, no check in flight
    "runs_open": "{runs} runs in progress",                 # two or more runs, no check
    "checking_one_and_run_one": "1 check running and 1 run in progress",
    "checking_one_and_runs": "1 check running and {runs} runs in progress",
    "checking_and_run_one": "{n} checks running and 1 run in progress",
    "checking_and_runs": "{n} checks running and {runs} runs in progress",
    "checks_off": "Checks are switched off for this worker",   # DS_CHECKS_ENABLED is false, and no run in progress
}
HEALTH_PROBLEM = {
    "contract_missing": "The database is missing functions this worker needs",      # the names are in params.missing
    "secret_missing": "The installation has no encryption key, so connections can't be read",
    "starting": "The worker is still starting",             # checked in, not yet listening
    "reconnecting": "The worker is reconnecting to the database",   # after a lost link, not yet listening again
    "stopping": "The worker is stopping",
}
# POST /check is given an id and needs its type. sys_get_data_source_check_info returns it
# (asked of the database session, supplement 2026-46-32). It is NOT part of the contract yet:
# when the database has it, /check uses it; when it hasn't, /check reads the one column from
# the table, as 2026.47.1 did. Once the as-built has the function it joins CONTRACT_FUNCTIONS
# and the table read goes.
CHECK_INFO_FUNCTION = "sys_get_data_source_check_info"
SQL_CHECK_INFO = "select sentinel.sys_get_data_source_check_info(v_data_source_id => $1)"
SQL_SOURCE_TYPE = "select source_type from sentinel.data_sources where source_id = $1"

# a database call that fails with one of these means the functions are gone or changed: check the contract again
CONTRACT_SQLSTATES = ("42883", "3F000", "42501", "42P01", "42704")

# ---- dispatch (package 2026-46-71; the database's half is directive 2026-46-69, section 4) ----
# The run functions, with the named parameters this build sends. Optional: when all of them are there,
# dispatch is on; when any is missing, dispatch is off, the checks run as before, /ready stays 200, and
# they are looked for again every 60 seconds. They join CONTRACT_FUNCTIONS when the as-built has them.
RUN_FUNCTIONS = {
    "sys_post_runs_scheduled": (),
    "sys_get_runs_due": ("v_limit",),
    "sys_get_workers": ("v_worker_type", "v_source_type"),
    "sys_post_run_begin": ("v_run_id", "v_queues"),
    "sys_post_run_waiting": ("v_run_id", "v_code", "v_params", "v_text"),
    "sys_post_partition_reclaim": ("v_run_id", "v_stage", "v_partition_id", "v_worker_id", "v_attempt", "v_code",
                                   "v_params", "v_text"),
    "sys_post_run_stage_end": ("v_run_id", "v_stage", "v_state", "v_code", "v_params", "v_text"),
    "sys_post_run_end": ("v_run_id", "v_state", "v_code", "v_params", "v_text"),
}
SQL_RUNS_SCHEDULED = "select sentinel.sys_post_runs_scheduled()"
SQL_RUNS_DUE = "select sentinel.sys_get_runs_due(v_limit => $1)"
SQL_WORKERS = "select sentinel.sys_get_workers(v_worker_type => $1, v_source_type => $2)"
SQL_RUN_BEGIN = "select sentinel.sys_post_run_begin(v_run_id => $1, v_queues => $2::jsonb)"
SQL_RUN_WAITING = ("select sentinel.sys_post_run_waiting(v_run_id => $1, v_code => $2, v_params => $3::jsonb, "
                   "v_text => $4)")
SQL_RECLAIM = ("select sentinel.sys_post_partition_reclaim(v_run_id => $1, v_stage => $2, v_partition_id => $3, "
               "v_worker_id => $4, v_attempt => $5, v_code => $6, v_params => $7::jsonb, v_text => $8)")
SQL_STAGE_END = ("select sentinel.sys_post_run_stage_end(v_run_id => $1, v_stage => $2, v_state => $3, v_code => $4, "
                 "v_params => $5::jsonb, v_text => $6)")
SQL_RUN_END = ("select sentinel.sys_post_run_end(v_run_id => $1, v_state => $2, v_code => $3, v_params => $4::jsonb, "
               "v_text => $5)")
STAGES = ("discover", "scan", "classify", "publish")    # in order; a worker's type is its stage's name
RUN_DUE_LIMIT = 50
RUN_HOLD_SEC = 30                   # a run whose handling failed, or whose ending was refused, is left this long
WORKER_REFUSED_SEC = 30             # a worker that answered busy or not_ready, or not at all, isn't chosen this long
PROBE_TIMEOUT_SEC = 5               # GET /status on a worker whose lease and heartbeat are both stale
PROBE_FRESH_SEC = 15                # how long that answer is used before asking again
NEAR_WAKE_SEC = 0.25                # a wait or a window that changes before the timer: looked at this long after the
#                                     database says it changes. The database already rounds the seconds up, so this is
#                                     never early, and a window that opens is acted on inside 2 seconds (D8, D28)
# The reasons the conductor sends: one code for one sentence, no full stop (fixtures/reasons.json).
# The database writes attempts_used_up on a queue, stopped_by_request and cancelled_by_request itself.
RUN_REASONS = {
    "source_busy": "Waiting for another run on this data source to finish",
    "workers_short": "Waiting for {asked} {stage} workers, and {free} are free",
    "outside_window": "Outside the run window, which opens at {time}",
    "no_worker_available": "No {stage} worker is free for this type of data source",
    "retry_wait": "Waiting to try again",
    "queue_stopped": "Waiting for a stopped queue to be resumed",
    "worker_lost": "The worker stopped responding and its work was taken back",
    "attempts_used_up": "The work failed and its retries are used up",
    "discovery_incomplete": "Discovery didn't finish, so nothing was marked missing",
    "discovery_partial": "Discovery couldn't list {n} places, so nothing under them was marked missing",
    "no_objects_found": "Nothing reached this stage",
    "objects_failed": "{n} objects couldn't be processed",
}

RECONNECT_MAX_WAIT_SEC = 30
CONTRACT_RETRY_SEC = 60             # how often the contract is checked again while it doesn't hold
CONTRACT_BROKEN_WAITS = (5, 10, 15) # under a running conductor (a rebuild): look again 5, 15 and 30 seconds after
#                                     the break, so a rebuild that takes seconds costs seconds; then every 60
LOCK_RETRY_SEC = 10
ERROR_COOL_OFF_SEC = 30             # after an error reading a connection or posting a result
LINK_COOL_OFF_SEC = 5               # after a database call that failed on the link: long enough not to sign in to
#                                     a customer's system in a loop while results can't be posted
STOP_GRACE_SEC = 30
DB_CALL_TIMEOUT_SEC = 30

log = logging.getLogger("ds_conductor")


# ---------------------------------------------------------------------------
# Settings. All by environment variable; the database's address as the V1 conductor
# has it (Docker secret files), each with an environment override for a dev run.
# ---------------------------------------------------------------------------
class SettingsError(Exception):
    """A setting that can't be used. The message names it."""


def _secret_text(path, name=None):
    """A secret file's value. The platform's files hold {"<name>": "<value>"}; a file
    that isn't that is taken as it is, with the line end removed."""
    with open(path, "r", encoding="utf-8") as _f:
        _raw = _f.read()
    _name = name or os.path.basename(path)
    try:
        _obj = json.loads(_raw)
        if isinstance(_obj, dict) and _name in _obj:
            return str(_obj[_name])
    except ValueError:
        pass
    return _raw.strip("\r\n")


def read_database_password(settings):
    """THE one place the conductor gets its database password: a Docker secret mounted
    as a file and read as it is (Kevin, 2026-11-11). Read at every connect, so a rotated
    secret is picked up by the next reconnect. If the ruling changes, only this changes."""
    return _secret_text(settings.db_password_file)


class Settings(object):
    def __init__(self, env=None):
        _env = os.environ if env is None else env
        self.secrets_dir = _env.get("DS_SECRETS_DIR", "/run/secrets")

        def _text(name, default=None):
            _v = _env.get(name)
            return _v.strip() if isinstance(_v, str) and _v.strip() else default

        def _int(name, default, low, high):
            _v = _text(name)
            if _v is None:
                return default
            try:
                _n = int(_v)
            except ValueError:
                _n = None
            if _n is None or not low <= _n <= high:
                raise SettingsError(name + ": '" + _v + "' is not a whole number between "
                                    + str(low) + " and " + str(high))
            return _n

        def _bool(name, default):
            _v = _text(name)
            if _v is None:
                return default
            if _v.lower() in ("1", "true", "yes", "on"):
                return True
            if _v.lower() in ("0", "false", "no", "off"):
                return False
            raise SettingsError(name + ": '" + _v + "' is not true or false")

        def _repository(env_name, secret_name, default=None):
            _v = _text(env_name)
            if _v is not None:
                return _v
            _path = os.path.join(self.secrets_dir, secret_name)
            if os.path.isfile(_path):
                try:
                    _v = _secret_text(_path, secret_name).strip()
                except OSError as _e:
                    raise SettingsError(secret_name + ": the secret file can't be read (" + type(_e).__name__ + ")")
                if _v:
                    return _v
            if default is None:
                raise SettingsError(env_name + ": not set, and there is no secret file " + _path)
            return default

        # --- who it is, and where it answers (the V1 conductor's names)
        self.name = _text("DS_SERVICE", "ds_conductor")
        self.address = _text("DS_SERVICE_EXTERNAL_HOST", self.name)
        self.port = _int("DS_SERVICE_EXTERNAL_PORT", 5500, 1, 65535)
        # --- the repository database
        self.db_host = _repository("DS_DB_HOST", "repository_host")
        _port = _repository("DS_DB_PORT", "repository_port", "5432")
        if not _port.isdigit() or not 1 <= int(_port) <= 65535:
            raise SettingsError("DS_DB_PORT / repository_port: '" + _port + "' is not a port number")
        self.db_port = int(_port)
        self.db_name = _repository("DS_DB_NAME", "repository_name", "data_sentinel")
        self.db_user = _repository("DS_DB_USER", "repository_username", "sentinel_worker")
        self.db_password_file = _text("DS_DB_PASSWORD_FILE", os.path.join(self.secrets_dir, "sentinel_worker_password"))
        if not os.path.isfile(self.db_password_file):
            raise SettingsError("DS_DB_PASSWORD_FILE: there is no file " + self.db_password_file)
        try:
            read_database_password(self)
        except OSError as _e:
            raise SettingsError("DS_DB_PASSWORD_FILE: " + self.db_password_file + " can't be read (" + type(_e).__name__ + ")")
        # --- the checks
        self.checks_enabled = _bool("DS_CHECKS_ENABLED", True)
        self.concurrency = _int("DS_CHECK_CONCURRENCY", 8, 1, 64)
        self.reserved = _int("DS_CHECK_RESERVED", 2, 0, 16)
        self.timeout_sec = _int("DS_CHECK_TIMEOUT_SEC", 30, 5, 300)
        self.poll_sec = _int("DS_CHECK_POLL_SEC", 60, 1, 3600)
        self.due_limit = _int("DS_CHECK_DUE_LIMIT", 50, 1, 500)
        self.heartbeat_sec = _int("DS_HEARTBEAT_SEC", 30, 1, 110)      # online means a heartbeat under 2 minutes old
        # --- dispatch (package 2026-46-71, section 13): the lease's numbers and the retries' are the database's
        self.dispatch = _bool("DS_DISPATCH", True)
        self.run_poll_sec = _int("DS_RUN_POLL_SEC", 30, 1, 3600)
        self.run_call_timeout_sec = _int("DS_RUN_CALL_TIMEOUT_SEC", 10, 1, 120)
        self.run_end_timeout_sec = _int("DS_RUN_END_TIMEOUT_SEC", 300, 10, 3600)
        self.reclaim_grace_sec = _int("DS_RECLAIM_GRACE_SEC", 180, 0, 3600)
        self.file_roots = [_r for _r in (_p.strip() for _p in (_text("DS_FILE_ROOTS", "") or "").split(":")) if _r]
        for _r in self.file_roots:
            if not os.path.isabs(_r):
                raise SettingsError("DS_FILE_ROOTS: '" + _r + "' is not an absolute path")
        self.ca_bundle = _text("DS_CA_BUNDLE")
        if self.ca_bundle and not os.path.isfile(self.ca_bundle):
            raise SettingsError("DS_CA_BUNDLE: there is no file " + self.ca_bundle)
        _proxy = _text("HTTPS_PROXY") or _text("https_proxy")
        if _proxy and "://" not in _proxy:
            raise SettingsError("HTTPS_PROXY: '" + _proxy + "' is not a URL")
        self.proxy = {"https": _proxy, "no_proxy": _text("NO_PROXY") or _text("no_proxy") or ""} if _proxy else None
        # --- logs
        self.log_level = (_text("DS_LOG_LEVEL", "info") or "info").lower()
        if self.log_level not in ("debug", "info", "warning", "error"):
            raise SettingsError("DS_LOG_LEVEL: '" + self.log_level + "' is not debug, info, warning or error")
        self.log_dir = _text("DS_LOG_DIR", "/mnt/logs")

    def describe(self):
        """The settings as one log line: nothing secret is in it."""
        return ("name=" + self.name + " address=" + self.address + ":" + str(self.port)
                + " database=" + self.db_name + " user=" + self.db_user
                + " checks=" + str(self.checks_enabled).lower() + " concurrency=" + str(self.concurrency)
                + " reserved=" + str(self.reserved) + " timeout_sec=" + str(self.timeout_sec)
                + " poll_sec=" + str(self.poll_sec) + " due_limit=" + str(self.due_limit)
                + " heartbeat_sec=" + str(self.heartbeat_sec)
                + " dispatch=" + ("on" if self.dispatch else "off") + " run_poll_sec=" + str(self.run_poll_sec)
                + " run_call_timeout_sec=" + str(self.run_call_timeout_sec)
                + " run_end_timeout_sec=" + str(self.run_end_timeout_sec)
                + " reclaim_grace_sec=" + str(self.reclaim_grace_sec)
                + " proxy=" + ("yes" if self.proxy else "no") + " ca_bundle=" + ("yes" if self.ca_bundle else "no"))


def setup_logging(settings):
    """One format, as the V1 conductor: time|level|message. To stdout always, and to
    <log dir>/<service>.log when the folder is there. Third-party libraries from warning up."""
    _fmt = logging.Formatter("%(asctime)s|%(levelname)s|%(message)s")
    _root = logging.getLogger()
    for _h in list(_root.handlers):
        _root.removeHandler(_h)
    _out = logging.StreamHandler(sys.stdout)
    _out.setFormatter(_fmt)
    _root.addHandler(_out)
    _root.setLevel(logging.WARNING)
    log.setLevel(getattr(logging, settings.log_level.upper()))
    _file_note = None
    if settings.log_dir and os.path.isdir(settings.log_dir):
        try:
            _fh = logging.handlers.WatchedFileHandler(os.path.join(settings.log_dir, settings.name + ".log"))
            _fh.setFormatter(_fmt)
            _root.addHandler(_fh)
        except OSError as _e:
            _file_note = "log file not opened (" + type(_e).__name__ + "); logging to stdout only"
    if _file_note:
        log.warning(_file_note)


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log_host(connection):
    """The host of a connection, for the log line: the one connection value ever logged.
    The name alone - never a URL with a path, never a user."""
    try:
        _h = connection.get("host")
        if not _h and connection.get("base_url"):
            _h = urllib.parse.urlsplit(str(connection["base_url"])).hostname
        _h = "".join(_ch for _ch in str(_h or "") if _ch.isalnum() or _ch in ".-_:[]\\")
        return _h[:120] or "-"
    except Exception:
        return "-"


def _hint(exc):
    return getattr(exc, "hint", None) if isinstance(exc, asyncpg.PostgresError) else None


def _is_link_error(exc):
    return isinstance(exc, (OSError, asyncio.TimeoutError, asyncpg.InterfaceError,
                            asyncpg.PostgresConnectionError, asyncpg.CannotConnectNowError,
                            asyncpg.AdminShutdownError, asyncpg.CrashShutdownError))


class _Skip(Exception):
    """This check ends with no result: the row is gone, inactive, or can't be read for now."""

    def __init__(self, reason, error=False, cool=None):
        self.reason = reason
        self.error = error
        self.cool = (ERROR_COOL_OFF_SEC if cool is None else cool) if error else 0
        super().__init__(reason)


def _link_state(sqlstate):
    """SQLSTATE classes 08 (connection) and 57 (operator intervention, shutdown)."""
    return str(sqlstate or "")[:2] in ("08", "57")


# ---------------------------------------------------------------------------
# The conductor
# ---------------------------------------------------------------------------
class Conductor(object):
    def __init__(self, settings):
        self.s = settings
        self.started_at = _now_iso()
        self.step = "settings"
        self.status = "starting"            # what it says about itself: starting | active | stopping
        self.worker_id = None
        self.exit_code = 0
        # --- database
        self.conn = None                    # the long-lived connection: LISTEN and the lock
        self.pool = None                    # a small pool for the function calls
        self.connected = False
        self.listening = False
        self.lock = "none"                  # none | waiting | held
        self.contract_ok = False
        self.contract_missing = []
        self.has_check_info = False         # the database has sys_get_data_source_check_info (see SQL_CHECK_INFO)
        self.has_health = False             # the database's heartbeat takes v_health (addendum 2026-46-35)
        self.dispatch_missing = None        # the run functions that are missing (None: not looked yet; []: all there)
        self.dispatch_said = None           # what the log last said about them
        self._recheck_dispatch = asyncio.Event()
        self._dispatch_recheck_at = 0.0
        self._link_trouble = False          # a connect failed or the link dropped since the last session began
        self._caps_dispatch = None          # what the last check-in's capabilities said about dispatch
        self._row_gone_said = False
        self.last_heartbeat = None
        self._lost = asyncio.Event()
        self._recheck_contract = asyncio.Event()
        self._hb_now = asyncio.Event()
        self._stopping = False
        self._tasks = []
        # --- the library's registry, read once
        self.types = {}
        self.unavailable = {}
        self.roots = []                     # [{"path", "ok"}]: every root that is set, and whether it was there at start
        self.usable_roots = []              # the ones that were there at start: for the capabilities only
        self.ca_file = None
        self.checks = None
        self.runs = None

    # ---- start and stop ---------------------------------------------------
    async def start(self):
        _loop = asyncio.get_running_loop()
        _types = ds_connect_lib.types()
        self.types = sorted(_types)
        self.unavailable = {_n: _i.missing for _n, _i in sorted(_types.items()) if not _i.available}
        self.ca_file = self._compose_ca_file()
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.s.concurrency + self.s.reserved, thread_name_prefix="check")
        await self._look_at_roots(_loop)
        self.checks = CheckLoop(self)
        self.runs = RunLoop(self)
        log.info("start version=%s connect_lib=%s %s types=%s unavailable=%s file_roots=%s",
                 __version__, ds_connect_lib.__version__, self.s.describe(), ",".join(self.types),
                 json.dumps(self.unavailable, sort_keys=True),
                 ",".join(_r["path"] + ("" if _r["ok"] else "(unusable)") for _r in self.roots) or "-")
        self._tasks = [_loop.create_task(self._supervise(), name="supervise"),
                       _loop.create_task(self._heartbeat_loop(), name="heartbeat"),
                       _loop.create_task(self.checks.pump(), name="check-loop"),
                       _loop.create_task(self.runs.pump(), name="run-loop"),
                       _loop.create_task(self.runs.timer(), name="run-timer")]

    def _compose_ca_file(self):
        """DS_CA_BUNDLE holds the customer's own authorities. Drivers want ONE file, so the
        system's authorities and the bundle are written together to a temporary file: public
        certificates, nothing secret. SSL_CERT_FILE points OpenSSL users (the ODBC driver)
        at the same file."""
        if not self.s.ca_bundle:
            return None
        _system = ds_connect_lib._system_ca_file()
        _fd, _path = tempfile.mkstemp(prefix="ds_ca_", suffix=".pem")
        with os.fdopen(_fd, "w", encoding="utf-8") as _out:
            for _p in (_system, self.s.ca_bundle):
                if _p:
                    with open(_p, "r", encoding="utf-8", errors="ignore") as _in:
                        _out.write(_in.read().rstrip() + "\n")
        os.environ["SSL_CERT_FILE"] = _path
        if not _system:
            log.warning("no system certificate bundle found; trusting DS_CA_BUNDLE only")
        return _path

    async def _look_at_roots(self, loop):
        """A look at each file root at start, for the log, /status and the capabilities only.
        Every root that is set is passed to the library whatever this finds: the library looks
        again when a path under it is checked, so a share that is mounted later works with no
        restart, and the loop itself never touches the file system."""
        self.roots, self.usable_roots = [], []
        for _root in self.s.file_roots:
            _r = await loop.run_in_executor(
                self.executor, functools.partial(ds_connect_lib.check, "directory", {"root_path": _root},
                                                 timeout=10, file_roots=[_root]))
            _ok = _r.status == "reachable"
            self.roots.append({"path": _root, "ok": _ok})
            if _ok:
                self.usable_roots.append(_root)
            else:
                log.warning("file root %s is not there at start (%s): data sources under it can't be checked until it is",
                            _root, _r.code)

    async def stop(self):
        """SIGTERM: say stopping, start no more checks, give the running ones up to 30
        seconds to finish and post, close the connections (which frees the lock)."""
        if self._stopping:
            return
        self._stopping = True
        self.status = "stopping"
        self.step = "stopping"
        log.info("stopping: %d check(s) in flight", len(self.checks.in_flight) if self.checks else 0)
        await self._send_heartbeat(final=True)
        if self.runs:
            self.runs.drop_calls()          # calls to workers in flight are dropped; nothing is released or ended
        if self.checks:
            await self.checks.drain(STOP_GRACE_SEC)
        for _t in self._tasks:
            _t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._close_links()
        self.executor.shutdown(wait=False, cancel_futures=True)
        log.info("stopped")

    def fatal(self, text):
        """A configuration error or a bug the contract says to stop on."""
        log.critical("%s: stopping", text)
        self.exit_code = 1
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except Exception:
            os._exit(1)

    def went_active(self):
        """The first due-list read is done: say active with the next heartbeat (sent now)."""
        if self.status == "starting":
            self.status = "active"
            self._hb_now.set()

    def can_work(self):
        return (self.connected and self.lock == "held" and self.contract_ok and self.listening
                and not self._stopping and self.worker_id is not None)

    @property
    def dispatch(self):
        """Dispatch runs when it is switched on and the database has every run function."""
        return bool(self.s.dispatch and self.dispatch_missing == [])

    # ---- health: what /ready answers and what goes with the heartbeat ---------
    def problem(self):
        """What stops the conductor doing its job, as {code, params, text}; None when nothing does."""
        _code, _params = None, {}
        if self._stopping:
            _code = "stopping"
        elif not self.contract_ok and self.connected and (self.contract_missing or self.worker_id is not None):
            # known to be missing, or broken under a running conductor (the names follow at the next look)
            _code, _params = "contract_missing", {"missing": list(self.contract_missing)}
        elif self.checks is not None and self.checks.problem == "secret_missing":
            _code = "secret_missing"
        elif not self.can_work():
            _code = "starting" if self.status == "starting" else "reconnecting"
        if _code is None:
            return None
        return {"code": _code, "params": _params, "text": HEALTH_PROBLEM[_code]}

    def ready(self):
        return self.problem() is None

    def work(self):
        """What the conductor is doing now, as {code, params, text}. Runs count when a queue of theirs is claimed."""
        _n = len(self.checks.in_flight) if self.checks is not None else 0
        _r = self.runs.with_claims if (self.runs is not None and self.dispatch) else 0
        if _r and _n:
            _code = {(True, True): "checking_one_and_run_one", (True, False): "checking_one_and_runs",
                     (False, True): "checking_and_run_one", (False, False): "checking_and_runs"}[(_n == 1, _r == 1)]
        elif _r:
            _code = "runs_open_one" if _r == 1 else "runs_open"
        elif not self.s.checks_enabled:
            _code = "checks_off"
        elif _n == 0:
            _code = "idle"
        else:
            _code = "checking_one" if _n == 1 else "checking"
        _params = {_k: _v for _k, _v in (("n", _n), ("runs", _r)) if "{" + _k + "}" in HEALTH_WORK[_code]}
        return {"code": _code, "params": _params, "text": HEALTH_WORK[_code].format(**_params)}

    def health(self):
        """The summary: ready, problem, work, and the figures /status has. Counts and codes only."""
        _problem = self.problem()
        _c = self.checks
        _doc = {"ready": _problem is None, "problem": _problem, "work": self.work(),
                "detail": {"in_flight": len(_c.in_flight) if _c else 0, "abandoned": len(_c.abandoned) if _c else 0,
                           "last_poll": _c.last_poll if _c else None, "last_hour": _c.last_hour() if _c else {},
                           "runs": self.runs.summary() if self.runs else {"dispatch": False}}}
        if len(json.dumps(_doc)) > HEALTH_MAX_CHARS:
            _doc.pop("detail")
        if len(json.dumps(_doc)) > HEALTH_MAX_CHARS and _problem is not None:
            _problem["params"] = {}
        return _doc

    # ---- the database link ------------------------------------------------
    async def _open_links(self):
        _kw = dict(host=self.s.db_host, port=self.s.db_port, user=self.s.db_user, database=self.s.db_name,
                   password=read_database_password(self.s), timeout=10, command_timeout=DB_CALL_TIMEOUT_SEC,
                   statement_cache_size=0, server_settings={"application_name": self.s.name})
        self._lost = asyncio.Event()
        self.conn = await asyncpg.connect(**_kw)
        self.conn.add_termination_listener(self._on_lost)
        self._keepalive(self.conn)
        self.pool = await asyncpg.create_pool(min_size=1, max_size=10, **_kw)     # checks, runs, endings, heartbeat
        self.connected = True

    @staticmethod
    def _keepalive(conn):
        """TCP keepalives on the long-lived connection: a link that died silently delivers
        no signals and has already lost the lock."""
        try:
            import socket
            _sock = conn._transport.get_extra_info("socket")
            _sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            for _name, _value in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
                if hasattr(socket, _name):
                    _sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, _name), _value)
        except Exception:
            pass

    def _on_lost(self, _conn):
        self._lost.set()

    async def _close_links(self):
        self.connected = False
        self.listening = False
        if self.lock != "none":
            if self.lock == "held" and not self._stopping:
                log.warning("lock lost: the database connection dropped")
            self.lock = "none"
        _conn, _pool, self.conn, self.pool = self.conn, self.pool, None, None
        for _closer in ((lambda: _conn.close(timeout=5)) if _conn else None,
                        (lambda: asyncio.wait_for(_pool.close(), 5)) if _pool else None):
            if _closer is None:
                continue
            try:
                await _closer()
            except Exception:
                pass
        try:
            if _conn is not None:
                _conn.terminate()
            if _pool is not None:
                _pool.terminate()
        except Exception:
            pass

    async def _wait(self, seconds, events=()):
        """Sleep, but wake early when the link is lost (that raises) or an event is set."""
        _waits = [asyncio.ensure_future(self._lost.wait())] + [asyncio.ensure_future(_e.wait()) for _e in events]
        try:
            await asyncio.wait(_waits, timeout=seconds, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for _w in _waits:
                _w.cancel()
        if self._lost.is_set():
            raise ConnectionError("the long-lived connection dropped")

    async def _supervise(self):
        """Connect, work until the link is lost, connect again. Never exits over a lost database."""
        _wait = 1
        _first = True
        while not self._stopping:
            self.step = "connecting" if _first else "reconnecting"
            try:
                await self._open_links()
                if not _first:
                    log.info("database link restored")
                _first, _wait = False, 1
                await self._session()
            except asyncio.CancelledError:
                raise
            except Exception as _e:
                self._link_trouble = True
                if self.connected:
                    log.warning("database link lost (%s)", type(_e).__name__)
                else:
                    log.warning("database not reachable (%s): next try in %ds", type(_e).__name__, _wait)
            finally:
                await self._close_links()
            if self._stopping:
                break
            self.step = "reconnecting"
            await asyncio.sleep(_wait)
            _wait = min(RECONNECT_MAX_WAIT_SEC, _wait * 2)

    async def _session(self):
        """One life of the database link: contract, lock, check-in, LISTEN, then the loop's
        timer until the link drops."""
        await self._hold_contract()
        # ---- the lock: without it, this instance does nothing
        self.step = "lock"
        _said = False
        while not await self.conn.fetchval("select pg_try_advisory_lock($1, $2)", LOCK_PRODUCT_KEY, LOCK_CONDUCTOR_INSTANCE):
            self.lock = "waiting"
            if not _said:
                log.info("lock waiting: another conductor holds it")
                _said = True
            await self._wait(LOCK_RETRY_SEC)
        self.lock = "held"
        log.info("lock taken")
        # ---- check-in: once per process; after a reconnect the heartbeat carries on
        if self.worker_id is None:
            self.step = "checkin"
            await self._checkin()
        self.step = "listening"
        await self.conn.add_listener("data_source_check", self._on_signal)
        await self.conn.add_listener("run_request", self._on_run_signal)
        self.listening = True
        self.step = "running"
        await self.runs.after_connect(self._link_trouble)
        self._link_trouble = False
        self.checks.wake()                  # the first read, and the read straight after every reconnect
        self.runs.wake()                    # signals sent while the link was down are lost: look now
        while True:
            _wait = self.s.poll_sec
            if self.s.dispatch and self.dispatch_missing:
                _wait = max(1.0, min(_wait, self._dispatch_recheck_at - time.monotonic()))
            await self._wait(_wait, events=(self._recheck_contract, self._recheck_dispatch))
            await self.conn.fetchval("select 1", timeout=10)        # a cheap statement: is the link alive?
            if self._recheck_contract.is_set():
                await self._hold_contract(broken=True)
                self.step = "running"
            elif self.s.dispatch and (self._recheck_dispatch.is_set()
                                      or (self.dispatch_missing and time.monotonic() >= self._dispatch_recheck_at)):
                await self._check_dispatch()
            self.checks.wake()

    def _on_signal(self, _conn, _pid, _channel, _payload):
        # only a wake-up: the due list has the order and everything else that's due
        if self.checks:
            self.checks.wake()

    def _on_run_signal(self, _conn, _pid, _channel, _payload):
        # any run id: the look reads everything anyway
        if self.runs:
            self.runs.wake()

    # ---- the contract -----------------------------------------------------
    async def _contract_gaps(self):
        _rows = await self.conn.fetch(CONTRACT_SQL, list(CONTRACT_FUNCTIONS) + [CHECK_INFO_FUNCTION] + list(RUN_FUNCTIONS))
        _login = await self.conn.fetchval("select current_user::text")
        self.dispatch_missing = self._run_gaps(_rows)
        self.has_check_info = any(_r["proname"] == CHECK_INFO_FUNCTION and _r["may_run"] for _r in _rows)
        # optional, like check_info: a heartbeat with no v_health is not a broken contract
        self.has_health = any(_r["proname"] == HEARTBEAT_FUNCTION and "v_health" in _r["args"] for _r in _rows)
        _gaps = []
        if _login != "sentinel_worker":
            _gaps.append("login is " + str(_login) + ", not sentinel_worker")
        for _fn in CONTRACT_FUNCTIONS:
            _mine = [_r for _r in _rows if _r["proname"] == _fn]
            if not _mine:
                _gaps.append(_fn)
            elif not any(_r["may_run"] for _r in _mine):
                _gaps.append(_fn + " (no EXECUTE)")
            elif _fn == "sys_post_data_source_check" and not any(
                    "v_message_code" in _r["args"] and "v_message_params" in _r["args"] for _r in _mine):
                _gaps.append(_fn + " (v_message_code, v_message_params)")
        return _login, _gaps

    @staticmethod
    def _run_gaps(rows):
        """The run functions that aren't there as this build calls them: missing, not runnable, or without a
        named parameter it sends."""
        _gaps = []
        for _fn, _params in RUN_FUNCTIONS.items():
            _mine = [_r for _r in rows if _r["proname"] == _fn]
            if not _mine:
                _gaps.append(_fn)
            elif not any(_r["may_run"] for _r in _mine):
                _gaps.append(_fn + " (no EXECUTE)")
            elif not any(all(_p in _r["args"] for _p in _params) for _r in _mine):
                _gaps.append(_fn + " (" + ", ".join(_p for _p in _params) + ")")
        return _gaps

    def _say_dispatch(self, recovered=False):
        """One info line when what's known about the run functions changes: never above info, because
        until the as-built has them, a database without them is the expected case (package 2026-46-71, 01 section 5)."""
        _now = (self.s.dispatch, tuple(self.dispatch_missing or ()))
        if _now == self.dispatch_said:
            return
        _first = self.dispatch_said is None
        self.dispatch_said = _now
        if not self.s.dispatch:
            log.info("dispatch=off (DS_DISPATCH): checks only")
        elif self.dispatch_missing:
            log.info("dispatch=no: the database has no %s; looked for again every %ds",
                     ", ".join(self.dispatch_missing), CONTRACT_RETRY_SEC)
        elif not _first:
            log.info("dispatch=yes: the database has the run functions now")

    async def _check_dispatch(self):
        """Look for the run functions again (every 60 seconds while any is missing, and when a call found one
        gone). A change is told to the database with a fresh check-in, which carries the capabilities."""
        self._recheck_dispatch.clear()
        try:
            _rows = await self.conn.fetch(CONTRACT_SQL, list(RUN_FUNCTIONS))
        except asyncpg.PostgresError:
            return
        self.dispatch_missing = self._run_gaps(_rows)
        self._dispatch_recheck_at = time.monotonic() + CONTRACT_RETRY_SEC
        self._say_dispatch()
        if self.dispatch != self._caps_dispatch and self.worker_id is not None:
            try:
                await self._checkin(keep_status=True)
            except Exception as _e:
                log.warning("check-in for the new capabilities failed (%s)", type(_e).__name__)
        if self.dispatch:
            self.runs.wake()

    def dispatch_broken(self, where):
        """A run call found a function gone or changed: dispatch off until it's looked for again."""
        if self.dispatch_missing == []:
            self.dispatch_missing = ["(" + where + ")"]
            log.info("dispatch=no: %s; looking again", where)
            self.dispatch_said = (self.s.dispatch, tuple(self.dispatch_missing))
        self._dispatch_recheck_at = time.monotonic() + CONTRACT_BROKEN_WAITS[0]
        self._recheck_dispatch.set()

    async def _hold_contract(self, broken=False):
        """Return when the database has what this build is written to. Until then: one log
        line that names what's missing, the same on /status, no checks, nothing posted."""
        self.step = "contract"
        self._recheck_contract.clear()
        self.contract_ok = False
        _waits = list(CONTRACT_BROKEN_WAITS) if broken else []
        if _waits:
            await self._wait(_waits.pop(0))
        _said = None
        while True:
            _login, _gaps = await self._contract_gaps()
            if _login != "sentinel_worker":
                self.contract_missing = _gaps
                self.fatal("the database login is " + str(_login) + ", not sentinel_worker")
                await asyncio.sleep(3600)
            if not _gaps:
                break
            self.contract_missing = _gaps
            if _gaps != _said:
                log.error("contract check failed: missing %s", "; ".join(_gaps))
                _said = _gaps
            await self._wait(_waits.pop(0) if _waits else CONTRACT_RETRY_SEC)
            self._recheck_contract.clear()
        self.contract_missing = []
        self.contract_ok = True
        self._dispatch_recheck_at = time.monotonic() + CONTRACT_RETRY_SEC
        log.info("%s check_info=%s health=%s dispatch=%s",
                 "contract check recovered" if (_said is not None or broken) else "contract check passed",
                 "yes" if self.has_check_info else "no", "yes" if self.has_health else "no",
                 "off" if not self.s.dispatch else ("yes" if self.dispatch else "no"))
        self.dispatch_said = None
        self._say_dispatch()
        self._hb_now.set()

    def contract_broken(self, where):
        """A call found the functions gone or changed (a rebuild, an older database)."""
        if self.contract_ok:
            self.contract_ok = False
            log.error("contract check failed: %s", where)
        self._recheck_contract.set()

    # ---- check-in and heartbeat -------------------------------------------
    def capabilities(self):
        return {"checks": {"types": list(self.types), "unavailable": dict(self.unavailable),
                           "file_roots": list(self.usable_roots), "timeout_sec": self.s.timeout_sec,
                           "concurrency": self.s.concurrency, "reserved": self.s.reserved,
                           "enabled": self.s.checks_enabled},
                "dispatch": self.dispatch,
                "reasons": sorted(RUN_REASONS) if self.dispatch else []}

    async def _checkin(self, keep_status=False):
        """Check in: at start, after the row was lost (a rebuild), and with keep_status when the capabilities
        changed under a running conductor (dispatch came or went) - then the status it had is kept."""
        _version = __version__ + " (connect " + ds_connect_lib.__version__ + ")"
        _status = self.status
        try:
            _answer = json.loads(await self.pool.fetchval(
                SQL_CHECKIN, WORKER_TYPE, self.s.name, _version, self.s.address, self.s.port,
                json.dumps(self.capabilities())))
        except asyncpg.PostgresError as _e:
            if _hint(_e) in ("worker_name_required", "worker_type_required", "capabilities_invalid", "not_service"):
                self.fatal("check-in refused (" + str(_hint(_e)) + ")")
                await asyncio.sleep(3600)
            raise
        self.worker_id = _answer["worker_id"]
        self._caps_dispatch = self.dispatch
        self._row_gone_said = False
        self.status = "starting" if self.status != "stopping" else "stopping"
        self.last_heartbeat = _now_iso()
        log.info("checked in worker_id=%s first=%s dispatch=%s", self.worker_id, str(_answer.get("first_checkin")).lower(),
                 str(self.dispatch).lower())
        if keep_status and _status != "starting":
            self.status = _status
            self._hb_now.set()              # say so at once: the check-in left the row at starting
        if self.checks:
            self.checks.wake()

    async def _heartbeat_call(self, status, health):
        if health is not None:
            return await self.pool.fetchval(SQL_HEARTBEAT_HEALTH, self.worker_id, status, json.dumps(health), timeout=10)
        if status is not None:
            return await self.pool.fetchval(SQL_HEARTBEAT, self.worker_id, status, timeout=10)
        return await self.pool.fetchval(SQL_HEARTBEAT_PLAIN, self.worker_id, timeout=10)

    async def _send_heartbeat(self, final=False):
        """Alive, the status, and the health summary. It goes on while the contract for checks
        doesn't hold - with ready false and the reason - as long as the conductor has its row:
        a conductor that is running and knows what's wrong must not look offline. Results are
        another matter: none is posted while the contract doesn't hold."""
        if self.worker_id is None or self.pool is None or (self.lock != "held" and not final):
            return
        _health = self.health() if self.has_health else None
        if _health is not None:
            log.debug("heartbeat health=%s", json.dumps(_health, sort_keys=True))
        try:
            try:
                await self._heartbeat_call(self.status, _health)
            except asyncpg.PostgresError as _e:
                _h = _hint(_e)
                if _h == "health_invalid" and _health is not None:
                    # a bug in the summary: say so, and don't go offline over it
                    log.error("heartbeat summary refused (health_invalid): sent again without it")
                    await self._heartbeat_call(self.status, None)
                elif _h == "worker_status_invalid":
                    log.error("heartbeat status refused (%s): sending without one", self.status)
                    await self._heartbeat_call(None, None)
                elif _h == "worker_not_found" and not final:
                    if not self._row_gone_said:
                        self._row_gone_said = True
                        log.info("worker row gone (the database was rebuilt): checking in again")
                    try:
                        await self._checkin()       # the old id is kept until this succeeds: the next heartbeat tries again
                    except asyncpg.PostgresError as _e2:
                        if _e2.sqlstate not in CONTRACT_SQLSTATES:
                            raise
                        self.contract_broken("check-in " + str(_e2.sqlstate))
                    return
                elif _h == "not_service":
                    self.fatal("heartbeat refused (not_service)")
                    return
                elif _e.sqlstate in CONTRACT_SQLSTATES:
                    self.contract_broken("heartbeat " + str(_e.sqlstate))
                    return
                else:
                    raise
            self.last_heartbeat = _now_iso()
        except Exception as _e:
            if not _is_link_error(_e):
                log.warning("heartbeat failed (%s)", type(_e).__name__)

    async def _heartbeat_loop(self):
        while True:
            try:
                await asyncio.wait_for(self._hb_now.wait(), timeout=self.s.heartbeat_sec)
            except asyncio.TimeoutError:
                pass
            self._hb_now.clear()
            await self._send_heartbeat()

    # ---- /status ------------------------------------------------------------
    def status_document(self):
        _c = self.checks
        return {
            "worker": {"name": self.s.name, "id": self.worker_id, "version": __version__,
                       "connect_lib": ds_connect_lib.__version__, "status": self.status,
                       "started_at": self.started_at, "step": self.step},
            "database": {"connected": self.connected, "listening": self.listening, "lock": self.lock,
                         "contract": {"ok": self.contract_ok, "missing": list(self.contract_missing)},
                         "last_heartbeat": self.last_heartbeat, "health_sent": self.has_health},
            "checks": {"enabled": self.s.checks_enabled, "last_poll": _c.last_poll if _c else None,
                       "polls": _c.due_reads if _c else 0,
                       "due_at_last_poll": _c.due_at_last_poll if _c else None,
                       "in_flight": sorted(_c.in_flight) if _c else [],
                       "abandoned": len(_c.abandoned) if _c else 0,
                       "capacity": self.s.concurrency, "reserved": self.s.reserved,
                       "last_hour": _c.last_hour() if _c else {},
                       "problem": _c.problem if _c else None,
                       "types": list(self.types), "unavailable": dict(self.unavailable),
                       "file_roots": [dict(_r) for _r in self.roots]},
            "runs": self.runs.status_block() if self.runs else {"dispatch": False},
            # what goes with the heartbeat (when the database's heartbeat takes it: database.health_sent)
            "health": self.health(),
        }


# ---------------------------------------------------------------------------
# The check loop: a part of its own, so dispatch can sit beside it later.
# ---------------------------------------------------------------------------
class CheckLoop(object):
    def __init__(self, conductor):
        self.c = conductor
        self.s = conductor.s
        self.in_flight = set()              # data source ids being checked
        self.abandoned = set()              # ids whose thread the conductor gave up on and that still runs
        self.cool_off = {}                  # id -> monotonic time before which it isn't started again
        self.ended = {}                     # id -> monotonic time its last check ended (see _poll)
        self.tasks = set()
        self.last_poll = None
        self.due_at_last_poll = None
        self.problem = None                 # e.g. secret_missing: nothing can be read until the install has its key
        self._wake = asyncio.Event()
        self._events = collections.deque()  # (monotonic time, kind) for the last hour's counts
        self._said_secret_missing = False
        self.due_reads = 0

    # ---- waking and capacity ----------------------------------------------
    def wake(self):
        self._wake.set()

    def _busy(self):
        return len(self.in_flight) + len(self.abandoned)

    def _slot_free(self, requested):
        _limit = self.s.concurrency + (self.s.reserved if requested else 0)
        return self._busy() < _limit

    def _count(self, kind):
        self._events.append((time.monotonic(), kind))

    def last_hour(self):
        _cut = time.monotonic() - 3600
        while self._events and self._events[0][0] < _cut:
            self._events.popleft()
        _out = {"reachable": 0, "unreachable": 0, "not_checkable": 0, "not_stored": 0, "errors": 0}
        for _, _kind in self._events:
            _out[_kind] = _out.get(_kind, 0) + 1
        return _out

    async def pump(self):
        """Wake-ups are merged: one due-list read runs at a time, and however many
        wake-ups arrive while it runs, one more read follows it."""
        while True:
            await self._wake.wait()
            self._wake.clear()
            try:
                await self._poll()
            except asyncio.CancelledError:
                raise
            except Exception as _e:
                self._count("errors")
                log.error("check loop error (%s in poll)", type(_e).__name__)

    async def _poll(self):
        if not self.c.can_work():
            return
        if not self.s.checks_enabled:
            self.c.went_active()
            return
        _pool = self.c.pool
        _read_at = time.monotonic()
        try:
            self.due_reads += 1
            _due = json.loads(await _pool.fetchval(SQL_DUE, self.s.due_limit))
        except Exception as _e:
            if isinstance(_e, asyncpg.PostgresError) and _e.sqlstate in CONTRACT_SQLSTATES:
                self.c.contract_broken("due list " + str(_e.sqlstate))
            elif _hint(_e) == "not_service":
                self.c.fatal("due list refused (not_service)")
            elif not _is_link_error(_e):
                self._count("errors")
                log.error("due list read failed (%s)", type(_e).__name__)
            return
        self.last_poll = _now_iso()
        self.due_at_last_poll = len(_due)
        self.c.went_active()
        _now = time.monotonic()
        for _old in [_i for _i, _t in self.ended.items() if _t < _now - 120]:
            del self.ended[_old]
        for _row in _due:
            _id = _row["data_source_id"]
            if _id in self.in_flight or _id in self.abandoned or self.cool_off.get(_id, 0) > _now:
                continue
            if self.ended.get(_id, 0) >= _read_at:
                # this list was read while that check was still posting: it may show the row as it was
                # before its result. The wake-up the check's end caused reads again; if the row is
                # still due then (a result that wasn't stored, a newer request), it starts there.
                continue
            _requested = bool(_row.get("requested"))
            if not self._slot_free(_requested):
                continue                    # left for the next wake-up; a later requested row may still fit
            self._start(_id, _row["source_type"], _requested)

    def _start(self, data_source_id, source_type, requested):
        self.in_flight.add(data_source_id)
        _task = asyncio.get_running_loop().create_task(self._one(data_source_id, source_type, requested))
        self.tasks.add(_task)
        _task.add_done_callback(self.tasks.discard)
        return _task

    async def drain(self, seconds):
        if self.tasks:
            await asyncio.wait(list(self.tasks), timeout=seconds)

    # ---- one check ----------------------------------------------------------
    async def _one(self, data_source_id, source_type, requested):
        """Runs in the loop; the library's check runs in a worker thread. Returns the
        database's answer, or None when the check ended with no result."""
        try:
            return await self._check_and_post(data_source_id, source_type, requested)
        except _Skip as _s:
            if _s.error:
                self._count("errors")
                self.cool_off[data_source_id] = time.monotonic() + _s.cool
                asyncio.get_running_loop().call_later(_s.cool + 0.2, self.wake)
            return _s
        except asyncio.CancelledError:
            raise
        except Exception as _e:
            # a failure inside the conductor itself: the class and where, never a traceback
            self._count("errors")
            self.cool_off[data_source_id] = time.monotonic() + ERROR_COOL_OFF_SEC
            asyncio.get_running_loop().call_later(ERROR_COOL_OFF_SEC + 0.5, self.wake)
            log.error("check id=%s type=%s failed inside the conductor (%s)", data_source_id, source_type,
                      type(_e).__name__)
            return _Skip("error", error=True)
        finally:
            self.in_flight.discard(data_source_id)
            self.ended[data_source_id] = time.monotonic()
            self.wake()                     # a check that just ended is a wake-up

    async def _check_and_post(self, data_source_id, source_type, requested):
        _lib = ds_connect_lib
        _started_at = None
        _host = "-"
        # 1. can the library check this type here? If not, the connection isn't read at all
        _result = _lib.precheck(source_type, file_roots=self.s.file_roots)
        if _result is None:
            # 2. the connection and the database's time, in one statement
            _started_at, _connection = await self._read_connection(data_source_id, source_type)
            _host = _log_host(_connection)
            # 3. the library's check in a worker thread, with the hard limit around it
            _loop = asyncio.get_running_loop()
            _future = _loop.run_in_executor(self.c.executor, functools.partial(
                _lib.check, source_type, _connection, timeout=self.s.timeout_sec,
                file_roots=self.s.file_roots, ca_file=self.c.ca_file, proxy=self.s.proxy))
            _connection = None              # the thread holds the only reference now
            try:
                _result = await asyncio.wait_for(asyncio.shield(_future), self.s.timeout_sec)
            except asyncio.TimeoutError:
                # the thread can't be killed: ignore what it returns, count it until it ends
                self.abandoned.add(data_source_id)
                _future.add_done_callback(functools.partial(self._thread_ended, data_source_id))
                _params = {"s": self.s.timeout_sec}
                _result = _lib.CheckResult("unreachable", self.s.timeout_sec * 1000, "check_timeout", _params,
                                           _lib.message("check_timeout", _params))
        # 4. post the result
        _answer = await self._post(data_source_id, source_type, _result, _started_at)
        _stored = bool(_answer.get("stored"))
        self._count(_result.status if _stored else "not_stored")
        log.info("check id=%s type=%s host=%s requested=%s status=%s code=%s ms=%s stored=%s changed=%s",
                 data_source_id, source_type, _host, str(bool(requested)).lower(), _result.status,
                 _result.code or "-", _result.ms if _result.ms is not None else "-",
                 str(_stored).lower(), str(bool(_answer.get("status_changed"))).lower())
        if _answer.get("scrubbed"):
            # the library's own scrub missed a secret: a fault in its mapping. Never the text.
            log.error("check id=%s type=%s code=%s: the database scrubbed a secret from this result",
                      data_source_id, source_type, _result.code or "-")
        return _answer

    def _thread_ended(self, data_source_id, _future):
        self.abandoned.discard(data_source_id)
        self.wake()

    async def _read_connection(self, data_source_id, source_type):
        _pool = self.c.pool
        try:
            if _pool is None:
                raise ConnectionError("no database link")
            _row = await _pool.fetchrow(SQL_CONNECTION, data_source_id)
            _connection = json.loads(_row["connection"])
            if self.problem == "secret_missing":        # a connection was read: the install has its key now
                self.problem = None
                self._said_secret_missing = False
            return _row["started_at"], _connection if isinstance(_connection, dict) else {}
        except asyncpg.PostgresError as _e:
            _h = _hint(_e)
            _state = _e.sqlstate
        except Exception as _e:
            if not _is_link_error(_e):
                log.error("check id=%s type=%s: connection not read (%s)", data_source_id, source_type, type(_e).__name__)
            raise _Skip("link", error=True, cool=LINK_COOL_OFF_SEC) from None
        if _h in ("data_source_inactive", "data_source_not_found"):
            raise _Skip(_h)                 # ordinary: deactivated or gone since the due list was read
        if _h == "secret_missing":
            self.problem = "secret_missing"
            if not self._said_secret_missing:
                self._said_secret_missing = True
                log.error("the install has no encryption key (secret_missing): no connection can be read until it has one")
            raise _Skip(_h, error=True)
        if _h == "not_service":
            self.c.fatal("connection read refused (not_service)")
            raise _Skip(_h, error=True)
        if _state in CONTRACT_SQLSTATES:
            self.c.contract_broken("connection read " + str(_state))
            raise _Skip("contract", error=True)
        if _link_state(_state):
            raise _Skip("link", error=True, cool=LINK_COOL_OFF_SEC)
        log.error("check id=%s type=%s: connection not read (%s %s)", data_source_id, source_type, _state, _h or "-")
        raise _Skip("read", error=True)

    async def _post(self, data_source_id, source_type, result, started_at, plain=False):
        _pool = self.c.pool
        _code = None if plain else result.code
        _params = None if plain or result.params is None else json.dumps(result.params)
        _args = [data_source_id, result.status, result.ms, result.message, _code, _params]
        try:
            if _pool is None:
                raise ConnectionError("no database link")
            if started_at is None:
                _answer = await _pool.fetchval(SQL_POST, *_args)        # v_checked_at left out: the database's now()
            else:
                _answer = await _pool.fetchval(SQL_POST_AT, *_args, started_at)
            return json.loads(_answer)
        except asyncpg.PostgresError as _e:
            _h = _hint(_e)
            _state = _e.sqlstate
        except Exception as _e:
            # nothing was written; the row is still due and the next wake-up checks it again
            if not _is_link_error(_e):
                log.error("check id=%s type=%s: result not posted (%s)", data_source_id, source_type, type(_e).__name__)
            raise _Skip("link", error=True, cool=LINK_COOL_OFF_SEC) from None
        if _h == "message_invalid" and not plain:
            log.error("check id=%s type=%s code=%s: the database refused the code or parameters (message_invalid); "
                      "posting once more without them", data_source_id, source_type, result.code or "-")
            return await self._post(data_source_id, source_type, result, started_at, plain=True)
        if _h == "data_source_not_found":
            raise _Skip(_h)                 # gone: the database was rebuilt
        if _h == "not_testable":
            log.warning("check id=%s type=%s: a virtual data source was due; dropped", data_source_id, source_type)
            raise _Skip(_h)
        if _h == "status_invalid":
            self.c.contract_broken("the database refused status " + result.status + " (older than addendum 40b)")
            raise _Skip(_h, error=True)
        if _h == "not_service":
            self.c.fatal("result refused (not_service)")
            raise _Skip(_h, error=True)
        if _state in CONTRACT_SQLSTATES:
            self.c.contract_broken("result post " + str(_state))
            raise _Skip("contract", error=True)
        if _link_state(_state):
            raise _Skip("link", error=True, cool=LINK_COOL_OFF_SEC)
        log.error("check id=%s type=%s: result not posted (%s %s)", data_source_id, source_type, _state, _h or "-")
        raise _Skip("post", error=True)

    # ---- POST /check --------------------------------------------------------
    async def run_one(self, data_source_id):
        """One check asked for directly: the same path, on a slot a requested check may
        use. Returns (http status, body)."""
        if not (self.c.can_work() and self.s.checks_enabled):
            return 503, {"error": "not_ready", "step": self.c.step}
        if data_source_id in self.in_flight or data_source_id in self.abandoned:
            return 409, {"error": "in_flight", "data_source_id": data_source_id}
        if not self._slot_free(True):
            return 429, {"error": "no_slot"}
        _type = None
        _refused = None
        try:
            if self.c.has_check_info:
                try:
                    _type = json.loads(await self.c.pool.fetchval(SQL_CHECK_INFO, data_source_id)).get("source_type")
                except asyncpg.PostgresError as _e:
                    if _e.sqlstate == "42883":              # the function went away (a rebuild): the table, this once
                        self.c.has_check_info = False
                    else:
                        _refused = _hint(_e) or "database"
            if _type is None and _refused is None and not self.c.has_check_info:
                _type = await self.c.pool.fetchval(SQL_SOURCE_TYPE, data_source_id)
                if _type is None:
                    _refused = "data_source_not_found"
        except Exception as _e:
            log.error("POST /check id=%s: type not read (%s)", data_source_id, type(_e).__name__)
            return 503, {"error": "database"}
        if _refused == "data_source_not_found":
            return 404, {"error": _refused, "data_source_id": data_source_id}
        if _refused in ("data_source_inactive", "not_testable"):
            return 409, {"error": _refused, "data_source_id": data_source_id}
        if _refused is not None or _type is None:
            log.error("POST /check id=%s: type not read (%s)", data_source_id, _refused or "no type")
            return 503, {"error": "database"}
        if data_source_id in self.in_flight or data_source_id in self.abandoned:
            return 409, {"error": "in_flight", "data_source_id": data_source_id}
        _answer = await self._start(data_source_id, _type, True)
        if isinstance(_answer, _Skip):
            if _answer.reason == "data_source_not_found":
                return 404, {"error": _answer.reason, "data_source_id": data_source_id}
            if _answer.reason in ("data_source_inactive", "not_testable"):
                return 409, {"error": _answer.reason, "data_source_id": data_source_id}
            return 503, {"error": _answer.reason}
        return 200, _answer


# ---------------------------------------------------------------------------
# Calls to workers. A small HTTP/1.1 client on asyncio: JSON in, JSON out, Connection: close, a hard
# time limit around the whole exchange. Nothing in the loop waits on it: every call runs as a task of
# its own, and its answer is a wake-up for the next look, never a decision.
# ---------------------------------------------------------------------------
HTTP_MAX_BYTES = 1 << 20


async def worker_call(host, port, method, path, body=None, timeout=10):
    """(HTTP status, JSON document or None). Raises OSError, asyncio.TimeoutError or ValueError when there
    is no usable answer: the address refused, nothing came back in time, or what came back isn't HTTP."""
    async def _exchange():
        _reader, _writer = await asyncio.open_connection(str(host), int(port))
        try:
            _data = json.dumps(body).encode("utf-8") if body is not None else b""
            _head = ["%s %s HTTP/1.1" % (method, path), "Host: %s:%s" % (host, port),
                     "User-Agent: ds_conductor/" + __version__, "Accept: application/json", "Connection: close"]
            if body is not None:
                _head += ["Content-Type: application/json", "Content-Length: %d" % len(_data)]
            _writer.write(("\r\n".join(_head) + "\r\n\r\n").encode("ascii") + _data)
            await _writer.drain()
            _raw = b""
            while len(_raw) <= HTTP_MAX_BYTES:
                _chunk = await _reader.read(65536)
                if not _chunk:
                    break
                _raw += _chunk
        finally:
            _writer.close()
        _head, _sep, _rest = _raw.partition(b"\r\n\r\n")
        _lines = _head.split(b"\r\n")
        if not _sep or not _lines[0].startswith(b"HTTP/"):
            raise ValueError("not an HTTP answer")
        _status = int(_lines[0].split()[1])
        _headers = {}
        for _line in _lines[1:]:
            _k, _, _v = _line.partition(b":")
            _headers[_k.strip().lower()] = _v.strip()
        if _headers.get(b"transfer-encoding", b"").lower() == b"chunked":
            _body, _pos = b"", 0
            while True:
                _end = _rest.index(b"\r\n", _pos)
                _size = int(_rest[_pos:_end].split(b";")[0], 16)
                if _size == 0:
                    break
                _body += _rest[_end + 2:_end + 2 + _size]
                _pos = _end + 2 + _size + 2
            _rest = _body
        elif b"content-length" in _headers:
            _rest = _rest[:int(_headers[b"content-length"])]
        try:
            _doc = json.loads(_rest) if _rest.strip() else None
        except ValueError:
            _doc = None
        return _status, _doc
    return await asyncio.wait_for(_exchange(), timeout)


# ---------------------------------------------------------------------------
# The run loop: dispatch (package 2026-46-71, 02-dispatch.md). It sits beside the check loop and shares
# the lock, the links, the contract check, the reconnect and the merged wake-ups. The database is the
# only authority: the loop keeps nothing between looks it couldn't read again, compares no times of its
# own (lease ages, waits and windows are the database's), and an error in one run holds that run back
# for 30 seconds while the others carry on.
# ---------------------------------------------------------------------------
class _RunCallFailed(Exception):
    """A run function couldn't be called (the link, or the function is gone): this look ends here."""


_KEEP = object()                    # a run whose wait this look leaves as it is


def _ended(state):
    return state in ("done", "done_with_errors", "failed", "skipped", "cancelled")


def _waiting(queue):
    """Objects dealt in and not yet done: what has to reach zero before a later stage's queue can finish."""
    return max(0, int(queue.get("objects_in") or 0) - int(queue.get("objects_done") or 0))


def _stage_order(stage):
    return STAGES.index(stage["stage"]) if stage.get("stage") in STAGES else len(STAGES)


class _Look(object):
    """What one look knows about the workers, and what it has done with them so far."""

    def __init__(self, loop, workers, read_at):
        _now = time.monotonic()
        self.workers = workers
        self.by_id = {_w["worker_id"]: _w for _w in workers}
        self.able = {}                      # source type -> {worker_id: able}, by the database
        # handed a queue in this look, or a /run to it is in flight, or one ended while this look was reading: what
        # was read may show it free from before its claim (the next look reads it as it is)
        self.read_at = read_at
        self.taken = set(loop.calls) | {_k for _k, _t in loop.call_ended.items() if isinstance(_k, int) and _t >= read_at}
        self.refused = {_w for _w, _t in loop.refused.items() if _t > _now}
        self.held_back = set()              # worker types an older run waiting for its full number holds back
        self.counts = {"open": 0, "scheduled": 0, "running": 0, "paused": 0, "waiting": {}}
        self.with_claims = 0

    def counting(self, stage, source_type):
        """The workers that count for a stage of a run: of the stage's type, free and able by the database, with
        an address, not handed a queue in this look, not refused a moment ago, and not held back by an older run.
        In name order, so the choice is the same every time."""
        if stage in self.held_back:
            return []
        _able = self.able.get(source_type, {})
        return sorted((_w for _w in self.workers
                       if _w.get("type") == stage and _w.get("free") and _able.get(_w["worker_id"])
                       and _w.get("address") and _w.get("port")
                       and _w["worker_id"] not in self.taken and _w["worker_id"] not in self.refused),
                      key=lambda _w: (str(_w.get("name") or ""), _w["worker_id"]))

    def online_able(self, stage, source_type):
        """Workers of the type that are online and able, busy or not: whether a full number could ever arrive."""
        _able = self.able.get(source_type, {})
        return sum(1 for _w in self.workers if _w.get("type") == stage and _w.get("online") and _able.get(_w["worker_id"]))

    def count(self, run, wait, claimed):
        self.counts["open"] += 1
        if run.get("state") in ("scheduled", "running", "paused"):
            self.counts[run["state"]] += 1
        _code = (wait[0] if wait else None) if wait is not _KEEP else ((run.get("wait") or {}).get("code"))
        if _code:
            self.counts["waiting"][_code] = self.counts["waiting"].get(_code, 0) + 1
        if claimed:
            self.with_claims += 1


class RunLoop(object):
    def __init__(self, conductor):
        self.c = conductor
        self.s = conductor.s
        self._wake = asyncio.Event()
        self._timer_handle = None
        self.looks = 0
        self.last_look = None
        self.look_ms = None
        self.calls = {}                     # worker_id -> (run, stage, partition): a /run call in flight
        self.call_ended = {}                # (run, stage, partition) and worker_id -> monotonic time its last /run ended
        self.tasks = set()                  # every call to a worker in flight, and every ending
        self.refused = {}                   # worker_id -> monotonic time before which it isn't chosen
        self.stops_sent = set()             # (run, stage, partition, attempt, why): a /stop is sent once
        self.faults_said = set()            # (run, stage, partition, attempt, kind): a fault is logged once
        self.probes = {}                    # worker_id -> task: GET /status in flight
        self.probed = {}                    # worker_id -> (monotonic time, no_answer | db_down | other)
        self.held = {}                      # run_id -> monotonic time: its handling failed; left alone till then
        self.end_held = {}                  # run_id -> monotonic time: its ending was refused; not tried till then
        self.ending = {}                    # run_id -> task: an ending in flight
        self.ending_done = {}               # run_id -> monotonic time its last ending task finished
        self.grace_until = 0.0
        self._grace_said = False
        self.counts = {"open": 0, "scheduled": 0, "running": 0, "paused": 0, "waiting": {}}
        self.with_claims = 0

    # ---- waking ---------------------------------------------------------------
    def wake(self):
        self._wake.set()

    async def pump(self):
        """One look at a time: a wake-up that arrives during a look causes one more straight after it."""
        while True:
            await self._wake.wait()
            self._wake.clear()
            _next = None
            try:
                _next = await self.look()
            except asyncio.CancelledError:
                raise
            except Exception as _e:
                log.error("run loop error (%s in look)", type(_e).__name__)
            self._schedule(_next)

    async def timer(self):
        while True:
            await asyncio.sleep(self.s.run_poll_sec)
            self.wake()

    def _schedule(self, seconds):
        """A nearer time than the timer: a queue's wait running out, a window opening or closing."""
        if self._timer_handle is not None:
            self._timer_handle.cancel()
            self._timer_handle = None
        if seconds is not None and seconds < self.s.run_poll_sec:
            self._timer_handle = asyncio.get_running_loop().call_later(max(0.2, seconds), self.wake)

    async def after_connect(self, trouble):
        """After every connect. When the link came back - this process lost it or couldn't reach the database,
        or the database itself started less than a grace period ago - nothing is reclaimed for
        DS_RECLAIM_GRACE_SEC: no worker could renew while the database was out, so every lease looks stale."""
        self.probed.clear()
        if not self.s.reclaim_grace_sec:
            return
        _why = "the database link came back" if trouble else None
        if _why is None:
            try:
                _up = await self.c.conn.fetchval("select extract(epoch from now() - pg_postmaster_start_time())::int",
                                                 timeout=10)
                if _up is not None and _up < self.s.reclaim_grace_sec:
                    _why = "the database started %ds ago" % _up
            except Exception:
                pass
        if _why:
            self.grace_until = time.monotonic() + self.s.reclaim_grace_sec
            self._grace_said = False
            log.info("reclaim grace %ds: %s", self.s.reclaim_grace_sec, _why)

    def drop_calls(self):
        for _t in list(self.tasks) + list(self.probes.values()):
            _t.cancel()

    # ---- what it says ---------------------------------------------------------------
    def summary(self):
        """For the health summary's detail: counts and codes only."""
        if not self.c.dispatch:
            return {"dispatch": False}
        return {"dispatch": True, "open": self.counts["open"], "running": self.counts["running"],
                "paused": self.counts["paused"], "waiting": dict(self.counts["waiting"])}

    def status_block(self):
        return {"dispatch": self.c.dispatch, "enabled": self.s.dispatch, "missing": list(self.c.dispatch_missing or []),
                "open": self.counts["open"], "scheduled": self.counts["scheduled"], "running": self.counts["running"],
                "paused": self.counts["paused"], "with_claims": self.with_claims, "waiting": dict(self.counts["waiting"]),
                "looks": self.looks, "last_look": self.last_look, "look_ms": self.look_ms,
                "calls_in_flight": {"run": len(self.calls), "all": len(self.tasks) + len(self.probes)},
                "endings_in_flight": len(self.ending),
                "reclaim_grace_left": max(0, int(self.grace_until - time.monotonic()))}

    # ---- the database ---------------------------------------------------------------
    async def _db(self, sql, *args, timeout=None):
        _pool = self.c.pool
        if _pool is None:
            raise _RunCallFailed()
        try:
            return json.loads(await _pool.fetchval(sql, *args, timeout=timeout or DB_CALL_TIMEOUT_SEC))
        except asyncpg.PostgresError as _e:
            if _e.sqlstate in CONTRACT_SQLSTATES:
                self.c.dispatch_broken(sql.split("sentinel.", 1)[1].split("(", 1)[0] + " " + str(_e.sqlstate))
                raise _RunCallFailed() from None
            if _hint(_e) == "not_service":
                self.c.fatal("run call refused (not_service)")
                raise _RunCallFailed() from None
            if _link_state(_e.sqlstate):
                raise _RunCallFailed() from None
            raise
        except _RunCallFailed:
            raise
        except Exception as _e:
            if _is_link_error(_e):
                raise _RunCallFailed() from None
            raise

    # ---- one look (02, section 3) ---------------------------------------------------------
    async def look(self):
        if not (self.c.can_work() and self.c.dispatch):
            self.counts = {"open": 0, "scheduled": 0, "running": 0, "paused": 0, "waiting": {}}
            self.with_claims = 0
            return None
        _t0 = time.monotonic()
        self.looks += 1
        for _old in [_k for _k, _t in self.call_ended.items() if _t < _t0 - 120]:
            del self.call_ended[_old]
        for _old in [_k for _k, _t in self.ending_done.items() if _t < _t0 - 120]:
            del self.ending_done[_old]
        try:
            _made = await self._db(SQL_RUNS_SCHEDULED)          # the database's clock tick: decides nothing here
            if _made.get("created") or _made.get("skipped"):
                log.info("runs scheduled created=%s skipped=%s",
                         ",".join(str(_r) for _r in _made.get("created") or []) or "-",
                         ",".join("%s:%s" % (_k.get("job_id"), _k.get("open_run_id")) for _k in _made.get("skipped") or []) or "-")
            _due = await self._db(SQL_RUNS_DUE, RUN_DUE_LIMIT)
            _look = _Look(self, await self._db(SQL_WORKERS, None, None), _t0)
            for _type in sorted({_r["data_source"]["source_type"] for _r in _due if self._needs_workers(_r)}):
                _look.able[_type] = {_w["worker_id"]: bool(_w.get("able"))
                                     for _w in await self._db(SQL_WORKERS, None, _type)}
        except _RunCallFailed:
            return None
        except asyncpg.PostgresError as _e:
            log.error("run look failed (%s %s)", _e.sqlstate, _hint(_e) or "-")
            return None
        _next = []
        _now = time.monotonic()
        for _old in [_k for _k, _t in self.refused.items() if _t <= _now]:
            del self.refused[_old]
        for _run in _due:                   # oldest request first
            _rid = _run["run_id"]
            if self.held.get(_rid, 0) > _now:
                _look.count(_run, _KEEP, self._claimed(_run))
                continue
            try:
                _wait = await self._one(_run, _look, _next)
                await self._write_wait(_run, _wait)
                _look.count(_run, _wait, self._claimed(_run))
            except _RunCallFailed:
                return None
            except Exception as _e:
                self.held[_rid] = time.monotonic() + RUN_HOLD_SEC
                _look.count(_run, _KEEP, self._claimed(_run))
                log.error("run id=%s failed inside the conductor (%s): left for %ds", _rid, type(_e).__name__, RUN_HOLD_SEC)
        self.counts, self.with_claims = _look.counts, _look.with_claims
        self.last_look = _now_iso()
        self.look_ms = int((time.monotonic() - _t0) * 1000)
        return min(_next) if _next else None

    @staticmethod
    def _claimed(run):
        return any(_q.get("state") == "claimed" for _st in run.get("stages") or [] for _q in _st.get("queues") or [])

    @staticmethod
    def _needs_workers(run):
        if run.get("cancel_requested") or not run.get("window_open", True):
            return False
        _stages = run.get("stages") or []
        if not any(_st.get("queue_count") for _st in _stages):
            return run.get("blocked_by") is None
        return any(_q.get("state") == "pending" for _st in _stages for _q in _st.get("queues") or [])

    async def _one(self, run, look, next_times):
        """One run: returns the wait it should carry (a (code, params) pair, None for none, or _KEEP)."""
        _stages = sorted(run.get("stages") or [], key=_stage_order)
        if run.get("window_changes_in") is not None:
            next_times.append(run["window_changes_in"] + NEAR_WAKE_SEC)
        if not any(_st.get("queue_count") for _st in _stages):
            return await self._not_begun(run, _stages, look)
        return await self._begun(run, _stages, look, next_times)

    # ---- a run that hasn't begun (02, section 4) ---------------------------------------------
    async def _not_begun(self, run, stages, look):
        _rid = run["run_id"]
        _type = run["data_source"]["source_type"]
        if run.get("cancel_requested"):
            return _KEEP                    # the database has ended it
        if run.get("blocked_by") is not None:
            return ("source_busy", {})
        if not run.get("window_open", True):
            return ("outside_window", {"time": run.get("window_opens_time") or "-"})
        _asked = {_st["stage"]: (1 if _st["stage"] == "discover" else int(_st.get("asked") or 0)) for _st in stages}
        _free = {_st["stage"]: look.counting(_st["stage"], _type) for _st in stages}
        _short = [_st["stage"] for _st in stages if len(_free[_st["stage"]]) < _asked[_st["stage"]]]
        _later = [_st["stage"] for _st in stages if _st["stage"] != "discover"]
        if not _short:
            _queues = {_s: _asked[_s] for _s in _later}
        elif run.get("if_short") == "start":
            _none = [_s for _s in _short if not _free[_s]]
            if _none:
                return ("no_worker_available", {"stage": _none[0]})
            _queues = {_s: min(_asked[_s], len(_free[_s])) for _s in _later}
        else:
            # waits for the full number, and holds those workers back from newer runs - when that number could
            # ever arrive: when as many of the type are online and able, busy or not, as it asks for
            for _s in _short:
                if look.online_able(_s, _type) >= _asked[_s]:
                    look.held_back.add(_s)
            _s = _short[0]
            return ("workers_short", {"asked": _asked[_s], "stage": _s, "free": len(_free[_s])})
        try:
            _answer = await self._db(SQL_RUN_BEGIN, _rid, json.dumps(_queues))
        except asyncpg.PostgresError as _e:
            _h = _hint(_e)
            if _h == "run_blocked":
                return ("source_busy", {})
            if _h == "outside_window":
                return ("outside_window", {"time": run.get("window_opens_time") or "-"})
            if _h == "workers_short":
                _s = (_short or _later or ["discover"])[0]
                return ("workers_short", {"asked": _asked.get(_s, 1), "stage": _s, "free": len(_free.get(_s, []))})
            if _h in ("run_not_open", "run_not_found"):
                return _KEEP
            self.held[_rid] = time.monotonic() + RUN_HOLD_SEC
            log.error("run id=%s begin refused (%s %s): a fault of the conductor's; left for %ds",
                      _rid, _e.sqlstate, _h or "-", RUN_HOLD_SEC)
            return _KEEP
        log.info("run id=%s begin queues=%s asked=%s if_short=%s", _rid,
                 ",".join(["discover:1"] + ["%s:%s" % (_s, _queues[_s]) for _s in _later]),
                 ",".join("%s:%s" % (_s, _asked[_s]) for _s in _later if _queues[_s] < _asked[_s]) or "-",
                 run.get("if_short"))
        # every queue at once - the later stages' too, before anything has reached them
        for _q in sorted(_answer.get("queues") or [], key=lambda _q: (STAGES.index(_q["stage"]), _q["partition_id"])):
            if _q.get("state") != "pending":
                continue
            _w = self._choose(look, _q["stage"], _type)
            if _w is not None:
                look.taken.add(_w["worker_id"])
                self._hand_out(_rid, _q["stage"], _q["partition_id"], _w)
        return None

    # ---- choosing a worker (02, section 5) ---------------------------------------------------
    def _choose(self, look, stage, source_type, avoid=None):
        """THE one place a worker is chosen, so that a rule for particular workers can go here later. Today:
        for a queue just given up by a failure, a worker other than its last one when there is one; otherwise
        by name."""
        _candidates = look.counting(stage, source_type)
        if avoid is not None:
            _others = [_w for _w in _candidates if _w["worker_id"] != avoid]
            _candidates = _others or _candidates
        return _candidates[0] if _candidates else None

    # ---- handing out (02, section 6) -------------------------------------------------------------
    def _hand_out(self, run_id, stage, partition_id, worker):
        self.calls[worker["worker_id"]] = (run_id, stage, partition_id)
        self._task(self._run_call(run_id, stage, partition_id, worker))

    def _task(self, coro):
        _t = asyncio.get_running_loop().create_task(coro)
        self.tasks.add(_t)
        _t.add_done_callback(self.tasks.discard)
        return _t

    async def _run_call(self, run_id, stage, partition_id, worker):
        """POST /run. It only asks: what makes the queue the worker's is its claim, and the conductor learns of
        that from the database. A call that wasn't answered decides nothing."""
        _wid = worker["worker_id"]
        _t0 = time.monotonic()
        _attempt = "-"
        try:
            _status, _doc = await worker_call(worker.get("address"), worker.get("port"), "POST", "/run",
                                              {"run_id": run_id, "stage": stage, "partition_id": partition_id},
                                              timeout=self.s.run_call_timeout_sec)
            _doc = _doc if isinstance(_doc, dict) else {}
            if _status == 200 and _doc.get("claimed"):
                _answer, _attempt = "claimed", _doc.get("attempt", "-")
            else:
                _answer = str(_doc.get("why") or ("http_%d" % _status))[:40]
                if _answer in ("busy", "not_ready", "wrong_stage") or _status in (400, 503) or _answer.startswith("http_"):
                    self.refused[_wid] = time.monotonic() + WORKER_REFUSED_SEC      # not what the database said
        except (OSError, asyncio.TimeoutError, ValueError, IndexError):
            _answer = "no_answer"
            self.refused[_wid] = time.monotonic() + WORKER_REFUSED_SEC
        finally:
            if self.calls.get(_wid) == (run_id, stage, partition_id):
                del self.calls[_wid]
            self.call_ended[(run_id, stage, partition_id)] = self.call_ended[_wid] = time.monotonic()
        (log.warning if _answer == "wrong_stage" else log.info)(
            "run id=%s handout stage=%s partition=%s worker_id=%s answer=%s attempt=%s ms=%d",
            run_id, stage, partition_id, _wid, _answer, _attempt, int((time.monotonic() - _t0) * 1000))
        self.wake()                         # a hand-out that failed is tried elsewhere at once

    def _stop_call(self, worker, run_id, stage, partition_id, why):
        """POST /stop: 'request' brings the worker's next renewal forward; 'expired' is the last word to a worker
        that stopped renewing. Not waited for, and it decides nothing."""
        if worker is None or not worker.get("address") or not worker.get("port"):
            return

        async def _go():
            try:
                _status, _ = await worker_call(worker["address"], worker["port"], "POST", "/stop",
                                               {"run_id": run_id, "stage": stage, "partition_id": partition_id, "why": why},
                                               timeout=self.s.run_call_timeout_sec)
                _answer = str(_status)
            except (OSError, asyncio.TimeoutError, ValueError, IndexError):
                _answer = "no_answer"
            log.info("run id=%s stop stage=%s partition=%s worker_id=%s why=%s answer=%s",
                     run_id, stage, partition_id, worker["worker_id"], why, _answer)
        self._task(_go())

    def _probe(self, worker):
        """GET /status on a worker whose lease and heartbeat are both stale, beside the loop: what it answers
        is read at the next look."""
        _wid = worker["worker_id"]
        if _wid in self.probes or not worker.get("address") or not worker.get("port"):
            if not worker.get("address") or not worker.get("port"):
                self.probed[_wid] = (time.monotonic(), "no_answer")
            return

        async def _go():
            try:
                _status, _doc = await worker_call(worker["address"], worker["port"], "GET", "/status", None,
                                                  timeout=PROBE_TIMEOUT_SEC)
                _db = (_doc or {}).get("database") if isinstance(_doc, dict) else None
                _outcome = "db_down" if isinstance(_db, dict) and _db.get("connected") is False else "other"
            except (OSError, asyncio.TimeoutError, ValueError, IndexError):
                _outcome = "no_answer"
            finally:
                self.probes.pop(_wid, None)
            self.probed[_wid] = (time.monotonic(), _outcome)
            log.info("worker id=%s status asked answer=%s", _wid, _outcome)
            self.wake()
        self.probes[_wid] = asyncio.get_running_loop().create_task(_go())

    # ---- a run that has begun (02, sections 7 to 10) -------------------------------------------
    async def _begun(self, run, stages, look, next_times):
        _rid = run["run_id"]
        _type = run["data_source"]["source_type"]
        _cancel = bool(run.get("cancel_requested"))
        _open = run.get("window_open", True)
        _claimed = _handing = _retry_waiting = _stopped = False
        _no_worker = []
        _in_flight = set(self.calls.values())
        for _st in stages:
            for _q in _st.get("queues") or []:
                _key = (_rid, _st["stage"], _q["partition_id"])
                _state = _q.get("state")
                if _state == "pending":
                    _left = int(_q.get("wait_left") or 0)
                    if _left > 0:
                        _retry_waiting = True
                        next_times.append(_left + NEAR_WAKE_SEC)
                    elif not _open or _cancel:
                        pass                # the window is closed, or the run is being cancelled: hand out nothing
                    elif _st["stage"] != "discover" and _waiting(_q) == 0 and not _st.get("more_coming"):
                        pass                # nothing will ever reach it: ending the stage closes it
                    elif _key in _in_flight or self.call_ended.get(_key, 0) >= look.read_at:
                        _handing = True     # a call for it is in flight, or ended after this look's read: next look
                    else:
                        _last = (_q.get("last_worker") or {}).get("worker_id") if _q.get("reason") else None
                        _w = self._choose(look, _st["stage"], _type, avoid=_last)
                        if _w is None:
                            _no_worker.append(_st["stage"])
                        else:
                            look.taken.add(_w["worker_id"])
                            self._hand_out(_rid, _st["stage"], _q["partition_id"], _w)
                            _handing = True
                elif _state == "claimed":
                    _claimed = True
                    await self._watch(run, _st, _q, look)
                elif _state == "stopped":
                    _stopped = True
        # endings: in order, one stage a look, beside the loop - and not from a read that began before this run's last
        # ending finished (it may show the run as it was before that ending)
        if (_rid not in self.ending and self.end_held.get(_rid, 0) <= time.monotonic()
                and self.ending_done.get(_rid, 0) < look.read_at):
            if _cancel:
                if not _claimed:
                    self._end(run, [("stage", _st["stage"], "cancelled", None, None) for _st in stages
                                    if not _ended(_st.get("state"))] + [("run", "cancelled", None, None)])
            else:
                _plan = self._ending_plan(stages)
                if _plan:
                    self._end(run, _plan)
        # the run's wait (02, section 10)
        if _claimed or _handing:
            return None
        if not _open:
            return ("outside_window", {"time": run.get("window_opens_time") or "-"})
        if _cancel:
            return _KEEP
        if _retry_waiting and not _no_worker:
            return ("retry_wait", {})
        if _no_worker:
            return ("no_worker_available", {"stage": _no_worker[0]})
        if _stopped and all(_q.get("state") in ("done", "failed", "cancelled", "stopped")
                            or (_q.get("state") == "pending" and _st["stage"] != "discover" and _waiting(_q) == 0
                                and not _st.get("more_coming"))
                            for _st in stages for _q in _st.get("queues") or []):
            return ("queue_stopped", {})
        return None

    async def _watch(self, run, stage, queue, look):
        """A claimed queue: nudge on a stop or cancel; when the lease is stale, the table in 02 section 7."""
        _rid, _stage, _part = run["run_id"], stage["stage"], queue["partition_id"]
        _wid = (queue.get("worker") or {}).get("worker_id")
        _attempt = queue.get("attempt")
        _worker = look.by_id.get(_wid)
        if not queue.get("lease_stale"):
            if queue.get("stop_requested") or run.get("cancel_requested"):
                _once = (_rid, _stage, _part, _attempt, "request")
                if _once not in self.stops_sent:
                    self.stops_sent.add(_once)
                    self._stop_call(_worker, _rid, _stage, _part, "request")
            return
        if self.grace_until > time.monotonic():
            if not self._grace_said:
                self._grace_said = True
                log.info("run id=%s stale lease stage=%s partition=%s left: reclaim grace %ds left", _rid, _stage, _part,
                         int(self.grace_until - time.monotonic()))
            return
        if queue.get("lease_expired"):
            _once = (_rid, _stage, _part, _attempt, "expired")
            if _once not in self.stops_sent:
                self.stops_sent.add(_once)
                self._stop_call(_worker, _rid, _stage, _part, "expired")
            await self._reclaim(_rid, _stage, _part, _wid, _attempt)
            return
        if _worker is None:
            await self._reclaim(_rid, _stage, _part, _wid, _attempt)        # its row is gone
            return
        if _worker.get("online"):
            if _worker.get("status") == "starting":
                return                      # it may be about to pick its queue up again
            _mine = ((_worker.get("health") or {}).get("detail") or {}).get("queue")
            if isinstance(_mine, dict) and (_mine.get("run_id"), _mine.get("stage"), _mine.get("partition_id")) == (_rid, _stage, _part):
                self._fault(_rid, _stage, _part, _wid, _attempt, "works", "works on this queue and doesn't renew its lease")
                return
            await self._reclaim(_rid, _stage, _part, _wid, _attempt)        # it has moved on, or restarted empty
            return
        _asked = self.probed.get(_wid)
        if _asked is None or time.monotonic() - _asked[0] > PROBE_FRESH_SEC:
            self._probe(_worker)
            return
        if _asked[1] == "no_answer":
            await self._reclaim(_rid, _stage, _part, _wid, _attempt)        # gone
        elif _asked[1] == "other":
            self._fault(_rid, _stage, _part, _wid, _attempt, "unreached",
                        "answers the conductor but doesn't reach the database, and doesn't say so")
        # db_down: it is holding its place, and carries on when the database is back

    def _fault(self, run_id, stage, partition_id, worker_id, attempt, kind, text):
        _once = (run_id, stage, partition_id, attempt, kind)
        if _once not in self.faults_said:
            self.faults_said.add(_once)
            log.warning("run id=%s fault stage=%s partition=%s worker_id=%s attempt=%s: the worker %s",
                        run_id, stage, partition_id, worker_id, attempt, text)

    async def _reclaim(self, run_id, stage, partition_id, worker_id, attempt):
        try:
            _answer = await self._db(SQL_RECLAIM, run_id, stage, partition_id, worker_id, attempt, "worker_lost", "{}",
                                     RUN_REASONS["worker_lost"])
        except asyncpg.PostgresError as _e:
            log.error("run id=%s reclaim stage=%s partition=%s refused (%s %s)", run_id, stage, partition_id,
                      _e.sqlstate, _hint(_e) or "-")
            return
        if _answer.get("reclaimed"):
            log.info("run id=%s reclaim stage=%s partition=%s worker_id=%s attempt=%s code=worker_lost state=%s",
                     run_id, stage, partition_id, worker_id, attempt, _answer.get("state"))
        else:                               # not an error: the worker renewed, or the queue moved on
            log.info("run id=%s reclaim stage=%s partition=%s worker_id=%s attempt=%s refused=%s",
                     run_id, stage, partition_id, worker_id, attempt, _answer.get("why"))

    # ---- endings (02, section 8) ----------------------------------------------------------
    def _ending_plan(self, stages):
        """The next ending this run can take: the first open stage, when the one before it has ended and none of
        its queues is claimed, stopped, or pending with work in it; with the run's own ending when that was its
        last open stage. None when nothing can end yet."""
        for _i, _st in enumerate(stages):
            if _ended(_st.get("state")):
                continue
            if _i > 0 and not _ended(stages[_i - 1].get("state")):
                return None
            _qs = _st.get("queues") or []
            if any(_q.get("state") in ("claimed", "stopped") for _q in _qs):
                return None
            if _st["stage"] == "discover":
                if not _qs or any(_q.get("state") not in ("done", "failed") for _q in _qs):
                    return None
            elif _st.get("more_coming") or any(_q.get("state") == "pending" and _waiting(_q) > 0 for _q in _qs):
                return None
            _how = self._stage_ending(_st)
            _plan = [("stage", _st["stage"]) + _how]
            if all(_ended(_o.get("state")) for _o in stages[_i + 1:]):
                _plan.append(("run",) + self._run_ending(stages, {_st["stage"]: _how[0]}))
            return _plan
        return [("run",) + self._run_ending(stages, {})]

    @staticmethod
    def _stage_ending(stage):
        """(state, code, params) for a stage that can end."""
        _qs = stage.get("queues") or []
        _failed_queue = any(_q.get("state") == "failed" for _q in _qs)
        _failed = sum(int(_q.get("objects_failed") or 0) for _q in _qs)
        if stage["stage"] == "discover":
            if _failed_queue:
                return ("failed", "attempts_used_up", {})
            if _failed:
                return ("done_with_errors", "discovery_partial", {"n": _failed})
            return ("done", None, None)
        if sum(int(_q.get("objects_in") or 0) for _q in _qs) == 0:
            return ("skipped", "no_objects_found", {})
        if _failed_queue:
            return ("done_with_errors", "attempts_used_up", {})
        if _failed:
            return ("done_with_errors", "objects_failed", {"n": _failed})
        return ("done", None, None)

    @staticmethod
    def _run_ending(stages, now_ended):
        """(state, code, params) for a run whose stages have all ended; now_ended has the ones this look ends."""
        def _state(_st):
            return now_ended.get(_st["stage"], _st.get("state"))

        def _failed_queue(_st):
            return any(_q.get("state") == "failed" for _q in _st.get("queues") or [])

        def _failed(_st):
            return sum(int(_q.get("objects_failed") or 0) for _q in _st.get("queues") or [])
        _disc = [_st for _st in stages if _st["stage"] == "discover"]
        _later = [_st for _st in stages if _st["stage"] != "discover"]
        if _disc and _state(_disc[0]) == "failed":
            return ("failed", "discovery_incomplete", {})
        if any(_state(_st) == "done_with_errors" and _failed_queue(_st) for _st in _later):
            return ("completed_with_errors", "attempts_used_up", {})
        _n = sum(_failed(_st) for _st in _later if _state(_st) == "done_with_errors")
        if _n:
            return ("completed_with_errors", "objects_failed", {"n": _n})
        if _disc and _state(_disc[0]) == "done_with_errors":
            return ("completed_with_errors", "discovery_partial", {"n": _failed(_disc[0])})
        return ("completed", None, None)

    def _end(self, run, plan):
        """Endings run beside the loop, one run's at a time, with the long limit: ending discover carries the
        missing pass, and ending the run the clearing of its queue rows."""
        _rid = run["run_id"]

        async def _go():
            try:
                for _step in plan:
                    _t0 = time.monotonic()
                    if _step[0] == "stage":
                        _, _stage, _state, _code, _params = _step
                        await self._db(SQL_STAGE_END, _rid, _stage, _state, _code,
                                       json.dumps(_params) if _code else None,
                                       RUN_REASONS[_code].format(**_params) if _code else None,
                                       timeout=self.s.run_end_timeout_sec)
                        log.info("run id=%s stage_end stage=%s state=%s%s ms=%d", _rid, _stage, _state,
                                 (" code=" + _code + "".join(" %s=%s" % (_k, _params[_k]) for _k in sorted(_params)))
                                 if _code else "", int((time.monotonic() - _t0) * 1000))
                    else:
                        _, _state, _code, _params = _step
                        await self._db(SQL_RUN_END, _rid, _state, _code, json.dumps(_params) if _code else None,
                                       RUN_REASONS[_code].format(**_params) if _code else None,
                                       timeout=self.s.run_end_timeout_sec)
                        log.info("run id=%s end state=%s%s ms=%d", _rid, _state,
                                 (" code=" + _code + "".join(" %s=%s" % (_k, _params[_k]) for _k in sorted(_params)))
                                 if _code else "", int((time.monotonic() - _t0) * 1000))
            except asyncpg.PostgresError as _e:
                _h = _hint(_e)
                self.end_held[_rid] = time.monotonic() + RUN_HOLD_SEC
                log.warning("run id=%s %s refused (%s %s): looked at again in %ds", _rid,
                            "stage_end stage=" + _step[1] if _step[0] == "stage" else "end", _e.sqlstate, _h or "-",
                            RUN_HOLD_SEC)
                asyncio.get_running_loop().call_later(RUN_HOLD_SEC + 0.5, self.wake)
            except (_RunCallFailed, asyncio.CancelledError):
                pass
            except Exception as _e:
                self.end_held[_rid] = time.monotonic() + RUN_HOLD_SEC
                log.error("run id=%s ending failed inside the conductor (%s)", _rid, type(_e).__name__)
            finally:
                self.ending.pop(_rid, None)
                self.ending_done[_rid] = time.monotonic()
                self.wake()
        self.ending[_rid] = self._task(_go())

    # ---- the run's wait (02, section 10) -----------------------------------------------------
    async def _write_wait(self, run, wait):
        """Written only when its code or parameters differ from what the due list showed."""
        if wait is _KEEP:
            return
        _now = run.get("wait") or {}
        if (_now.get("code"), _now.get("params") or {}) == ((wait[0], wait[1]) if wait else (None, {})):
            return
        _code, _params = (wait[0], wait[1]) if wait else (None, {})
        try:
            await self._db(SQL_RUN_WAITING, run["run_id"], _code, json.dumps(_params) if _code else None,
                           RUN_REASONS[_code].format(**_params) if _code else None)
        except asyncpg.PostgresError as _e:
            log.warning("run id=%s wait not written (%s %s)", run["run_id"], _e.sqlstate, _hint(_e) or "-")
            return
        log.info("run id=%s wait code=%s%s", run["run_id"], _code or "-",
                 "".join(" %s=%s" % (_k, _params[_k]) for _k in sorted(_params)) if _code else "")


# ---------------------------------------------------------------------------
# The service. For people and for the stack, never for the app: these endpoints have no
# sign-in, so the stack publishes no port for the conductor and nginx has no location for it.
# ---------------------------------------------------------------------------
app = Quart(__name__)
conductor = None
settings = None


def load_settings(env=None):
    """Called by main.py before the server starts, so a setting that can't be used stops
    the process at once with a message that names it."""
    global settings
    settings = Settings(env)
    return settings


@app.before_serving
async def _startup():
    global conductor, settings
    if settings is None:
        settings = Settings()
    setup_logging(settings)
    conductor = Conductor(settings)
    await conductor.start()


@app.after_serving
async def _shutdown():
    if conductor is not None:
        await conductor.stop()


@app.route("/health", methods=["GET"])
async def health():
    """200 while the process is up. The container's health check."""
    return jsonify({"status": "up"}), 200


@app.route("/ready", methods=["GET"])
async def ready():
    """200 when the conductor is doing its work: connected, contract held, lock held, listening, and
    nothing in its way. The same answer the heartbeat's summary gives as 'ready'."""
    _ok = conductor is not None and conductor.ready()
    return jsonify({"ready": bool(_ok), "step": conductor.step if conductor else "settings"}), (200 if _ok else 503)


@app.route("/status", methods=["GET"])
async def status():
    """The state as JSON: ids and counts. No name, no host, no connection value, no message text."""
    if conductor is None:
        return jsonify({"worker": {"step": "settings"}}), 200
    return jsonify(conductor.status_document()), 200


@app.route("/check", methods=["POST"])
async def check():
    """Run one data source's check through the same path and return the database's answer."""
    if conductor is None or conductor.checks is None:
        return jsonify({"error": "not_ready"}), 503
    _body = await request.get_json(silent=True)
    _id = _body.get("data_source_id") if isinstance(_body, dict) else None
    if isinstance(_id, bool) or not isinstance(_id, int) or _id <= 0:
        return jsonify({"error": "data_source_id must be a whole number"}), 400
    _status, _answer = await conductor.checks.run_one(_id)
    return jsonify(_answer), _status
