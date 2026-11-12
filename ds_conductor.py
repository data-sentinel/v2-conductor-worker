# ds_conductor.py - Data Sentinel Vantage (V2) conductor
#
# The first V2 worker. After work package 2026-46-31 it does one job: it connects to the V2
# repository database as sentinel_worker, says it is running, and answers every data source
# availability check the database says is due. Dispatching scans comes later, into this same
# service, beside the check loop: it will share the database link, the lock and the heartbeat.
#
# The V1 conductor's dispatch code (conduct_runs, eval_scope, insert_partitions, dispatch_agent)
# is NOT in this file: it was written against V1 tables that V2 does not have.
#
#   settings -> database link -> contract check -> single-instance lock -> check-in
#            -> LISTEN data_source_check -> heartbeat -> check loop
#
# What it never does: write to a table, read data_source_secrets, call sentinelapi, keep a
# connection object beyond the check that read it, or log a connection value other than the host.
#
#__version__ = '2026.32.2'   # last V1 conductor (runs, partitions and dispatch on the V1 repository)
#__version__ = '2026.47.1'   # VANTAGE (V2) first build: availability checks through ds_connect_lib; check-in and
#                              heartbeat through functions; one instance at a time (advisory lock); /health,
#                              /ready, /status, POST /check. No dispatch yet.
__version__ = '2026.47.2'    # architect's reply 2026-46-33: every file root that is SET goes to the library, which
#                              looks at it when a path under it is checked - a share mounted after start works with
#                              no restart, and the look at start is for the log, /status and the capabilities only;
#                              POST /check asks sys_get_data_source_check_info for the type when the database has
#                              that function, and reads the table as before when it hasn't.
#                              Addendum 2026-46-35: a health summary goes with every heartbeat when the database's
#                              heartbeat takes one - ready, what stops the worker (problem), what it is doing (work) -
#                              so the app's Workers panel can show the conductor; the heartbeat now carries on while
#                              the contract for checks doesn't hold, saying so.

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
    "checks_off": "Checks are switched off for this worker",   # DS_CHECKS_ENABLED is false
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
        log.info("start version=%s connect_lib=%s %s types=%s unavailable=%s file_roots=%s",
                 __version__, ds_connect_lib.__version__, self.s.describe(), ",".join(self.types),
                 json.dumps(self.unavailable, sort_keys=True),
                 ",".join(_r["path"] + ("" if _r["ok"] else "(unusable)") for _r in self.roots) or "-")
        self._tasks = [_loop.create_task(self._supervise(), name="supervise"),
                       _loop.create_task(self._heartbeat_loop(), name="heartbeat"),
                       _loop.create_task(self.checks.pump(), name="check-loop")]

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
        """What the conductor is doing now, as {code, params, text}."""
        _n = len(self.checks.in_flight) if self.checks is not None else 0
        if not self.s.checks_enabled:
            _code, _params = "checks_off", {}
        elif _n == 0:
            _code, _params = "idle", {}
        elif _n == 1:
            _code, _params = "checking_one", {}
        else:
            _code, _params = "checking", {"n": _n}
        return {"code": _code, "params": _params, "text": HEALTH_WORK[_code].format(**_params)}

    def health(self):
        """The summary: ready, problem, work, and the figures /status has. Counts and codes only."""
        _problem = self.problem()
        _c = self.checks
        _doc = {"ready": _problem is None, "problem": _problem, "work": self.work(),
                "detail": {"in_flight": len(_c.in_flight) if _c else 0, "abandoned": len(_c.abandoned) if _c else 0,
                           "last_poll": _c.last_poll if _c else None, "last_hour": _c.last_hour() if _c else {}}}
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
        self.pool = await asyncpg.create_pool(min_size=1, max_size=4, **_kw)
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
        self.listening = True
        self.step = "running"
        self.checks.wake()                  # the first read, and the read straight after every reconnect
        while True:
            await self._wait(self.s.poll_sec, events=(self._recheck_contract,))
            await self.conn.fetchval("select 1", timeout=10)        # a cheap statement: is the link alive?
            if self._recheck_contract.is_set():
                await self._hold_contract(broken=True)
                self.step = "running"
            self.checks.wake()

    def _on_signal(self, _conn, _pid, _channel, _payload):
        # only a wake-up: the due list has the order and everything else that's due
        if self.checks:
            self.checks.wake()

    # ---- the contract -----------------------------------------------------
    async def _contract_gaps(self):
        _rows = await self.conn.fetch(CONTRACT_SQL, list(CONTRACT_FUNCTIONS) + [CHECK_INFO_FUNCTION])
        _login = await self.conn.fetchval("select current_user::text")
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
        log.info("%s check_info=%s health=%s",
                 "contract check recovered" if (_said is not None or broken) else "contract check passed",
                 "yes" if self.has_check_info else "no", "yes" if self.has_health else "no")
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
                "dispatch": False}

    async def _checkin(self):
        _version = __version__ + " (connect " + ds_connect_lib.__version__ + ")"
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
        self._row_gone_said = False
        self.status = "starting" if self.status != "stopping" else "stopping"
        self.last_heartbeat = _now_iso()
        log.info("checked in worker_id=%s first=%s", self.worker_id, str(_answer.get("first_checkin")).lower())
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
