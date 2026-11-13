# ds_connect_lib.py - Data Sentinel shared connection library
#
# The one place a Python worker signs in to a customer's system.
#
#   V2 surface (2026.47.1, first used by the conductor):
#       types()        the registry: which source types have a connector, and which can run in this image
#       connect()      reach the host, sign in once, return a handle (a context manager)
#       check()        connect, one minimal read, close -> CheckResult; never raises
#       precheck()     the not_checkable answers, decided without a connection
#       message()      the catalogue's sentence for a code and its parameters
#       catalogue()    the message catalogue as data (the app's translations follow it)
#       from_legacy()  a V1 connection in V2 keys
#
#   V1 surface (2026.40.04, what the classify worker calls - kept unchanged):
#       logger, set_secrets_dir, reset_connect_globals, get_secret, aes_decrypt,
#       decrypt_connection_password, DATACONNECTION_SQL, CON_TYPES_DATABASE, CONNECT_TIMEOUT_SEC,
#       oracle_mode, diagnose_connection, resolve_connection, db_connection, fetch_first_column
#
# Rules the V2 surface keeps (work package 2026-46-31, 02-connection-library.md):
#   - it knows nothing about the conductor or the repository database;
#   - importing it never fails because a driver is missing: every driver loads when it is needed;
#   - synchronous and safe in threads: nothing is shared between two data sources;
#   - nothing is written to disk; no connection value is logged;
#   - a check is read-only and makes ONE sign-in attempt;
#   - no secret leaves in a message, a parameter, an exception or a return value.
#
#__version__ = (none prior - first extraction of connection machinery from ds_scan_worker per DS_scanner_worker_organization.md)
#__version__ = '2026.40.01'   # first cut: secrets + AES decrypt, dataconnections resolve, single-connection dispatch (oracle sid/service, sqlserver, postgres), fetch_first_column value contract
#__version__ = '2026.40.02'   # SCANNER-FAITHFUL resolve: the platform stores the port INSIDE host ("server:1521",
#                              partitioned like the scanner; no port/sid JSON keys exist) - passing the raw value
#                              made the driver resolve "server:1521" literally (gaierror live on the swarm); sid
#                              dispatch by con_type alone
#__version__ = '2026.40.03'   # ORACLE THICK MODE, scanner parity: lazy one-time init_oracle_client from
#                              /app/instantclient_21_13 (DS_ORACLE_CLIENT_DIR overrides) on first Oracle
#                              connection; instant client absent -> logged THIN fallback for dev boxes;
#                              tcp_connect_timeout passed only in thin (thick rejects the kwarg)
#__version__ = '2026.40.04'   # SCANNER PARITY + DIAGNOSIS: thick mode REQUIRED (no silent thin fallback;
#                              DS_ORACLE_ALLOW_THIN=1 for dev boxes, and every line then says THIN); Oracle
#                              connects through the scanner's exact SessionPool construction, runs the
#                              record's initStr callproc and the SELECT 1 FROM dual smoke test; DATACONNECTION
#                              SQL reads initStr; diagnose_connection() explains a failure from THIS container
#                              (dns, tcp probe of host:port with timeout/refused/open, driver code -> cause,
#                              mode, user) for the run log and /dbtest
#__version__ = '2026.47.1'   # VANTAGE (V2): the registry and the V2 surface above - 19 source types on the V2
#                              connection keys, each with a connect and a check; the message catalogue (codes +
#                              parameters, one code per sentence); host reach before the driver (same failure,
#                              same code, whatever the type); one sign-in attempt; time limits per step; secret
#                              scrub; from_legacy for workers still on a V1 database. The V1 surface is unchanged
#                              apart from a lock around the one-time Oracle thick initialisation.
#__version__ = '2026.47.2'   # architect's reply 2026-46-33: no_reply - a host that took the connection and then said
#                              nothing is reported with the limit that applied, and check_timeout is kept for the
#                              whole limit and for a check with no host; file roots are looked at when a path is
#                              checked, so a share mounted after start works (root_not_mounted names a root that
#                              isn't there); from_legacy turns Laserfiche's certificatetrust over, because V1 had
#                              it backwards; 41 codes in the catalogue.
__version__ = '2026.47.3'    # for the discovery walks (discover_note_2026.47.1): handle.call and the HTTP handle's surface
#                              named as a caller's to use; connect(..., retries=N) for 429 and 503 on a long walk, with
#                              retry_after in service_error when it gives up; handle.token_for(resource) on the Entra types;
#                              handle.as_user(email) on gmail and gdocs; optional permissions in types() (Teams chats);
#                              a handle used from several threads is tested. Nothing that 2026.47.2 had changes.

import os
import re
import json
import stat
import base64
import socket
import struct
import logging
import time
import threading
import collections
import importlib
import importlib.util
import urllib.parse
from collections import namedtuple
from contextlib import contextmanager

module_logger = logging.getLogger("ds_connect_lib")


def logger(message, level="info", scope="run_scope"):
    """Same injectable logger convention as the other DS libraries."""
    _fn = getattr(module_logger, level if level != "warn" else "warning", module_logger.info)
    _fn(str(scope) + "|" + str(message))


# ===========================================================================
# V1 SURFACE (2026.40.04) - unchanged; the classify worker's calls
# ===========================================================================

# ---------------------------------------------------------------------------
# Layer 1 - secrets and crypto
# Secret files follow the platform convention: <secrets_dir>/<name> containing
# a JSON object keyed by the secret's own name: {"aeskey": "...."}.
# ---------------------------------------------------------------------------
_secrets_dir = os.environ.get("DS_SECRETS_DIR", "/run/secrets")
_aes_cache = {}


def set_secrets_dir(path):
    """Override the secrets mount (dev containers differ from prod)."""
    global _secrets_dir
    _secrets_dir = str(path)
    _aes_cache.clear()


def reset_connect_globals():
    _aes_cache.clear()


def get_secret(secret_name):
    """Read one platform secret. False on any failure (caller decides severity)."""
    try:
        with open(_secrets_dir + "/" + str(secret_name), "r", encoding="utf-8") as _f:
            _content = json.load(_f)
        return _content[secret_name]
    except Exception:
        return False


def aes_decrypt(enc, key, iv):
    """AES-CBC + PKCS7, base64 input - byte-for-byte the platform's scheme."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    _iv = str(iv).encode("utf-8")
    _enc = base64.b64decode(enc)
    _cipher = AES.new(str(key).encode("utf-8"), AES.MODE_CBC, _iv)
    return unpad(_cipher.decrypt(_enc), 16).decode("utf-8", "ignore")


def decrypt_connection_password(encrypted_text):
    """Decrypt a dataconnections password. Key/IV are read once and cached;
    a missing key or a failed decrypt raises - a connection with an
    undecryptable password must fail loudly, never connect with ciphertext."""
    if "key" not in _aes_cache:
        _k = get_secret("aeskey")
        _v = get_secret("aesiv")
        if _k is False or _v is False:
            raise RuntimeError("aeskey/aesiv secrets unavailable at " + _secrets_dir)
        _aes_cache["key"], _aes_cache["iv"] = _k, _v
    return aes_decrypt(encrypted_text, _aes_cache["key"], _aes_cache["iv"])


# ---------------------------------------------------------------------------
# Layer 2 - connection resolution (repo-client-free)
# The consumer runs DATACONNECTION_SQL on ITS repo pool and hands the record
# here. resolve_connection() is pure apart from the secrets read.
# ---------------------------------------------------------------------------
# The exact field set the scanner reads - the platform stores NO separate port
# or sid key: the port travels INSIDE the host value ("orahost.internal:1521"),
# and sid-ness is the con_type itself (oracle_sid vs oracle_service).
DATACONNECTION_SQL = (
    "SELECT con_id, con_type, "
    "connection_json->>'host' AS host, "
    "connection_json->>'database' AS database, "
    "connection_json->>'schema' AS schema, "
    "connection_json->>'username' AS username, "
    "connection_json->>'password' AS password, "
    "connection_json->>'certificatetrust' AS certificatetrust, "
    "connection_json->>'initStr' AS initstr "
    "FROM sentinel.dataconnections WHERE con_id = $1"
)

CON_TYPES_DATABASE = frozenset(
    ("oracle_sid", "oracle_service", "sqlserver", "postgres", "postgresql"))

_DEFAULT_PORTS = {"oracle_sid": 1521, "oracle_service": 1521,
                  "sqlserver": 1433, "postgres": 5432, "postgresql": 5432}

CONNECT_TIMEOUT_SEC = 5

# Oracle THICK mode, mimicking the scanner: it calls
# oracledb.init_oracle_client(lib_dir="/app/instantclient_21_13") at startup,
# which some client databases REQUIRE (legacy password verifiers, wallets).
# Thick init is process-wide and irreversible, so it happens once, lazily, on
# the first Oracle connection: instant client present -> thick (scanner
# parity); absent (dev boxes) -> log and stay thin. DS_ORACLE_CLIENT_DIR
# overrides the scanner's path.
_oracle_client_dir = os.environ.get("DS_ORACLE_CLIENT_DIR", "/app/instantclient_21_13")
# Thick is REQUIRED (scanner parity: the scanner has no thin fallback). A dev box
# without the instant client sets DS_ORACLE_ALLOW_THIN=1 to run thin, and every
# log line and /dbtest response then says THIN so a thin result is never mistaken
# for the production path.
_oracle_allow_thin = str(os.environ.get("DS_ORACLE_ALLOW_THIN", "")).strip().lower() in ("1", "true", "yes")
_oracle_thick = {"attempted": False, "thick": False, "error": None}
_oracle_thick_lock = threading.Lock()     # 2026.47.1: the one-time init is now safe when two threads arrive together


def oracle_mode():
    """'thick' | 'thin' | 'uninitialized' - for logs and /dbtest."""
    if not _oracle_thick["attempted"]:
        return "uninitialized"
    return "thick" if _oracle_thick["thick"] else "thin"


def _oracle_init_thick(oracledb):
    with _oracle_thick_lock:
        if _oracle_thick["attempted"]:
            if not _oracle_thick["thick"] and not _oracle_allow_thin:
                raise RuntimeError(_oracle_thick["error"])
            return _oracle_thick["thick"]
        _oracle_thick["attempted"] = True
        try:
            oracledb.init_oracle_client(lib_dir=_oracle_client_dir)
            _oracle_thick["thick"] = True
            logger("db_connection|oracle THICK client initialized from " + _oracle_client_dir
                   + " (client version " + ".".join(str(_v) for _v in oracledb.clientversion()) + ")",
                   "info", "run_scope")
        except Exception as _e:
            _msg = ("oracle instant client NOT usable at " + _oracle_client_dir + ": "
                    + str(_e).split(chr(10))[0][:160]
                    + " - the scanner image ships it (COPY instantclient + apt libaio1); "
                    "classify must too, or set DS_ORACLE_CLIENT_DIR")
            _oracle_thick["error"] = _msg
            if _oracle_allow_thin:
                logger("db_connection|" + _msg + " - DS_ORACLE_ALLOW_THIN set, running THIN",
                       "warning", "run_scope")
            else:
                logger("db_connection|" + _msg, "error", "run_scope")
                raise RuntimeError(_msg)
        return _oracle_thick["thick"]


# ---------------------------------------------------------------------------
# Connection diagnosis - run when a connect fails, so the log and /dbtest say
# WHERE it failed from THIS container: name resolution, TCP reachability, then
# the driver's own code mapped to its usual cause.
# ---------------------------------------------------------------------------
_ERROR_HINTS = (
    ("DPY-6005", "TCP connect to the listener failed (thin driver)"),
    ("ORA-12170", "TNS connect timeout - the listener host/port did not answer"),
    ("ORA-12541", "no listener on that host/port"),
    ("ORA-12514", "listener reached, SERVICE name unknown to it - check 'database' on the record"),
    ("ORA-12505", "listener reached, SID unknown to it - check con_type/'database' on the record"),
    ("ORA-12154", "TNS alias could not be resolved (tnsnames.ora / TNS_ADMIN)"),
    ("ORA-01017", "connected; username/password rejected"),
    ("ORA-28000", "connected; account locked"),
    ("ORA-28001", "connected; password expired"),
    ("ORA-28040", "connected; server requires an authentication protocol only the THICK client provides"),
    ("ORA-00942", "connected and authenticated; the SQL names a table/view this user cannot see"),
    ("ORA-01031", "connected and authenticated; insufficient privileges for the SQL"),
    ("DPI-1047", "instant client library not found - thick mode cannot initialise"),
    ("DPY-3015", "password verifier type not supported by the THIN driver - needs thick"),
    ("08001", "ODBC: could not open the TCP connection (SQL Server)"),
    ("28000", "ODBC: login rejected (SQL Server)"),
)


def _tcp_probe(host, port, timeout=5.0):
    """(dns, tcp) strings describing what THIS container can reach."""
    try:
        _addrs = sorted({_a[4][0] for _a in socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_TCP)})
    except Exception as _e:
        return "dns FAILED (" + str(_e).split(chr(10))[0][:80] + ")", "not attempted"
    _dns = "dns ok -> " + ",".join(_addrs[:3])
    _t0 = time.time()
    try:
        _s = socket.create_connection((host, int(port)), timeout=timeout)
        _s.close()
        return _dns, "tcp " + str(port) + " OPEN in " + str(round(time.time() - _t0, 2)) + "s (listener answered - the failure is in the Oracle/driver handshake, not the network)"
    except socket.timeout:
        return _dns, "tcp " + str(port) + " TIMEOUT after " + str(timeout) + "s (SYN dropped: firewall or route from this container's node)"
    except ConnectionRefusedError:
        return _dns, "tcp " + str(port) + " REFUSED (host reached, nothing listening on that port)"
    except Exception as _e:
        return _dns, "tcp " + str(port) + " error: " + str(_e).split(chr(10))[0][:80]


def diagnose_connection(conn_def, exc, probe=True):
    """One dict + one line explaining a failed connect. Never raises."""
    try:
        _msg = str(exc).split(chr(10))[0][:300]
        _hint = next((_h for _code, _h in _ERROR_HINTS if _code in _msg), "see driver message")
        _d = {"con_id": conn_def.get("con_id"), "con_type": conn_def.get("con_type"),
              "host": conn_def.get("host"), "port": conn_def.get("port"),
              "database": conn_def.get("database"), "username": conn_def.get("username"),
              "init_str": bool(conn_def.get("init_str")),
              "oracle_mode": oracle_mode() if str(conn_def.get("con_type", "")).startswith("oracle") else None,
              "error": type(exc).__name__ + ": " + _msg, "hint": _hint}
        if probe and conn_def.get("host"):
            _d["dns"], _d["tcp"] = _tcp_probe(conn_def["host"], conn_def.get("port") or 0)
        _d["line"] = ("con_id " + str(_d["con_id"]) + " (" + str(_d["con_type"]) + " " + str(_d["host"])
                      + ":" + str(_d["port"]) + "/" + str(_d["database"]) + " as " + str(_d["username"])
                      + (", mode " + str(_d["oracle_mode"]) if _d.get("oracle_mode") else "")
                      + ") failed: " + _d["error"] + " | " + _hint
                      + ((" | " + _d["dns"] + " | " + _d["tcp"]) if "tcp" in _d else ""))
        return _d
    except Exception as _e:
        return {"error": repr(exc), "line": "con_id ? failed: " + repr(exc) + " (diagnose error " + repr(_e) + ")"}


def resolve_connection(con_details):
    """dataconnections record (mapping) -> normalized connection definition.
    Decrypts the password. Raises on a missing field or a failed decrypt."""
    _d = dict(con_details or {})
    _type = str(_d.get("con_type") or "").strip().lower()
    if not _type:
        raise ValueError("dataconnections record has no con_type")
    # host arrives as "server" or "server:port" - partition EXACTLY as the
    # scanner does. Passing the un-split value to a driver makes the resolver
    # look up "server:1521" literally -> "Name or service not known" (found
    # live: classify failed on the same swarm where the scanner connected).
    _host_raw = (_d.get("host") or "").strip()
    _server, _sep, _embedded_port = _host_raw.partition(":")
    _port = int(_embedded_port) if _embedded_port.strip().isdigit() else int(_DEFAULT_PORTS.get(_type, 0) or 0)
    _def = {
        "con_id": _d.get("con_id"),
        "con_type": _type,
        "host": _server.strip(),
        "port": _port,
        "database": (_d.get("database") or "").strip(),
        "schema": (_d.get("schema") or "").strip(),
        "username": (_d.get("username") or "").strip(),
        "certificatetrust": _d.get("certificatetrust"),
        # Oracle session initialisation call (a stored procedure the scanner runs
        # on every new session - VPD context, schema switch); same key the
        # scanner reads, run the same way
        "init_str": str(_d.get("initstr") or "").strip(),
    }
    if _type in CON_TYPES_DATABASE:
        for _need in ("host", "database", "username"):
            if not _def[_need]:
                raise ValueError("con_id " + str(_def["con_id"]) + ": missing '" + _need + "'")
    _pw = _d.get("password")
    _def["password"] = decrypt_connection_password(_pw) if _pw else ""
    return _def


# ---------------------------------------------------------------------------
# Layer 3 - drivers (single-connection tier; the pool tier lands with the
# scanner migration). Every driver imports lazily with a named install hint.
# ---------------------------------------------------------------------------
def _need(module_name, pip_name):
    try:
        return __import__(module_name)
    except ImportError:
        raise RuntimeError("driver '" + module_name + "' not installed - pip install " + pip_name)


@contextmanager
def db_connection(conn_def):
    """One live connection to the external database, closed on exit.
    Dispatch by canonical con_type; unsupported types raise by name."""
    _t = conn_def["con_type"]
    _conn = None
    try:
        if _t in ("oracle_sid", "oracle_service"):
            oracledb = _need("oracledb", "oracledb")
            _oracle_init_thick(oracledb)
            # ---- scanner parity: this block mirrors create_connection_pool_oracle
            # in ds_scan_worker (makedsn by con_type, SessionPool with the same
            # options, initStr callproc, SELECT 1 FROM dual smoke test) so a list
            # load and a scan of the same con_id take the same code path.
            if _t == "oracle_sid":
                _dsn = oracledb.makedsn(conn_def["host"], conn_def["port"], sid=conn_def["database"])
            else:
                _dsn = oracledb.makedsn(conn_def["host"], conn_def["port"], service_name=conn_def["database"])
            logger("db_connection|oracle dsn- " + str(_dsn) + " mode=" + oracle_mode(), "info", "run_scope")
            _pool_fn = getattr(oracledb, "SessionPool", None) or oracledb.create_pool
            _getmode = getattr(oracledb, "SPOOL_ATTRVAL_WAIT", None) or oracledb.POOL_GETMODE_WAIT
            _kw = dict(user=conn_def["username"], password=conn_def["password"], dsn=_dsn,
                       min=1, max=3, increment=1, getmode=_getmode, homogeneous=True,
                       threaded=True, ping_interval=60)
            if not _oracle_thick["thick"]:
                _kw["tcp_connect_timeout"] = CONNECT_TIMEOUT_SEC     # thin-only kwarg
            _pool = _pool_fn(**_kw)
            oracledb.defaults.fetch_lobs = False
            _conn = _pool.acquire()
            _conn._ds_pool = _pool
            _cur = _conn.cursor()
            _init = conn_def.get("init_str") or ""
            if _init:
                # same parse as the scanner: PROC(arg, 'str', null)
                try:
                    _proc = _init.split("(")[0].strip()
                    _args_str = _init[_init.find("(") + 1:_init.rfind(")")]
                    _args = re.split(r""",(?![^']*'\s*,)""", _args_str) if _args_str.strip() else []
                    _fargs = [None if _a.strip().lower() == "null" else _a.strip().strip("'") for _a in _args]
                    _cur.callproc(_proc, _fargs)
                    logger("db_connection|initStr ran: " + _proc + "(" + str(len(_fargs)) + " args)", "info", "run_scope")
                except Exception as _ie:
                    logger("db_connection|initStr FAILED (" + _init[:80] + "): " + type(_ie).__name__ + ": "
                           + str(_ie).split(chr(10))[0][:200] + " - continuing without it, as the scanner does",
                           "error", "run_scope")
            _cur.execute("SELECT 1 FROM dual")
            _cur.fetchone()
            _cur.close()
        elif _t == "sqlserver":
            pyodbc = _need("pyodbc", "pyodbc")
            _tsc = "YES" if str(conn_def.get("certificatetrust") or "").strip().lower() in ("yes", "true", "1") else "NO"
            _odbc = ("DRIVER={ODBC Driver 18 for SQL Server};"
                     "SERVER=" + conn_def["host"] + "," + str(conn_def["port"]) + ";"
                     "DATABASE=" + conn_def["database"] + ";"
                     "UID=" + conn_def["username"] + ";PWD=" + conn_def["password"] + ";"
                     "Encrypt=YES;trustServerCertificate=" + _tsc + ";"
                     "LoginTimeout=" + str(CONNECT_TIMEOUT_SEC) + ";")
            _conn = pyodbc.connect(_odbc, timeout=CONNECT_TIMEOUT_SEC)
        elif _t in ("postgres", "postgresql"):
            psycopg2 = _need("psycopg2", "psycopg2-binary")
            _conn = psycopg2.connect(host=conn_def["host"], port=conn_def["port"],
                                     dbname=conn_def["database"], user=conn_def["username"],
                                     password=conn_def["password"],
                                     connect_timeout=CONNECT_TIMEOUT_SEC)
        else:
            raise ValueError("con_type '" + str(_t) + "' is not a supported database type")
        logger("db_connection|connected con_id=" + str(conn_def.get("con_id"))
               + " type=" + _t + " host=" + conn_def["host"], "info", "run_scope")
        yield _conn
    finally:
        if _conn is not None:
            _p = getattr(_conn, "_ds_pool", None)
            try:
                if _p is not None:
                    _p.release(_conn)
                    _p.close(force=True)
                else:
                    _conn.close()
            except Exception:
                try:
                    _conn.close()
                except Exception:
                    pass


def fetch_first_column(conn, sql, max_values=None):
    """THE value contract for list loaders: first column of every row, cast to
    text, trimmed, nulls and empties dropped, de-duplicated preserving first
    occurrence. max_values guards a runaway query (None = unlimited)."""
    _cur = conn.cursor()
    try:
        _cur.execute(sql)
        _seen = set()
        _values = []
        while True:
            _rows = _cur.fetchmany(10000)
            if not _rows:
                break
            for _r in _rows:
                _v = _r[0]
                if _v is None:
                    continue
                _s = str(_v).strip()
                if not _s or _s in _seen:
                    continue
                _seen.add(_s)
                _values.append(_s)
                if max_values and len(_values) >= max_values:
                    logger("fetch_first_column|max_values " + str(max_values)
                           + " reached - result truncated", "warning", "run_scope")
                    return _values
        return _values
    finally:
        try:
            _cur.close()
        except Exception:
            pass


# ===========================================================================
# V2 SURFACE (2026.47.1)
# ===========================================================================

SCRUBBED = "•••"     # what a secret is replaced with; the repository database uses the same three dots
MESSAGE_MAX_CHARS = 200
REASON_MAX_CHARS = 120
SECRET_MIN_CHARS = 6                # shorter values are not scrubbed: they would blank out ordinary words

DEFAULT_TIMEOUT_SEC = 30            # the whole check
STEP_LOOKUP_SEC = 5                 # name lookup
STEP_TCP_SEC = 10                   # TCP connection
STEP_TOKEN_SEC = 10                 # a token request
STEP_CALL_SEC = 15                  # one API call, one statement, one driver sign-in
RETRY_WAIT_MAX_SEC = 300            # connect(..., retries=N): the longest a Retry-After is waited for, once
_CLEANUP_MARGIN_SEC = 1.0           # the library answers this much before the caller's own limit of the same length

_APP_NAME = "Data Sentinel"         # what a DBA sees as the client's name
_ODBC_DRIVER = "ODBC Driver 18 for SQL Server"

# ---------------------------------------------------------------------------
# 1. The message catalogue
#    One code for one sentence: the app shows these in other languages from the
#    code and the parameters. fixtures/message-catalogue.json is generated from
#    this list (catalogue()); the tests compare the two.
# ---------------------------------------------------------------------------
_CATALOGUE = (
    # --- network
    ("host_not_found",          "unreachable",   "Host not found: {host}", ("host",)),
    ("no_answer",               "unreachable",   "No answer from {host} on port {port} within {s} seconds", ("host", "port", "s")),
    ("refused",                 "unreachable",   "Connection refused by {host} on port {port}", ("host", "port")),
    ("tls_cert_expired",        "unreachable",   "TLS failed: the certificate of {host} has expired", ("host",)),
    ("tls_cert_untrusted",      "unreachable",   "TLS failed: the certificate of {host} isn't trusted", ("host",)),
    ("tls_cert_mismatch",       "unreachable",   "TLS failed: the certificate doesn't match {host}", ("host",)),
    ("tls_failed",              "unreachable",   "TLS failed: no secure connection could be set up with {host}", ("host",)),
    # --- sign-in
    ("signin_rejected",         "unreachable",   "Sign-in failed: the user name or password was rejected for {account}", ("account",)),
    ("signin_locked",           "unreachable",   "Sign-in failed: the account {account} is locked", ("account",)),
    ("signin_password_expired", "unreachable",   "Sign-in failed: the password for {account} has expired", ("account",)),
    ("secret_expired",          "unreachable",   "Sign-in failed: the client secret has expired", ()),
    ("secret_wrong",            "unreachable",   "Sign-in failed: the client secret is wrong", ()),
    ("app_not_found",           "unreachable",   "Sign-in failed: there's no app with client ID {client_id} in tenant {tenant_id}", ("client_id", "tenant_id")),
    ("tenant_not_found",        "unreachable",   "Sign-in failed: tenant {tenant_id} wasn't found", ("tenant_id",)),
    ("token_rejected",          "unreachable",   "Sign-in failed: the access token was rejected", ()),
    ("key_rejected",            "unreachable",   "Sign-in failed: the service-account key was rejected", ()),
    ("delegation_denied",       "unreachable",   "Sign-in failed: the service account isn't allowed to act as {delegated_user}", ("delegated_user",)),
    # --- after sign-in
    ("permission_missing",      "unreachable",   "Signed in, but the app hasn't been granted {permission}", ("permission",)),
    ("database_missing",        "unreachable",   "Connected to {host}, but database {database} doesn't exist", ("host", "database")),
    ("database_unavailable",    "unreachable",   "Connected to {host}, but database {database} doesn't exist or the account can't open it", ("host", "database")),
    ("service_missing",         "unreachable",   "Connected to {host}, but the listener doesn't know service {service_name}", ("host", "service_name")),
    ("sid_missing",             "unreachable",   "Connected to {host}, but the listener doesn't know SID {sid}", ("host", "sid")),
    ("repository_missing",      "unreachable",   "Connected to {host}, but repository {repository_id} doesn't exist", ("host", "repository_id")),
    ("no_read_database",        "unreachable",   "Signed in, but the account can't read database {database}", ("database",)),
    ("no_read_root",            "unreachable",   "Signed in, but the account can't read the root folder of repository {repository_id}", ("repository_id",)),
    ("session_init_failed",     "unreachable",   "Signed in, but the session initialisation call {procedure} failed", ("procedure",)),
    # --- files
    ("path_not_found",          "unreachable",   "Path not found: {root_path}", ("root_path",)),
    ("path_not_folder",         "unreachable",   "The path {root_path} isn't a folder", ("root_path",)),
    ("path_not_readable",       "unreachable",   "The path {root_path} can't be listed by the account the worker runs as", ("root_path",)),
    ("path_outside_roots",      "unreachable",   "The path {root_path} is outside the folders mounted for the workers", ("root_path",)),
    # --- general
    ("service_error",           "unreachable",   "{host} answered with an error ({status} {status_text})", ("host", "status", "status_text")),
    ("check_timeout",           "unreachable",   "The check didn't finish within {s} seconds", ("s",)),
    ("connection_incomplete",   "unreachable",   "The connection is incomplete: {key} has no value", ("key",)),
    ("unexpected",              "unreachable",   "The check failed: {reason}", ("reason",)),
    # --- not checkable
    ("not_checkable",           "not_checkable", "This type of data source can't be checked yet", ()),
    ("checker_missing",         "not_checkable", "The worker that runs checks is missing {component}, so it can't check this data source", ("component",)),
    ("roots_not_mounted",       "not_checkable", "The worker that runs checks has no file folders mounted, so it can't check this data source", ()),
    # --- added by the conductor build 2026.47.1 (not in the package's 37)
    ("client_not_allowed",      "unreachable",   "Sign-in failed: {host} doesn't accept connections from the worker's address", ("host",)),
    ("no_read_service",         "unreachable",   "Signed in, but the account can't read from {host}", ("host",)),
    # --- added by 2026.47.2 (architect's reply 2026-46-33)
    ("no_reply",                "unreachable",   "Connected to {host}, but it didn't answer within {s} seconds", ("host", "s")),
    ("root_not_mounted",        "not_checkable", "The worker that runs checks doesn't have {root} mounted, so it can't check this data source", ("root",)),
)
_BY_CODE = {_c[0]: _c for _c in _CATALOGUE}

CheckResult = namedtuple("CheckResult", "status ms code params message")
TypeInfo = namedtuple("TypeInfo", "checkable available missing secret_keys permissions optional", defaults=(None,))
# 'optional': permissions a walk may need for an option of its own that the check doesn't ask about (2026.47.3),
# so the app can tell the administrator. Read the fields by name: more may be added.


def catalogue():
    """The message catalogue as data: [{code, status, message, params}]."""
    return [{"code": _c[0], "status": _c[1], "message": _c[2], "params": list(_c[3])} for _c in _CATALOGUE]


def _clean_value(value):
    """A parameter as it appears in a sentence: one line, no control characters."""
    _s = "" if value is None else str(value)
    _s = re.sub(r"[\x00-\x1f\x7f  ]+", " ", _s)
    return re.sub(r" {2,}", " ", _s).strip()


def message(code, params=None, lang="en"):
    """The catalogue's sentence for a code, with its values filled in: one sentence,
    no full stop, no line break, 200 characters at most. A sentence that would be
    longer is shortened by trimming its longest value (the parameters keep the full
    one). 'lang' is accepted for the callers' sake; the library's own text is English,
    and the app translates from the code and the parameters."""
    _entry = _BY_CODE.get(str(code)) or _BY_CODE["unexpected"]
    _params = params if isinstance(params, dict) else {}
    _values = {_k: (_clean_value(_params.get(_k)) or "?") for _k in _entry[3]}
    _text = _entry[2].format(**_values)
    for _ in range(6):
        if len(_text) <= MESSAGE_MAX_CHARS or not _values:
            break
        _key = max(_values, key=lambda _k: len(_values[_k]))
        _keep = len(_values[_key]) - (len(_text) - MESSAGE_MAX_CHARS) - 1
        if _keep < 1:
            break
        _values[_key] = _values[_key][:_keep].rstrip() + "…"
        _text = _entry[2].format(**_values)
    if len(_text) > MESSAGE_MAX_CHARS:
        _text = _text[:MESSAGE_MAX_CHARS - 1].rstrip() + "…"
    return _text.rstrip(" .")


class ConnectError(Exception):
    """Why a connect failed: a catalogue code and the values of its sentence.
    str() is the sentence. It never carries a secret or a driver's exception."""

    def __init__(self, code, params=None):
        self.code = str(code)
        self.params = dict(params or {})
        super().__init__(message(self.code, self.params))

    @property
    def status(self):
        return (_BY_CODE.get(self.code) or _BY_CODE["unexpected"])[1]


class _StepTimeout(Exception):
    """A step did not finish inside its limit."""


# ---------------------------------------------------------------------------
# 2. Secrets: which values must never leave, and the scrub
# ---------------------------------------------------------------------------
def _collect_strings(value, into):
    if isinstance(value, str):
        into.add(value)
        for _line in value.splitlines():
            into.add(_line.strip())
    elif isinstance(value, dict):
        for _v in value.values():
            _collect_strings(_v, into)
    elif isinstance(value, (list, tuple)):
        for _v in value:
            _collect_strings(_v, into)


def _secret_values(secret_keys, connection):
    """Every secret string of this connection, longest first. For a json secret,
    every string inside it counts, and so does each line of a multi-line one."""
    _found = set()
    for _k in secret_keys:
        _collect_strings(connection.get(_k), _found)
    return sorted((_s for _s in _found if len(_s) >= SECRET_MIN_CHARS), key=len, reverse=True)


def _scrub(text, secrets):
    if not isinstance(text, str):
        return text
    for _s in secrets:
        if _s in text:
            text = text.replace(_s, SCRUBBED)
    return text


_CRED_URL_RE = re.compile(r"//[^/\s:@]*:[^/\s@]*@")
_CRED_PAIR_RE = re.compile(
    r"""(?ix) ["']? [\w.\-]* (?:password|passwd|pwd|secret|token|key) [\w.\-]* ["']? \s* [=:] \s*
        (?: "[^"]*" | '[^']*' | \{[^}]*\} | [^\s;,&'"]+ ) [;,&]? """)
_CRED_BEARER_RE = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}")


def _reason(exc, secrets=()):
    """The one place a driver's words reach a message: the first line of the
    error, with anything that looks like credentials removed, every secret of
    this connection replaced, trimmed to 120 characters."""
    _text = exc if isinstance(exc, str) else (str(exc) or type(exc).__name__)
    _line = next((_l.strip() for _l in _text.splitlines() if _l.strip()), "") or "unknown error"
    _line = _CRED_URL_RE.sub("//", _line)
    _line = _CRED_PAIR_RE.sub("", _line)
    _line = _CRED_BEARER_RE.sub("", _line)
    _line = _scrub(_line, secrets)
    _line = _clean_value(_line).rstrip(" .:;,")
    if len(_line) > REASON_MAX_CHARS:
        _line = _line[:REASON_MAX_CHARS - 1].rstrip() + "…"
    return _line or "unknown error"


# ---------------------------------------------------------------------------
# 3. One check's context: its time limit and what the caller passed in
# ---------------------------------------------------------------------------
class _Ctx(object):
    def __init__(self, source_type, connection, timeout, file_roots, ca_file, proxy, secrets):
        try:
            _t = float(timeout)
        except (TypeError, ValueError):
            _t = float(DEFAULT_TIMEOUT_SEC)
        if _t <= 0:
            _t = float(DEFAULT_TIMEOUT_SEC)
        self.source_type = source_type
        self.c = connection
        self.limit_s = int(_t) if _t == int(_t) else round(_t, 1)
        self.t0 = time.monotonic()
        self.t_end = self.t0 + (_t - _CLEANUP_MARGIN_SEC if _t > 2 * _CLEANUP_MARGIN_SEC else _t)
        self.file_roots = [str(_r) for _r in (file_roots or []) if str(_r or "").strip()]
        self.ca_file = str(ca_file) if ca_file else None
        self.proxy = dict(proxy) if isinstance(proxy, dict) else {}
        self.secrets = secrets
        self.connected = False          # a TCP connection to the host has succeeded
        self.checking = True            # False for connect(): the limits then end with the sign-in
        self.cap = None                 # the limit of the step now running, in seconds
        self.retries = 0                # connect(..., retries=N): how often a 429 or 503 is tried again on a long walk

    def left(self):
        return self.t_end - time.monotonic()

    def timed_out(self):
        """The whole limit ran out, or a call with no host never returned (a file system
        that hangs). 's' is the whole limit."""
        return ConnectError("check_timeout", {"s": self.limit_s})

    def no_reply(self, host, cap=None):
        """A step after the connection ran out of time: the host took the connection and
        then said nothing - usually the wrong port, the wrong protocol or a hung service.
        's' is the limit that applied to that step, as for no_answer."""
        if not host:
            return self.timed_out()
        _s = self.cap if cap is None else cap
        try:
            _s = max(1, int(round(float(_s))))
        except (TypeError, ValueError):
            _s = self.limit_s
        return ConnectError("no_reply", {"host": host, "s": _s})

    def step(self, cap):
        """Seconds this step may take: its own limit, capped by the time that's left."""
        _left = self.left()
        if _left <= 0.05:
            raise self.timed_out()
        self.cap = min(float(cap), _left)
        return self.cap

    def driver(self, module_name, component=None):
        """Import a driver when it is needed; a missing one is not_checkable."""
        _err = None
        try:
            return importlib.import_module(module_name)
        except Exception:
            _err = ConnectError("checker_missing", {"component": component or module_name})
        raise _err


def _run_limited(fn, seconds):
    """Run a call that has no timeout of its own (a name lookup, a look at a
    network mount) and stop waiting after 'seconds'. The helper thread is a
    daemon: one that never returns can't keep the process alive."""
    _box = {}

    def _target():
        try:
            _box["value"] = fn()
        except BaseException as _e:      # handed to the caller below
            _box["error"] = _e

    _t = threading.Thread(target=_target, name="ds_connect_lib.limited", daemon=True)
    _t.start()
    _t.join(seconds)
    if _t.is_alive():
        raise _StepTimeout()
    if "error" in _box:
        raise _box["error"]
    return _box.get("value")


@contextmanager
def _watchdog(ctx, seconds, kill, host=None):
    """Give a blocking driver call 'seconds'. When they pass, 'kill' ends it from
    outside (it closes the socket under the driver), and the caller gets no_reply."""
    _fired = threading.Event()

    def _fire():
        _fired.set()
        try:
            kill()
        except Exception:
            pass

    _timer = threading.Timer(seconds, _fire)
    _timer.daemon = True
    _timer.start()
    _err = None
    try:
        yield _fired
    except Exception:
        if not _fired.is_set():
            raise
        _err = ctx.no_reply(host, seconds)
    finally:
        _timer.cancel()
    if _err is not None:
        raise _err


def _kill_fd(fileno):
    """Shut a driver's socket down through a copy of its descriptor: the blocked
    call returns with an error at once, and nothing of the driver's is touched."""
    _s = socket.socket(fileno=os.dup(fileno))
    try:
        _s.shutdown(socket.SHUT_RDWR)
    finally:
        _s.close()


# ---------------------------------------------------------------------------
# 4. Reaching the host: the library looks before the driver does, so the same
#    failure gets the same code whatever the type.
#       1. resolve the name          -> host_not_found
#       2. open a TCP connection     -> no_answer | refused
#       3. hand over to the driver
# ---------------------------------------------------------------------------
def _getaddrinfo(host, port):
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def _socket_connect(family, sockaddr, timeout):
    _s = socket.socket(family, socket.SOCK_STREAM)
    try:
        _s.settimeout(timeout)
        _s.connect(sockaddr)
        return _s
    except BaseException:
        _s.close()
        raise


def _bare_host(host):
    """The name a lookup takes: no IPv6 brackets, no SQL Server instance."""
    _h = str(host or "").strip()
    if "\\" in _h:
        _h = _h.split("\\", 1)[0]
    if _h.startswith("[") and _h.endswith("]"):
        _h = _h[1:-1]
    return _h


def _lookup(ctx, host, port=None, shown=None):
    """Step 1. Returns [(family, sockaddr)]."""
    _cap = ctx.step(STEP_LOOKUP_SEC)
    _infos = None
    try:
        _infos = _run_limited(lambda: _getaddrinfo(_bare_host(host), int(port or 0)), _cap)
    except Exception:
        _infos = None
    if not _infos:
        raise ConnectError("host_not_found", {"host": shown or _bare_host(host)})
    _seen, _out = set(), []
    for _i in _infos:
        if _i[4] not in _seen:
            _seen.add(_i[4])
            _out.append((_i[0], _i[4]))
    return _out


def _tcp_open(ctx, infos, host, port):
    """Step 2. Returns (socket, address). The caller closes the socket."""
    _cap = ctx.step(STEP_TCP_SEC)
    _t_end = time.monotonic() + _cap
    _refused = False
    _silent = False
    for _family, _sockaddr in infos[:4]:
        _left = _t_end - time.monotonic()
        if _left <= 0:
            _silent = True
            break
        try:
            _sock = _socket_connect(_family, _sockaddr, _left)
            ctx.connected = True
            return _sock, _sockaddr[0]
        except ConnectionRefusedError:
            _refused = True
        except (socket.timeout, TimeoutError):
            _silent = True
        except OSError:
            _silent = True              # no route, network unreachable: nothing answered
    if _refused and not _silent:
        raise ConnectError("refused", {"host": host, "port": port})
    raise ConnectError("no_answer", {"host": host, "port": port, "s": max(1, int(round(_cap)))})


def _reach(ctx, host, port, on_connect=None, shown=None):
    """Steps 1 and 2 for a host and a port. Returns (address, on_connect's answer).
    on_connect(socket) lets a connector ask one protocol question on the probe
    connection before it is closed (PostgreSQL: does the server speak TLS?)."""
    _shown = shown or _bare_host(host)
    _infos = _lookup(ctx, host, port, shown=_shown)
    _sock, _addr = _tcp_open(ctx, _infos, _shown, port)
    try:
        _answer = on_connect(_sock) if on_connect else None
    finally:
        try:
            _sock.close()
        except Exception:
            pass
    return _addr, _answer


# ---------------------------------------------------------------------------
# 5. Certificates
# ---------------------------------------------------------------------------
def _system_ca_file():
    """The system's authorities as one file, for a driver that wants a path."""
    import ssl
    for _p in (os.environ.get("SSL_CERT_FILE"), ssl.get_default_verify_paths().cafile,
               "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"):
        if _p and os.path.isfile(_p):
            return _p
    return None


def _ssl_context(ca_file=None):
    """Trust the system's authorities, or the bundle the caller passed (the system's
    plus the customer's own, as one file)."""
    import ssl
    return ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()


def _tls_code(exc):
    """A certificate failure -> its catalogue code."""
    _code = getattr(exc, "verify_code", None)
    _text = (str(getattr(exc, "verify_message", "") or "") + " " + str(exc)).lower()
    if _code == 10 or "certificate has expired" in _text:
        return "tls_cert_expired"
    if _code in (62, 63, 64) or "hostname mismatch" in _text or "ip address mismatch" in _text \
            or "doesn't match" in _text or "does not match" in _text:
        return "tls_cert_mismatch"
    if _code is not None or "certificate verify failed" in _text or "self-signed" in _text \
            or "self signed" in _text or "unable to get local issuer" in _text or "unknown ca" in _text:
        return "tls_cert_untrusted"
    return "tls_failed"


# ---------------------------------------------------------------------------
# 6. The handle connect() returns
# ---------------------------------------------------------------------------
class Handle(object):
    """A signed-in connection to a customer's system. '.client' is what a scanner
    works with: the driver's connection for a database, the client for MongoDB,
    the session for an HTTP type, the resolved path for a file system. Leaving
    the 'with' block closes everything; a token lives as long as the handle.

    For the HTTP types these are a caller's to use too, and a change to any of them is
    announced as a change to this library's calls is (2026.47.3):
        handle.call(method, url, **kw)   one call with the proxy, the time limits, the mapping of
                                         TLS and network failures to codes, and the 429/503 handling
                                         (connect's 'retries'); returns the response, or raises ConnectError
        handle.token                     the bearer: handle.token() is the current token,
                                         handle.token.auth() the Authorization header
        handle.token_for(resource)       Entra types: a bearer for another resource from the same app
        handle.as_user(email)            gmail, gdocs: a bearer with the same scopes acting as that user
        handle.base_url, .site_host, .roles, .shown_host, .repository_id, .scopes
                                         where the type has them (None or absent where it hasn't)
        handle.http                      kept for code written on 2026.47.2; handle.call is the same call
    Threads: an HTTP handle may be used from several threads at once (the bearer has a lock,
    the connection pool keeps 10 connections per host; more threads wait for one, they don't
    fail), and so may a mongo handle. A database handle (postgres, sqlserver, oracle_*) is one
    per thread."""

    def __init__(self, source_type, client, closer=None, **extra):
        self.source_type = source_type
        self.client = client
        self._closer = closer
        self._closed = False
        for _k, _v in extra.items():
            setattr(self, _k, _v)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False

    def call(self, method, url, **kw):
        """One HTTP call on this handle's session (HTTP types only). See the class's note."""
        _http = getattr(self, "http", None)
        if _http is None:
            raise AttributeError("call() is for the HTTP types; " + str(self.source_type) + " has no HTTP session")
        return _http.call(method, url, **kw)

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self._closer is not None:
                self._closer()
        except Exception:
            pass

    def __repr__(self):
        return "<ds_connect_lib.Handle " + str(self.source_type) + (" closed" if self._closed else "") + ">"


# ---------------------------------------------------------------------------
# 7. The registry
#    One entry per source type with a connector:
#       fields       (key, required, default) in the order a missing one is reported
#       secret_keys  the keys whose values must never leave
#       needs        what the image must carry (see _REQUIREMENTS)
#       permissions  what the scanner needs granted (Microsoft and Google types), as help for the app
#       open         (connection, ctx) -> Handle      reach the host and sign in once
#       probe        (handle, connection, ctx)        the one small read that proves the account can work
# ---------------------------------------------------------------------------
_Connector = namedtuple("_Connector", "source_type fields secret_keys needs permissions open probe optional",
                        defaults=(None,))
_CONNECTORS = {}
# the order types() lists them in: databases, Microsoft, Google, the rest, files
_TYPE_ORDER = ("postgres", "sqlserver", "oracle_service", "oracle_sid", "mongo", "databricks", "fabric", "dynamics",
               "dataverse", "sharepoint", "onedrive", "msoutlook", "teams", "gmail", "gdocs", "box", "laserfiche",
               "blink", "directory")


def _register(source_type, fields, secret_keys, needs, open_fn, probe_fn, permissions=None, optional=None):
    _CONNECTORS[source_type] = _Connector(source_type, tuple(fields), tuple(secret_keys), tuple(needs),
                                          tuple(permissions) if permissions else None, open_fn, probe_fn,
                                          tuple(optional) if optional else None)


def _module_present(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def _odbc_missing():
    if not _module_present("pyodbc"):
        return "pyodbc"
    try:
        _names = importlib.import_module("pyodbc").drivers()
    except Exception:
        return "unixODBC"
    return None if _ODBC_DRIVER in _names else _ODBC_DRIVER


_ELF_MACHINES = {"x86_64": 0x3E, "amd64": 0x3E, "aarch64": 0xB7, "arm64": 0xB7}


def _oracle_client_present():
    """Is there an Oracle client in the folder, built for this machine? An x86-64 client
    copied into an arm64 image is there and can't load: that is 'missing' too."""
    import platform
    try:
        _libs = sorted(_f for _f in os.listdir(_oracle_client_dir) if _f.startswith("libclntsh.so"))
        if not _libs:
            return False
        with open(os.path.join(_oracle_client_dir, _libs[0]), "rb") as _f:
            _head = _f.read(20)
    except OSError:
        return False
    _want = _ELF_MACHINES.get(platform.machine().lower())
    if len(_head) < 20 or _head[:4] != b"\x7fELF" or _want is None:
        return True                     # not something this can judge: the first connect will
    return struct.unpack("<H", _head[18:20])[0] == _want


def _oracle_missing():
    if not _module_present("oracledb"):
        return "python-oracledb"
    if _oracle_allow_thin or _oracle_thick["thick"] or _oracle_client_present():
        return None
    return "Oracle Instant Client"


def _modules_missing(*pairs):
    def _check():
        for _module, _component in pairs:
            if not _module_present(_module):
                return _component
        return None
    return _check


# requirement -> a function that returns None, or the name of the component that is missing
_REQUIREMENTS = {
    "postgres": _modules_missing(("psycopg2", "psycopg2")),
    "sqlserver": _odbc_missing,
    "oracle": _oracle_missing,
    "mongo": _modules_missing(("pymongo", "PyMongo"), ("dns", "dnspython")),
    "http": _modules_missing(("requests", "Requests")),
    "jwt": _modules_missing(("requests", "Requests"), ("jwt", "PyJWT"), ("cryptography", "cryptography")),
    "none": lambda: None,
}


def _missing_component(connector):
    for _need_name in connector.needs:
        _m = _REQUIREMENTS[_need_name]()
        if _m:
            return _m
    return None


def types():
    """The registry: {source_type: TypeInfo}. 'checkable' is true for every type listed
    (a type the library has no connector for is not listed). 'available' says whether
    it can run in this image; when it can't, 'missing' names the component."""
    _out = {}
    for _name in sorted(_CONNECTORS, key=lambda _n: (_TYPE_ORDER.index(_n) if _n in _TYPE_ORDER else len(_TYPE_ORDER), _n)):
        _c = _CONNECTORS[_name]
        _m = _missing_component(_c)
        _out[_name] = TypeInfo(True, _m is None, _m, _c.secret_keys, _c.permissions, _c.optional)
    return _out


def _is_empty(value):
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (dict, list, tuple)):
        return len(value) == 0
    return False


def _require_complete(connector, connection):
    """A required value that is missing ends the check before anything is contacted."""
    for _key, _required, _default in connector.fields:
        if _required and _is_empty(connection.get(_key)):
            raise ConnectError("connection_incomplete", {"key": _key})


def _port_of(connection, default):
    _p = connection.get("port")
    try:
        return int(_p) if not _is_empty(_p) else int(default)
    except (TypeError, ValueError):
        return int(default)


def _as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")


# ---------------------------------------------------------------------------
# 8. The public calls
# ---------------------------------------------------------------------------
def _norm_type(source_type):
    return str(source_type or "").strip().lower()


def _not_checkable(code, params=None):
    _p = dict(params or {})
    return CheckResult("not_checkable", None, code, _p, message(code, _p))


def precheck(source_type, file_roots=None):
    """The answers that need no connection. Returns a not_checkable CheckResult when
    this worker can't check the type at all - no connector, a driver that isn't in
    the image, a file system type and no file roots - and None when a check can run.
    Nothing is contacted."""
    _st = _norm_type(source_type)
    _c = _CONNECTORS.get(_st)
    if _c is None:
        return _not_checkable("not_checkable")
    _m = _missing_component(_c)
    if _m:
        return _not_checkable("checker_missing", {"component": _m})
    if _st == "directory" and not [_r for _r in (file_roots or []) if str(_r or "").strip()]:
        return _not_checkable("roots_not_mounted")
    return None


def _open(connector, connection, ctx):
    _m = _missing_component(connector)
    if _m:
        raise ConnectError("checker_missing", {"component": _m})
    if connector.source_type == "directory" and not ctx.file_roots:
        raise ConnectError("roots_not_mounted")
    _require_complete(connector, connection)
    return connector.open(connection, ctx)


def _prepare(source_type, connection, timeout, file_roots, ca_file, proxy):
    _st = _norm_type(source_type)
    _connector = _CONNECTORS.get(_st)
    if _connector is None:
        raise ConnectError("not_checkable")
    _c = dict(connection) if isinstance(connection, dict) else {}
    _secrets = _secret_values(_connector.secret_keys, _c)
    return _connector, _c, _Ctx(_st, _c, timeout, file_roots, ca_file, proxy, _secrets)


def _safe_error(exc, secrets):
    """Any exception -> a ConnectError that carries no secret and no driver exception."""
    if isinstance(exc, ConnectError):
        _entry = _BY_CODE.get(exc.code)
        if _entry is None:
            return ConnectError("unexpected", {"reason": _reason(exc.code, secrets)})
        _params = {}
        for _k in _entry[3]:
            if _k in exc.params and exc.params[_k] is not None:
                _v = exc.params[_k]
                _params[_k] = _scrub(_v, secrets) if isinstance(_v, str) else _v
        return ConnectError(exc.code, _params)
    if isinstance(exc, _StepTimeout):
        return None
    return ConnectError("unexpected", {"reason": _reason(exc, secrets)})


def connect(source_type, connection, *, timeout=DEFAULT_TIMEOUT_SEC, file_roots=None, ca_file=None, proxy=None,
            retries=0):
    """Reach the host, sign in once, and return a Handle: the client or session a
    scanner would work with. Use it in a 'with' block; leaving it closes everything.

        source_type   a V2 source type ('postgres', 'sharepoint', 'directory' ...)
        connection    the V2 connection object: stored values and secrets, by key
        timeout       seconds for the whole sign-in
        file_roots    the folders mounted for the workers (file system types)
        ca_file       one file with every authority to trust; None = the system's
        proxy         {'https': url, 'no_proxy': 'a,b'} for the HTTP types; None = no proxy
        retries       HTTP types, for a long walk: a 429 or 503 is tried again up to this many times,
                      waiting as Retry-After says (5 minutes at most a wait), or 2, 4, 8 ... 60 seconds
                      when it doesn't say; when it gives up, service_error's params carry 'retry_after',
                      the seconds the server last asked for. 0 (the default, and always for check()):
                      one retry, only when Retry-After says and the wait fits in the time that's left

    Raises ConnectError(code, params) on failure; nothing else, and never with a secret."""
    _err = None
    _secrets = ()
    try:
        _connector, _c, _ctx = _prepare(source_type, connection, timeout, file_roots, ca_file, proxy)
        _secrets = _ctx.secrets
        _ctx.checking = False
        try:
            _ctx.retries = max(0, min(100, int(retries or 0)))
        except (TypeError, ValueError):
            _ctx.retries = 0
        _handle = _open(_connector, _c, _ctx)
        _ctx.t_end = float("inf")       # 'timeout' was for the sign-in; what the caller does next is the caller's
        return _handle
    except Exception as _e:
        _err = _safe_error(_e, _secrets) or ConnectError("check_timeout", {"s": timeout})
    raise _err          # raised outside the handler: no driver exception travels with it


def check(source_type, connection, *, timeout=DEFAULT_TIMEOUT_SEC, file_roots=None, ca_file=None, proxy=None):
    """connect, one minimal read, close. Returns a CheckResult; never raises.

        status   'reachable' | 'unreachable' | 'not_checkable'
        ms       how long the check took, in whole milliseconds; None for not_checkable
        code     None when reachable, otherwise a catalogue code
        params   None when reachable, otherwise a flat dict of the values in the message
        message  None when reachable, otherwise message(code, params)"""
    _t0 = time.monotonic()
    _secrets = ()
    _err = None
    try:
        _pre = precheck(source_type, file_roots=file_roots)
        if _pre is not None:
            return _pre
        _connector, _c, _ctx = _prepare(source_type, connection, timeout, file_roots, ca_file, proxy)
        _secrets = _ctx.secrets
        _handle = _open(_connector, _c, _ctx)
        try:
            _connector.probe(_handle, _c, _ctx)
        finally:
            _handle.close()
        return CheckResult("reachable", int((time.monotonic() - _t0) * 1000), None, None, None)
    except Exception as _e:
        try:
            _err = _safe_error(_e, _secrets) or ConnectError("check_timeout", {"s": timeout})
        except Exception:
            _err = ConnectError("unexpected", {"reason": "the failure could not be described"})
    _status = _err.status
    _params = dict(_err.params)
    _message = _scrub(message(_err.code, _params), _secrets)
    _ms = None if _status == "not_checkable" else int((time.monotonic() - _t0) * 1000)
    return CheckResult(_status, _ms, _err.code, _params, _message)


# ===========================================================================
# CONNECTORS
# ===========================================================================
_GRAPH_DEFAULT = "https://graph.microsoft.com"

# ---------------------------------------------------------------------------
# postgres
#   sign-in: to 'database', with 'ssl_mode'            read: select 1
#   ONE sign-in: libpq's own 'prefer' signs in twice when the password is wrong
#   (once with TLS, once without - measured: two failed logins per check). So the
#   library asks the server on the probe connection whether it speaks TLS, and
#   then tells libpq 'require' or 'disable': the same outcome as 'prefer', with
#   one attempt.
# ---------------------------------------------------------------------------
_PG_SSL_REQUEST = struct.pack("!ii", 8, 80877103)
_PG_PREFIX_RE = re.compile(r'^connection to server at "[^"]*"(?: \([^)]*\))?, port \d+ failed: ')
_PG_SEVERITY_RE = re.compile(r"^[A-ZÀ-Ü]+:\s+")


def _pg_ask_tls(ctx, shown):
    def _ask(sock):
        try:
            sock.settimeout(ctx.step(STEP_TCP_SEC))
            sock.sendall(_PG_SSL_REQUEST)
            return sock.recv(1)
        except (socket.timeout, TimeoutError):
            _silent = True
        except OSError:
            return b""
        if _silent:
            raise ctx.no_reply(shown)
    return _ask


def _pg_first_line(exc):
    _line = next((_l.strip() for _l in str(exc).splitlines() if _l.strip()), "")
    _line = _PG_PREFIX_RE.sub("", _line)
    return _PG_SEVERITY_RE.sub("", _line)


def _pg_tls_diagnose(ctx, host, addr, port, ca_file, check_hostname):
    """libpq only says 'certificate verify failed'. Shake hands once more on a
    connection of our own - no sign-in - to learn which certificate fault it is."""
    import ssl
    _sock = None
    try:
        _family = socket.AF_INET6 if ":" in str(addr) else socket.AF_INET
        _sock = _socket_connect(_family, (addr, port), min(5.0, ctx.step(STEP_TCP_SEC)))
        _sock.sendall(_PG_SSL_REQUEST)
        if _sock.recv(1) != b"S":
            return "tls_failed"
        _context = _ssl_context(ca_file)
        _context.check_hostname = bool(check_hostname)
        _tls = _context.wrap_socket(_sock, server_hostname=_bare_host(host))
        _tls.close()
        return "tls_cert_untrusted"
    except ssl.SSLCertVerificationError as _e:
        return _tls_code(_e)
    except Exception:
        return "tls_cert_untrusted"
    finally:
        try:
            if _sock is not None:
                _sock.close()
        except Exception:
            pass


def _pg_error(exc, c, ctx, host, addr, port, mode, ca_file):
    """psycopg2 gives no SQLSTATE for a failed connect, so the server's sentence is
    matched. English, French and Spanish servers are covered for the three the
    package lists (28P01, 3D000, 42501); anything else is 'unexpected' with its text."""
    _text = str(exc)
    _low = _text.lower()
    _shown = _bare_host(host)
    _db = c.get("database")
    if "password authentication failed" in _low or "authentification par mot de passe" in _low \
            or "la autentificaci" in _low or "authentication failed for user" in _low \
            or ('role "' in _low and "does not exist" in _low and "database" not in _low.split("does not exist")[0]):
        return ConnectError("signin_rejected", {"account": c.get("username")})
    if "no pg_hba.conf entry" in _low or "pg_hba.conf" in _low:
        return ConnectError("client_not_allowed", {"host": _shown})
    if ('database "' in _low and "does not exist" in _low) or "n'existe pas" in _low and "base de donn" in _low \
            or "no existe la base de datos" in _low:
        return ConnectError("database_missing", {"host": _shown, "database": _db})
    if "permission denied for database" in _low or "droit refus" in _low and "base de donn" in _low \
            or "permiso denegado a la base de datos" in _low:
        return ConnectError("no_read_database", {"database": _db})
    if "certificate verify failed" in _low or "certificate has expired" in _low:
        return ConnectError(_pg_tls_diagnose(ctx, host, addr, port, ca_file, mode == "verify-full"), {"host": _shown})
    if "does not match host name" in _low:
        return ConnectError("tls_cert_mismatch", {"host": _shown})
    if "ssl" in _low and ("does not support ssl" in _low or "ssl error" in _low or "ssl syscall" in _low
                          or "root certificate" in _low or "could not" in _low):
        return ConnectError("tls_failed", {"host": _shown})
    if "timeout expired" in _low or "timed out" in _low:
        return ctx.no_reply(_shown) if ctx.connected else ConnectError("no_answer", {"host": _shown, "port": port, "s": STEP_TCP_SEC})
    if "connection refused" in _low:
        return ConnectError("refused", {"host": _shown, "port": port})
    if "could not translate host name" in _low:
        return ConnectError("host_not_found", {"host": _shown})
    return ConnectError("unexpected", {"reason": _reason(_pg_first_line(exc), ctx.secrets)})


def _pg_open(c, ctx):
    psycopg2 = ctx.driver("psycopg2")
    _host = str(c["host"]).strip()
    _port = _port_of(c, 5432)
    _mode = str(c.get("ssl_mode") or "prefer").strip().lower()
    _addr, _tls = _reach(ctx, _host, _port, on_connect=_pg_ask_tls(ctx, _bare_host(_host)) if _mode in ("prefer", "allow") else None)
    if _mode in ("prefer", "allow"):
        _mode = "require" if _tls == b"S" else "disable"
    _kw = dict(host=_bare_host(_host), hostaddr=_addr, port=_port, dbname=str(c["database"]),
               user=str(c["username"]), password=str(c["password"]), sslmode=_mode,
               connect_timeout=max(2, int(ctx.step(STEP_CALL_SEC))), application_name=_APP_NAME,
               gssencmode="disable")
    ctx.cap = _kw["connect_timeout"]                # whole seconds: what libpq is really given
    _ca = None
    if _mode in ("verify-ca", "verify-full"):
        _ca = ctx.ca_file or _system_ca_file()
        _kw["sslrootcert"] = _ca or "system"
    _err = None
    try:
        _conn = psycopg2.connect(**_kw)
    except Exception as _e:
        _err = _pg_error(_e, c, ctx, _host, _addr, _port, _mode, _ca)
    if _err is not None:
        raise _err
    return Handle("postgres", _conn, _conn.close, shown_host=_bare_host(_host))


def _pg_probe(handle, c, ctx):
    _conn = handle.client
    _err = None
    try:
        with _watchdog(ctx, ctx.step(STEP_CALL_SEC), lambda: _kill_fd(_conn.fileno()), host=handle.shown_host):
            _cur = _conn.cursor()
            _cur.execute("select 1")
            _cur.fetchone()
            _cur.close()
    except ConnectError:
        raise
    except Exception as _e:
        _err = ConnectError("unexpected", {"reason": _reason(_pg_first_line(_e), ctx.secrets)})
    if _err is not None:
        raise _err


_register("postgres",
          fields=(("host", True, None), ("port", False, 5432), ("database", True, None), ("username", True, None),
                  ("password", True, None), ("ssl_mode", False, "prefer")),
          secret_keys=("password",), needs=("postgres",), open_fn=_pg_open, probe_fn=_pg_probe)


# ---------------------------------------------------------------------------
# sqlserver
#   sign-in: to 'database', with 'encrypt' and 'trust_server_certificate'     read: select 1
#   host 'server\instance': the port is left off, and the driver finds the instance.
# ---------------------------------------------------------------------------
_ODBC_NATIVE_RE = re.compile(r"\((\d{3,6})\)")
_ODBC_PREFIX_RE = re.compile(r"^(?:\[[^\]]*\]\s*)+")


def _odbc_value(value):
    """A value inside an ODBC connection string: braced, so ';' and '=' in a password are safe."""
    return "{" + str(value).replace("}", "}}") + "}"


def _mssql_error(exc, c, ctx, shown, port):
    _text = " ".join(str(_a) for _a in getattr(exc, "args", ()) or (str(exc),))
    _low = _text.lower()
    _native = set(int(_n) for _n in _ODBC_NATIVE_RE.findall(_text))
    _account = c.get("username")
    if 4060 in _native:
        return ConnectError("database_unavailable", {"host": shown, "database": c.get("database")})
    if 18486 in _native:
        return ConnectError("signin_locked", {"account": _account})
    if _native & {18487, 18488}:
        return ConnectError("signin_password_expired", {"account": _account})
    if 18456 in _native:
        return ConnectError("signin_rejected", {"account": _account})
    if 40615 in _native:
        return ConnectError("client_not_allowed", {"host": shown})
    if "ssl provider" in _low or "certificate" in _low or "ssl routines" in _low or " tls" in _low:
        if "certificate" in _low or "self-signed" in _low or "self signed" in _low:
            return ConnectError(_tls_code(_text), {"host": shown})
        return ConnectError("tls_failed", {"host": shown})
    if "login timeout expired" in _low or "hyt00" in _low or "timeout expired" in _low:
        if ctx.connected:
            return ctx.no_reply(shown)
        if port is None:                # a named instance: no connection of ours to go by
            return ConnectError("unexpected", {"reason": "the sign-in to the named instance timed out"})
        return ConnectError("no_answer", {"host": shown, "port": port, "s": STEP_TCP_SEC})
    if "connection refused" in _low and port is not None:
        return ConnectError("refused", {"host": shown, "port": port})
    _line = next((_l.strip() for _l in _text.splitlines() if _l.strip()), "")
    return ConnectError("unexpected", {"reason": _reason(_ODBC_PREFIX_RE.sub("", _line), ctx.secrets)})


def _mssql_open(c, ctx):
    pyodbc = ctx.driver("pyodbc")
    pyodbc.pooling = False              # nothing shared between two data sources, not even by the driver manager
    _host = str(c["host"]).strip()
    _shown = _bare_host(_host)
    _named = "\\" in _host
    _port = None if _named else _port_of(c, 1433)
    if _named:
        _lookup(ctx, _host, shown=_shown)                       # no port to try: the driver finds the instance
        _server = _host
    else:
        _reach(ctx, _host, _port)
        _server = "tcp:" + _shown + "," + str(_port)
    _cap = max(1, int(ctx.step(STEP_CALL_SEC)))
    ctx.cap = _cap
    _string = ";".join((
        "DRIVER={" + _ODBC_DRIVER + "}",
        "SERVER=" + _odbc_value(_server),
        "DATABASE=" + _odbc_value(c["database"]),
        "UID=" + _odbc_value(c["username"]),
        "PWD=" + _odbc_value(c["password"]),
        "Encrypt=" + ("yes" if _as_bool(c.get("encrypt"), True) else "no"),
        "TrustServerCertificate=" + ("yes" if _as_bool(c.get("trust_server_certificate"), False) else "no"),
        "ConnectRetryCount=0",
        "LoginTimeout=" + str(_cap),
        "APP=" + _odbc_value(_APP_NAME))) + ";"
    _err = None
    try:
        _conn = pyodbc.connect(_string, timeout=_cap, autocommit=True)
    except Exception as _e:
        _err = _mssql_error(_e, c, ctx, _shown, _port)
    if _err is not None:
        raise _err
    return Handle("sqlserver", _conn, _conn.close, shown_host=_shown, port=_port)


def _mssql_probe(handle, c, ctx):
    _conn = handle.client
    _err = None
    try:
        _conn.timeout = max(1, int(ctx.step(STEP_CALL_SEC)))    # the driver's own statement timeout
        ctx.cap = _conn.timeout
        _cur = _conn.cursor()
        _cur.execute("select 1")
        _cur.fetchone()
        _cur.close()
    except ConnectError:
        raise
    except Exception as _e:
        _low = str(_e).lower()
        if "timeout" in _low or "hyt00" in _low:
            _err = ctx.no_reply(handle.shown_host)
        else:
            _err = _mssql_error(_e, c, ctx, handle.shown_host, handle.port)
    if _err is not None:
        raise _err


_register("sqlserver",
          fields=(("host", True, None), ("port", False, 1433), ("database", True, None), ("username", True, None),
                  ("password", True, None), ("trust_server_certificate", False, False), ("encrypt", False, True)),
          secret_keys=("password",), needs=("sqlserver",), open_fn=_mssql_open, probe_fn=_mssql_probe)


# ---------------------------------------------------------------------------
# oracle_service, oracle_sid
#   sign-in: through the Oracle client (thick mode), as the scanner does; then the
#   session initialisation call when one is set      read: select 1 from dual
#   A failing session_init fails the connect: a scan on a session without its
#   context may see nothing, or the wrong rows.
# ---------------------------------------------------------------------------
_ORA_CODE_RE = re.compile(r"\b((?:ORA|DPY|DPI)-\d{4,5})\b")
_ORA_DSN_UNSAFE_RE = re.compile(r"[()=\s]")


def _ora_error(exc, c, ctx, shown, port, kind):
    _text = str(exc)
    _codes = set(_ORA_CODE_RE.findall(_text))
    _full = getattr(getattr(exc, "args", (None,))[0] if getattr(exc, "args", None) else None, "full_code", None)
    if _full:
        _codes.add(str(_full))
    _low = _text.lower()
    _account = c.get("username")

    def _has(*names):
        return any(_n in _codes for _n in names)

    if _has("ORA-01017"):
        return ConnectError("signin_rejected", {"account": _account})
    if _has("ORA-28000"):
        return ConnectError("signin_locked", {"account": _account})
    if _has("ORA-28001"):
        return ConnectError("signin_password_expired", {"account": _account})
    if _has("ORA-12514", "DPY-6001"):
        return ConnectError("service_missing", {"host": shown, "service_name": c.get("service_name")})
    if _has("ORA-12505", "DPY-6003"):
        return ConnectError("sid_missing", {"host": shown, "sid": c.get("sid")})
    if _has("ORA-12541") or (_has("DPY-6005") and "refused" in _low):
        return ConnectError("refused", {"host": shown, "port": port})
    if _has("ORA-12170", "ORA-12535") or (_has("DPY-6005") and "timed out" in _low):
        # the library's own probe has already connected: what timed out is the listener's answer
        if ctx.connected:
            return ctx.no_reply(shown)
        return ConnectError("no_answer", {"host": shown, "port": port, "s": STEP_TCP_SEC})
    if _has("ORA-01045"):
        return ConnectError("no_read_database", {"database": c.get(kind)})
    if _has("DPI-1047"):
        return ConnectError("checker_missing", {"component": "Oracle Instant Client"})
    if _has("DPY-4024", "ORA-03156", "DPI-1067"):
        return ctx.no_reply(shown)
    return ConnectError("unexpected", {"reason": _reason(_text, ctx.secrets)})


def _ora_run_session_init(cursor, init):
    """The scanner's parse, unchanged: PROC(arg, 'text', null)."""
    _proc = init.split("(")[0].strip()
    _args = []
    if "(" in init and ")" in init:
        _args_str = init[init.find("(") + 1:init.rfind(")")]
        _args = re.split(r""",(?![^']*'\s*,)""", _args_str) if _args_str.strip() else []
    _fargs = [None if _a.strip().lower() == "null" else _a.strip().strip("'") for _a in _args]
    cursor.callproc(_proc, _fargs)


def _ora_open_for(kind):
    def _open(c, ctx):
        oracledb = ctx.driver("oracledb", "python-oracledb")
        _no_client = False
        try:
            _oracle_init_thick(oracledb)        # process-wide, once; DS_ORACLE_ALLOW_THIN lets a dev box run thin
        except Exception:
            _no_client = True
        if _no_client:
            raise ConnectError("checker_missing", {"component": "Oracle Instant Client"})
        _host = str(c["host"]).strip()
        _shown = _bare_host(_host)
        _port = _port_of(c, 1521)
        _target = str(c[kind]).strip()
        if _ORA_DSN_UNSAFE_RE.search(_shown) or _ORA_DSN_UNSAFE_RE.search(_target):
            raise ConnectError("unexpected", {"reason": "the host or the " + ("service name" if kind == "service_name" else "SID")
                                                        + " holds a character a connect descriptor can't carry"})
        _reach(ctx, _host, _port)
        _cap = max(1, int(ctx.step(STEP_CALL_SEC)))
        ctx.cap = _cap
        _dsn = ("(DESCRIPTION=(CONNECT_TIMEOUT=" + str(_cap) + ")(TRANSPORT_CONNECT_TIMEOUT=" + str(min(_cap, STEP_TCP_SEC))
                + ")(RETRY_COUNT=0)(ADDRESS=(PROTOCOL=TCP)(HOST=" + _shown + ")(PORT=" + str(_port) + "))"
                + "(CONNECT_DATA=(" + ("SERVICE_NAME" if kind == "service_name" else "SID") + "=" + _target + ")))")
        _err = None
        _conn = None
        try:
            _conn = oracledb.connect(user=str(c["username"]), password=str(c["password"]), dsn=_dsn)
        except Exception as _e:
            _err = _ora_error(_e, c, ctx, _shown, _port, kind)
        if _err is not None:
            raise _err
        _init = str(c.get("session_init") or "").strip()
        if _init:
            _failed = False
            try:
                try:
                    _conn.call_timeout = int(ctx.step(STEP_CALL_SEC) * 1000)
                except ConnectError:
                    raise
                except Exception:
                    pass
                _cur = _conn.cursor()
                _ora_run_session_init(_cur, _init)
                _cur.close()
                try:
                    _conn.call_timeout = 0          # the limit was for this call only
                except Exception:
                    pass
            except ConnectError:
                _conn.close()
                raise
            except Exception:
                _failed = True
            if _failed:
                try:
                    _conn.close()
                except Exception:
                    pass
                raise ConnectError("session_init_failed", {"procedure": _init.split("(")[0].strip()[:60]})
        return Handle("oracle_" + ("service" if kind == "service_name" else "sid"), _conn, _conn.close,
                      shown_host=_shown, port=_port, kind=kind)
    return _open


def _ora_probe(handle, c, ctx):
    _conn = handle.client
    _err = None
    try:
        try:
            _conn.call_timeout = int(ctx.step(STEP_CALL_SEC) * 1000)
        except ConnectError:
            raise
        except Exception:
            pass
        _cur = _conn.cursor()
        _cur.execute("select 1 from dual")
        _cur.fetchone()
        _cur.close()
    except ConnectError:
        raise
    except Exception as _e:
        _err = _ora_error(_e, c, ctx, handle.shown_host, handle.port, handle.kind)
    if _err is not None:
        raise _err


_register("oracle_service",
          fields=(("host", True, None), ("port", False, 1521), ("service_name", True, None), ("username", True, None),
                  ("password", True, None), ("session_init", False, None)),
          secret_keys=("password",), needs=("oracle",), open_fn=_ora_open_for("service_name"), probe_fn=_ora_probe)
_register("oracle_sid",
          fields=(("host", True, None), ("port", False, 1521), ("sid", True, None), ("username", True, None),
                  ("password", True, None), ("session_init", False, None)),
          secret_keys=("password",), needs=("oracle",), open_fn=_ora_open_for("sid"), probe_fn=_ora_probe)


# ---------------------------------------------------------------------------
# mongo
#   sign-in: by 'scheme', with 'tls' and 'auth_database'      read: connectionStatus
#   mongodb+srv: the first step is the SRV lookup, and the hosts it returns are
#   what's connected to. 'port' is used with the standard scheme only.
# ---------------------------------------------------------------------------
def _srv_lookup(name, seconds):
    """[(host, port)] from the _mongodb._tcp SRV record of a DNS seed list."""
    _resolver = importlib.import_module("dns.resolver")
    _answer = _resolver.resolve("_mongodb._tcp." + name, "SRV", lifetime=seconds)
    return [(str(_r.target).rstrip("."), int(_r.port)) for _r in _answer]


def _mongo_error(exc, c, ctx, shown, port):
    _text = str(exc)
    _low = _text.lower()
    _code = getattr(exc, "code", None)
    if _code == 18 or "authentication failed" in _low or "'code': 18" in _low or "auth failed" in _low:
        return ConnectError("signin_rejected", {"account": c.get("username")})
    if "certificate verify failed" in _low or "certificate has expired" in _low or "hostname mismatch" in _low:
        return ConnectError(_tls_code(_text), {"host": shown})
    if "ssl handshake failed" in _low or "ssl:" in _low or "tlsv1" in _low or "wrong version number" in _low:
        return ConnectError("tls_failed", {"host": shown})
    if "dns query name does not exist" in _low or "dns response does not contain an answer" in _low \
            or "name or service not known" in _low or "nodename nor servname" in _low or "no address associated" in _low:
        return ConnectError("host_not_found", {"host": shown})
    if "connection refused" in _low and port is not None:
        return ConnectError("refused", {"host": shown, "port": port})
    if "timed out" in _low or "timeout" in _low:
        return ctx.no_reply(shown)
    return ConnectError("unexpected", {"reason": _reason(_text, ctx.secrets)})


def _mongo_open(c, ctx):
    pymongo = ctx.driver("pymongo", "PyMongo")
    _host = str(c["host"]).strip()
    _shown = _bare_host(_host)
    _scheme = str(c.get("scheme") or "mongodb+srv").strip().lower()
    _port = None
    if _scheme == "mongodb+srv":
        ctx.driver("dns.resolver", "dnspython")
        _members = None
        try:
            _members = _run_limited(lambda: _srv_lookup(_shown, STEP_LOOKUP_SEC), ctx.step(STEP_LOOKUP_SEC) + 1)
        except ConnectError:
            raise
        except Exception:
            _members = None
        if not _members:
            raise ConnectError("host_not_found", {"host": _shown})
        _last = None
        for _member, _member_port in _members[:3]:          # the first member that answers is enough
            try:
                _reach(ctx, _member, _member_port, shown=_shown)
                _last = None
                break
            except ConnectError as _e:
                _last = ConnectError(_e.code, _e.params)
        if _last is not None:
            raise _last
        _uri = "mongodb+srv://" + _shown + "/"
    else:
        _port = _port_of(c, 27017)
        _reach(ctx, _host, _port)
        _uri = "mongodb://" + (_host if _host.startswith("[") or ":" not in _host else "[" + _host + "]") + ":" + str(_port) + "/"
    _cap_ms = int(ctx.step(STEP_CALL_SEC) * 1000)
    _tls = _as_bool(c.get("tls"), True)
    _kw = dict(username=str(c["username"]), password=str(c["password"]),
               authSource=str(c.get("auth_database") or "admin"), tls=_tls,
               serverSelectionTimeoutMS=_cap_ms, connectTimeoutMS=min(_cap_ms, STEP_TCP_SEC * 1000),
               retryReads=False, retryWrites=False, appname=_APP_NAME)
    if ctx.checking:
        _kw["socketTimeoutMS"] = _cap_ms            # a check's read is short; a scanner sets its own
    if _tls and ctx.ca_file:
        _kw["tlsCAFile"] = ctx.ca_file
    _err = None
    _client = None
    try:
        _client = pymongo.MongoClient(_uri, **_kw)
        _client.admin.command("ping")           # the first command opens a connection, and that signs in
    except Exception as _e:
        _err = _mongo_error(_e, c, ctx, _shown, _port)
    if _err is not None:
        try:
            if _client is not None:
                _client.close()
        except Exception:
            pass
        raise _err
    return Handle("mongo", _client, _client.close, shown_host=_shown, port=_port)


def _mongo_probe(handle, c, ctx):
    _err = None
    try:
        handle.client.admin.command("connectionStatus")
    except Exception as _e:
        _err = _mongo_error(_e, c, ctx, handle.shown_host, handle.port)
    if _err is not None:
        raise _err


_register("mongo",
          fields=(("scheme", False, "mongodb+srv"), ("host", True, None), ("port", False, 27017), ("username", True, None),
                  ("password", True, None), ("auth_database", False, "admin"), ("tls", False, True)),
          secret_keys=("password",), needs=("mongo",), open_fn=_mongo_open, probe_fn=_mongo_probe)


# ===========================================================================
# The HTTP types
#   One requests session per handle, never shared. It takes no setting from the
#   environment: the proxy and the certificate bundle are what the caller passed.
#   One attempt per call; ONE retry for a 429 or 503 that says how long to wait,
#   when the wait fits in the time that's left.
# ===========================================================================
_HTTP_STATUS_TEXT = None


def _status_text(status):
    global _HTTP_STATUS_TEXT
    if _HTTP_STATUS_TEXT is None:
        import http.client
        _HTTP_STATUS_TEXT = dict(http.client.responses)
    return _HTTP_STATUS_TEXT.get(int(status), "Error")


def _endpoint(url):
    """The address a URL is called at. Itself; the tests point it at a local server."""
    return url


def _quiet_http_logging():
    """At debug level the HTTP libraries print request headers: keep them at warning or above."""
    for _name in ("urllib3", "requests", "pymongo", "oracledb"):
        _l = logging.getLogger(_name)
        if _l.level == logging.NOTSET or _l.level < logging.WARNING:
            _l.setLevel(logging.WARNING)


def _url_parts(value, key="base_url"):
    """(scheme://host[:port], host, full URL without a trailing slash). A value that is not an
    http(s) URL is an incomplete connection."""
    _u = str(value or "").strip().rstrip("/")
    _p = urllib.parse.urlsplit(_u)
    if _p.scheme not in ("http", "https") or not _p.hostname:
        raise ConnectError("connection_incomplete", {"key": key})
    return _p.scheme + "://" + _p.netloc.rsplit("@", 1)[-1], _p.hostname, _u


def _no_proxy_match(host, port, no_proxy):
    _host = str(host or "").lower()
    for _entry in str(no_proxy or "").split(","):
        _e = _entry.strip().lower()
        if not _e:
            continue
        if _e == "*":
            return True
        if ":" in _e and not _e.startswith("["):
            _e, _, _p = _e.rpartition(":")
            if _p.isdigit() and int(_p) != int(port or 0):
                continue
        _e = _e.lstrip("*").lstrip(".")
        if _host == _e or _host.endswith("." + _e):
            return True
    return False


def _find_ssl_error(exc):
    import ssl
    _seen = set()
    _stack = [exc]
    while _stack:
        _e = _stack.pop()
        if _e is None or id(_e) in _seen:
            continue
        _seen.add(id(_e))
        if isinstance(_e, ssl.SSLError):
            return _e
        _stack.extend([getattr(_e, "__cause__", None), getattr(_e, "__context__", None), getattr(_e, "reason", None)])
        _stack.extend(_a for _a in getattr(_e, "args", ()) if isinstance(_a, BaseException))
    return None


class _Http(object):
    def __init__(self, ctx, verify=True):
        self.requests = ctx.driver("requests", "Requests")
        _quiet_http_logging()
        self.ctx = ctx
        self.session = self.requests.Session()
        self.session.trust_env = False                      # no proxy, no bundle, no .netrc from the environment
        self.session.headers["User-Agent"] = "DataSentinel-connect/" + __version__
        self.verify = bool(verify)
        self.session.verify = (ctx.ca_file or _system_ca_file() or True) if self.verify else False

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass

    def proxy_for(self, url):
        _p = urllib.parse.urlsplit(url)
        _proxy = self.ctx.proxy.get("https") if _p.scheme == "https" else None
        if not _proxy or _no_proxy_match(_p.hostname, _p.port, self.ctx.proxy.get("no_proxy")):
            return None
        return _proxy

    def reach(self, url, shown=None):
        """Steps 1 and 2 for a URL: the port is the scheme's unless one is given. Behind a
        proxy both are skipped: the worker can't open a direct connection there, and trying
        would report a failure that isn't one."""
        _real = _endpoint(url)
        _p = urllib.parse.urlsplit(_real)
        _shown = shown or urllib.parse.urlsplit(url).hostname
        if self.proxy_for(_real):
            return _shown
        _reach(self.ctx, _p.hostname, _p.port or (443 if _p.scheme == "https" else 80), shown=_shown)
        return _shown

    def call(self, method, url, step=STEP_CALL_SEC, shown=None, **kw):
        """One call inside the check's limits. Returns the response for any answer that is
        not a 5xx or a 429; those, and every network or TLS failure, are a ConnectError."""
        import warnings
        _requests = self.requests
        _real = _endpoint(url)
        _target = urllib.parse.urlsplit(_real)
        _shown = shown or urllib.parse.urlsplit(url).hostname
        _port = _target.port or (443 if _target.scheme == "https" else 80)
        _proxy = self.proxy_for(_real)
        _tries = 0
        _asked = None                   # the last Retry-After the server gave, in seconds
        while True:
            _cap = self.ctx.step(step)
            _err = None
            _resp = None
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")         # the 'unverified HTTPS' warning of trust_server_certificate
                    _resp = self.session.request(method, _real, timeout=(min(_cap, STEP_TCP_SEC), _cap),
                                                 proxies={"https": _proxy} if _proxy else {},
                                                 allow_redirects=False, **kw)
            except _requests.exceptions.SSLError as _e:
                _err = ConnectError(_tls_code(_find_ssl_error(_e) or _e), {"host": _shown})
            except _requests.exceptions.ProxyError:
                _err = ConnectError("unexpected", {"reason": "the proxy refused or dropped the connection to " + str(_shown)})
            except _requests.exceptions.ConnectTimeout:
                _err = ConnectError("no_answer", {"host": _shown, "port": _port, "s": max(1, int(round(min(_cap, STEP_TCP_SEC))))})
            except _requests.exceptions.Timeout:
                _err = self.ctx.no_reply(_shown, _cap)
            except _requests.exceptions.ConnectionError as _e:
                _low = str(_e).lower()
                if _find_ssl_error(_e) is not None:
                    _err = ConnectError(_tls_code(_find_ssl_error(_e)), {"host": _shown})
                elif "name or service not known" in _low or "nameresolutionerror" in _low or "failed to resolve" in _low \
                        or "nodename nor servname" in _low or "getaddrinfo failed" in _low:
                    _err = ConnectError("host_not_found", {"host": _shown})
                elif "connection refused" in _low:
                    _err = ConnectError("refused", {"host": _shown, "port": _port})
                elif "timed out" in _low:
                    _err = self.ctx.no_reply(_shown, _cap)
                else:
                    _err = ConnectError("unexpected", {"reason": "the connection to " + str(_shown) + " was closed before an answer came"})
            except _requests.exceptions.RequestException as _e:
                _err = ConnectError("unexpected", {"reason": _reason(type(_e).__name__, self.ctx.secrets)})
            if _err is not None:
                raise _err
            _status = _resp.status_code
            if _status in (429, 503):
                _wait = self._retry_after(_resp)
                if _wait is not None:
                    _asked = _wait
                _more = self.ctx.retries        # a long walk's retries; 0: the check's single retry
                if _tries < max(1, _more):
                    if _more and _wait is None:
                        _wait = min(60.0, 2.0 ** (_tries + 1))          # 2, 4, 8 ... 60
                    if _more and _wait is not None:
                        _wait = min(_wait, RETRY_WAIT_MAX_SEC)
                    if _wait is not None and _wait <= self.ctx.left() - 1.0:
                        _tries += 1
                        time.sleep(_wait)
                        continue
            if _status >= 500 or _status == 429:
                _params = {"host": _shown, "status": _status, "status_text": _status_text(_status)}
                if self.ctx.retries and _asked is not None:
                    _params["retry_after"] = int(-(-_asked // 1))
                raise ConnectError("service_error", _params)
            return _resp

    @staticmethod
    def _retry_after(resp):
        _v = str(resp.headers.get("Retry-After") or "").strip()
        if not _v:
            return None
        if _v.isdigit():
            return float(_v)
        try:
            from email.utils import parsedate_to_datetime
            import datetime as _dt
            return max(0.0, (parsedate_to_datetime(_v) - _dt.datetime.now(_dt.timezone.utc)).total_seconds())
        except Exception:
            return None


def _json_body(resp):
    try:
        _b = resp.json()
        return _b if isinstance(_b, dict) else {}
    except Exception:
        return {}


def _jwt_claims(token):
    """The claims of a token, unverified: only to see which permissions it holds."""
    try:
        _part = str(token).split(".")[1]
        return json.loads(base64.urlsafe_b64decode(_part + "=" * (-len(_part) % 4)))
    except Exception:
        return None


class _Bearer(object):
    """A token for one handle. It lives as long as the handle and is asked for again
    when it has expired, so a long scan keeps working."""

    def __init__(self, fetch):
        self._fetch = fetch             # () -> (token, seconds it lasts)
        self._lock = threading.Lock()
        self._token = None
        self._until = 0.0

    def __call__(self):
        with self._lock:
            if self._token is None or time.monotonic() >= self._until:
                _token, _lasts = self._fetch()
                self._token = _token
                self._until = time.monotonic() + max(30.0, float(_lasts or 300) - 120.0)
            return self._token

    def auth(self):
        return {"Authorization": "Bearer " + self()}


def _http_handle(source_type, http, bearer=None, **extra):
    return Handle(source_type, http.session, http.close, http=http, token=bearer, **extra)


def _http_open(fn, verify_key=None):
    """Wrap an HTTP connector's sign-in: the session is closed if the sign-in fails."""
    def _open(c, ctx):
        _http = _Http(ctx, verify=not _as_bool(c.get(verify_key), False) if verify_key else True)
        try:
            return fn(c, ctx, _http)
        except BaseException:
            _http.close()
            raise
    return _open


# ---------------------------------------------------------------------------
# Entra (Microsoft) sign-in: client credentials. The authority follows the
# endpoint's cloud, as V1's Teams connector did: an endpoint ending in .us signs
# in at login.microsoftonline.us, one ending in .cn at login.chinacloudapi.cn,
# everything else at login.microsoftonline.com.
# ---------------------------------------------------------------------------
def _entra_authority(host):
    _h = str(host or "").lower()
    if _h.endswith(".us") or _h.endswith(".mil"):
        return "https://login.microsoftonline.us"
    if _h.endswith(".cn"):
        return "https://login.chinacloudapi.cn"
    return "https://login.microsoftonline.com"


def _graph_for_sharepoint(host):
    """The Graph endpoint of the cloud a SharePoint host lives in."""
    _h = str(host or "").lower()
    if _h.endswith(".sharepoint-mil.us"):
        return "https://dod-graph.microsoft.us"
    if _h.endswith(".us"):
        return "https://graph.microsoft.us"
    if _h.endswith(".cn"):
        return "https://microsoftgraph.chinacloudapi.cn"
    return _GRAPH_DEFAULT


_AADSTS_RE = re.compile(r"AADSTS(\d+)")


def _entra_fetch(ctx, http, c, authority, resource):
    """One token request. Returns (token, seconds it lasts)."""
    _url = authority + "/" + urllib.parse.quote(str(c["tenant_id"]).strip(), safe="") + "/oauth2/v2.0/token"
    http.reach(_url)
    _resp = http.call("POST", _url, step=STEP_TOKEN_SEC,
                      data={"grant_type": "client_credentials", "client_id": str(c["client_id"]).strip(),
                            "client_secret": str(c["client_secret"]), "scope": resource + "/.default"})
    _body = _json_body(_resp)
    if _resp.status_code == 200 and _body.get("access_token"):
        return str(_body["access_token"]), _body.get("expires_in") or 3600
    _description = str(_body.get("error_description") or "")
    _codes = set(str(_x) for _x in (_body.get("error_codes") or [])) | set(_AADSTS_RE.findall(_description))
    if "7000215" in _codes:
        raise ConnectError("secret_wrong")
    if "7000222" in _codes:
        raise ConnectError("secret_expired")
    if "700016" in _codes:
        raise ConnectError("app_not_found", {"client_id": c.get("client_id"), "tenant_id": c.get("tenant_id")})
    if _codes & {"90002", "900023", "900021"}:
        raise ConnectError("tenant_not_found", {"tenant_id": c.get("tenant_id")})
    raise ConnectError("unexpected", {"reason": _reason(
        _description or ("the token request answered " + str(_resp.status_code) + " " + _status_text(_resp.status_code)),
        ctx.secrets)})


def _entra_bearer(ctx, http, c, authority, resource):
    _bearer = _Bearer(lambda: _entra_fetch(ctx, http, c, authority, resource))
    _bearer()                           # the sign-in: once
    return _bearer


def _entra_token_for(ctx, http, c, authority):
    """handle.token_for(resource) on the Entra types: a bearer for another resource from the same app and the
    same credentials, such as https://storage.azure.com for OneLake (2026.47.3). One per resource, kept with
    the handle and renewed like the first. Raises ConnectError as a sign-in does."""
    _made = {}
    _lock = threading.Lock()

    def token_for(resource):
        _r = str(resource or "").strip().rstrip("/")
        if not _r.lower().startswith("https://"):
            raise ConnectError("unexpected", {"reason": "token_for needs the resource as an https address"})
        with _lock:
            _bearer = _made.get(_r.lower())
            if _bearer is None:
                _bearer = _Bearer(lambda: _entra_fetch(ctx, http, c, authority, _r))
                _made[_r.lower()] = _bearer
        _bearer()
        return _bearer
    return token_for


def _read_denied(resp, permission=None, host=None):
    """401 after sign-in: the token was rejected. 403: the permission when it can be named."""
    if resp.status_code == 401:
        return ConnectError("token_rejected")
    if resp.status_code == 403:
        if permission:
            return ConnectError("permission_missing", {"permission": permission})
        return ConnectError("no_read_service", {"host": host})
    return None


def _unexpected_answer(ctx, resp, what):
    return ConnectError("unexpected", {"reason": _reason(
        what + " answered " + str(resp.status_code) + " " + _status_text(resp.status_code), ctx.secrets)})


# ---------------------------------------------------------------------------
# sharepoint, onedrive, msoutlook, teams (Microsoft Graph)
#   sign-in: an Entra token for the Graph endpoint, holding every permission the scanner needs
#   read:    sharepoint  the root site of base_url's host (Sites.Selected only: the token is the pass)
#            onedrive, msoutlook  one user id          teams  one team id
#   Permissions are application permissions. Each entry lists the least one first, then
#   the wider ones that also satisfy it; the first name is what a failure reports.
# ---------------------------------------------------------------------------
_USER_READ = ("User.Read.All", "User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All")
_FILES_READ = ("Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All", "Sites.ReadWrite.All", "Sites.FullControl.All")
_GROUP_READ = ("Group.Read.All", "Group.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All")
_GRAPH_PERMISSIONS = {
    "sharepoint": (("Sites.Read.All", "Sites.ReadWrite.All", "Sites.Manage.All", "Sites.FullControl.All", "Sites.Selected"),),
    "onedrive": (_USER_READ, _FILES_READ),
    "msoutlook": (_USER_READ, ("Mail.Read", "Mail.ReadWrite")),
    "teams": (_GROUP_READ,
              ("Channel.ReadBasic.All", "ChannelSettings.Read.All", "ChannelSettings.ReadWrite.All") + _GROUP_READ[:2],
              ("ChannelMessage.Read.All",) + _GROUP_READ[:2],
              _FILES_READ),
}
_TEAMS_FILTER = "resourceProvisioningOptions/Any(x:x eq 'Team')"


def _graph_open_for(source_type):
    def _sign_in(c, ctx, http):
        _site_host = None
        if source_type == "sharepoint":
            _origin, _site_host, _full = _url_parts(c.get("base_url"))
            http.reach(_full)                               # the SharePoint host itself: a typing error is host_not_found
            _graph = _graph_for_sharepoint(_site_host)
        else:
            _graph, _ghost, _full = _url_parts(c.get("base_url") or _GRAPH_DEFAULT)
        _graph_host = urllib.parse.urlsplit(_graph).hostname
        _bearer = _entra_bearer(ctx, http, c, _entra_authority(_graph_host), _graph)
        _claims = _jwt_claims(_bearer())
        _roles = None
        if isinstance(_claims, dict):
            _roles = [str(_r) for _r in (_claims.get("roles") or [])]
            for _alternatives in _GRAPH_PERMISSIONS[source_type]:
                if not any(_a in _roles for _a in _alternatives):
                    raise ConnectError("permission_missing", {"permission": _alternatives[0]})
        http.reach(_graph)
        return _http_handle(source_type, http, _bearer, base_url=_graph, roles=_roles, site_host=_site_host,
                            token_for=_entra_token_for(ctx, http, c, _entra_authority(_graph_host)))
    return _http_open(_sign_in)


def _graph_probe(handle, c, ctx):
    _http, _graph, _type = handle.http, handle.base_url, handle.source_type
    _host = urllib.parse.urlsplit(_graph).hostname
    if _type == "sharepoint":
        _site_roles = [_r for _r in (handle.roles or []) if _r.startswith("Sites.")]
        if _site_roles and all(_r == "Sites.Selected" for _r in _site_roles):
            return                      # which sites were granted is scope; the root site is often not one of them
        _resp = _http.call("GET", _graph + "/v1.0/sites/" + handle.site_host, params={"$select": "id"},
                           headers=handle.token.auth())
        if _resp.status_code in (400, 404):
            raise ConnectError("host_not_found", {"host": handle.site_host})
        _permission = "Sites.Read.All"
    elif _type == "teams":
        _resp = _http.call("GET", _graph + "/v1.0/groups", headers=handle.token.auth(),
                           params={"$filter": _TEAMS_FILTER, "$select": "id", "$top": "1"})
        _permission = "Group.Read.All"
    else:
        _resp = _http.call("GET", _graph + "/v1.0/users", params={"$select": "id", "$top": "1"},
                           headers=handle.token.auth())
        _permission = "User.Read.All"
    if _resp.status_code == 200:
        return
    raise _read_denied(_resp, permission=_permission, host=_host) or _unexpected_answer(ctx, _resp, _host)


_ENTRA_FIELDS = (("base_url", True, None), ("tenant_id", True, None), ("client_id", True, None), ("client_secret", True, None))
_GRAPH_FIELDS = (("base_url", False, _GRAPH_DEFAULT),) + _ENTRA_FIELDS[1:]
# what a walk may need for an option of its own, which the check doesn't ask about (2026.47.3)
_GRAPH_OPTIONAL = {"teams": ("Chat.Read.All",)}     # chats with their members and messages, when the walk reads chats
for _t in ("sharepoint", "onedrive", "msoutlook", "teams"):
    _register(_t, fields=_ENTRA_FIELDS if _t == "sharepoint" else _GRAPH_FIELDS, secret_keys=("client_secret",),
              needs=("http",), open_fn=_graph_open_for(_t), probe_fn=_graph_probe,
              permissions=tuple(_a[0] for _a in _GRAPH_PERMISSIONS[_t]), optional=_GRAPH_OPTIONAL.get(_t))


# ---------------------------------------------------------------------------
# dynamics, dataverse          read: WhoAmI
# fabric                       read: the first page of workspaces (base_url with or without /v1)
#   sign-in: an Entra token for the environment (or the Fabric API) in base_url.
#   What the app may read there is set inside the product, not in the token, so a
#   403 on the read can't name a permission: no_read_service.
# ---------------------------------------------------------------------------
def _entra_api_open_for(source_type):
    def _sign_in(c, ctx, http):
        _origin, _host, _full = _url_parts(c.get("base_url"))
        http.reach(_full)
        _bearer = _entra_bearer(ctx, http, c, _entra_authority(_host), _origin)
        return _http_handle(source_type, http, _bearer, base_url=_origin, shown_host=_host,
                            token_for=_entra_token_for(ctx, http, c, _entra_authority(_host)))
    return _http_open(_sign_in)


def _dynamics_probe(handle, c, ctx):
    _resp = handle.http.call("GET", handle.base_url + "/api/data/v9.2/WhoAmI",
                             headers=dict(handle.token.auth(), Accept="application/json", **{"OData-Version": "4.0"}))
    if _resp.status_code == 200:
        return
    raise _read_denied(_resp, host=handle.shown_host) or _unexpected_answer(ctx, _resp, handle.shown_host)


def _fabric_probe(handle, c, ctx):
    _resp = handle.http.call("GET", handle.base_url + "/v1/workspaces", headers=handle.token.auth())
    if _resp.status_code == 200:
        return
    raise _read_denied(_resp, host=handle.shown_host) or _unexpected_answer(ctx, _resp, handle.shown_host)


for _t in ("dynamics", "dataverse"):
    _register(_t, fields=_ENTRA_FIELDS, secret_keys=("client_secret",), needs=("http",),
              open_fn=_entra_api_open_for(_t), probe_fn=_dynamics_probe)
_register("fabric", fields=_ENTRA_FIELDS, secret_keys=("client_secret",), needs=("http",),
          open_fn=_entra_api_open_for("fabric"), probe_fn=_fabric_probe)


# ---------------------------------------------------------------------------
# databricks
#   sign-in: the access token          read: the token's own user (SCIM Me)
#   'workspace_id' isn't used.
# ---------------------------------------------------------------------------
def _databricks_sign_in(c, ctx, http):
    _origin, _host, _full = _url_parts(c.get("base_url"))
    http.reach(_full)
    _token = str(c["access_token"])
    return _http_handle("databricks", http, _Bearer(lambda: (_token, 10 ** 9)), base_url=_origin, shown_host=_host)


def _databricks_probe(handle, c, ctx):
    _resp = handle.http.call("GET", handle.base_url + "/api/2.0/preview/scim/v2/Me", headers=handle.token.auth())
    if _resp.status_code == 200:
        return
    if _resp.status_code in (401, 403):
        raise ConnectError("token_rejected")
    raise _unexpected_answer(ctx, _resp, handle.shown_host)


_register("databricks",
          fields=(("base_url", True, None), ("workspace_id", False, None), ("access_token", True, None)),
          secret_keys=("access_token",), needs=("http",), open_fn=_http_open(_databricks_sign_in),
          probe_fn=_databricks_probe)


# ---------------------------------------------------------------------------
# gmail, gdocs (Google Workspace)
#   sign-in: a service-account token acting as 'delegated_user' (domain-wide delegation),
#            READ-ONLY scopes only - each of them is in the list V1 asked for, so a
#            customer's existing delegation covers them
#   read:    gmail  users.getProfile        gdocs  Drive about (the user only)
#            both   one directory user
#   No mail and no file is read.
#
#   WHAT A PASS PROVES: the sign-in, and the delegation for these scopes and no others.
#   For domain-wide delegation every scope asked for has to be in the admin's list by
#   name; a wider one there doesn't cover a narrower one. Until the scanners are on this
#   library they ask for their own, longer list, so a pass here says nothing about that list.
#   RULE FOR THE SCANNER MIGRATION: a scanner takes its scopes from this registry
#   (types()[type].permissions, and handle.scopes), so a check and a scan can never ask
#   for different things. A scope a scanner needs is added HERE, and the check then asks for it too.
# ---------------------------------------------------------------------------
_GOOGLE_DIRECTORY_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"
_GOOGLE_SCOPES = {
    "gmail": ("https://www.googleapis.com/auth/gmail.readonly", _GOOGLE_DIRECTORY_SCOPE),
    "gdocs": ("https://www.googleapis.com/auth/drive.readonly", _GOOGLE_DIRECTORY_SCOPE),
}
_GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
_JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"


def _signed_jwt(ctx, claims, private_key_pem, passphrase=None, key_id=None, algorithm="RS256"):
    """An assertion signed with the pasted key. The key never touches the disk; a key
    that can't be read is the key being rejected."""
    jwt = ctx.driver("jwt", "PyJWT")
    _serialization = ctx.driver("cryptography.hazmat.primitives.serialization", "cryptography")
    _token = None
    try:
        _key = _serialization.load_pem_private_key(
            str(private_key_pem).encode("utf-8"),
            password=str(passphrase).encode("utf-8") if passphrase else None)
        _token = jwt.encode(claims, _key, algorithm=algorithm, headers={"kid": key_id} if key_id else None)
    except Exception:
        _token = None
    if not _token:
        raise ConnectError("key_rejected")
    return _token if isinstance(_token, str) else _token.decode("ascii")


def _google_fetch(ctx, http, c, source_type, reach=True):
    """One token request. reach=False for handle.as_user: the token host was reached at the sign-in."""
    _key = c.get("credentials_json") if isinstance(c.get("credentials_json"), dict) else {}
    for _part in ("client_email", "private_key"):
        if _is_empty(_key.get(_part)):
            raise ConnectError("connection_incomplete", {"key": "credentials_json"})
    _token_uri = str(_key.get("token_uri") or _GOOGLE_TOKEN_URI).strip()
    if not _token_uri.lower().startswith("https://"):
        raise ConnectError("connection_incomplete", {"key": "credentials_json"})
    _user = str(c["delegated_user"]).strip()
    _now = int(time.time())
    _assertion = _signed_jwt(ctx, {"iss": str(_key["client_email"]), "sub": _user,
                                   "scope": " ".join(_GOOGLE_SCOPES[source_type]), "aud": _token_uri,
                                   "iat": _now, "exp": _now + 600},
                             _key["private_key"], key_id=_key.get("private_key_id"))
    if reach:
        http.reach(_token_uri)
    _resp = http.call("POST", _token_uri, step=STEP_TOKEN_SEC, data={"grant_type": _JWT_GRANT, "assertion": _assertion})
    _body = _json_body(_resp)
    if _resp.status_code == 200 and _body.get("access_token"):
        return str(_body["access_token"]), _body.get("expires_in") or 3600
    _error = str(_body.get("error") or "").lower()
    _description = str(_body.get("error_description") or "").lower()
    if _error in ("unauthorized_client", "access_denied") or "invalid email" in _description or "user id" in _description:
        raise ConnectError("delegation_denied", {"delegated_user": _user})
    if _error in ("invalid_grant", "invalid_client") or _resp.status_code == 401:
        raise ConnectError("key_rejected")
    raise ConnectError("unexpected", {"reason": _reason(
        str(_body.get("error_description") or _body.get("error") or
            ("the token request answered " + str(_resp.status_code) + " " + _status_text(_resp.status_code))), ctx.secrets)})


GOOGLE_AS_USER_KEPT = 256           # handle.as_user: the most users whose bearers a handle keeps at once


def _google_as_user(ctx, http, c, source_type):
    """handle.as_user(email) on gmail and gdocs: a bearer with the same scopes and 'sub' set to that user of the
    domain, signed with the key the handle already holds - one token request, no lookup or probe (2026.47.3).
    The most recent GOOGLE_AS_USER_KEPT are kept with the handle and renewed like the first."""
    _made = collections.OrderedDict()
    _lock = threading.Lock()

    def as_user(email):
        _user = str(email or "").strip()
        if "@" not in _user:
            raise ConnectError("connection_incomplete", {"key": "delegated_user"})
        with _lock:
            _bearer = _made.pop(_user.lower(), None)
            if _bearer is None:
                _c = dict(c, delegated_user=_user)
                _bearer = _Bearer(lambda: _google_fetch(ctx, http, _c, source_type, reach=False))
            _made[_user.lower()] = _bearer
            while len(_made) > GOOGLE_AS_USER_KEPT:
                _made.popitem(last=False)
        _bearer()
        return _bearer
    return as_user


def _google_open_for(source_type):
    def _sign_in(c, ctx, http):
        _bearer = _Bearer(lambda: _google_fetch(ctx, http, c, source_type))
        _bearer()
        return _http_handle(source_type, http, _bearer, scopes=_GOOGLE_SCOPES[source_type],
                            as_user=_google_as_user(ctx, http, c, source_type))
    return _http_open(_sign_in)


def _google_read(handle, ctx, url, params, scope):
    _host = urllib.parse.urlsplit(url).hostname
    handle.http.reach(url)
    _resp = handle.http.call("GET", url, params=params, headers=handle.token.auth())
    if _resp.status_code == 200:
        return
    if _resp.status_code == 401:
        raise ConnectError("key_rejected")
    if _resp.status_code == 403:
        raise ConnectError("permission_missing", {"permission": scope})
    raise _unexpected_answer(ctx, _resp, _host)


def _google_probe(handle, c, ctx):
    if handle.source_type == "gmail":
        _google_read(handle, ctx, "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                     {"fields": "emailAddress"}, _GOOGLE_SCOPES["gmail"][0])
    else:
        _google_read(handle, ctx, "https://www.googleapis.com/drive/v3/about",
                     {"fields": "user/permissionId"}, _GOOGLE_SCOPES["gdocs"][0])
    _google_read(handle, ctx, "https://admin.googleapis.com/admin/directory/v1/users",
                 {"customer": "my_customer", "maxResults": "1", "fields": "users/id"}, _GOOGLE_DIRECTORY_SCOPE)


for _t in ("gmail", "gdocs"):
    _register(_t, fields=(("credentials_json", True, None), ("delegated_user", True, None)),
              secret_keys=("credentials_json",), needs=("jwt",), open_fn=_google_open_for(_t),
              probe_fn=_google_probe, permissions=_GOOGLE_SCOPES[_t])


# ---------------------------------------------------------------------------
# box
#   sign-in: the JWT sign-in as the app's service account, from the pasted configuration
#   read:    users/me
#   The configuration is passed as content; nothing goes to disk.
# ---------------------------------------------------------------------------
_BOX_TOKEN_URL = "https://api.box.com/oauth2/token"
_BOX_ME_URL = "https://api.box.com/2.0/users/me"


def _box_fetch(ctx, http, c):
    import secrets as _secrets
    _cfg = c.get("credentials_json") if isinstance(c.get("credentials_json"), dict) else {}
    _app = _cfg.get("boxAppSettings") if isinstance(_cfg.get("boxAppSettings"), dict) else {}
    _auth = _app.get("appAuth") if isinstance(_app.get("appAuth"), dict) else {}
    if any(_is_empty(_v) for _v in (_app.get("clientID"), _app.get("clientSecret"), _auth.get("privateKey"),
                                    _cfg.get("enterpriseID"))):
        raise ConnectError("connection_incomplete", {"key": "credentials_json"})
    _assertion = _signed_jwt(ctx, {"iss": str(_app["clientID"]), "sub": str(_cfg["enterpriseID"]),
                                   "box_sub_type": "enterprise", "aud": _BOX_TOKEN_URL,
                                   "jti": _secrets.token_hex(32), "exp": int(time.time()) + 45},
                             _auth["privateKey"], passphrase=_auth.get("passphrase"), key_id=_auth.get("publicKeyID"))
    http.reach(_BOX_TOKEN_URL)
    _resp = http.call("POST", _BOX_TOKEN_URL, step=STEP_TOKEN_SEC,
                      data={"grant_type": _JWT_GRANT, "assertion": _assertion,
                            "client_id": str(_app["clientID"]), "client_secret": str(_app["clientSecret"])})
    _body = _json_body(_resp)
    if _resp.status_code == 200 and _body.get("access_token"):
        return str(_body["access_token"]), _body.get("expires_in") or 3600
    if _resp.status_code in (400, 401, 403):
        raise ConnectError("key_rejected")
    raise _unexpected_answer(ctx, _resp, "the token request")


def _box_sign_in(c, ctx, http):
    _bearer = _Bearer(lambda: _box_fetch(ctx, http, c))
    _bearer()
    return _http_handle("box", http, _bearer)


def _box_probe(handle, c, ctx):
    _resp = handle.http.call("GET", _BOX_ME_URL, params={"fields": "id"}, headers=handle.token.auth())
    if _resp.status_code == 200:
        return
    if _resp.status_code == 401:
        raise ConnectError("key_rejected")
    if _resp.status_code == 403:
        raise ConnectError("no_read_service", {"host": urllib.parse.urlsplit(_BOX_ME_URL).hostname})
    raise _unexpected_answer(ctx, _resp, urllib.parse.urlsplit(_BOX_ME_URL).hostname)


_register("box", fields=(("credentials_json", True, None),), secret_keys=("credentials_json",), needs=("jwt",),
          open_fn=_http_open(_box_sign_in), probe_fn=_box_probe)


# ---------------------------------------------------------------------------
# laserfiche
#   sign-in: a repository token, with 'trust_server_certificate'    read: the root folder's entry (id 1)
# ---------------------------------------------------------------------------
def _laserfiche_sign_in(c, ctx, http):
    _origin, _host, _base = _url_parts(c.get("base_url"))
    _repo = str(c["repository_id"]).strip()
    _account = str(c["username"])
    http.reach(_base)
    _url = _base + "/v1/Repositories/" + urllib.parse.quote(_repo, safe="") + "/Token"

    def _fetch():
        _resp = http.call("POST", _url, step=STEP_TOKEN_SEC,
                          data={"grant_type": "password", "username": _account, "password": str(c["password"])})
        _body = _json_body(_resp)
        if _resp.status_code == 200 and _body.get("access_token"):
            return str(_body["access_token"]), _body.get("expires_in") or 900
        if _resp.status_code == 404:
            raise ConnectError("repository_missing", {"host": _host, "repository_id": _repo})
        if _resp.status_code in (400, 401, 403):
            raise ConnectError("signin_rejected", {"account": _account})
        raise _unexpected_answer(ctx, _resp, "the token request")

    _bearer = _Bearer(_fetch)
    _bearer()
    return _http_handle("laserfiche", http, _bearer, base_url=_base, shown_host=_host, repository_id=_repo, account=_account)


def _laserfiche_probe(handle, c, ctx):
    _resp = handle.http.call("GET", handle.base_url + "/v1/Repositories/"
                             + urllib.parse.quote(handle.repository_id, safe="") + "/Entries/1",
                             params={"$select": "id"}, headers=handle.token.auth())
    if _resp.status_code == 200:
        return
    if _resp.status_code == 401:
        raise ConnectError("signin_rejected", {"account": handle.account})
    if _resp.status_code in (403, 404):
        raise ConnectError("no_read_root", {"repository_id": handle.repository_id})
    raise _unexpected_answer(ctx, _resp, handle.shown_host)


_register("laserfiche",
          fields=(("base_url", True, None), ("repository_id", True, None), ("username", True, None),
                  ("password", True, None), ("trust_server_certificate", False, False)),
          secret_keys=("password",), needs=("http",),
          open_fn=_http_open(_laserfiche_sign_in, verify_key="trust_server_certificate"), probe_fn=_laserfiche_probe)


# ---------------------------------------------------------------------------
# blink
#   sign-in: the login                 read: the login returns a token; that's the pass
# ---------------------------------------------------------------------------
def _blink_sign_in(c, ctx, http):
    _origin, _host, _base = _url_parts(c.get("base_url"))
    _account = str(c["username"])
    http.reach(_base)

    def _fetch():
        _resp = http.call("POST", _base + "/interface/v1/login", step=STEP_TOKEN_SEC,
                          json={"username": _account, "password": str(c["password"])})
        _body = _json_body(_resp)
        if _resp.status_code == 200 and _body.get("access_token"):
            return str(_body["access_token"]), _body.get("expires_in") or 900
        if _resp.status_code in (400, 401, 403):
            raise ConnectError("signin_rejected", {"account": _account})
        if _resp.status_code == 200:
            raise ConnectError("unexpected", {"reason": "the login answered without a token"})
        raise _unexpected_answer(ctx, _resp, "the login")

    _bearer = _Bearer(_fetch)
    _bearer()
    return _http_handle("blink", http, _bearer, base_url=_base, shown_host=_host)


def _blink_probe(handle, c, ctx):
    return                              # the login returned a token; nothing more is read


_register("blink", fields=(("base_url", True, None), ("username", True, None), ("password", True, None)),
          secret_keys=("password",), needs=("http",), open_fn=_http_open(_blink_sign_in), probe_fn=_blink_probe)


# ---------------------------------------------------------------------------
# directory
#   no sign-in                                   read: the first entry of root_path
#   The path is one the scanners' containers see; the caller passes the roots
#   that are SET for the workers, whether or not each is there right now.
#   'host' is optional and nothing reads it. In this order:
#       no roots are set                          not_checkable  roots_not_mounted   (decided in precheck)
#       the path isn't under any root that's set  unreachable    path_outside_roots
#       its root isn't there or can't be listed   not_checkable  root_not_mounted
#       the root is there                         the path's own tests
#   So a share that appears after the worker started works at the next check.
# ---------------------------------------------------------------------------
def _dir_limited(ctx, fn):
    _timed_out = False
    try:
        return _run_limited(fn, ctx.step(STEP_CALL_SEC))
    except _StepTimeout:
        _timed_out = True               # a network mount that has stopped answering
    if _timed_out:
        raise ctx.timed_out()


def _dir_open(c, ctx):
    _stored = str(c["root_path"])
    _roots = list(ctx.file_roots)

    def _look():
        _real = os.path.realpath(_stored)           # links and dots resolved
        _mine = None                                # (the root as set, the root resolved): the longest that holds the path
        for _r in _roots:
            _root = os.path.realpath(_r)
            if _real == _root or _real.startswith(_root.rstrip(os.sep) + os.sep):
                if _mine is None or len(_root) > len(_mine[1]):
                    _mine = (_r, _root)
        if _mine is None:
            return "path_outside_roots", None, None
        try:                                        # its root: there, a folder, and listable?
            if not stat.S_ISDIR(os.stat(_mine[1]).st_mode):
                return "root_not_mounted", None, _mine[0]
            with os.scandir(_mine[1]) as _it:
                next(_it, None)
        except OSError:
            return "root_not_mounted", None, _mine[0]
        try:
            _st = os.stat(_real)
        except (FileNotFoundError, NotADirectoryError):
            return "path_not_found", None, None
        except PermissionError:
            return "path_not_readable", None, None
        if not stat.S_ISDIR(_st.st_mode):
            return "path_not_folder", None, None
        return None, _real, None

    _code, _real, _root_set = _dir_limited(ctx, _look)
    if _code == "root_not_mounted":
        raise ConnectError(_code, {"root": _root_set})
    if _code:
        raise ConnectError(_code, {"root_path": _stored})
    return Handle("directory", _real, None, root_path=_stored)


def _dir_probe(handle, c, ctx):
    _real = handle.client

    def _first_entry():
        try:
            with os.scandir(_real) as _it:          # the first entry only: no file is opened, no tree is walked
                next(_it, None)
            return None
        except PermissionError:
            return "path_not_readable"
        except FileNotFoundError:
            return "path_not_found"
        except NotADirectoryError:
            return "path_not_folder"

    _code = _dir_limited(ctx, _first_entry)
    if _code:
        raise ConnectError(_code, {"root_path": handle.root_path})


_register("directory",
          fields=(("host", False, None), ("root_path", True, None)),
          secret_keys=(), needs=("none",), open_fn=_dir_open, probe_fn=_dir_probe)




# ===========================================================================
# V1 CONNECTIONS -> V2 KEYS
# ===========================================================================
_ENTRA_V1 = {"baseUrl": "base_url", "tenantId": "tenant_id", "clientId": "client_id", "clientSecret": "client_secret"}
_GRAPH_V1 = {"URL": "base_url", "AzureTenant": "tenant_id", "OAuthClientId": "client_id",
             "OAuthClientSecret": "client_secret"}

# V1 key -> V2 key, per type. Every other key keeps its name; a key that is not a
# V2 connection key of the type (scope: sites, folders, schemas, dates, omit lists) is dropped.
_LEGACY_RENAMES = {
    "postgres": {},
    "sqlserver": {"certificatetrust": "trust_server_certificate"},
    "oracle_service": {"database": "service_name", "initStr": "session_init"},
    "oracle_sid": {"database": "sid", "initStr": "session_init"},
    "mongo": {},
    "databricks": {"baseUrl": "base_url", "workspaceId": "workspace_id", "accessToken": "access_token"},
    "fabric": _ENTRA_V1, "dynamics": _ENTRA_V1, "dataverse": _ENTRA_V1,
    "sharepoint": _GRAPH_V1, "onedrive": _GRAPH_V1, "msoutlook": _GRAPH_V1, "teams": _GRAPH_V1,
    "gmail": {"gmailCreds": "credentials_json"},
    "gdocs": {"gmailCreds": "credentials_json"},
    "box": {},
    "laserfiche": {"baseUrl": "base_url", "repoId": "repository_id", "certificatetrust": "trust_server_certificate"},
    "blink": {"baseUrl": "base_url"},
    "directory": {"filepath": "root_path"},
}

# the V2 connection keys of each type, with the default a V1 record can't carry
_V2_KEYS = {
    "postgres": {"host": None, "port": 5432, "database": None, "username": None, "password": None, "ssl_mode": "prefer"},
    "sqlserver": {"host": None, "port": 1433, "database": None, "username": None, "password": None,
                  "trust_server_certificate": False, "encrypt": True},
    "oracle_service": {"host": None, "port": 1521, "service_name": None, "username": None, "password": None,
                       "session_init": None},
    "oracle_sid": {"host": None, "port": 1521, "sid": None, "username": None, "password": None, "session_init": None},
    "mongo": {"scheme": "mongodb+srv", "host": None, "port": 27017, "username": None, "password": None,
              "auth_database": "admin", "tls": True},
    "databricks": {"base_url": None, "workspace_id": None, "access_token": None},
    "fabric": {"base_url": None, "tenant_id": None, "client_id": None, "client_secret": None},
    "dynamics": {"base_url": None, "tenant_id": None, "client_id": None, "client_secret": None},
    "dataverse": {"base_url": None, "tenant_id": None, "client_id": None, "client_secret": None},
    "sharepoint": {"base_url": None, "tenant_id": None, "client_id": None, "client_secret": None},
    "onedrive": {"base_url": _GRAPH_DEFAULT, "tenant_id": None, "client_id": None, "client_secret": None},
    "msoutlook": {"base_url": _GRAPH_DEFAULT, "tenant_id": None, "client_id": None, "client_secret": None},
    "teams": {"base_url": _GRAPH_DEFAULT, "tenant_id": None, "client_id": None, "client_secret": None},
    "gmail": {"credentials_json": None, "delegated_user": None},
    "gdocs": {"credentials_json": None, "delegated_user": None},
    "box": {"credentials_json": None},
    "laserfiche": {"base_url": None, "repository_id": None, "username": None, "password": None,
                   "trust_server_certificate": False},
    "blink": {"base_url": None, "username": None, "password": None},
    "directory": {"host": None, "root_path": None},
}

_V1_TRUE = ("true", "1", "yes", "y")                # what V1's str_to_bool takes as true
_V1_YES = ("true", "1", "t", "y", "yes")            # what V1's normalize_yes_no takes as yes (SQL Server)


def _v1_flag(value, words):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in words


_PORT_IN_HOST_RE = re.compile(r"^(?P<host>\[[^\]]+\]|[^:,\s]+)\s*[:,]\s*(?P<port>\d{1,5})$")


def _json_object(value):
    """A V1 value that is JSON text, or already an object -> a dict (None when it is neither)."""
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            _v = json.loads(value)
            return _v if isinstance(_v, dict) else None
        except ValueError:
            return None
    return None


def from_legacy(source_type, v1_connection):
    """A V1 connection (sentinel.dataconnections.connection_json, password already
    decrypted by the caller) in V2 keys, so everything after it is the same code.

    Beyond renaming: the port is split out of 'host'; Blink gets 'https://';
    Laserfiche's 'certificatetrust' is turned over (V1 had it backwards);
    Google's 'user_email' is lifted out of the key as 'delegated_user'; OneDrive
    and Outlook get the default Graph endpoint (V1 never read their URL); MongoDB
    is the DNS seed list scheme with TLS, as V1 always was; values typed as text
    in V1 become numbers and booleans; everything about scope is dropped.
    Box: V1 stored a PATH to the key file. The caller reads that file and passes
    its content as 'credentials_json'; the library never opens a path."""
    _st = _norm_type(source_type)
    if _st == "postgresql":
        _st = "postgres"
    _keys = _V2_KEYS.get(_st)
    if _keys is None:
        raise ValueError("no connector for source type '" + _st + "'")
    _v1 = dict(v1_connection or {})
    _renames = _LEGACY_RENAMES.get(_st, {})
    _out = {}
    for _k, _v in _v1.items():
        _k2 = _renames.get(_k, _k)
        if _k2 in _keys and not _is_empty(_v) and (_k2 not in _out or _k in _renames):
            _out[_k2] = _v
    # --- per type
    if "host" in _out and "port" in _keys:
        _m = _PORT_IN_HOST_RE.match(str(_out["host"]).strip())
        if _m and "\\" not in _m.group("host"):
            _out["host"] = _m.group("host")
            _out["port"] = int(_m.group("port"))
    if isinstance(_out.get("host"), str):
        _out["host"] = _out["host"].strip()
    if "port" in _out:
        try:
            _out["port"] = int(str(_out["port"]).strip())
        except ValueError:
            del _out["port"]
    if _st == "laserfiche":
        # V1 had this one backwards: it handed 'certificatetrust' to requests as verify=, so
        # true VALIDATED the certificate and anything else (false, or no value) didn't. V2's
        # field means what it says, so the value is turned over here: the connection behaves
        # in V2 as it did in V1, and the form then shows honestly that it isn't validated.
        _out["trust_server_certificate"] = not _v1_flag(_v1.get("certificatetrust"), _V1_TRUE)
    elif _st == "sqlserver" and "trust_server_certificate" in _out:
        _out["trust_server_certificate"] = _v1_flag(_out["trust_server_certificate"], _V1_YES)     # straight through
    for _b in ("trust_server_certificate", "encrypt", "tls"):
        if _b in _out:
            _out[_b] = _as_bool(_out[_b])
    if _st in ("onedrive", "msoutlook"):
        _out["base_url"] = _GRAPH_DEFAULT
    if _st == "blink" and isinstance(_out.get("base_url"), str):
        _u = _out["base_url"].strip().rstrip("/")
        _out["base_url"] = _u if "://" in _u else "https://" + _u
    if _st in ("gmail", "gdocs", "box") and "credentials_json" in _out:
        _obj = _json_object(_out["credentials_json"])
        if _obj is None:
            del _out["credentials_json"]
        else:
            if _st in ("gmail", "gdocs"):
                _user = _obj.pop("user_email", None)
                if not _is_empty(_user) and _is_empty(_out.get("delegated_user")):
                    _out["delegated_user"] = str(_user).strip()
            _out["credentials_json"] = _obj
    if _st == "mongo":
        _out["scheme"] = "mongodb+srv"
        _out["tls"] = True
    for _k, _default in _keys.items():
        if _k not in _out and _default is not None:
            _out[_k] = _default
    return _out


# ---------------------------------------------------------------------------
# What this image can check:  python ds_connect_lib.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("ds_connect_lib " + __version__)
    for _name, _info in sorted(types().items()):
        print("  " + _name.ljust(16) + ("available" if _info.available else "missing: " + str(_info.missing)))
