#!/usr/bin/env python3
# Local Service Monitor - macOS backend
# Discovers listening TCP/UDP endpoints, identifies processes/services,
# classifies by access scope + service type, probes protocols, records
# history in SQLite, and exposes a loopback-only, CSRF-protected HTTP API.
#
# Standard library + psutil only. No build system, no CDN, no telemetry.

import os
import re
import sys
import json
import time
import socket
import ssl
import stat
import shlex
import subprocess
import threading
import sqlite3
import webbrowser
import traceback
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
DB_PATH = os.path.join(APP_DIR, "history.sqlite")
INDEX_PATH = os.path.join(APP_DIR, "index.html")

VERSION = "1.0.0"
DEFAULT_PORT = 8848
API_PREFIX = "/api/"

# ---------------------------------------------------------------------------
# Defaults / settings
# ---------------------------------------------------------------------------
DEFAULT_SETTINGS = {
    "tcp_enabled": True,
    "udp_enabled": True,
    "ipv4_enabled": True,
    "ipv6_enabled": True,
    "auto_prober": True,
    "gentle_gui_probing": True,
    "probe_timeout_ms": 900,
    "probe_max_workers": 8,
    "show_unknown": True,
    "show_system": True,
    "aggregate_by": "process",
    "show_confidence": True,
    "history_retention_days": 30,
    "public_verify_enabled": False,
    "public_verify_url": "",
    "lan_ranges": ["10.0.0.0/8", "172.16.0.0/12",
                   "192.168.0.0/16", "169.254.0.0/16"],
}

ERROR_LOG = deque(maxlen=200)


def log_error(where, exc=None):
    entry = {
        "ts": time.time(),
        "where": where,
        "error": str(exc) if exc else "",
        "trace": traceback.format_exc() if exc else "",
    }
    ERROR_LOG.append(entry)


# ---------------------------------------------------------------------------
# Config store
# ---------------------------------------------------------------------------
class Config:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = dict(DEFAULT_SETTINGS)
        self.load()

    def load(self):
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                    saved = json.load(fh)
                if isinstance(saved, dict):
                    for k in DEFAULT_SETTINGS:
                        if k in saved:
                            self.data[k] = saved[k]
        except Exception as exc:
            log_error("config.load", exc)

    def save(self):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, sort_keys=True)
        except Exception as exc:
            log_error("config.save", exc)

    def get(self, key):
        with self.lock:
            return self.data.get(key, DEFAULT_SETTINGS.get(key))

    def update(self, patch):
        with self.lock:
            for k, v in patch.items():
                if k in DEFAULT_SETTINGS:
                    self.data[k] = v
        self.save()


CONFIG = Config()

# ---------------------------------------------------------------------------
# Sensitive-info redaction for command lines (Portbook-style)
# ---------------------------------------------------------------------------
SECRET_KEY_RE = re.compile(
    r"(?i)(api[-_]?key|apikey|token|secret|password|passwd|pwd|"
    r"access[-_]?key|auth|credential|private[-_]?key|bearer)"
)
REDACT = "••••••"


def redact_cmdline(argv):
    out = []
    for i, tok in enumerate(argv):
        low = tok.lower()
        if "=" in tok:
            key, _, val = tok.partition("=")
            if SECRET_KEY_RE.search(key) and val:
                out.append(f"{key}={REDACT}")
                continue
        if SECRET_KEY_RE.search(low):
            # flag style: --api-key <value>  -> mask next token
            out.append(tok)
            continue
        out.append(tok)
    # second pass: mask value after a sensitive flag
    masked = []
    skip_next_val = False
    for tok in out:
        if skip_next_val and not tok.startswith("-"):
            masked.append(REDACT)
            skip_next_val = False
            continue
        masked.append(tok)
        if re.search(r"(?i)(api[-_]?key|token|secret|password|passwd)$", tok) and tok.startswith("-"):
            skip_next_val = True
    return " ".join(masked)


# ---------------------------------------------------------------------------
# Process info (psutil + lsof/ps fallback), with permission handling
# ---------------------------------------------------------------------------
class ProcCache:
    """Caches per-PID identity fields and primed CPU samples."""

    def __init__(self):
        self.lock = threading.Lock()
        self.identity = {}   # pid -> (name, exe, cmdline, ppid, uid, create_ts, user)
        self.cpu_last = {}   # pid -> last cpu_percent sample timestamp
        self.started = set()  # pids we have primed for cpu_percent

    def _identity_raw(self, proc):
        def safe(fn, default=None):
            try:
                return fn()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                return default
            except Exception:
                return default
        return {
            "name": safe(proc.name, ""),
            "exe": safe(proc.exe, ""),
            "cmdline": safe(proc.cmdline, None),
            "ppid": safe(proc.ppid, None),
            "uids": safe(proc.uids, None),
            "create_time": safe(proc.create_time, None),
            "username": safe(proc.username, ""),
            "status": safe(proc.status, ""),
        }

    def info(self, pid):
        if not HAVE_PSUTIL:
            return {"permission": "unavailable", "pid": pid}
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return {"permission": "gone", "pid": pid}
        except Exception as exc:
            log_error("proc.open", exc)
            return {"permission": "denied", "pid": pid}
        ident = self._identity_raw(proc)
        perm = "ok"
        if ident["exe"] in (None, "") and ident["name"] in (None, ""):
            perm = "denied"
        ident["pid"] = pid
        ident["permission"] = perm
        return ident

    def cpu_sample(self, proc):
        # cpu_percent needs two calls spaced over time; prime on first sight.
        pid = proc.pid
        with self.lock:
            primed = pid in self.started
            self.started.add(pid)
        try:
            if not primed:
                proc.cpu_percent(interval=None)  # prime, returns 0
                return None
            return proc.cpu_percent(interval=None)
        except psutil.AccessDenied:
            return None
        except Exception:
            return None

    def memory_mb(self, proc):
        try:
            return proc.memory_info().rss / (1024.0 * 1024.0)
        except psutil.AccessDenied:
            return None
        except Exception:
            return None


PROCCACHE = ProcCache()


def ps_processes_by_pid():
    """Fallback map pid -> {'name':...,'user':...} using ps(1) when no psutil."""
    try:
        out = subprocess.run(
            ["/bin/ps", "-axo", "pid=,comm=,user="],
            capture_output=True, text=True, timeout=5,
        ).stdout
        m = {}
        for line in out.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) >= 2 and parts[0].isdigit():
                m[int(parts[0])] = {"name": os.path.basename(parts[1]),
                                    "user": parts[2] if len(parts) > 2 else ""}
        return m
    except Exception as exc:
        log_error("ps.fallback", exc)
        return {}


# ---------------------------------------------------------------------------
# lsof parsing (Sloth-style): TCP LISTEN + UDP endpoints, IPv4/IPv6
# ---------------------------------------------------------------------------
def run_lsof(args):
    try:
        p = subprocess.run(["/usr/sbin/lsof", "-nP"] + args,
                           capture_output=True, text=True, timeout=15)
        return p.stdout.splitlines()
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("lsof.run", exc)
        return None


NAME_RE = re.compile(r"^(?P<ip>.*?)(?P<colon>:\??)(?P<port>\d+)?$")


def parse_lsof_name(name):
    """Parse an lsof NAME like '127.0.0.1:8080', '*:7000', '[::1]:8222',
    '*:*'. Returns (ip, port) with port int or None."""
    name = name.strip()
    # strip (LISTEN) etc already removed by caller
    if name.startswith("["):  # IPv6 [addr]:port
        depth = 0
        i = 0
        while i < len(name):
            if name[i] == "[":
                depth += 1
            elif name[i] == "]":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        ip = name[1:i]
        rest = name[i + 1:]
        port = None
        if rest.startswith(":"):
            pr = rest[1:]
            if pr.isdigit():
                port = int(pr)
        return ip, port
    # IPv4 / wildcard
    if name.count(":") == 1:
        ip, _, port = name.partition(":")
        return (ip or "*"), (int(port) if port.isdigit() else None)
    # bare wildcard
    if name in ("*", "*:*"):
        return "*", None
    if ":" in name:
        ip, _, port = name.rpartition(":")
        return (ip or "*"), (int(port) if port.isdigit() else None)
    return name, None


def scan_lsof_endpoints(settings):
    """Return list of endpoint dicts from lsof."""
    endpoints = []
    lines = None
    if settings.get("tcp_enabled"):
        lines = run_lsof(["-iTCP", "-sTCP:LISTEN"])
        if lines:
            endpoints += _parse_lsof_block(lines, "tcp")
    if settings.get("udp_enabled"):
        ul = run_lsof(["-iUDP"])
        if ul:
            endpoints += _parse_lsof_block(ul, "udp")
    return endpoints


def _parse_lsof_block(lines, proto):
    res = []
    if not lines:
        return res
    header = lines[0].split()
    try:
        idx_cmd = header.index("COMMAND")
        idx_pid = header.index("PID")
        idx_user = header.index("USER")
        idx_type = header.index("TYPE")
        idx_name = header.index("NAME")
    except ValueError:
        return res
    for line in lines[1:]:
        cols = line.split(None, idx_name)
        if len(cols) <= idx_name:
            continue
        cmd = cols[idx_cmd]
        try:
            pid = int(cols[idx_pid])
        except ValueError:
            continue
        user = cols[idx_user]
        ftype = cols[idx_type]
        name = cols[idx_name].strip()
        # drop trailing state marker for TCP
        name = re.sub(r"\s*\(LISTEN\)\s*$", "", name)
        ip, port = parse_lsof_name(name)
        if port is None:
            # UDP endpoints without a bound port (e.g. '*:*') are ordinary
            # sockets, not listening endpoints; TCP LISTEN always has a port.
            if proto == "udp":
                continue
        # normalize wildcards to canonical addresses so lsof and psutil merge
        if ip in ("*", ""):
            ip = "0.0.0.0" if ftype != "IPv6" else "::"
        family = "ipv6" if ftype == "IPv6" else "ipv4" if ftype == "IPv4" else "?"
        res.append({
            "proto": proto, "ip": ip, "port": port,
            "family": family, "pid": pid,
            "lsof_cmd": cmd, "user": user,
        })
    return res


# ---------------------------------------------------------------------------
# psutil cross-check (Sloth: socket<->process association; robust primary source)
# ---------------------------------------------------------------------------
def scan_psutil_endpoints(settings):
    out = []
    if not HAVE_PSUTIL:
        return out
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        # lsof for own-user still works; note the degradation
        return out
    except Exception as exc:
        log_error("psutil.conns", exc)
        return out
    for c in conns:
        if not c.laddr:
            continue
        ip = c.laddr.ip
        port = c.laddr.port
        fam = "ipv6" if _looks_v6(ip) else "ipv4"
        if fam == "ipv6" and not settings.get("ipv6_enabled"):
            continue
        if fam == "ipv4" and not settings.get("ipv4_enabled"):
            continue
        if c.type == socket.SOCK_STREAM:
            if not settings.get("tcp_enabled"):
                continue
            if c.status != psutil.CONN_LISTEN:
                continue
            proto = "tcp"
        elif c.type == socket.SOCK_DGRAM:
            if not settings.get("udp_enabled"):
                continue
            if port == 0:
                continue
            proto = "udp"
        else:
            continue
        out.append({
            "proto": proto, "ip": ip or "*", "port": port,
            "family": fam, "pid": c.pid or 0, "user": "",
        })
    return out


def _looks_v6(ip):
    return ":" in ip


def _ip_equivalent(a, b):
    """Treat '*' / '::' / '' wildcards as matching any concrete address."""
    if a == b:
        return True
    wild = ("*", "::", "", None)
    if a in wild or b in wild:
        return True
    # 0.0.0.0 == *, :: == wildcard
    return (a in ("0.0.0.0", "::") or b in ("0.0.0.0", "::"))


def _norm_ip(ip, family):
    """Canonical form used for cross-source dedupe."""
    if ip in ("*", "", None):
        return "::" if family == "ipv6" else "0.0.0.0"
    return ip


# ---------------------------------------------------------------------------
# Address scope classification
# ---------------------------------------------------------------------------
def ip_in_network(ip, cidr):
    try:
        net, _, bits = cidr.partition("/")
        bits = int(bits or 32)
    except Exception:
        return False
    try:
        packed_net = socket.inet_pton(socket.AF_INET if net.count(".") else socket.AF_INET6, net)
        packed_ip = socket.inet_pton(socket.AF_INET if ip.count(".") else socket.AF_INET6, ip)
    except Exception:
        return False
    if len(packed_net) != len(packed_ip):
        return False
    mask_bits = bits
    total = len(packed_net) * 8
    cmp_bytes = mask_bits // 8
    if packed_net[:cmp_bytes] != packed_ip[:cmp_bytes]:
        return False
    rem = mask_bits % 8
    if rem and cmp_bytes < len(packed_net):
        mask = (0xFF << (8 - rem)) & 0xFF
        if (packed_net[cmp_bytes] & mask) != (packed_ip[cmp_bytes] & mask):
            return False
    return True


LOOPBACK4 = {"127.0.0.1", "127.0.0.0"}
LOOPBACK6 = {"::1"}


def scope_of_endpoint(ip):
    """Return one of loopback/wildcard/lan/public for a bound IP."""
    if ip in ("*", "::", "") or ip is None:
        return "wildcard"
    if ip == "127.0.0.1" or ip.startswith("127."):
        return "loopback"
    if ip == "::1":
        return "loopback"
    if ip == "0.0.0.0" or ip == "::":
        return "wildcard"
    for rng in CONFIG.get("lan_ranges") or []:
        if ip_in_network(ip, rng):
            return "lan"
    # link-local / multicast etc still count as local-ish; non-loopback non-LAN
    return "public"


# ---------------------------------------------------------------------------
# Protocol probing (bounded, low-risk, cached).  Runs off the scan thread.
# ---------------------------------------------------------------------------
class ProbeCache:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {}   # key -> {proto, service, headers?, status, ts, kind}
        self.inflight = set()  # probe keys currently being worked on

    def get(self, key):
        with self.lock:
            return self.data.get(key)

    def put(self, key, value):
        value = dict(value)
        value["ts"] = time.time()
        with self.lock:
            self.data[key] = value

    def keys_for(self, pid, port, ip):
        return [k for k in list(self.data)
                if k.split("|")[:3] == [str(pid), str(port), ip]]

    def drop_stale(self):
        cutoff = time.time() - 600
        with self.lock:
            for k in [k for k, v in self.data.items() if v.get("ts", 0) < cutoff]:
                self.data.pop(k, None)


PROBECACHE = ProbeCache()
PROBE_POOL = ThreadPoolExecutor(max_workers=max(1, int(CONFIG.get("probe_max_workers"))))


def _is_gui_app(svc):
    """Heuristic: a process whose executable lives inside a macOS .app
    bundle is a GUI application (or a helper spawned by one). Sending it
    request bytes can trigger its UI to open, so auto-probing only reads
    (connect + banner sniff, zero transmitted bytes). Plain daemons and
    servers (Homebrew, /usr/sbin, node, python, ...) are unaffected,
    keeping this tool fully usable on generic servers."""
    exe = svc.get("exe") or ""
    return "/Contents/MacOS/" in exe or "/Contents/Helpers/" in exe or \
        "/Contents/XPCServices/" in exe

# System daemons whose ports must never be auto-probed: sending any request
# (even a plain HTTP GET) can make them pop UI windows (e.g. AirPlay
# Receiver on ControlCenter's 5000/7000). Manual re-probe still allowed.
# Ports that pop system/app windows on a bare TCP connection (AirPlay
# receiver etc.) must never be auto-probed. Third-party apps are handled
# differently: we probe a non-existent path instead of "/" so we never
# trigger their "open panel" logic.
NO_AUTO_PROBE_NAMES = {
    "ControlCenter", "rapportd", "sharingd", "mDNSResponder",
    "identityservicesd", "apsd", "UserEventAgent", "distnoted",
    "notifyd", "configd", "sandboxd", "powerd",
}


def _timeout():
    return max(0.2, float(CONFIG.get("probe_timeout_ms")) / 1000.0)


def _open_conn(ip, port):
    fam = socket.AF_INET6 if _looks_v6(ip) else socket.AF_INET
    if fam == socket.AF_INET6 and ip == "::":
        ip = "::1"
    if ip == "*":
        ip = "127.0.0.1"
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(_timeout())
    s.connect((ip, port))
    return s


def _try_tls(ip, port):
    raw = None
    try:
        raw = _open_conn(ip, port)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # self-signed: distinguish from connect failure
        s = ctx.wrap_socket(raw, server_hostname=ip)
        s.close()
        return "tls_ok"
    except ssl.SSLCertVerificationError:
        return "tls_ok"
    except (ssl.SSLError, ConnectionResetError):
        # server closed on plain text / not TLS
        try:
            if raw:
                raw.close()
        except Exception:
            pass
        return "not_tls"
    except (socket.timeout, TimeoutError):
        if raw:
            try:
                raw.close()
            except Exception:
                pass
        return "timeout"
    except OSError:
        if raw:
            try:
                raw.close()
            except Exception:
                pass
        return "unreachable"


def _read_head(s, n=2048):
    s.settimeout(_timeout())
    buf = b""
    try:
        while len(buf) < n:
            chunk = s.recv(512)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                # headers done; grab a little body for HTML sniffing
                if len(buf) > buf.find(b"\r\n\r\n") + 260:
                    break
    except Exception:
        pass
    try:
        s.close()
    except Exception:
        pass
    return buf


# Unknown probe-only path: some desktop app servers pop their own UI window
# when their "/" handler is hit, but only for routes they recognise; a 404
# stub for this sentinel path is inert. If the sentinel shows no HTML we fall
# back to HEAD / -- headers only, no GET on the root -- to still detect real
# web UIs via content-type.
PROBE_PATH = "/__local_service_monitor_probe__"


def _http_exchange(ip, port, scheme, method, path):
    try:
        s = _open_conn(ip, port)
        if scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        host = f"{ip}:{port}"
        req = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: LocalServiceMonitor/1.0\r\n"
               "Connection: close\r\n\r\n").encode()
        s.sendall(req)
        head = _read_head(s)
    except Exception:
        return None
    text = head.decode("latin-1", "replace")
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text)
    if not m:
        return None
    status = int(m.group(1))
    # collect Server / content-type / upgrade hints
    server = ""
    ctype = ""
    ws = False
    for line in text.split("\r\n"):
        low = line.lower()
        if low.startswith("server:"):
            server = line.split(":", 1)[1].strip()
        if low.startswith("content-type:"):
            ctype = line.split(":", 1)[1].strip().lower()
        if "upgrade: websocket" in low or "101 switching" in low:
            ws = True
    # body sniff: is there actual HTML markup after the headers?
    sep = head.find(b"\r\n\r\n")
    body = head[sep + 4:] if sep >= 0 else b""
    body_low = body.lstrip()[:200].lower()
    is_html_body = body_low.startswith(b"<!doctype html") or \
        body_low.startswith(b"<html")
    return {"status": status, "server": server, "websocket": ws,
            "content_type": ctype, "html_body": is_html_body}


def _probe_http(ip, port, scheme="http"):
    """Non-intrusive HTTP fingerprint. GET the sentinel path first; only
    if that response carries no HTML do we HEAD the root for its
    content-type. A plain GET / is never sent during auto-probing."""
    first = _http_exchange(ip, port, scheme, "GET", PROBE_PATH)
    if first is not None and _is_browser_openable(first):
        return first
    second = _http_exchange(ip, port, scheme, "HEAD", "/")
    if second is not None and _is_browser_openable(second):
        second["probe_root"] = True
        return second
    return first if first is not None else second


def _probe_banner(ip, port):
    try:
        s = _open_conn(ip, port)
    except Exception:
        return None
    try:
        head = _read_head(s, 256)
    except Exception:
        return None
    return head


def _banner_proto(b):
    """Fingerprint a server-first banner without having sent anything."""
    if b is None or len(b) == 0:
        return None
    txt = b.decode("latin-1", "replace")
    if txt.startswith("SSH-"):
        return {"proto": "ssh", "service": "SSH", "reachable": True,
                "detail": {"banner": txt.split("\r\n", 1)[0]}}
    if "mysql" in txt.lower() or (b[0:1] == b"\x0a"):
        return {"proto": "mysql", "service": "MySQL", "reachable": True}
    if txt.startswith("-ERR") or txt.startswith("+PONG"):
        return {"proto": "redis", "service": "Redis", "reachable": True}
    if b[0:1] in (b"R", b"N") and len(b) >= 8:
        return {"proto": "postgres", "service": "PostgreSQL", "reachable": True}
    return {"proto": "tcp", "service": "TCP", "reachable": True}


def probe_endpoint(ip, port, known_cmdline="", passive=False):
    """Run a small, bounded set of low-risk probes for one TCP endpoint.
    Returns a dict describing the identified app-layer protocol.

    passive=True is used for GUI applications during auto-probing: the
    process connects and only READS what the server sends first, never
    transmitting a request byte. Sending anything (even to a non-existent
    path) can make some desktop apps pop their own windows. Passive probes
    still fingerprint banner-first protocols (SSH/MySQL/Redis/Postgres)."""
    result = {"proto": None, "service": None, "detail": {}, "reachable": False,
              "passive": passive}
    if port is None:
        return result
    # SSH banner first (cheap, non-intrusive read)
    b = _probe_banner(ip, port)
    fp = _banner_proto(b)
    if fp:
        fp["passive"] = passive
        fp.setdefault("detail", {})
        result = fp
        if passive:
            return result
        # keep detail dict for later stages
        if result["proto"] in ("ssh", "mysql", "redis", "postgres"):
            return result
    if passive:
        # reachable (b is not None means TCP connect succeeded) but no
        # request bytes sent: record reachability only, honestly.
        result.update(reachable=b is not None)
        return result
    # Redis explicit PING
    try:
        s = _open_conn(ip, port)
        s.sendall(b"PING\r\n")
        head = _read_head(s, 64)
        if head.startswith(b"+PONG"):
            result.update(proto="redis", service="Redis", reachable=True)
            return result
    except Exception:
        pass
    # HTTPS then HTTP
    tls = _try_tls(ip, port)
    if tls == "tls_ok":
        http = _probe_http(ip, port, scheme="https")
        if http:
            result.update(proto="https", reachable=True, detail=http)
            result["service"] = _http_service_name(http, known_cmdline)
            return result
    http = _probe_http(ip, port, scheme="http")
    if http:
        result.update(proto="http", reachable=True, detail=http)
        result["service"] = _http_service_name(http, known_cmdline)
        return result
    if tls == "tls_ok":
        # TLS but not HTTP -> generic secure TCP
        result.update(proto="tls", service="TLS/TCP", reachable=True)
        return result
    # reachable, unidentified raw TCP
    if b is not None and len(b) > 0:
        result.update(proto="tcp", service="TCP", reachable=True)
        return result
    return result


def _is_browser_openable(http_result):
    """Strict rule: only count as a browsable web UI when the response is
    actually an HTML page (200/3xx with text/html or HTML markup in body).
    JSON APIs, 404/403 error stubs, WebSocket handshakes (426), unknown
    binary bodies etc. do NOT qualify."""
    if not http_result:
        return False
    status = http_result.get("status") or 0
    ctype = (http_result.get("content_type") or "").lower()
    if "json" in ctype or "javascript" in ctype:
        return False
    if status in (301, 302, 303, 307, 308):
        return True   # redirect leads the browser to a page
    if status != 200:
        return False  # 404/403/401/426/5xx: service may run fine, but no UI
    if "text/html" in ctype or "xhtml" in ctype:
        return True
    if http_result.get("html_body"):
        return True
    return False


def _http_service_name(http_result, cmdline):
    server = (http_result.get("server") or "").lower()
    if "uvicorn" in server:
        return "FastAPI/Uvicorn"
    if "gunicorn" in server:
        return "Gunicorn"
    if "nginx" in server:
        return "Nginx"
    if "apache" in server:
        return "Apache"
    if "caddy" in server:
        return "Caddy"
    if "tornado" in server:
        return "Tornado"
    if "werkzeug" in server:
        return "Flask/Werkzeug"
    low = cmdline.lower()
    if "vite" in low:
        return "Vite"
    if "next" in low:
        return "Next.js"
    return "HTTP"


# ---------------------------------------------------------------------------
# Service identification rules (layer 1 + 3): process/exe/cmdline driven.
# Tags are canonical lowercase slugs; the UI translates them per language.
# Rules only assign DOMAIN tags (database, dns, proxy...); capability tags
# (web-ui / rest-api / websocket) are decided exclusively by the probe in
# classify(), so nothing is ever tagged as having a web page unverified.
# ---------------------------------------------------------------------------
APP_RULES = [
    # (match regex on exe/name/cmdline) -> (service_type, app_name, tags, conf)
    # -- AI / local models
    (r"(?i)\bollama\b", "AI Service", "Ollama", ["ai-service", "rest-api"], "confirmed"),
    (r"(?i)lm[\s_-]?studio", "AI Service", "LM Studio", ["ai-service", "rest-api"], "confirmed"),
    (r"(?i)comfyui|comfy[\s_-]?ui", "AI Service", "ComfyUI", ["ai-service"], "confirmed"),
    (r"(?i)stable[\s_-]?diffusion|\bsd[\s_-]?webui\b", "AI Service", "Stable Diffusion", ["ai-service"], "high"),
    (r"(?i)\bkobold\b|text[\s_-]?generation[\s_-]?webui|vllm", "AI Service", "LLM Serving", ["ai-service", "rest-api"], "high"),
    # -- development servers
    (r"(?i)\bjupyter\b|jupyter-", "Development", "Jupyter", ["development"], "confirmed"),
    (r"(?i)\bvite\b|vite-node", "Development", "Vite", ["development"], "confirmed"),
    (r"(?i)next[\s_-]?server|next[\s_-]dev|\bnext\b", "Development", "Next.js", ["development"], "high"),
    (r"(?i)flask|werkzeug", "Web Framework", "Flask", ["development"], "high"),
    (r"(?i)uvicorn|fastapi|hypercorn", "Web Framework", "FastAPI", ["development"], "high"),
    (r"(?i)\brail[sy]s\b|\bphp[\s_-]?serve|\bartisan\b", "Web Framework", "App Server", ["development"], "high"),
    (r"(?i)\bnode\b", "Runtime", "Node.js", ["development"], "low"),
    (r"(?i)python|http\.server|\buv\b|\bgunicorn\b|twisted|tornado", "Runtime", "Python", ["development"], "low"),
    # -- databases / storage engines
    (r"(?i)postgres|pg_ctl", "Database", "PostgreSQL", ["database"], "confirmed"),
    (r"(?i)\bmysqld?\b|mariadbd?\b", "Database", "MySQL", ["database"], "confirmed"),
    (r"(?i)\bredis-?server\b|\bredis\b", "Database", "Redis", ["database", "cache"], "confirmed"),
    (r"(?i)memcached", "Cache", "Memcached", ["cache"], "confirmed"),
    (r"(?i)mongod\b|mongodb", "Database", "MongoDB", ["database"], "confirmed"),
    (r"(?i)clickhouse", "Database", "ClickHouse", ["database", "analytics"], "confirmed"),
    (r"(?i)sqlite.*serve|sqld", "Database", "SQLite Server", ["database"], "low"),
    (r"(?i)etcd|consul|zk[\s_-]?server|zookeeper|tidb|pd[\s_-]?server", "Coordination", "Key-Value Store", ["database", "coordination"], "high"),
    # -- search
    (r"(?i)elasticsearch|opensearch|meilisearch|\bsolr\b|typesense", "Search", "Search Engine", ["search", "rest-api"], "confirmed"),
    # -- message queues / streaming
    (r"(?i)rabbitmq|beam\.sasl", "Message Queue", "RabbitMQ", ["message-queue"], "confirmed"),
    (r"(?i)\bkafka\b|kafka[\s_-]?server", "Message Queue", "Kafka", ["message-queue"], "confirmed"),
    (r"(?i)nats[\s_-]?server", "Message Queue", "NATS", ["message-queue"], "confirmed"),
    (r"(?i)mosquitto|\bemqx\b", "IoT Broker", "MQTT Broker", ["iot", "message-queue"], "confirmed"),
    (r"(?i)zeromq|\bzmq\b", "Message Queue", "ZeroMQ", ["message-queue"], "low"),
    # -- infrastructure
    (r"(?i)\bdockerd?\b|docker-proxy|com\.docker\.|containerd", "Container", "Docker", ["container"], "confirmed"),
    (r"(?i)\bkubelet\b|kube[\s_-]?apiserver|k3s|containerd", "Container", "Kubernetes", ["container"], "high"),
    (r"(?i)\bsshd?\b", "Remote Access", "SSH", ["remote-access"], "confirmed"),
    # -- web servers / proxies / load balancers
    (r"(?i)\bnginx\b", "Web Server", "Nginx", ["web-server"], "confirmed"),
    (r"(?i)\bapache2?\b|httpd", "Web Server", "Apache", ["web-server"], "confirmed"),
    (r"(?i)\bcaddy\b", "Web Server", "Caddy", ["web-server"], "confirmed"),
    (r"(?i)\btomcat\b|jetty|glassfish|wildfly", "Web Server", "Java App Server", ["web-server"], "confirmed"),
    (r"(?i)\bhaproxy\b|traefik|\benvoy\b|lighttpd", "Load Balancer", "Proxy/LB", ["proxy", "web-server"], "confirmed"),
    (r"(?i)\bsquid\b|privoxy|\bclash\b|mihomo|v2ray|xray|sing[\s_-]?box", "Proxy", "Proxy Server", ["proxy"], "high"),
    # -- network services (generic server-side)
    (r"(?i)\bnamed\b|unbound|dnsmasq|pdns|\bbind\b", "DNS Server", "DNS Server", ["dns"], "confirmed"),
    (r"(?i)postfix|exim|dovecot|\bcyrus\b|opendkim", "Mail Server", "Mail Server", ["mail"], "confirmed"),
    (r"(?i)slapd|openldap|389[\s_-]?ds", "Directory", "LDAP", ["directory"], "confirmed"),
    (r"(?i)\bsmbd\b|\bnmbd\b|samba|\bsmbd\b", "File Sharing", "SMB/CIFS", ["file-storage"], "confirmed"),
    (r"(?i)nfsd|nfs[\s_-]?server|glusterd|ceph[\s_-]?(osd|mon|mgr|mds)", "File Sharing", "File Storage", ["file-storage"], "confirmed"),
    (r"(?i)chronyd?|\bntpd\b|ntp[\s_-]?d", "Time Service", "NTP", ["time-sync"], "confirmed"),
    (r"(?i)dhcpd|kea[\s_-]?(dhcp|dhcp4|dhcp6)|dnsmasq", "DHCP", "DHCP Server", ["dhcp"], "confirmed"),
    (r"(?i)minio|seaweedfs|jupiter[\s_-]?fs", "Object Storage", "Object Storage", ["file-storage"], "confirmed"),
    # -- monitoring / observability
    (r"(?i)prometheus|node[\s_-]?exporter|grafana|zabbix|\bnetdata\b|telegraf|victoria[\s_-]?metrics|thanos", "Monitoring", "Monitoring Stack", ["monitoring", "rest-api"], "confirmed"),
    (r"(?i)snmpd|snmp[\s_-]?trap", "Monitoring", "SNMP", ["monitoring"], "confirmed"),
    # -- macOS system daemons (best-effort display names)
    (r"(?i)ControlCe", "System Service", "ControlCenter", ["system-service"], "confirmed"),
    (r"(?i)rapportd", "System Service", "Rapportd", ["system-service"], "confirmed"),
    (r"(?i)mDNSResponder|Bonjour", "System Service", "Bonjour", ["system-service", "dns"], "confirmed"),
    (r"(?i)avahi", "System Service", "Avahi", ["system-service", "dns"], "confirmed"),
    (r"(?i)\bsharingd\b|\bapsd\b|\bidentityservicesd\b|\bUserEventAgent\b|\bdistnoted\b|\bnotifyd\b|\bconfigd\b|\bsandboxd\b|\bpowerd\b|\brunningboardd\b|\blogd\b", "System Service", "macOS Daemon", ["system-service"], "confirmed"),
]


def identify_process(app_name, exe, name, cmdline):
    hay = " ".join(filter(None, [app_name, exe, name, cmdline]))
    for pattern, svc_type, app, tags, conf in APP_RULES:
        if re.search(pattern, hay):
            return {"service_type": svc_type, "app": app,
                    "tags": list(tags), "confidence": conf,
                    "basis": [{"kind": "rule", "pattern": pattern,
                               "field": name or exe or app}]}
    return None


# ---------------------------------------------------------------------------
# macOS app bundle lookup (best-effort app display name)
# ---------------------------------------------------------------------------
def app_display_name(exe):
    m = re.search(r"(/[^/]+\.app)/", exe or "")
    if not m:
        return None
    bundle = m.group(0).rstrip("/")
    plist = os.path.join(bundle, "Contents", "Info.plist")
    try:
        import plistlib
        with open(plist, "rb") as fh:
            data = plistlib.load(fh)
        return data.get("CFBundleDisplayName") or data.get("CFBundleName")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Aggregation: group endpoints by process identity
# ---------------------------------------------------------------------------
def stable_id(pid, create_time):
    base = f"{pid}"
    if create_time:
        base += f":{int(create_time)}"
    return base


def build_services(endpoints, first_seen_map, aggregate_by="process"):
    """Aggregate endpoints into service records.

    aggregate_by='process'  : one service per PID (all its endpoints merged)
    aggregate_by='endpoint' : one service per (pid, proto, ip, port)
    Never merges on port number or name similarity alone.
    """
    # group endpoints by pid
    by_pid = {}
    for ep in endpoints:
        pid = ep.get("pid") or 0
        by_pid.setdefault(pid, []).append(ep)
    if aggregate_by == "endpoint":
        groups = []
        for pid, eps in by_pid.items():
            for ep in eps:
                groups.append((pid, [ep]))
    else:
        groups = list(by_pid.items())

    services = []
    for pid, eps in groups:
        if pid == 0:
            # kernel/other - cannot attribute
            continue
        ident = PROCCACHE.info(pid)
        name = ident.get("name") or eps[0].get("lsof_cmd") or ""
        exe = ident.get("exe") or ""
        cmdlist = ident.get("cmdline")
        cmdline = redact_cmdline(cmdlist) if cmdlist else ""
        create_time = ident.get("create_time")
        perm = ident.get("permission", "ok")
        ppid = ident.get("ppid")
        user = ident.get("username") or eps[0].get("user") or ""
        app = app_display_name(exe)

        sid = stable_id(pid, create_time)
        if aggregate_by == "endpoint" and eps:
            ep0 = eps[0]
            sid += f"#{ep0['proto']}-{ep0['ip']}-{ep0['port']}"

        # endpoints -> dedupe display
        seen_ep = set()
        endpoints_out = []
        for ep in eps:
            key = (ep["ip"], ep["port"], ep["proto"], ep["family"])
            if key in seen_ep:
                continue
            seen_ep.add(key)
            endpoints_out.append({
                "ip": ep["ip"], "port": ep["port"],
                "proto": ep["proto"], "family": ep["family"],
                "scope": scope_of_endpoint(ep["ip"]),
            })

        ports = sorted({e["port"] for e in endpoints_out if e["port"] is not None})

        # scopes summary
        raw_scopes = {e["scope"] for e in endpoints_out}
        has_loopback = "loopback" in raw_scopes
        has_wildcard = "wildcard" in raw_scopes
        has_lan = "lan" in raw_scopes
        has_public = "public" in raw_scopes

        # identification layer 1/3
        rule = identify_process(app, exe, name, cmdline)

        # web-ish detection: prober result (layer 2) merges later in Monitor;
        # here only process-based guesses.
        services.append({
            "id": sid, "pid": pid, "ppid": ppid,
            "proc_name": name, "app_name": app,
            "exe": exe, "cmdline": cmdline, "user": user,
            "started_ts": create_time,
            "permission": perm,
            "endpoints": endpoints_out,
            "ports": ports,
            "protocols": sorted({e["proto"] for e in endpoints_out}),
            "scopes": {
                "loopback": has_loopback, "wildcard": has_wildcard,
                "lan": has_lan, "public_condition": has_public,
                "public_verified": False,
            },
            "identify": rule,
            "app_layer": None,       # filled by probe merge
            "probed": False,
            "tags": (rule or {}).get("tags", []),
            "service_type": (rule or {}).get("service_type"),
            "confidence": (rule or {}).get("confidence", "unknown"),
            "basis": (rule or {}).get("basis", []),
            "first_seen_ts": first_seen_map.get(sid, time.time()),
        })
    return services


# ---------------------------------------------------------------------------
# Classification into the 5 categories + secondary tags
# ---------------------------------------------------------------------------
WEB_LAYERS = {"http", "https", "websocket"}

# Well-known ports -> domain tag, so generic servers get sensible tags even
# when no process rule matched (deployments on other machines).
PORT_TAGS = {
    20: "file-transfer", 21: "file-transfer", 22: "remote-access",
    23: "remote-access", 25: "mail", 53: "dns", 67: "dhcp", 68: "dhcp",
    69: "file-transfer", 110: "mail", 123: "time-sync", 143: "mail",
    161: "monitoring", 389: "directory", 443: "web-server", 465: "mail",
    514: "syslog", 587: "mail", 636: "directory", 853: "dns",
    993: "mail", 995: "mail", 1194: "vpn", 1521: "database",
    1723: "vpn", 2049: "file-storage", 2181: "coordination",
    3000: "development", 3128: "proxy", 3306: "database", 4222: "message-queue",
    4369: "message-queue", 5173: "development", 5432: "database",
    5672: "message-queue", 5900: "remote-access", 6379: "database",
    5353: "dns", 5355: "dns",
    7687: "database", 8080: "web-server", 8081: "web-server",
    8443: "web-server", 8888: "development", 9000: "file-storage",
    9092: "message-queue", 9200: "search", 9300: "search",
    11211: "cache", 15672: "monitoring", 16379: "database",
    19999: "backup", 27017: "database", 44444: "database",
    51820: "vpn", 54321: "development", 6881: "file-transfer",
}


def classify(service):
    """Category is driven by two independent dimensions:
      - service type: is it a browser-openable web UI (http/https serving HTML)
      - access scope: widest confirmed scope
    JSON APIs / WebSocket-only endpoints / 426 endpoints are HTTP but not
    browser-openable pages, so they are Non-Web (with an API tag kept)."""
    layer = service.get("app_layer")
    is_web = bool(service.get("browser_openable"))
    scopes = service["scopes"]

    if layer in ("ssh", "postgres", "mysql", "redis", "tls", "tcp"):
        category = "non-web"
    elif layer in ("http", "https") and not is_web:
        # HTTP-speaking but not a browsable page (API, websocket handshake…)
        category = "non-web"
    elif is_web:
        if scopes.get("public_verified"):
            category = "internet-web"
        elif scopes.get("lan") or scopes.get("public_condition") or scopes.get("wildcard"):
            category = "lan-web"
        else:
            category = "local-web"
    elif service.get("probed") and not service.get("reachable"):
        category = "unknown"      # probed but dead: keep unknown, allow re-probe
    elif service.get("identify"):
        category = "non-web"      # known process service without probe result yet
    else:
        category = "unknown"

    # tags: domain tags come from rules + well-known ports; capability tags
    # are only ever set from real probe evidence.
    tags = set(service.get("tags") or [])
    if is_web:
        tags.add("web-ui")
    if layer in ("http", "https") and not is_web:
        tags.add("rest-api")
    if service.get("app_layer") == "websocket":
        tags.add("websocket")
    if service.get("app_layer") in ("tls", "https"):
        tags.add("encrypted")
    for e in service.get("endpoints", []):
        pt = PORT_TAGS.get(e.get("port"))
        if pt:
            tags.add(pt)
    if not tags:
        tags.add("unknown")

    service["category"] = category
    service["tags"] = sorted(tags)
    return service


# ---------------------------------------------------------------------------
# Resource sampling
# ---------------------------------------------------------------------------
def sample_resources(service):
    if not HAVE_PSUTIL:
        service["cpu_percent"] = None
        service["memory_mb"] = None
        return
    try:
        proc = psutil.Process(service["pid"])
        service["cpu_percent"] = PROCCACHE.cpu_sample(proc)
        service["memory_mb"] = PROCCACHE.memory_mb(proc)
    except Exception:
        service["cpu_percent"] = None
        service["memory_mb"] = None


# ---------------------------------------------------------------------------
# History store (SQLite)
# ---------------------------------------------------------------------------
class History:
    def __init__(self):
        self.lock = threading.Lock()
        self.ok = True
        try:
            self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS events("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ts REAL, type TEXT, service_id TEXT, name TEXT,"
                "port INTEGER, proto TEXT, detail TEXT)")
            self.conn.commit()
        except Exception as exc:
            self.ok = False
            log_error("history.open", exc)

    def add(self, etype, service_id, name, port, proto, detail=""):
        if not self.ok:
            return
        try:
            detail_json = detail if isinstance(detail, str) and not detail.startswith(("{", "[")) \
                else json.dumps(detail, ensure_ascii=False)
            with self.lock:
                self.conn.execute(
                    "INSERT INTO events(ts,type,service_id,name,port,proto,detail)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (time.time(), etype, service_id, name, port, proto, detail_json))
                self.conn.commit()
        except Exception as exc:
            self.ok = False
            log_error("history.add", exc)

    def query(self, since=None, until=None, etype=None, limit=500):
        if not self.ok:
            return []
        q = "SELECT ts,type,service_id,name,port,proto,detail FROM events"
        conds, args = [], []
        if since:
            conds.append("ts>=?")
            args.append(since)
        if until:
            conds.append("ts<=?")
            args.append(until)
        if etype:
            conds.append("type=?")
            args.append(etype)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        try:
            with self.lock:
                rows = self.conn.execute(q, args).fetchall()
            return [dict(zip(
                ["ts", "type", "service_id", "name", "port", "proto", "detail"],
                r)) for r in rows]
        except Exception as exc:
            log_error("history.query", exc)
            return []

    def clear(self):
        if not self.ok:
            return False
        try:
            with self.lock:
                self.conn.execute("DELETE FROM events")
                self.conn.commit()
            return True
        except Exception as exc:
            log_error("history.clear", exc)
            return False

    def prune(self, days):
        if not self.ok:
            return
        try:
            cutoff = time.time() - days * 86400
            with self.lock:
                self.conn.execute("DELETE FROM events WHERE ts<?", (cutoff,))
                self.conn.commit()
        except Exception as exc:
            log_error("history.prune", exc)


HISTORY = History()

# resource history kept in memory for charts: id -> deque of (ts, cpu, mem)
RESOURCE_HISTORY = {}


def record_resource(service):
    hist = RESOURCE_HISTORY.setdefault(service["id"], deque(maxlen=180))
    hist.append((time.time(),
                 service.get("cpu_percent"),
                 service.get("memory_mb")))


# ---------------------------------------------------------------------------
# Process stop (safe: identity verify + protections)
# ---------------------------------------------------------------------------
SYSTEM_PROTECTED_NAMES = {
    "launchd", "kernel_task", "loginwindow", "WindowServer", "syslogd",
    "apsd", "configd", "notifyd", "distnoted", "sandboxd", "securityd",
    "opendirectoryd", "diskarbitrationd", "powerd", "UserEventAgent",
}


def stop_process(pid, expect_name, expect_create):
    if not HAVE_PSUTIL:
        return {"ok": False, "error": "psutil_unavailable"}
    if pid == os.getpid():
        return {"ok": False, "error": "self_stop_forbidden"}
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"ok": False, "error": "not_found"}
    except Exception as exc:
        log_error("stop.open", exc)
        return {"ok": False, "error": "denied"}
    try:
        cur_name = proc.name()
        cur_create = proc.create_time()
    except psutil.AccessDenied:
        return {"ok": False, "error": "denied"}
    # PID-reuse guard: identity must still match what the UI saw
    if expect_name and cur_name and cur_name != expect_name:
        return {"ok": False, "error": "identity_mismatch"}
    if expect_create and cur_create and abs(cur_create - expect_create) > 2:
        return {"ok": False, "error": "identity_mismatch"}
    if cur_name in SYSTEM_PROTECTED_NAMES:
        return {"ok": False, "error": "protected_system_process"}
    # SIGTERM (graceful), never SIGKILL automatically
    try:
        proc.terminate()
    except psutil.AccessDenied:
        return {"ok": False, "error": "denied"}
    except Exception as exc:
        log_error("stop.terminate", exc)
        return {"ok": False, "error": "failed"}
    return {"ok": True, "pid": pid, "name": cur_name}


# ---------------------------------------------------------------------------
# Monitor: orchestrates scans, diffing, probing, classification
# ---------------------------------------------------------------------------
class Monitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.snapshot = []            # last services list
        self.first_seen = {}          # id -> ts
        self.prev_ids = set()
        self._ever_scanned = False
        self._known_ever = set()      # ids seen in any past scan
        self.last_scan_ts = 0
        self.last_scan_ms = 0
        self.scanning = False
        self.device_name = socket.gethostname()
        self._permission_ok = True
        self._boot_time = time.time()

    def scan(self):
        with self.lock:
            if self.scanning:
                return self.snapshot
            self.scanning = True
        t0 = time.time()
        snap = None
        try:
            settings = {k: CONFIG.get(k) for k in DEFAULT_SETTINGS}
            eps = scan_lsof_endpoints(settings)
            # psutil adds reliable family + cross-check; merge on
            # (pid, proto, port) and treat wildcard vs concrete IP as equal.
            def known(ep, e):
                return (ep["pid"] == e["pid"] and ep["proto"] == e["proto"]
                        and ep["port"] == e["port"]
                        and _ip_equivalent(ep["ip"], e["ip"]))
            for e in scan_psutil_endpoints(settings):
                if not any(known(ep, e) for ep in eps):
                    eps.append(e)
            # final dedupe across sources (wildcard forms may differ)
            dedup, seen_keys = [], set()
            for ep in eps:
                key = (ep["pid"], ep["proto"], ep["port"],
                       _norm_ip(ep["ip"], ep["family"]))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                dedup.append(ep)
            eps = dedup
            services = build_services(eps, self.first_seen,
                                      settings.get("aggregate_by", "process"))
            self._permission_ok = not any(
                s.get("permission") == "denied" for s in services)

            # merge probe cache into services (layer 2), no new probing here
            for svc in services:
                self._merge_probe(svc)

            # classify + sample
            for svc in services:
                classify(svc)
                sample_resources(svc)
                record_resource(svc)

            # filter by settings
            services = self._apply_filters(services, settings)

            now = time.time()
            for svc in services:
                self.first_seen.setdefault(svc["id"], now)
                svc["last_seen_ts"] = now

            self._diff_and_record(services)
            self._schedule_probes(services, settings)

            self.snapshot = services
            self.prev_ids = {s["id"] for s in services}
            self.last_scan_ts = now
            self.last_scan_ms = (time.time() - t0) * 1000
        except Exception as exc:
            log_error("monitor.scan", exc)
        finally:
            with self.lock:
                self.scanning = False
        return self.snapshot

    def _apply_filters(self, services, settings):
        out = []
        for s in services:
            if s["category"] == "unknown" and not settings.get("show_unknown"):
                continue
            if "system-service" in s.get("tags", []) and not settings.get("show_system"):
                continue
            out.append(s)
        return out

    def _merge_probe(self, svc):
        """Attach cached protocol result to a service if any endpoint matches."""
        for ep in svc["endpoints"]:
            if ep["proto"] != "tcp":
                continue
            key = f"{svc['pid']}|{ep['port']}|{ep['ip']}"
            cached = PROBECACHE.get(key)
            if cached and not cached.get("proto") and cached.get("passive"):
                # passive probe reached the port but the app speaks no
                # banner protocol and we sent nothing: record honestly.
                svc["probed"] = True
                svc["reachable"] = cached.get("reachable", False)
                svc["passive_probe"] = True
                if cached.get("reachable"):
                    svc["basis"].append({"kind": "passive",
                                         "reachable": True})
                continue
            if cached and cached.get("proto"):
                svc["probed"] = True
                svc["reachable"] = cached.get("reachable", False)
                svc["app_layer"] = cached.get("proto")
                if cached.get("service"):
                    svc["detected_service"] = cached["service"]
                if cached.get("detail"):
                    svc["probe_detail"] = cached["detail"]
                if cached.get("passive"):
                    svc["passive_probe"] = True
                # browser-openable UI is what qualifies as a "Web service"
                if cached["proto"] in ("http", "https"):
                    svc["browser_openable"] = _is_browser_openable(
                        cached.get("detail"))
                elif cached["proto"] == "websocket":
                    svc["browser_openable"] = False
                # upgrade confidence with probe evidence
                if cached["proto"] in WEB_LAYERS:
                    if svc["confidence"] == "unknown":
                        svc["confidence"] = "high"
                    b = {"kind": "probe", "proto": cached["proto"],
                         "reachable": cached.get("reachable", False)}
                    if cached["detail"].get("status"):
                        b["status"] = cached["detail"]["status"]
                    if cached["detail"].get("server"):
                        b["server"] = cached["detail"]["server"]
                    svc["basis"].append(b)
                return

    def _schedule_probes(self, services, settings):
        if not settings.get("auto_prober"):
            return
        PROBECACHE.drop_stale()
        gentle = settings.get("gentle_gui_probing", True)
        for svc in services:
            if (svc.get("proc_name") or "") in NO_AUTO_PROBE_NAMES:
                continue  # do not auto-probe system daemons (window popups)
            passive = gentle and _is_gui_app(svc)
            for ep in svc["endpoints"]:
                if ep["proto"] != "tcp":
                    continue
                key = f"{svc['pid']}|{ep['port']}|{ep['ip']}"
                with PROBECACHE.lock:
                    if key in PROBECACHE.inflight:
                        continue
                cached = PROBECACHE.get(key)
                # probe when no cache, or stale (>5min), or never reachable
                # (shorter retry for dead endpoints); a cached passive
                # result is upgraded by an active full probe on demand
                need = (not cached) or \
                    (time.time() - cached.get("ts", 0) > 300) or \
                    (not cached.get("reachable") and
                     time.time() - cached.get("ts", 0) > 60)
                if need:
                    ip = ep["ip"] if ep["ip"] not in ("*", "::") else "127.0.0.1"
                    with PROBECACHE.lock:
                        PROBECACHE.inflight.add(key)
                    PROBECACHE.put(key + "|inflight", {"proto": None})
                    PROBE_POOL.submit(self._do_probe, key, ip, ep["port"],
                                      svc.get("cmdline", ""), passive)

    def _do_probe(self, key, ip, port, cmdline, passive=False):
        try:
            res = probe_endpoint(ip, port, cmdline, passive=passive)
            PROBECACHE.put(key, res)
        except Exception as exc:
            log_error("probe", exc)
        finally:
            with PROBECACHE.lock:
                PROBECACHE.inflight.discard(key)
                PROBECACHE.data.pop(key + "|inflight", None)

    def _diff_and_record(self, services):
        cur_ids = {s["id"] for s in services}
        # disappeared (was present last scan, gone now)
        for gone in self.prev_ids - cur_ids:
            prev = next((x for x in self.snapshot if x["id"] == gone), None)
            HISTORY.add("disappeared", gone,
                        prev["proc_name"] if prev else "",
                        prev["ports"][0] if prev and prev["ports"] else None,
                        ",".join(prev["protocols"]) if prev else "", "")
        first_scan = not self._ever_scanned
        for s in services:
            if s["id"] not in self.prev_ids:
                etype = "first_seen" if (first_scan or
                                         s["id"] not in self._known_ever) else "appeared"
                HISTORY.add(etype, s["id"], s["proc_name"],
                            s["ports"][0] if s["ports"] else None,
                            ",".join(s["protocols"]), "")
            self._known_ever.add(s["id"])
        self._ever_scanned = True
        # port / address changes for continuing services
        for s_id in cur_ids & self.prev_ids:
            prev = next((x for x in self.snapshot if x["id"] == s_id), None)
            if not prev:
                continue
            s = next(x for x in services if x["id"] == s_id)
            cur_eps = {(e["ip"], e["port"], e["proto"]) for e in s["endpoints"]}
            prev_eps = {(e["ip"], e["port"], e["proto"]) for e in prev["endpoints"]}
            if cur_eps != prev_eps:
                HISTORY.add("endpoint_change", s_id, s["proc_name"],
                            s["ports"][0] if s["ports"] else None,
                            ",".join(s["protocols"]),
                            f"was={sorted(map(str, prev_eps))} now={sorted(map(str, cur_eps))}")
        # identification change
        for s_id in cur_ids & self.prev_ids:
            prev = next((x for x in self.snapshot if x["id"] == s_id), None)
            s = next(x for x in services if x["id"] == s_id)
            if prev and prev.get("category") != s.get("category"):
                HISTORY.add("classification_change", s_id, s["proc_name"],
                            s["ports"][0] if s["ports"] else None,
                            ",".join(s["protocols"]),
                            f"{prev.get('category')} -> {s.get('category')}")

    def get_snapshot(self):
        with self.lock:
            return list(self.snapshot)

    def status(self):
        lsof_ok = os.path.exists("/usr/sbin/lsof")
        return {
            "scanning": self.scanning,
            "last_scan_ts": self.last_scan_ts,
            "last_scan_ms": round(self.last_scan_ms, 1),
            "device_name": self.device_name,
            "boot_ts": self._boot_time,
            "service_count": len(self.snapshot),
            "psutil": HAVE_PSUTIL,
            "version": VERSION,
            "python": sys.version.split()[0],
            "lsof_ok": lsof_ok,
            "permission_ok": self._permission_ok,
        }


MONITOR = Monitor()


# ---------------------------------------------------------------------------
# HTTP API + server
# ---------------------------------------------------------------------------
CSRF_TOKEN = os.urandom(24).hex()


def is_authorized(handler, body_bytes=None, is_mutation=False):
    # loopback transport check
    client = handler.client_address[0]
    if client not in ("127.0.0.1", "::1"):
        return False
    tok = handler.headers.get("X-CSRF-Token", "")
    if not secrets_eq(tok, CSRF_TOKEN):
        return False
    origin = handler.headers.get("Origin") or handler.headers.get("Referer") or ""
    if origin:
        host = urlparse(origin).netloc or ""
        if host and host.split(":")[0] not in ("127.0.0.1", "localhost", "::1"):
            return False
    if is_mutation:
        # double-submit: mutation requires the header (already checked above)
        return True
    return True


def secrets_eq(a, b):
    import hmac
    return hmac.compare_digest(a or "", b or "")


class Handler(BaseHTTPRequestHandler):
    server_version = f"LocalServiceMonitor/{VERSION}"

    def log_message(self, *a):
        pass  # keep stdout quiet

    def _send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 1_000_000:
            return b""
        return self.rfile.read(length)

    def _serve_index(self):
        try:
            with open(INDEX_PATH, "r", encoding="utf-8") as fh:
                html = fh.read()
            html = html.replace("__CSRF_TOKEN__", CSRF_TOKEN)
            data = html.encode("utf-8")
        except FileNotFoundError:
            data = b"<h1>index.html not found</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path in ("/", "/index.html"):
            return self._serve_index()
        if path.startswith(API_PREFIX):
            if not is_authorized(self):
                return self._send_json(403, {"error": "forbidden"})
            return self.route_get(path, parse_qs(u.query))
        return self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path
        if path.startswith(API_PREFIX):
            if not is_authorized(self, is_mutation=True):
                return self._send_json(403, {"error": "forbidden"})
            body = self._read_body()
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
            except Exception:
                payload = {}
            return self.route_post(path, payload)
        return self._send_json(404, {"error": "not_found"})

    # -- GET routes -------------------------------------------------------
    def route_get(self, path, qs):
        if path == API_PREFIX + "services":
            return self._send_json(200, {"services": MONITOR.get_snapshot(),
                                         "status": MONITOR.status()})
        if path == API_PREFIX + "status":
            return self._send_json(200, MONITOR.status())
        if path == API_PREFIX + "history":
            since = _fnum(qs, "since")
            until = _fnum(qs, "until")
            etype = (qs.get("type") or [""])[0] or None
            limit = int((qs.get("limit") or ["500"])[0])
            return self._send_json(200, {"events": HISTORY.query(
                since, until, etype, min(limit, 2000)),
                "sqlite_ok": HISTORY.ok})
        if path == API_PREFIX + "settings":
            cfg = {k: CONFIG.get(k) for k in DEFAULT_SETTINGS}
            return self._send_json(200, {"settings": cfg,
                                         "csrf": CSRF_TOKEN})
        if path == API_PREFIX + "resources":
            sid = (qs.get("id") or [""])[0]
            hist = RESOURCE_HISTORY.get(sid)
            pts = list(hist) if hist else []
            return self._send_json(200, {"id": sid,
                                         "points": [{"ts": p[0],
                                                     "cpu": p[1],
                                                     "mem": p[2]}
                                                    for p in pts]})
        if path == API_PREFIX + "errors":
            return self._send_json(200, {"errors": list(ERROR_LOG)[-50:]})
        if path == API_PREFIX + "verify-public":
            return self._send_json(200, verify_public_status())
        return self._send_json(404, {"error": "not_found"})

    # -- POST routes ------------------------------------------------------
    def route_post(self, path, payload):
        if path == API_PREFIX + "scan":
            snap = MONITOR.scan()
            return self._send_json(200, {"services": snap,
                                         "status": MONITOR.status()})
        if path == API_PREFIX + "reprobe":
            sid = str(payload.get("id", ""))
            svc = next((s for s in MONITOR.get_snapshot() if s["id"] == sid), None)
            if not svc:
                return self._send_json(404, {"error": "not_found"})
            for ep in svc["endpoints"]:
                if ep["proto"] != "tcp":
                    continue
                key = f"{svc['pid']}|{ep['port']}|{ep['ip']}"
                PROBECACHE.data.pop(key, None)
                ip = ep["ip"] if ep["ip"] not in ("*", "::") else "127.0.0.1"
                PROBE_POOL.submit(MONITOR._do_probe, key, ip, ep["port"],
                                  svc.get("cmdline", ""))
            return self._send_json(200, {"ok": True, "queued": True})
        if path == API_PREFIX + "stop":
            pid = int(payload.get("pid", -1))
            res = stop_process(pid, payload.get("name"),
                               payload.get("create_time"))
            if res.get("ok"):
                HISTORY.add("stopped", str(pid), res.get("name", ""), None, "", "")
            return self._send_json(200 if res.get("ok") else 400, res)
        if path == API_PREFIX + "settings":
            patch = payload.get("settings", payload)
            if isinstance(patch, dict):
                # validate types loosely; only known keys stored
                clean = {k: v for k, v in patch.items() if k in DEFAULT_SETTINGS}
                CONFIG.update(clean)
                nw = max(1, int(CONFIG.get("probe_max_workers")))
                if nw != PROBE_POOL._max_workers:
                    globals()["PROBE_POOL"] = ThreadPoolExecutor(max_workers=nw)
            return self._send_json(200, {"ok": True,
                                         "settings": {k: CONFIG.get(k)
                                                      for k in DEFAULT_SETTINGS}})
        if path == API_PREFIX + "history/clear":
            ok = HISTORY.clear()
            return self._send_json(200, {"ok": ok})
        return self._send_json(404, {"error": "not_found"})


def _fnum(qs, key):
    try:
        v = (qs.get(key) or [None])[0]
        return float(v) if v not in (None, "") else None
    except Exception:
        return None


def verify_public_status():
    """Public reachability requires an explicit external verification
    mechanism, off by default. Never sends local data without user consent."""
    if not CONFIG.get("public_verify_enabled"):
        return {"status": "unverified",
                "reason": "external verification disabled"}
    url = CONFIG.get("public_verify_url") or ""
    if not url:
        return {"status": "unverified", "reason": "no verify endpoint configured"}
    # If the user explicitly opted in, a real reachability check is attempted.
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "LSM-verify/1.0"})
        with urllib.request.urlopen(req, timeout=6) as r:
            code = getattr(r, "status", 200)
        return {"status": "attempted", "http": code, "url": url,
                "note": "manual endpoint response; not a port-open proof"}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


# ---------------------------------------------------------------------------
# Background refresher
# ---------------------------------------------------------------------------
STOP = threading.Event()


def refresher():
    # initial history prune
    try:
        HISTORY.prune(int(CONFIG.get("history_retention_days") or 30))
    except Exception:
        pass
    while not STOP.is_set():
        try:
            MONITOR.scan()
        except Exception as exc:
            log_error("refresher", exc)
        # cadence: front-end drives manual refresh too; keep a gentle
        # server-side refresh so charts/first_seen advance.
        STOP.wait(3.0)


def find_free_port(preferred):
    for p in [preferred, 0]:
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            return srv
        except OSError:
            continue
    raise RuntimeError("cannot bind loopback server")


def main():
    port = int(os.environ.get("LSM_PORT", DEFAULT_PORT))
    srv = find_free_port(port)
    actual = srv.server_address[1]
    threading.Thread(target=refresher, daemon=True).start()
    url = f"http://127.0.0.1:{actual}/"
    print(f"Local Service Monitor v{VERSION}")
    print(f"psutil: {'available' if HAVE_PSUTIL else 'MISSING (degraded)'}")
    print(f"API bound to loopback: {url}")
    print(f"CSRF/session token is injected into the served page.")
    try:
        # initial scan then open browser
        MONITOR.scan()
        if not os.environ.get("LSM_NO_BROWSER"):
            webbrowser.open(url)
    except Exception as exc:
        log_error("startup", exc)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        STOP.set()
        srv.shutdown()


if __name__ == "__main__":
    main()
