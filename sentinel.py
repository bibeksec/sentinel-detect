#!/usr/bin/env python3
"""
Sentinel - single-file log-based threat detection engine.

Reads SSH auth logs and nginx/Apache access logs, runs stateful sliding-window
detections, and reports attacks mapped to MITRE ATT&CK.

Zero required dependencies (Python 3.9+). PyYAML is optional, for YAML rule files.

Quick start:
    python sentinel.py --demo                      # see it work instantly
    python sentinel.py scan /var/log/auth.log      # auto-detects log type
    python sentinel.py scan auth.log access.log --format html -o report.html
    python sentinel.py follow /var/log/auth.log    # live monitoring
    python sentinel.py selftest                    # run built-in tests
    python sentinel.py rules                       # list detections + ATT&CK coverage

Use only on systems and logs you own or are authorized to analyze.
"""
from __future__ import annotations

import argparse
import html
import ipaddress
import json
import re
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

__version__ = "1.0.0"

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
RULE_TYPES = {"match", "threshold", "distinct", "followed_by"}


# ----------------------------------------------------------------------------
# Data models
# ----------------------------------------------------------------------------
@dataclass
class Event:
    ts: datetime
    source: str  # "ssh" | "web"
    fields: dict[str, Any] = field(default_factory=dict)
    raw: str = ""


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    attack: list[str]
    group: str
    first_seen: datetime
    last_seen: datetime
    count: int
    evidence: list[str]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre_attack": self.attack,
            "group": self.group,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "evidence": self.evidence[:5],
        }


# ----------------------------------------------------------------------------
# Parsers
# ----------------------------------------------------------------------------
SSH_RE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$")
FAILED_RE = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")
WEB_RE = re.compile(
    r'^(?P<ip>[\d.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)


def parse_ssh(lines: Iterable[str], year: int | None = None) -> Iterator[Event]:
    """Parse OpenSSH lines. Syslog has no year, so one is inferred (or supplied)."""
    now = datetime.now(timezone.utc)
    for line in lines:
        line = line.rstrip("\n")
        m = SSH_RE.match(line)
        if not m:
            continue
        y = year or now.year
        try:
            ts = datetime.strptime(f"{y} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        ts = ts.replace(tzinfo=timezone.utc)
        if year is None and ts > now + timedelta(days=1):  # e.g. December log read in January
            ts = ts.replace(year=ts.year - 1)
        for rx, name in ((FAILED_RE, "failed_login"), (ACCEPTED_RE, "accepted_login"), (INVALID_RE, "invalid_user")):
            mm = rx.search(m["msg"])
            if mm:
                fields = {"event": name, "user": mm["user"], "src_ip": mm["ip"], "host": m["host"]}
                yield Event(ts, "ssh", fields, line)
                break


def parse_web(lines: Iterable[str], year: int | None = None) -> Iterator[Event]:
    """Parse nginx/Apache combined access logs."""
    for line in lines:
        line = line.rstrip("\n")
        m = WEB_RE.match(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        fields = {
            "src_ip": m["ip"],
            "method": m["method"],
            "path": m["path"],
            "status": int(m["status"]),
            "user_agent": m["ua"],
        }
        yield Event(ts, "web", fields, line)


PARSERS = {"ssh": parse_ssh, "web": parse_web}


def sniff_type(sample: list[str]) -> str | None:
    """Guess the log type from the first lines."""
    scores = {"ssh": 0, "web": 0}
    for line in sample:
        if SSH_RE.match(line):
            scores["ssh"] += 1
        elif WEB_RE.match(line):
            scores["web"] += 1
    best = max(scores, key=scores.get)
    return best if scores[best] else None


# ----------------------------------------------------------------------------
# Rules (built in, so the tool works as a single file; extra rules load from files)
# ----------------------------------------------------------------------------
BUILTIN_RULES: list[dict] = [
    {
        "id": "SSH-001", "title": "SSH brute force (many failed logins from one IP)",
        "severity": "high", "attack": ["T1110.001"], "logsource": "ssh",
        "detection": {"type": "threshold", "filter": {"event": "failed_login"},
                      "group_by": "src_ip", "count": 5, "window": "60s"},
    },
    {
        "id": "SSH-002", "title": "SSH password spraying (many usernames from one IP)",
        "severity": "high", "attack": ["T1110.003"], "logsource": "ssh",
        "detection": {"type": "distinct", "filter": {"event": ["failed_login", "invalid_user"]},
                      "group_by": "src_ip", "field": "user", "count": 6, "window": "5m"},
    },
    {
        "id": "SSH-003", "title": "Successful SSH login after brute force",
        "severity": "critical", "attack": ["T1110", "T1078"], "logsource": "ssh",
        "detection": {"type": "followed_by", "group_by": "src_ip", "window": "10m",
                      "first": {"filter": {"event": "failed_login"}, "count": 4},
                      "then": {"event": "accepted_login"}},
    },
    {
        "id": "SSH-004", "title": "Direct root login over SSH",
        "severity": "medium", "attack": ["T1078.003"], "logsource": "ssh",
        "detection": {"type": "match", "filter": {"event": "accepted_login", "user": "root"}, "group_by": "src_ip"},
    },
    {
        "id": "WEB-001", "title": "Web scanner / directory brute forcing (404 flood)",
        "severity": "medium", "attack": ["T1595.002", "T1595.003"], "logsource": "web",
        "detection": {"type": "threshold", "filter": {"status": 404},
                      "group_by": "src_ip", "count": 15, "window": "30s"},
    },
    {
        "id": "WEB-002", "title": "SQL injection attempt in request",
        "severity": "high", "attack": ["T1190"], "logsource": "web",
        "detection": {"type": "match", "group_by": "src_ip", "filter": {"path|contains": [
            "union select", "union%20select", "union+select", "' or 1=1", "%27%20or%201=1",
            "sleep(", "benchmark(", "information_schema", "xp_cmdshell"]}},
    },
    {
        "id": "WEB-003", "title": "Path traversal / sensitive file access attempt",
        "severity": "high", "attack": ["T1190", "T1083"], "logsource": "web",
        "detection": {"type": "match", "group_by": "src_ip", "filter": {"path|contains": [
            "../", "..%2f", "%2e%2e", "/etc/passwd", "/.env", "/.git/config", "wp-config"]}},
    },
    {
        "id": "WEB-004", "title": "Known offensive tool user-agent",
        "severity": "low", "attack": ["T1595.002"], "logsource": "web",
        "detection": {"type": "match", "group_by": "src_ip", "filter": {"user_agent|contains": [
            "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "wpscan", "hydra"]}},
    },
    {
        "id": "WEB-005", "title": "Cross-site scripting (XSS) attempt in request",
        "severity": "medium", "attack": ["T1190"], "logsource": "web",
        "detection": {"type": "match", "group_by": "src_ip", "filter": {"path|contains": [
            "<script", "%3cscript", "onerror=", "javascript:", "alert(1)"]}},
    },
    {
        "id": "WEB-006", "title": "Command injection / webshell probe in request",
        "severity": "high", "attack": ["T1190", "T1059"], "logsource": "web",
        "detection": {"type": "match", "group_by": "src_ip", "filter": {"path|contains": [
            ";cat%20", "|cat%20", "%3bwhoami", "cmd.exe", "/bin/sh", "c99.php", "shell.php", "${jndi:"]}},
    },
]


class RuleError(ValueError):
    pass


def parse_window(value: str | int) -> int:
    if isinstance(value, int):
        return value
    m = re.fullmatch(r"(\d+)([smh])", str(value).strip())
    if not m:
        raise RuleError(f"bad window '{value}' (use e.g. 30s, 5m, 1h)")
    return int(m[1]) * {"s": 1, "m": 60, "h": 3600}[m[2]]


def validate_rule(data: dict, origin: str = "?") -> dict:
    for key in ("id", "title", "severity", "logsource", "detection"):
        if key not in data:
            raise RuleError(f"{origin}: missing '{key}'")
    if data["severity"] not in SEV_ORDER:
        raise RuleError(f"{origin}: severity must be one of {sorted(SEV_ORDER)}")
    if data["logsource"] not in PARSERS:
        raise RuleError(f"{origin}: logsource must be one of {sorted(PARSERS)}")
    det = dict(data["detection"])
    if det.get("type") not in RULE_TYPES:
        raise RuleError(f"{origin}: detection.type must be one of {sorted(RULE_TYPES)}")
    if det["type"] != "match":
        if "window" not in det:
            raise RuleError(f"{origin}: '{det['type']}' rules need a window")
        det["window_s"] = parse_window(det["window"])
    if det["type"] in ("threshold", "distinct") and "count" not in det:
        raise RuleError(f"{origin}: '{det['type']}' rules need a count")
    if det["type"] == "distinct" and "field" not in det:
        raise RuleError(f"{origin}: 'distinct' rules need a field")
    if det["type"] == "followed_by" and not ({"first", "then"} <= det.keys()):
        raise RuleError(f"{origin}: 'followed_by' rules need 'first' and 'then'")
    out = dict(data)
    out["detection"] = det
    out.setdefault("attack", [])
    return out


def load_rule_files(directory: str) -> list[dict]:
    """Load extra rules from *.json (always) and *.yml/*.yaml (if PyYAML is installed)."""
    rules = []
    for p in sorted(Path(directory).glob("*")):
        if p.suffix == ".json":
            data = json.loads(p.read_text())
        elif p.suffix in (".yml", ".yaml"):
            try:
                import yaml  # optional dependency
            except ImportError:
                print(f"warning: skipping {p.name} (install PyYAML for YAML rules, or use .json)", file=sys.stderr)
                continue
            data = yaml.safe_load(p.read_text())
        else:
            continue
        rules.append(validate_rule(data, str(p)))
    return rules


def get_rules(extra_dir: str | None = None, disabled: Iterable[str] = ()) -> list[dict]:
    rules = [validate_rule(r, r["id"]) for r in BUILTIN_RULES]
    if extra_dir:
        by_id = {r["id"]: r for r in rules}
        for r in load_rule_files(extra_dir):
            by_id[r["id"]] = r  # custom rules can override built-ins by id
        rules = list(by_id.values())
    off = set(disabled)
    return [r for r in rules if r["id"] not in off]


def matches(filt: dict[str, Any] | None, fields: dict[str, Any]) -> bool:
    """All keys must match. Modifiers: key|contains, key|startswith, key|re. Lists mean any-of."""
    for key, expected in (filt or {}).items():
        name, _, mod = key.partition("|")
        actual = fields.get(name)
        if actual is None:
            return False
        options = expected if isinstance(expected, list) else [expected]
        actual_s = str(actual).lower()
        if mod == "contains":
            ok = any(str(o).lower() in actual_s for o in options)
        elif mod == "startswith":
            ok = any(actual_s.startswith(str(o).lower()) for o in options)
        elif mod == "re":
            ok = any(re.search(str(o), str(actual), re.I) for o in options)
        elif mod == "":
            ok = actual in options or actual_s in [str(o).lower() for o in options]
        else:
            raise RuleError(f"unknown modifier '{mod}'")
        if not ok:
            return False
    return True


# ----------------------------------------------------------------------------
# Detection engine
# ----------------------------------------------------------------------------
def _alert(rule: dict, group: str, evs: list[Event]) -> Alert:
    return Alert(rule["id"], rule["title"], rule["severity"], rule["attack"], group,
                 evs[0].ts, evs[-1].ts, len(evs), [e.raw for e in evs])


def run_rule(rule: dict, events: list[Event], allow: set[str]) -> list[Alert]:
    det = rule["detection"]
    kind = det["type"]
    window = timedelta(seconds=det.get("window_s", 0))
    cooldown = timedelta(seconds=det.get("cooldown_s", det.get("window_s", 300)))
    group_key = det.get("group_by", "src_ip")
    filt = det.get("filter")
    alerts: list[Alert] = []
    muted: dict[str, datetime] = {}
    buckets: dict[str, deque] = defaultdict(deque)
    armed: dict[str, tuple[datetime, list[Event]]] = {}

    for ev in events:
        if ev.source != rule["logsource"]:
            continue
        g = str(ev.fields.get(group_key, "unknown"))
        if g in allow or (g in muted and ev.ts < muted[g]):
            continue

        if kind == "match":
            if matches(filt, ev.fields):
                alerts.append(_alert(rule, g, [ev]))
                muted[g] = ev.ts + cooldown

        elif kind in ("threshold", "distinct"):
            if not matches(filt, ev.fields):
                continue
            q = buckets[g]
            q.append(ev)
            while q and ev.ts - q[0].ts > window:
                q.popleft()
            if kind == "threshold":
                hit = len(q) >= det["count"]
            else:
                hit = len({e.fields.get(det["field"]) for e in q}) >= det["count"]
            if hit:
                alerts.append(_alert(rule, g, list(q)))
                muted[g] = ev.ts + cooldown
                q.clear()

        elif kind == "followed_by":
            first, then = det["first"], det["then"]
            if g in armed and ev.ts > armed[g][0]:
                del armed[g]
            if g in armed and matches(then, ev.fields):
                chain = armed.pop(g)[1] + [ev]
                alerts.append(_alert(rule, g, chain))
                muted[g] = ev.ts + cooldown
                continue
            if matches(first.get("filter"), ev.fields):
                q = buckets[g]
                q.append(ev)
                while q and ev.ts - q[0].ts > window:
                    q.popleft()
                if len(q) >= first["count"] and g not in armed:
                    armed[g] = (ev.ts + window, list(q))
                    q.clear()
    return alerts


def detect(events: Iterable[Event], rules: list[dict], min_severity: str = "low",
           allow: Iterable[str] = ()) -> list[Alert]:
    evs = sorted(events, key=lambda e: e.ts)
    allow_set = set(allow)
    out: list[Alert] = []
    for rule in rules:
        out.extend(run_rule(rule, evs, allow_set))
    out = [a for a in out if SEV_ORDER[a.severity] >= SEV_ORDER[min_severity]]
    out.sort(key=lambda a: (a.first_seen, -SEV_ORDER[a.severity]))
    return out


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
COLORS = {"low": "\033[36m", "medium": "\033[33m", "high": "\033[31m", "critical": "\033[1;31m"}
HTML_COLORS = {"low": "#2b7a9b", "medium": "#c98a00", "high": "#d33", "critical": "#8b0000"}


def fmt_alert(a: Alert, color: bool) -> str:
    c, r = (COLORS[a.severity], "\033[0m") if color else ("", "")
    span = f"{a.first_seen:%Y-%m-%d %H:%M:%S} -> {a.last_seen:%H:%M:%S}"
    return (f"{c}[{a.severity.upper():8}]{r} {a.rule_id}  {a.title}\n"
            f"           source={a.group}  events={a.count}  {span}\n"
            f"           ATT&CK: {', '.join(a.attack) or '-'}")


def summary_text(alerts: list[Alert], n_events: int) -> str:
    sev = Counter(a.severity for a in alerts)
    top = Counter(a.group for a in alerts).most_common(5)
    techs = sorted({t for a in alerts for t in a.attack})
    lines = ["", "=" * 60, f"SUMMARY: {n_events} events parsed, {len(alerts)} alerts"]
    lines.append("By severity: " + (", ".join(f"{s}={sev[s]}" for s in ("critical", "high", "medium", "low") if sev[s]) or "none"))
    if top:
        lines.append("Top sources: " + ", ".join(f"{ip} ({n})" for ip, n in top))
    if techs:
        lines.append("ATT&CK techniques seen: " + ", ".join(techs))
    return "\n".join(lines)


def html_report(alerts: list[Alert], n_events: int) -> str:
    rows = []
    for a in alerts:
        ev = "<br>".join(html.escape(e) for e in a.evidence[:3])
        rows.append(
            f"<tr><td><span class='sev' style='background:{HTML_COLORS[a.severity]}'>{a.severity.upper()}</span></td>"
            f"<td>{html.escape(a.rule_id)}</td><td>{html.escape(a.title)}</td><td>{html.escape(a.group)}</td>"
            f"<td>{a.count}</td><td>{a.first_seen:%Y-%m-%d %H:%M:%S}</td>"
            f"<td>{html.escape(', '.join(a.attack))}</td><td class='ev'>{ev}</td></tr>"
        )
    sev = Counter(a.severity for a in alerts)
    cards = "".join(
        f"<div class='card' style='border-top:4px solid {HTML_COLORS[s]}'><b>{sev[s]}</b><span>{s}</span></div>"
        for s in ("critical", "high", "medium", "low")
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Sentinel Report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;background:#f6f7f9;color:#222}}
h1{{margin:0}}.sub{{color:#666;margin-bottom:1.5rem}}.cards{{display:flex;gap:1rem;margin-bottom:1.5rem}}
.card{{background:#fff;padding:1rem 1.5rem;border-radius:6px;display:flex;flex-direction:column;min-width:90px}}
.card b{{font-size:1.8rem}}table{{border-collapse:collapse;width:100%;background:#fff}}
th,td{{padding:.5rem .7rem;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top;font-size:.9rem}}
th{{background:#1f2937;color:#fff}}.sev{{color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700}}
.ev{{font-family:monospace;font-size:.75rem;color:#555;max-width:420px;word-break:break-all}}</style></head><body>
<h1>Sentinel Detection Report</h1>
<div class="sub">Generated {datetime.now():%Y-%m-%d %H:%M} &middot; {n_events} events analysed &middot; {len(alerts)} alerts</div>
<div class="cards">{cards}</div>
<table><tr><th>Severity</th><th>Rule</th><th>Detection</th><th>Source</th><th>Events</th><th>First seen</th>
<th>ATT&amp;CK</th><th>Evidence</th></tr>{''.join(rows) or '<tr><td colspan=8>No alerts.</td></tr>'}</table>
</body></html>"""


INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]


def block_suggestions(alerts: list[Alert], allow: set[str]) -> list[str]:
    """Suggest firewall rules for high+ severity sources. Suggestions only; review before running."""
    ips = []
    for a in alerts:
        if SEV_ORDER[a.severity] < SEV_ORDER["high"] or a.group in allow or a.group in ips:
            continue
        try:
            ip = ipaddress.ip_address(a.group)
        except ValueError:
            continue
        if any(ip in net for net in INTERNAL_NETS):
            continue
        ips.append(a.group)
    return [f"iptables -A INPUT -s {ip} -j DROP" for ip in ips]


# ----------------------------------------------------------------------------
# Demo data + self-test
# ----------------------------------------------------------------------------
def demo_logs() -> tuple[list[str], list[str]]:
    """Deterministic synthetic logs containing known attacks plus benign noise."""
    ssh, web = [], []
    n = [1000]

    def s(t: str, msg: str):
        n[0] += 7
        ssh.append(f"Oct  2 {t} srv01 sshd[{n[0]}]: {msg}")

    def w(t: str, ip: str, path: str, status: int = 200, ua: str = "Mozilla/5.0"):
        web.append(f'{ip} - - [02/Oct/2026:{t} +0000] "GET {path} HTTP/1.1" {status} 512 "-" "{ua}"')

    for i in range(30):  # benign
        s(f"09:{i:02d}:10", "Accepted publickey for alice from 10.0.0.5 port 50000 ssh2")
        w(f"09:{i:02d}:20", "10.0.0.8", "/index.html")
    s("09:40:00", "Failed password for alice from 10.0.0.5 port 50000 ssh2")  # a typo is not an attack
    for i in range(8):  # brute force, then success
        s(f"10:00:{i * 3:02d}", f"Failed password for admin from 203.0.113.7 port 4{i}00 ssh2")
    s("10:00:40", "Accepted password for admin from 203.0.113.7 port 4999 ssh2")
    for i, u in enumerate(["root", "test", "oracle", "ubuntu", "postgres", "git", "ftp"]):  # spray
        s(f"10:20:{i * 10:02d}", f"Invalid user {u} from 198.51.100.23 port 3{i}00")
    s("11:00:00", "Accepted publickey for root from 192.0.2.99 port 22022 ssh2")
    for i in range(25):  # scanner
        w(f"12:00:{i:02d}", "203.0.113.50", f"/admin{i}.php", 404, "gobuster/3.6")
    w("12:05:00", "198.51.100.77", "/item?id=1%20union%20select%20null,version()--")
    w("12:06:00", "198.51.100.78", "/download?f=../../etc/passwd", 403)
    w("12:07:00", "198.51.100.79", "/search?q=<script>alert(1)</script>")
    w("12:08:00", "198.51.100.80", "/x?c=%3bwhoami", 500)
    return ssh, web


def selftest() -> int:
    rules = get_rules()
    t0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)

    def ev(off, event, ip="1.2.3.4", user="bob"):
        return Event(t0 + timedelta(seconds=off), "ssh", {"event": event, "src_ip": ip, "user": user}, f"r{off}")

    def ids(alerts):
        return {a.rule_id for a in alerts}

    tests = {
        "brute force fires at threshold": lambda: "SSH-001" in ids(detect([ev(i, "failed_login") for i in range(5)], rules)),
        "no alert below threshold": lambda: "SSH-001" not in ids(detect([ev(i, "failed_login") for i in range(4)], rules)),
        "slow attempts outside window ignored": lambda: "SSH-001" not in ids(detect([ev(i * 30, "failed_login") for i in range(8)], rules)),
        "spray needs distinct users": lambda: "SSH-002" in ids(detect([ev(i, "invalid_user", user=f"u{i}") for i in range(6)], rules))
        and "SSH-002" not in ids(detect([ev(i, "invalid_user", user="root") for i in range(10)], rules)),
        "success after brute force is critical": lambda: any(
            a.rule_id == "SSH-003" and a.severity == "critical"
            for a in detect([ev(i, "failed_login") for i in range(5)] + [ev(60, "accepted_login")], rules)),
        "success without failures is quiet": lambda: "SSH-003" not in ids(detect([ev(0, "accepted_login")], rules)),
        "IPs are isolated": lambda: "SSH-001" not in ids(detect([ev(i, "failed_login", ip=f"9.9.9.{i}") for i in range(5)], rules)),
        "cooldown limits floods": lambda: len([a for a in detect([ev(i, "failed_login") for i in range(20)], rules) if a.rule_id == "SSH-001"]) <= 4,
        "allowlist suppresses alerts": lambda: not detect([ev(i, "failed_login") for i in range(9)], rules, allow=["1.2.3.4"]),
        "garbage lines ignored": lambda: list(parse_ssh(["junk", ""])) == [] and list(parse_web(["junk"])) == [],
        "rule validation rejects bad rules": lambda: _raises(lambda: validate_rule({"id": "x"})),
        "bad window rejected": lambda: _raises(lambda: parse_window("5 minutes")),
        "log type sniffing": lambda: sniff_type(demo_logs()[0][:5]) == "ssh" and sniff_type(demo_logs()[1][:5]) == "web",
    }

    def end_to_end():
        ssh, web = demo_logs()
        evs = list(parse_ssh(ssh, 2026)) + list(parse_web(web))
        alerts = detect(evs, rules)
        expect = {"SSH-001", "SSH-002", "SSH-003", "SSH-004", "WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-005", "WEB-006"}
        benign = [a for a in alerts if a.group in ("10.0.0.5", "10.0.0.8")]
        return ids(alerts) == expect and not benign

    tests["end-to-end: all attacks found, zero false positives"] = end_to_end

    failed = 0
    for name, fn in tests.items():
        try:
            ok = bool(fn())
        except Exception as e:  # noqa: BLE001
            ok, name = False, f"{name} ({e})"
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        failed += not ok
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    return 1 if failed else 0


def _raises(fn) -> bool:
    try:
        fn()
    except RuleError:
        return True
    return False


# ----------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------
def read_events(paths: list[str], log_type: str, year: int | None) -> list[Event]:
    events: list[Event] = []
    for path in paths:
        with open(path, errors="replace") as f:
            lines = f.readlines()
        kind = log_type if log_type != "auto" else sniff_type(lines[:50])
        if kind is None:
            print(f"warning: could not detect log type of {path}; use --type ssh|web", file=sys.stderr)
            continue
        events.extend(PARSERS[kind](lines, year))
    return events


def report(alerts, n_events, args, rules_allow) -> int:
    color = sys.stdout.isatty() and not getattr(args, "output", None)
    if args.format == "json":
        text = json.dumps([a.to_dict() for a in alerts], indent=2)
    elif args.format == "html":
        text = html_report(alerts, n_events)
    else:
        text = "\n".join(fmt_alert(a, color) for a in alerts) + summary_text(alerts, n_events)
    if args.output:
        Path(args.output).write_text(text)
        print(f"report written to {args.output} ({len(alerts)} alerts)", file=sys.stderr)
    else:
        print(text)
    if args.block:
        sugg = block_suggestions(alerts, rules_allow)
        print("\n# Suggested firewall rules (review before running):", file=sys.stderr)
        for s in sugg:
            print(s, file=sys.stderr)
    worst = max((SEV_ORDER[a.severity] for a in alerts), default=-1)
    return 1 if worst >= SEV_ORDER[args.fail_on] else 0


def cmd_scan(args) -> int:
    rules = get_rules(args.rules, args.disable)
    allow = set(filter(None, (args.allow or "").split(",")))
    if args.demo:
        ssh, web = demo_logs()
        events = list(parse_ssh(ssh, 2026)) + list(parse_web(web))
        print("(demo mode: synthetic logs with planted attacks)\n", file=sys.stderr)
    else:
        if not args.logs:
            print("error: give at least one log file, or use --demo", file=sys.stderr)
            return 2
        events = read_events(args.logs, args.type, args.year)
    alerts = detect(events, rules, args.min_severity, allow)
    return report(alerts, len(events), args, allow)


def cmd_follow(args) -> int:
    rules = get_rules(args.rules, args.disable)
    allow = set(filter(None, (args.allow or "").split(",")))
    with open(args.log, errors="replace") as f:
        first = f.readlines()[:50]
        kind = args.type if args.type != "auto" else sniff_type(first)
        if kind is None:
            print("could not detect log type; use --type", file=sys.stderr)
            return 2
        f.seek(0, 0 if args.from_start else 2)
        events: deque[Event] = deque()
        seen: set = set()
        print(f"Watching {args.log} as '{kind}' logs. Ctrl+C to stop.", file=sys.stderr)
        keep = timedelta(hours=1)
        try:
            while True:
                lines = f.readlines()
                if lines:
                    events.extend(PARSERS[kind](lines, args.year))
                    newest = max(e.ts for e in events) if events else None
                    while events and newest and newest - events[0].ts > keep:
                        events.popleft()
                    for a in detect(events, rules, args.min_severity, allow):
                        key = (a.rule_id, a.group, a.first_seen)
                        if key not in seen:
                            seen.add(key)
                            print(fmt_alert(a, sys.stdout.isatty()), flush=True)
                else:
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\nstopped.", file=sys.stderr)
    return 0


def cmd_rules(args) -> int:
    rules = get_rules(args.rules)
    for r in rules:
        print(f"{r['id']:8} [{r['severity']:8}] {r['title']}  ({', '.join(r['attack'])})")
    cov: dict[str, list[str]] = {}
    for r in rules:
        for t in r["attack"]:
            cov.setdefault(t, []).append(r["id"])
    print("\nMITRE ATT&CK coverage:")
    for t in sorted(cov):
        print(f"  {t:12} {', '.join(cov[t])}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Log-based threat detection engine",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Quick start:")[1])
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--demo", action="store_true", help="shortcut for: scan --demo")
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--type", choices=["auto", "ssh", "web"], default="auto", help="log type (default: auto-detect)")
        sp.add_argument("--rules", metavar="DIR", help="extra rule files (.json, or .yml with PyYAML)")
        sp.add_argument("--disable", nargs="*", default=[], metavar="ID", help="rule ids to turn off")
        sp.add_argument("--allow", metavar="IPS", help="comma-separated IPs to ignore (your own servers, scanners you run)")
        sp.add_argument("--min-severity", choices=list(SEV_ORDER), default="low")
        sp.add_argument("--year", type=int, help="year for syslog timestamps (default: inferred)")

    s = sub.add_parser("scan", help="analyse log files")
    s.add_argument("logs", nargs="*", help="log files (types auto-detected)")
    s.add_argument("--demo", action="store_true", help="run on built-in synthetic logs")
    s.add_argument("--format", choices=["table", "json", "html"], default="table")
    s.add_argument("-o", "--output", help="write report to a file")
    s.add_argument("--block", action="store_true", help="suggest firewall rules for high/critical sources")
    s.add_argument("--fail-on", choices=list(SEV_ORDER), default="critical", help="exit 1 if an alert this severe fires")
    common(s)
    s.set_defaults(fn=cmd_scan)

    f = sub.add_parser("follow", help="watch a log live (like tail -f) and alert as attacks happen")
    f.add_argument("log")
    f.add_argument("--from-start", action="store_true", help="process existing content first")
    common(f)
    f.set_defaults(fn=cmd_follow)

    r = sub.add_parser("rules", help="list detections and ATT&CK coverage")
    r.add_argument("--rules", metavar="DIR")
    r.set_defaults(fn=cmd_rules)

    t = sub.add_parser("selftest", help="run built-in tests")
    t.set_defaults(fn=lambda a: selftest())
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--demo":  # allow `sentinel.py --demo`
        argv = ["scan"] + argv
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 0
    try:
        return args.fn(args)
    except (RuleError, FileNotFoundError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:  # e.g. piping into `head`
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
