"""
realtime_detector.py — Real-time HTTP Log Anomaly Detector

Folosire:
    # Varianta 1 — tail direct pe fisier local
    python realtime_detector.py --log dataset_raw.log --model exp5a_tuned

    # Varianta 2 — tail pe containerul Docker
    python realtime_detector.py --docker website-web-server-1 --model exp5a_tuned

    # Varianta 3 — simuleaza real-time pe un log existent (pentru testare)
    python realtime_detector.py --log dataset_test_v2.log --model exp5a_tuned --simulate

Optiuni:
    --model     PREFIX    prefix model (ex: exp5a_tuned → cauta exp5a_tuned_iso.pkl etc.)
    --window    SECUNDE   dimensiunea ferestrei sliding window per IP (default: 60)
    --threshold FLOAT     threshold manual pentru ISO (default: din model)
    --output    FILE      salveaza alertele intr-un fisier JSON
    --no-color            dezactiveaza culorile ANSI
    --simulate            ruleaza pe fisier existent cu delay simulat
"""

import re
import sys
import time
import json
import pickle
import argparse
import subprocess
import urllib.parse
from collections import deque, Counter
from datetime import datetime
import numpy as np



# Regex patterns (identice cu cele din training) 
SQLI = re.compile(
    r"('|%27|--|union[\s+]select|select[\s+].*from|insert[\s+]into|"
    r"drop[\s+]table|or[\s+]1=1|and[\s+]1=1|sleep\s*\(|benchmark\s*\(|"
    r"waitfor[\s+]delay|xp_cmdshell|information_schema|pg_sleep|"
    r"dbms_lock|dbms_pipe|utl_inaddr|rdb\$|order[\s+]by[\s+]\d)",
    re.IGNORECASE
)
XSS = re.compile(
    r"(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|"
    r"alert\s*\(|prompt\s*\(|confirm\s*\(|<img|<svg|<iframe|"
    r"document\.cookie|document\.write|\.innerHTML|eval\s*\()",
    re.IGNORECASE
)
PATH_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|/proc/self|"
    r"/windows/win\.ini|WEB-INF|web\.xml|%252e)",
    re.IGNORECASE
)
CMDI = re.compile(
    r"(allow_url_include|auto_prepend_file|php://input|phpinfo\s*\(|"
    r"/bin/sh|/bin/bash|cmd\.exe|\$\(|`[^`]+`|wget[\s+]|curl[\s+]|"
    r";[\s]*\w|\|[\s]*\w)",
    re.IGNORECASE
)
RECON = re.compile(
    r"(robots\.txt|sitemap\.xml|\.env|\.git|\.htaccess|wp-admin|"
    r"phpmyadmin|swagger|api-docs|actuator|/latest/meta-data|"
    r"computeMetadata|winscp\.ini|ws_ftp\.ini|\.bak|\.sql|WEB-INF|"
    r"web\.xml|vim_settings|vb_test\.php)",
    re.IGNORECASE
)
SPECIAL = re.compile(r"[<>\"'%;)(\/\\=\-\+\|`\$]")

LOG_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
    r' - [^\[]*\[(?P<time>[^\]]+)\]'
    r' "(?P<request>[^"]*)"'
    r' (?P<status>\d{3})'
    r' (?P<bytes>\d+)'
    r' "[^"]*"'
    r' "(?P<ua>[^"]*)"'
    r' (?P<rt>[\d.]+)'
    r' "(?P<args>[^"]*)"'
)

FEATURE_COLS = [
    "length", "has_sqli", "has_xss", "has_path_traversal", "has_cmdi",
    "special_char_count", "digit_ratio", "upper_ratio", "space_count",
    "entropy", "token_count", "has_encoding"
]




# Feature extraction 

def _entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    t = len(s)
    return -sum((v / t) * np.log2(v / t) for v in c.values())


def extract_features(payload: str) -> np.ndarray:
    s = str(payload)
    return np.array([[
        float(len(s)),
        int(bool(SQLI.search(s))),
        int(bool(XSS.search(s))),
        int(bool(PATH_TRAVERSAL.search(s))),
        int(bool(CMDI.search(s))),
        len(SPECIAL.findall(s)),
        sum(c.isdigit() for c in s) / max(len(s), 1),
        sum(c.isupper() for c in s) / max(len(s), 1),
        s.count(" "),
        _entropy(s),
        len(s.split()),
        int(bool(re.search(r"%[0-9a-fA-F]{2}", s))),
    ]])


def rule_based_label(payload: str, ip: str = "") -> tuple:
    """Clasificare rapida bazata pe regex (fara model ML)."""
    decoded = urllib.parse.unquote(payload)
    if SQLI.search(decoded):           return "anom", "sqli"
    if XSS.search(decoded):            return "anom", "xss"
    if PATH_TRAVERSAL.search(decoded): return "anom", "path-traversal"
    if CMDI.search(decoded):           return "anom", "cmdi"
    if RECON.search(decoded):          return "anom", "recon"
    return "norm", "norm"


#  Sliding Window per IP 

class IPWindow:
    """Fereastra temporala pentru un IP — ultimele WINDOW_SEC secunde."""

    def __init__(self, window_sec: int = 60):
        self.window_sec   = window_sec
        self.requests     = deque()   # (timestamp, status, path, is_anomaly)
        self.alert_count  = 0

    def add(self, ts: float, status: int, path: str, is_anomaly: bool):
        self.requests.append((ts, status, path, is_anomaly))
        self._evict(ts)

    def _evict(self, now: float):
        while self.requests and now - self.requests[0][0] > self.window_sec:
            self.requests.popleft()

    def stats(self, now: float) -> dict:
        self._evict(now)
        if not self.requests:
            return {}
        statuses  = [r[1] for r in self.requests]
        paths     = [r[2] for r in self.requests]
        anomalies = sum(1 for r in self.requests if r[3])
        return {
            "req_count":       len(self.requests),
            "req_per_min":     len(self.requests) * (60 / self.window_sec),
            "error_ratio":     sum(1 for s in statuses if s >= 400) / len(statuses),
            "unique_paths":    len(set(paths)),
            "anomaly_ratio":   anomalies / len(self.requests),
            "anomaly_count":   anomalies,
        }

    def is_suspicious(self, now: float) -> bool:
        s = self.stats(now)
        if not s:
            return False
        # Reguli comportamentale — semne de scan/brute-force
        if s["req_per_min"] > 60:    return True   # mai mult de 1 req/sec
        if s["error_ratio"]  > 0.5:  return True   # >50% erori
        if s["unique_paths"] > 20:   return True   # path scanning
        if s["anomaly_ratio"] > 0.3: return True   # >30% anomalii
        return False


#  Log parser 

def parse_line(line: str) -> dict | None:
    m = LOG_RE.search(line)
    if not m:
        return None

    ip      = m.group("ip")
    request = m.group("request")
    status  = int(m.group("status"))
    ua      = m.group("ua")
    args    = m.group("args")
    rt      = float(m.group("rt"))

    # Parse timestamp
    try:
        ts_str = m.group("time")
        ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except Exception:
        ts = time.time()

    parts = request.split(" ")
    if len(parts) < 2:
        return None
    method    = parts[0]
    full_path = parts[1]

    if "?" in full_path:
        path, qs = full_path.split("?", 1)
    else:
        path, qs = full_path, ""

    payload = urllib.parse.unquote(qs if qs and qs not in ("-", "") else path)

    return {
        "ip":      ip,
        "ts":      ts,
        "method":  method,
        "path":    path,
        "payload": payload,
        "status":  status,
        "bytes":   int(m.group("bytes")),
        "ua":      ua,
        "rt":      rt,
    }


#  Detector 

class RealTimeDetector:
    def __init__(self, model_prefix: str, window_sec: int = 60,
                 manual_threshold: float = None):
        self.window_sec = window_sec
        self.windows    = {}   # ip -> IPWindow
        self.alert_log  = []
        self.stats      = {"total": 0, "anomalies": 0, "by_type": Counter()}
        
        # Initializarea atributelor cu None pentru a evita AttributeErrors
        self.iso = None
        self.rf  = None
        self.le  = None

        print(f"[+] Incarcare modele din '{model_prefix}_*' ...")
        
        try:
            with open(f"{model_prefix}_iso.pkl", "rb") as f:
                self.iso = pickle.load(f)
            with open(f"{model_prefix}_rf.pkl",  "rb") as f:
                self.rf  = pickle.load(f)
            with open(f"{model_prefix}_le.pkl",  "rb") as f:
                self.le = pickle.load(f)
        except FileNotFoundError as e:
            print(f"[!] EROARE: Nu am gasit fisierul model: {e.filename}")
            sys.exit(1) # Script-ul se opreste daca nu gaseste modelele necesare

        # Threshold logic
        if manual_threshold is not None:
            self.threshold = manual_threshold
            print(f"    Threshold manual: {self.threshold:.4f}")
        elif self.iso is not None:
            self.threshold = None
            # Acceseaza .contamination daca self.iso are acest atribut, altfel afiseaza 'N/A'
            contam = getattr(self.iso, 'contamination', 'N/A')
            print(f"    Threshold: auto (contamination={contam})")

        print(f"    Window size: {window_sec}s per IP")
        print()

    def _get_window(self, ip: str) -> IPWindow:
        if ip not in self.windows:
            self.windows[ip] = IPWindow(self.window_sec)
        return self.windows[ip]

    def process(self, parsed: dict) -> dict | None:
        """Proceseaza un request si returneaza alerta daca e anomalie."""
        self.stats["total"] += 1

        ip      = parsed["ip"]
        payload = parsed["payload"]
        ts      = parsed["ts"]
        status  = parsed["status"]

        # Features textuale
        X = extract_features(payload)

        # Scor ISO
        iso_score = float(-self.iso.score_samples(X)[0])

        # Decizie threshold
        if self.threshold is not None:
            is_anomaly_iso = iso_score >= self.threshold
        else:
            is_anomaly_iso = self.iso.predict(X)[0] == -1

        # Clasificare RF (attack type)
        attack_type = "norm"
        if self.le is not None:
            rf_pred_enc = self.rf.predict(X)[0]
            attack_type = self.le.inverse_transform([rf_pred_enc])[0]

        # Reguli comportamentale (fallback pentru recon)
        rule_label, rule_type = rule_based_label(payload, ip)
        if rule_label == "anom" and attack_type == "norm":
            attack_type = rule_type

        is_anomaly = is_anomaly_iso or (rule_label == "anom")

        # Update sliding window
        window = self._get_window(ip)
        window.add(ts, status, parsed["path"], is_anomaly)
        win_stats     = window.stats(ts)
        win_suspicious = window.is_suspicious(ts)

        if is_anomaly:
            self.stats["anomalies"] += 1
            self.stats["by_type"][attack_type] += 1

            alert = {
                "ts":           datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                "ip":           ip,
                "method":       parsed["method"],
                "path":         parsed["path"],
                "payload":      payload[:120],
                "status":       status,
                "iso_score":    round(iso_score, 4),
                "attack_type":  attack_type,
                "win_req_min":  round(win_stats.get("req_per_min", 0), 1),
                "win_anomalies":win_stats.get("anomaly_count", 0),
                "win_suspicious": win_suspicious,
            }
            self.alert_log.append(alert)
            return alert

        # Log request normal (verbose mode ar putea afisa si astea)
        return None


#  Display 

def print_alert(alert: dict):
    atype = alert["attack_type"]
    
    
    ts_str = alert['ts']
    ip_str = f"{alert['ip']:>15}"
    type_str = f"[{atype.upper():>14}]"
    method_str = f"{alert['method']:>4}"
    score_str = f"score={alert['iso_score']:.3f}"

    win_warn = ""
    if alert["win_suspicious"]:
        win_warn = f" [SCAN: {alert['win_req_min']:.0f}req/min, {alert['win_anomalies']} anomalii]"

    print(f"{ts_str} {ip_str} {type_str} {method_str} {alert['path'][:40]:40} {score_str}{win_warn}")
    
    if alert["payload"] and alert["payload"] != alert["path"]:
        payload_prefix = ' ' * 15
        print(f"  {payload_prefix}  payload: {alert['payload'][:80]}")


def print_stats(detector: RealTimeDetector):
    t = detector.stats["total"]
    a = detector.stats["anomalies"]
    rate = (a / t * 100) if t > 0 else 0
    print(f"\n{''*70}")
    print(f"  Total: {t} requesturi | Anomalii: {str(a)} ({rate:.1f}%)")
    for atype, count in detector.stats["by_type"].most_common():
        
        print(f"  {f'{atype:>16}'}: {count}")
    active_ips = sum(1 for w in detector.windows.values()
                     if len(w.requests) > 0)
    suspicious = sum(1 for ip, w in detector.windows.items()
                     if w.is_suspicious(time.time()))
    print(f"  IP-uri active: {active_ips} | Suspecte: {str(suspicious)}")
    print(''*70)


#  Log sources 

def tail_file(path: str):
    """Generator — yield linii noi din fisier (tail -f)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)   # go to end
        while True:
            line = f.readline()
            if line:
                yield line.rstrip()
            else:
                time.sleep(0.05)


def tail_docker(container: str):
    """Generator — yield linii noi din docker logs --follow."""
    proc = subprocess.Popen(
        ["docker", "logs", "--follow", "--tail", "0", container],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        for line in proc.stdout:
            yield line.rstrip()
    except KeyboardInterrupt:
        proc.terminate()


def simulate_file(path: str, delay: float = 0.01):
    """Generator — legeste fisier existent cu delay simulat (pentru testare)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip()
            time.sleep(delay)


#  Main 

def main():
    global USE_COLOR

    parser = argparse.ArgumentParser(
        description="Real-time HTTP Log Anomaly Detector",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Exemple:
  python realtime_detector.py --log /path/to/access.log --model exp5a_tuned
  python realtime_detector.py --docker website-web-server-1 --model exp5a_tuned
  python realtime_detector.py --log dataset_test_v2.log --model exp5a_tuned --simulate
        """
    )
    parser.add_argument("--log",       help="Calea catre fisierul de log nginx")
    parser.add_argument("--docker",    help="Numele containerului Docker (foloseste docker logs --follow)")
    parser.add_argument("--model",     default="exp5a_tuned", help="Prefix model (default: exp5a_tuned)")
    parser.add_argument("--window",    type=int,   default=60,   help="Sliding window in secunde (default: 60)")
    parser.add_argument("--threshold", type=float, default=None, help="Threshold manual ISO (default: auto)")
    parser.add_argument("--output",    help="Fisier JSON pentru salvarea alertelor")
    parser.add_argument("--simulate",  action="store_true", help="Simuleaza real-time pe fisier existent")
    parser.add_argument("--delay",     type=float, default=0.005, help="Delay intre linii in modul simulate (default: 0.005s)")
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False

    if not args.log and not args.docker:
        parser.error("Trebuie specificat --log sau --docker")

    

    #  Init detector 
    detector = RealTimeDetector(
        model_prefix=args.model,
        window_sec=args.window,
        manual_threshold=args.threshold,
    )

    #  Header coloane 
    print(f"{'TIME':>8}  {'IP':>15}  {'TYPE':>16}  {'METHOD':>6}  {'PATH':40}  SCORE")
    print("" * 110)

    #  Source 
    if args.docker:
        source = tail_docker(args.docker)
        print(f"[*] Ascult pe containerul Docker: {args.docker}")
    elif args.simulate:
        source = simulate_file(args.log, delay=args.delay)
        print(f"[*] Simulare pe fisier: {args.log} (delay={args.delay}s/linie)")
    else:
        source = tail_file(args.log)
        print(f"[*] Tail pe fisier: {args.log}")

    print("[*] Ctrl+C pentru oprire\n")

    #  Main loop 
    last_stats = time.time()
    try:
        for line in source:
            parsed = parse_line(line)
            if parsed:
                print(f"DEBUG: IP={parsed['ip']} | Payload={parsed['payload']}")
            if not parsed:
                continue

            alert = detector.process(parsed)
            if alert:
                print_alert(alert)

            # Afiseaza statistici la fiecare 30 secunde
            if time.time() - last_stats > 30:
                print_stats(detector)
                last_stats = time.time()

    except KeyboardInterrupt:
        pass

    #  Final stats 
    print_stats(detector)

    if args.output and detector.alert_log:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(detector.alert_log, f, indent=2, ensure_ascii=False)
        print(f"\n[+] {len(detector.alert_log)} alerte salvate → {args.output}")

    print("\n[*] Detector oprit.")


if __name__ == "__main__":
    main()