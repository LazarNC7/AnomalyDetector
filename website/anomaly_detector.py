"""
Are 4 combinatii train/test:

  1. Antreneaza pe CSV, testeaza pe CSV (split intern)
     python anomaly_detector.py --train-csv payload_train.csv --test-csv payload_test.csv

  2. Antreneaza pe CSV, testeaza pe LOG
     python anomaly_detector.py --train-csv payload_train.csv --test-log dataset_test.log

  3. Antreneaza pe LOG, testeaza pe LOG (split intern)
     python anomaly_detector.py --train-log dataset_train.log --test-log dataset_test.log

  4. Antreneaza pe LOG, testeaza pe CSV
     python anomaly_detector.py --train-log dataset_train.log --test-csv payload_test.csv

Optiuni aditionale:
  --output   PREFIX    prefix pentru fisierele de output (default: results)
  --no-plots           nu afisa grafice (doar salveaza)
"""

import re
import pickle
import argparse
import urllib.parse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    ConfusionMatrixDisplay, roc_curve, auc
)
import warnings
warnings.filterwarnings("ignore")


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
ZAP_IP  = "172.18.0.3"

LOG_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
    r' - [^\[]*\[[^\]]+\]'
    r' "(?P<request>[^"]*)"'
    r' (?P<status>\d{3})'
    r' \d+'
    r' "[^"]*"'
    r' "(?P<ua>[^"]*)"'
    r' [\d.]+'
    r' "(?P<args>[^"]*)"'
)

FEATURE_COLS = [
    "length", "has_sqli", "has_xss", "has_path_traversal", "has_cmdi",
    "special_char_count", "digit_ratio", "upper_ratio", "space_count",
    "entropy", "token_count", "has_encoding"
]

ATTACK_ORDER  = ["norm", "sqli", "xss", "path-traversal", "cmdi", "recon"]
PALETTE = {
    "norm":           "#4CAF50",
    "sqli":           "#F44336",
    "xss":            "#FF9800",
    "path-traversal": "#9C27B0",
    "cmdi":           "#2196F3",
    "recon":          "#795548",
}


def _entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    t = len(s)
    return -sum((v / t) * np.log2(v / t) for v in c.values())


def extract_features(payloads, lengths):
    records = []
    for payload, length in zip(payloads, lengths):
        s = str(payload)
        records.append({
            "length":             float(length),
            "has_sqli":           int(bool(SQLI.search(s))),
            "has_xss":            int(bool(XSS.search(s))),
            "has_path_traversal": int(bool(PATH_TRAVERSAL.search(s))),
            "has_cmdi":           int(bool(CMDI.search(s))),
            "special_char_count": len(SPECIAL.findall(s)),
            "digit_ratio":        sum(c.isdigit() for c in s) / max(len(s), 1),
            "upper_ratio":        sum(c.isupper() for c in s) / max(len(s), 1),
            "space_count":        s.count(" "),
            "entropy":            _entropy(s),
            "token_count":        len(s.split()),
            "has_encoding":       int(bool(re.search(r"%[0-9a-fA-F]{2}", s))),
        })
    return pd.DataFrame(records)[FEATURE_COLS]



def load_csv(path):
    """Incarca http_params.csv → DataFrame cu coloanele: payload, length, attack_type, label"""
    df = pd.read_csv(path)
    df.columns = [c.strip().strip('"') for c in df.columns]
    df["payload"]     = df["payload"].astype(str).str.strip('"')
    df["length"]      = pd.to_numeric(df["length"], errors="coerce").fillna(0)
    df["attack_type"] = df["attack_type"].astype(str).str.strip('"').str.strip()
    df["label"]       = df["label"].astype(str).str.strip('"').str.strip()
    return df


def _ground_truth_from_log(ip, path, query, ua):
    target  = f"{path}?{query}" if query and query not in ("-", "") else path
    decoded = urllib.parse.unquote(target)
    if SQLI.search(decoded):           return "anom", "sqli"
    if XSS.search(decoded):            return "anom", "xss"
    if PATH_TRAVERSAL.search(decoded): return "anom", "path-traversal"
    if CMDI.search(decoded):           return "anom", "cmdi"
    if ip == ZAP_IP or RECON.search(decoded): return "anom", "recon"
    return "norm", "norm"


def load_log(path):
    """Incarca dataset_raw.log → DataFrame cu coloanele: payload, length, attack_type, label"""
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LOG_RE.search(line)
            if not m:
                continue
            ip      = m.group("ip")
            request = m.group("request")
            ua      = m.group("ua")
            query   = m.group("args")

            parts = request.split(" ")
            if len(parts) < 2:
                continue
            full_path = parts[1]
            path_only, qs = (full_path.split("?", 1)
                             if "?" in full_path else (full_path, ""))

            payload = urllib.parse.unquote(qs if qs and qs not in ("-", "") else path_only)
            label, attack_type = _ground_truth_from_log(ip, path_only, qs, ua)

            rows.append({
                "payload":     payload,
                "length":      len(payload),
                "attack_type": attack_type,
                "label":       label,
            })
    return pd.DataFrame(rows)


def load_source(csv_path=None, log_path=None, label=""):
    """Incarca din CSV sau LOG si afiseaza statistici."""
    if csv_path:
        print(f"[+] Incarcare {label} din CSV: {csv_path}")
        df = load_csv(csv_path)
    else:
        print(f"[+] Incarcare {label} din LOG: {log_path}")
        df = load_log(log_path)

    print(f"    {len(df)} randuri")
    print(f"    Labels:  {df['label'].value_counts().to_dict()}")
    print(f"    Attacks: {df['attack_type'].value_counts().to_dict()}")
    return df



def train_models(df_train):
    """Antreneaza Isolation Forest + Random Forest pe df_train."""
    X = extract_features(df_train["payload"], df_train["length"]).values
    y_binary = (df_train["label"] == "anom").astype(int).values

    le = LabelEncoder()
    le.fit(df_train["attack_type"])
    y_multi = le.transform(df_train["attack_type"])

    # Isolation Forest
    cont = float(np.clip(y_binary.mean(), 0.01, 0.49))
    iso  = IsolationForest(n_estimators=200, contamination=cont,
                           random_state=42, n_jobs=-1)
    iso.fit(X)

    # Random Forest
    rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    rf.fit(X, y_multi)

    return iso, rf, le



def evaluate(iso, rf, le, df_test, output_prefix, no_plots=False):
    """Evalueaza modelele pe df_test si salveaza rezultate."""
    X        = extract_features(df_test["payload"], df_test["length"]).values
    y_binary = (df_test["label"] == "anom").astype(int).values

    # Isolation Forest predictions
    iso_pred  = (iso.predict(X) == -1).astype(int)
    iso_score = -iso.score_samples(X)

    # Random Forest predictions — mapam clasele necunoscute la "norm"
    known = set(le.classes_)
    df_test = df_test.copy()
    df_test["attack_mapped"] = df_test["attack_type"].apply(
        lambda x: x if x in known else "norm"
    )
    y_multi  = le.transform(df_test["attack_mapped"])
    rf_raw   = rf.predict(X)
    rf_pred  = rf_raw  # encoded

    df_test["iso_predicted"] = iso_pred
    df_test["iso_score"]     = iso_score
    df_test["rf_predicted"]  = le.inverse_transform(rf_pred)

    # Print reports
    print("\n" + "="*55)
    print("ISOLATION FOREST — binar (norm vs anom)")
    print("="*55)
    print(classification_report(y_multi, rf_pred,
                                  labels=range(len(le.classes_)),
                                  target_names=le.classes_,
                                  zero_division=0))

    print("="*55)
    print("RANDOM FOREST — multiclass (attack type)")
    print("="*55)
    print(classification_report(y_multi, rf_pred,
                                  labels=range(len(le.classes_)),
                                  target_names=le.classes_,
                                  zero_division=0))

    # Save CSV
    out_csv = f"{output_prefix}_predictions.csv"
    df_test.to_csv(out_csv, index=False)
    print(f"\n[+] Predictii salvate → {out_csv}")

    # Plots
    _plot(df_test, y_binary, iso_pred, iso_score,
          y_multi, rf_pred, le, output_prefix, no_plots)

    return df_test



def _plot(df, yb_true, iso_pred, iso_score, ym_true, rf_pred, le,
          prefix, no_plots):
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle(f"Results — {prefix}", fontsize=14)

    # Confusion matrix ISO
    cm1 = confusion_matrix(yb_true, iso_pred)
    ConfusionMatrixDisplay(cm1, display_labels=["Normal", "Anomaly"]).plot(
        ax=axes[0][0], colorbar=False)
    axes[0][0].set_title("Isolation Forest — binar")

    # Confusion matrix RF
    cm2 = confusion_matrix(ym_true, rf_pred, labels=range(len(le.classes_)))
    ConfusionMatrixDisplay(cm2, display_labels=le.classes_).plot(
        ax=axes[0][1], colorbar=False)
    axes[0][1].set_title("Random Forest — multiclass")
    axes[0][1].tick_params(axis="x", rotation=30)

    # ROC
    if len(np.unique(yb_true)) > 1:
        fpr, tpr, _ = roc_curve(yb_true, iso_score)
        roc_auc = auc(fpr, tpr)
        axes[0][2].plot(fpr, tpr, color="#1565C0", lw=2,
                        label=f"AUC = {roc_auc:.3f}")
        axes[0][2].plot([0, 1], [0, 1], "k--", lw=1)
        axes[0][2].set_xlabel("False positive rate")
        axes[0][2].set_ylabel("True positive rate")
        axes[0][2].set_title("ROC — Isolation Forest")
        axes[0][2].legend()
    else:
        axes[0][2].text(0.5, 0.5, "O singura clasa\nin test set",
                        ha="center", va="center", fontsize=12)
        axes[0][2].set_title("ROC — N/A")

    # Score distribution
    present = [a for a in ATTACK_ORDER if a in df["attack_type"].values]
    for label in present:
        subset = df[df["attack_type"] == label]["iso_score"]
        axes[1][0].hist(subset, bins=30, alpha=0.6,
                        label=label, color=PALETTE.get(label, "gray"))
    axes[1][0].set_xlabel("Anomaly score")
    axes[1][0].set_ylabel("Count")
    axes[1][0].set_title("Distributie score per attack type")
    axes[1][0].legend(fontsize=8)

    # Detection rate per attack type
    det = df.groupby("attack_type")["iso_predicted"].mean()
    det = det.reindex(present).dropna()
    if not det.empty:
        bars = axes[1][1].bar(det.index, det.values * 100,
                               color=[PALETTE.get(k, "gray") for k in det.index])
        axes[1][1].set_ylabel("% detectat ca anomalie")
        axes[1][1].set_title("Rata detectie ISO per attack type")
        axes[1][1].set_ylim(0, 115)
        for bar, val in zip(bars, det.values):
            axes[1][1].text(bar.get_x() + bar.get_width() / 2,
                            bar.get_height() + 2,
                            f"{val*100:.1f}%", ha="center", fontsize=9)

    # Compozitie
    counts = df["attack_type"].value_counts().reindex(present).dropna()
    axes[1][2].pie(counts.values,
                   labels=counts.index,
                   colors=[PALETTE.get(k, "gray") for k in counts.index],
                   autopct="%1.1f%%", startangle=90)
    axes[1][2].set_title("Compozitie dataset testat")

    plt.tight_layout()
    out_png = f"{prefix}_results.png"
    plt.savefig(out_png, dpi=150, bbox_inches="tight")
    print(f"[+] Graf salvat → {out_png}")
    if not no_plots:
        plt.show()
    plt.close()



def main():
    parser = argparse.ArgumentParser(
        description="Anomaly detector flexibil — train/test pe CSV sau LOG",
        formatter_class=argparse.RawTextHelpFormatter,
        
    )
    parser.add_argument("--train-csv", help="Antreneaza pe CSV (http_params.csv)")
    parser.add_argument("--train-log", help="Antreneaza pe LOG (dataset_raw.log)")
    parser.add_argument("--test-csv",  help="Testeaza pe CSV")
    parser.add_argument("--test-log",  help="Testeaza pe LOG")
    parser.add_argument("--output",    default="results", help="Prefix output (default: results)")
    parser.add_argument("--no-plots",  action="store_true", help="Nu afisa grafice")
    args = parser.parse_args()

    # Validare argumente
    if not args.train_csv and not args.train_log:
        parser.error("Trebuie specificat --train-csv SAU --train-log")
    if args.train_csv and args.train_log:
        parser.error("Specifica doar unul: --train-csv SAU --train-log")
    if not args.test_csv and not args.test_log:
        parser.error("Trebuie specificat --test-csv SAU --test-log")
    if args.test_csv and args.test_log:
        parser.error("Specifica doar unul: --test-csv SAU --test-log")

    # Detectie combinatie
    train_src = "csv" if args.train_csv else "log"
    test_src  = "csv" if args.test_csv  else "log"
    same_source = (args.train_csv and args.test_csv and args.train_csv == args.test_csv) or \
                  (args.train_log and args.test_log and args.train_log == args.test_log)

    print(f"\n{'='*55}")
    print(f"  Mod: train={train_src.upper()} | test={test_src.upper()}")
    if same_source:
        print(f"  (Acelasi fisier → split 80/20 automat)")
    print(f"{'='*55}\n")

    # Incarcare date
    df_train_full = load_source(args.train_csv, args.train_log, "TRAIN")

    if same_source:
        # Split intern 80/20 stratificat
        df_train, df_test = train_test_split(
            df_train_full, test_size=0.2,
            random_state=42,
            stratify=df_train_full["label"]
        )
        print(f"\n    Split: {len(df_train)} train | {len(df_test)} test")
    else:
        df_test = load_source(args.test_csv, args.test_log, "TEST")
        df_train = df_train_full

    # Antrenare
    print("\n[+] Antrenare modele ...")
    iso, rf, le = train_models(df_train)
    print(f"    Isolation Forest: contamination={iso.contamination:.3f}")
    print(f"    Random Forest: clase={list(le.classes_)}")

    # Salvare modele
    with open(f"{args.output}_iso.pkl", "wb") as f: pickle.dump(iso, f)
    with open(f"{args.output}_rf.pkl",  "wb") as f: pickle.dump(rf, f)
    with open(f"{args.output}_le.pkl",  "wb") as f: pickle.dump(le, f)
    print(f"[+] Modele salvate cu prefix '{args.output}'")

    # Evaluare
    print("\n[+] Evaluare pe test set ...")
    evaluate(iso, rf, le, df_test, args.output, args.no_plots)

    print("\n[+] Gata!")


if __name__ == "__main__":
    main()