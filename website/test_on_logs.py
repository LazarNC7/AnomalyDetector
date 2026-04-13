"""
    python test_on_logs.py --log dataset_raw.log
"""

import re
import pickle
import argparse
import urllib.parse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import (
    classification_report, confusion_matrix,
    ConfusionMatrixDisplay, roc_curve, auc
)

#  Acelasi regex de features ca in train_model.py 

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
SPECIAL = re.compile(r"[<>\"'%;)(\/\\=\-\+\|`\$]")

RECON = re.compile(
    r"(robots\.txt|sitemap\.xml|\.env|\.git|\.htaccess|wp-admin|"
    r"phpmyadmin|swagger|api-docs|actuator|/latest/meta-data|"
    r"computeMetadata|winscp\.ini|ws_ftp\.ini|\.bak|\.sql|WEB-INF|"
    r"web\.xml|vim_settings|vb_test\.php)",
    re.IGNORECASE
)

ZAP_IP = "172.18.0.3"

LOG_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
    r' - [^\[]*'
    r'\[(?P<time>[^\]]+)\]'
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


def _entropy(s):
    if not s:
        return 0.0
    from collections import Counter
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
    return pd.DataFrame(records)


def ground_truth(ip, path, query, ua):
    """Eticheta reala bazata pe reguli — pentru evaluare."""
    target = f"{path}?{query}" if query and query not in ("-", "") else path
    decoded = urllib.parse.unquote(target)

    if SQLI.search(decoded):
        return "anom", "sqli"
    if XSS.search(decoded):
        return "anom", "xss"
    if PATH_TRAVERSAL.search(decoded):
        return "anom", "path-traversal"
    if CMDI.search(decoded):
        return "anom", "cmdi"
    if ip == ZAP_IP or RECON.search(decoded):
        return "anom", "recon"
    return "norm", "norm"


def parse_log(log_path):
    """Parseaza log-ul si extrage payload-uri."""
    rows = []
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LOG_RE.search(line)
            if not m:
                continue
            ip      = m.group("ip")
            request = m.group("request")
            status  = m.group("status")
            ua      = m.group("ua")
            args    = m.group("args")

            parts = request.split(" ")
            if len(parts) < 2:
                continue
            full_path = parts[1]
            if "?" in full_path:
                path, query = full_path.split("?", 1)
            else:
                path, query = full_path, ""

            # Payload = query string sau path-ul complet daca nu e query
            payload = query if query and query not in ("-", "") else path
            # Decodare URL pentru detectie mai buna
            payload_decoded = urllib.parse.unquote(payload)

            true_label, true_attack = ground_truth(ip, path, query, ua)

            rows.append({
                "ip":           ip,
                "path":         path,
                "payload":      payload_decoded,
                "length":       len(payload_decoded),
                "status":       status,
                "true_label":   true_label,
                "true_attack":  true_attack,
            })

    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="dataset_raw.log")
    args = parser.parse_args()

    # Incarcare modele 
    print("[+] Incarcare modele ...")
    with open("model_iso.pkl", "rb") as f:
        iso = pickle.load(f)
    with open("model_rf.pkl", "rb") as f:
        rf = pickle.load(f)
    with open("label_encoder.pkl", "rb") as f:
        le = pickle.load(f)

    # Parsare log 
    print(f"[+] Parsare {args.log} ...")
    df = parse_log(args.log)
    print(f"    {len(df)} requesturi parsate")
    print(f"    Ground truth: {df['true_label'].value_counts().to_dict()}")
    print(f"    Attack types: {df['true_attack'].value_counts().to_dict()}")

    # Features + predictii 
    print("[+] Extragere features si predictii ...")
    X = extract_features(df["payload"], df["length"])[FEATURE_COLS].values

    # Isolation Forest
    iso_raw   = iso.predict(X)
    iso_pred  = (iso_raw == -1).astype(int)
    iso_score = -iso.score_samples(X)

    # Random Forest
    rf_pred_encoded = rf.predict(X)
    rf_pred_labels  = le.inverse_transform(rf_pred_encoded)

    df["iso_predicted"]  = iso_pred
    df["iso_score"]      = iso_score
    df["rf_predicted"]   = rf_pred_labels

    # Evaluare 
    y_true_binary = (df["true_label"] == "anom").astype(int).values

    print("\n" + "="*55)
    print("ISOLATION FOREST — binar (norm vs anom)")
    print("="*55)
    print(classification_report(y_true_binary, iso_pred,
                                  target_names=["normal", "anomaly"]))

    # Pentru RF, mapam true_attack la ce stie modelul
    known_classes = set(le.classes_)
    df["true_attack_mapped"] = df["true_attack"].apply(
        lambda x: x if x in known_classes else "norm"
    )
    y_true_multi  = le.transform(df["true_attack_mapped"])
    rf_pred_enc2  = le.transform(
        pd.Series(rf_pred_labels).apply(
            lambda x: x if x in known_classes else "norm"
        )
    )

    print("\n" + "="*55)
    print("RANDOM FOREST — multiclass (attack type)")
    print("="*55)
    print(classification_report(y_true_multi, rf_pred_enc2,
                                  target_names=le.classes_))

    # Salvare predictii 
    df.to_csv("predictions.csv", index=False)
    print("\n[+] Predictii salvate → predictions.csv")

    # Grafice 
    print("[+] Generare grafice ...")
    _plot_results(df, y_true_binary, iso_pred, iso_score,
                  y_true_multi, rf_pred_enc2, le)


def _plot_results(df, yb_true, iso_pred, iso_score,
                  ym_true, rf_pred_enc, le):
    palette = {
        "norm":           "#4CAF50",
        "sqli":           "#F44336",
        "xss":            "#FF9800",
        "path-traversal": "#9C27B0",
        "cmdi":           "#2196F3",
        "recon":          "#795548",
    }

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle("Test Results — dataset_raw.log", fontsize=14)

    # Confusion matrix ISO
    cm1 = confusion_matrix(yb_true, iso_pred)
    ConfusionMatrixDisplay(cm1, display_labels=["Normal", "Anomaly"]).plot(
        ax=axes[0][0], colorbar=False)
    axes[0][0].set_title("Isolation Forest — binar")

    # Confusion matrix RF
    cm2 = confusion_matrix(ym_true, rf_pred_enc)
    ConfusionMatrixDisplay(cm2, display_labels=le.classes_).plot(
        ax=axes[0][1], colorbar=False)
    axes[0][1].set_title("Random Forest — multiclass")
    axes[0][1].tick_params(axis="x", rotation=30)

    # ROC curve ISO
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

    # Score distribution pe attack type real
    attack_order = [a for a in ["norm","sqli","xss","path-traversal","cmdi","recon"]
                    if a in df["true_attack"].values]
    for label in attack_order:
        subset = df[df["true_attack"] == label]["iso_score"]
        axes[1][0].hist(subset, bins=30, alpha=0.55,
                        label=label, color=palette.get(label, "gray"))
    axes[1][0].set_xlabel("Anomaly score")
    axes[1][0].set_ylabel("Count")
    axes[1][0].set_title("Distributie score per attack type")
    axes[1][0].legend(fontsize=8)

    # Detection rate per attack type (ISO)
    det = df.groupby("true_attack")["iso_predicted"].mean()
    det = det.reindex(attack_order).dropna()
    bars = axes[1][1].bar(det.index, det.values * 100,
                           color=[palette.get(k, "gray") for k in det.index])
    axes[1][1].set_ylabel("% detectat ca anomalie")
    axes[1][1].set_title("Rata detectie ISO per attack type")
    axes[1][1].set_ylim(0, 115)
    for bar, val in zip(bars, det.values):
        axes[1][1].text(bar.get_x() + bar.get_width()/2,
                        bar.get_height() + 2,
                        f"{val*100:.1f}%", ha="center", fontsize=9)

    # Compozitie dataset testat
    counts = df["true_attack"].value_counts().reindex(attack_order).dropna()
    axes[1][2].pie(counts.values,
                   labels=counts.index,
                   colors=[palette.get(k, "gray") for k in counts.index],
                   autopct="%1.1f%%", startangle=90)
    axes[1][2].set_title("Compozitie log testat")

    plt.tight_layout()
    plt.savefig("test_results.png", dpi=150, bbox_inches="tight")
    print("[+] Graf salvat → test_results.png")
    plt.show()


if __name__ == "__main__":
    main()