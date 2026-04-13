"""
    python train_model.py --csv http_params.csv
"""

import re
import pickle
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

#  Feature engineering (aceleasi features folosite si la testare) 

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


def _entropy(s):
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    t = len(s)
    return -sum((v / t) * np.log2(v / t) for v in c.values())


def extract_features(payloads, lengths):
    """Extrage features dintr-o lista de payload-uri si lungimi."""
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


FEATURE_COLS = [
    "length", "has_sqli", "has_xss", "has_path_traversal", "has_cmdi",
    "special_char_count", "digit_ratio", "upper_ratio", "space_count",
    "entropy", "token_count", "has_encoding"
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="http_params.csv")
    args = parser.parse_args()

    # Incarcare date 
    print(f"[+] Incarcare {args.csv} ...")
    df = pd.read_csv(args.csv)
    df.columns = [c.strip().strip('"') for c in df.columns]
    df["payload"]     = df["payload"].astype(str).str.strip('"')
    df["length"]      = pd.to_numeric(df["length"], errors="coerce").fillna(0)
    df["attack_type"] = df["attack_type"].astype(str).str.strip('"').str.strip()
    df["label"]       = df["label"].astype(str).str.strip('"').str.strip()

    print(f"    {len(df)} randuri totale")
    print(f"    Distributie attack_type:\n{df['attack_type'].value_counts().to_string()}")

    #  Features
    print("[+] Extragere features ...")
    X = extract_features(df["payload"], df["length"])[FEATURE_COLS].values

    # Label binar: 0 = norm, 1 = anom
    y_binary = (df["label"] == "anom").astype(int).values

    # Label multiclass: norm/sqli/xss/path-traversal/cmdi
    le = LabelEncoder()
    y_multi = le.fit_transform(df["attack_type"])

    # Split 
    X_train, X_test, yb_train, yb_test, ym_train, ym_test = train_test_split(
        X, y_binary, y_multi, test_size=0.2, random_state=42, stratify=y_binary
    )

    # Isolation Forest (anomaly detection, unsupervised) 
    print("[+] Antrenare Isolation Forest ...")
    cont = float(np.clip((df["label"] == "anom").mean(), 0.01, 0.49))
    iso = IsolationForest(n_estimators=200, contamination=cont,
                          random_state=42, n_jobs=-1)
    iso.fit(X_train)

    iso_pred = (iso.predict(X_test) == -1).astype(int)
    print("\n--- Isolation Forest (binar) ---")
    print(classification_report(yb_test, iso_pred,
                                 target_names=["normal", "anomaly"]))

    # Random Forest (supervised, multiclass) 
    print("[+] Antrenare Random Forest (multiclass) ...")
    rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    rf.fit(X_train, ym_train)

    rf_pred = rf.predict(X_test)
    print("\n--- Random Forest (multiclass) ---")
    print(classification_report(ym_test, rf_pred,
                                 target_names=le.classes_))

    # Salvare modele 
    with open("model_iso.pkl", "wb") as f:
        pickle.dump(iso, f)
    with open("model_rf.pkl", "wb") as f:
        pickle.dump(rf, f)
    with open("label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)
    print("\n[+] Modele salvate: model_iso.pkl, model_rf.pkl, label_encoder.pkl")

    # Plots 
    print("[+] Generare grafice training ...")
    _plot_training(X_test, yb_test, ym_test, iso, iso_pred, rf, rf_pred, le)


def _plot_training(X_test, yb_test, ym_test, iso, iso_pred, rf, rf_pred, le):
    palette = {
        "norm":           "#4CAF50",
        "sqli":           "#F44336",
        "xss":            "#FF9800",
        "path-traversal": "#9C27B0",
        "cmdi":           "#2196F3",
        "recon":          "#795548",
    }

    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    fig.suptitle("Training Results — http_params.csv", fontsize=14)

    # Confusion matrix Isolation Forest
    cm1 = confusion_matrix(yb_test, iso_pred)
    ConfusionMatrixDisplay(cm1, display_labels=["Normal", "Anomaly"]).plot(
        ax=axes[0], colorbar=False)
    axes[0].set_title("Isolation Forest — binar")

    # Confusion matrix Random Forest
    cm2 = confusion_matrix(ym_test, rf_pred)
    ConfusionMatrixDisplay(cm2, display_labels=le.classes_).plot(
        ax=axes[1], colorbar=False)
    axes[1].set_title("Random Forest — multiclass")
    axes[1].tick_params(axis="x", rotation=30)

    # Feature importance RF
    importances = rf.feature_importances_
    feat_names = [
        "length", "has_sqli", "has_xss", "has_path_tr", "has_cmdi",
        "special_chars", "digit_ratio", "upper_ratio", "spaces",
        "entropy", "tokens", "has_encoding"
    ]
    idx = np.argsort(importances)
    axes[2].barh([feat_names[i] for i in idx], importances[idx],
                 color="#1565C0", alpha=0.8)
    axes[2].set_title("Feature importance (RF)")
    axes[2].set_xlabel("Importance")

    plt.tight_layout()
    plt.savefig("training_results.png", dpi=150, bbox_inches="tight")
    print("[+] Graf salvat => training_results.png")
    plt.show()


if __name__ == "__main__":
    main()
