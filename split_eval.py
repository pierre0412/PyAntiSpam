#!/usr/bin/env python3
"""Évalue la répartition métadonnées (RF) / contenu (CamemBERT) hors échantillon.

Validation croisée groupée par domaine expéditeur, répétée sur plusieurs graines.
Aucun historique expéditeur dans les métadonnées : on mesure le signal propre.
Lecture seule.
"""

import os
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from pyantispam.ml.feature_extractor import FeatureExtractor  # noqa: E402
from embeddings_pilot import build_embedding_text, compute_embeddings, load_real_samples  # noqa: E402

SEEDS = [0, 1, 2, 3, 4]
META_PREFIXES = ("auth_", "temporal_", "x_spam", "from_dkim", "has_list", "replyto",
                 "message_id", "received_hops", "sender_suspicious_tld", "sender_has_",
                 "sender_domain_length", "sender_local_length")


def metrics(y_true, y_pred):
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return rec, prec, fpr


def main():
    samples = load_real_samples()
    y = np.array([1 if s["is_spam"] else 0 for s in samples])
    groups = np.array([s["email_data"].get("sender_domain", f"__none_{i}") for i, s in enumerate(samples)])
    print(f"mails: {len(samples)} (spam={int(y.sum())}), domaines: {len(set(groups))}")

    ex = FeatureExtractor()
    names = ex.get_feature_names()
    meta_names = [n for n in names if n.startswith(META_PREFIXES)]
    content_names = [n for n in names if n not in meta_names and not n.startswith("sender_")]
    print(f"métadonnées: {len(meta_names)} features | contenu RF: {len(content_names)} features")

    feats = [ex.extract_features(s["email_data"]) for s in samples]
    X_meta = np.array([[f.get(n, 0.0) for n in meta_names] for f in feats])
    X_cont = np.array([[f.get(n, 0.0) for n in content_names] for f in feats])
    X_emb = compute_embeddings([build_embedding_text(s["email_data"]) for s in samples])

    rows = {k: [] for k in ["CamemBERT", "RF contenu", "RF métadonnées", "combiné"]}
    for seed in SEEDS:
        cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        preds = {k: np.zeros(len(y)) for k in rows}
        for tr, te in cv.split(X_emb, y, groups):
            lr = LogisticRegression(class_weight="balanced", max_iter=1000).fit(X_emb[tr], y[tr])
            preds["CamemBERT"][te] = lr.predict_proba(X_emb[te])[:, 1]

            sc = StandardScaler().fit(X_cont[tr])
            rf = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42,
                                        class_weight="balanced").fit(sc.transform(X_cont[tr]), y[tr])
            preds["RF contenu"][te] = rf.predict_proba(sc.transform(X_cont[te]))[:, 1]

            sm = StandardScaler().fit(X_meta[tr])
            rfm = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42,
                                         class_weight="balanced").fit(sm.transform(X_meta[tr]), y[tr])
            preds["RF métadonnées"][te] = rfm.predict_proba(sm.transform(X_meta[te]))[:, 1]

        preds["combiné"] = (preds["CamemBERT"] + preds["RF métadonnées"]) / 2
        for k in rows:
            rows[k].append(metrics(y, (preds[k] >= 0.5).astype(int)))

    print()
    print(f"{'modèle':<16} {'rappel spam':>12} {'précision spam':>15} {'faux positifs':>14}")
    for k, vals in rows.items():
        arr = np.array(vals)
        r, p, f = arr.mean(axis=0)
        print(f"{k:<16} {r:>12.2f} {p:>15.2f} {f:>14.2f}   (écart-type rappel {arr[:,0].std():.2f})")


if __name__ == "__main__":
    main()
