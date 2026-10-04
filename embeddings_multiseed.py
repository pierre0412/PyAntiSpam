#!/usr/bin/env python3
"""Variance des résultats du pilote embeddings sur plusieurs graines de validation croisée.

Lecture seule. Encode une seule fois, puis évalue la régression logistique sur
plusieurs découpages (groupés par domaine expéditeur) pour voir si un écart entre
modèles dépasse le bruit.
"""

import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).parent))

from embeddings_pilot import (  # noqa: E402
    EMBEDDING_MODEL,
    build_embedding_text,
    compute_embeddings,
    evaluate_embeddings_logreg,
    load_real_samples,
)

SEEDS = [0, 1, 2, 3, 4]


def main():
    samples = load_real_samples()
    y = np.array([1 if s["is_spam"] else 0 for s in samples])
    groups = np.array([s["email_data"].get("sender_domain", f"__none_{i}") for i, s in enumerate(samples)])
    texts = [build_embedding_text(s["email_data"]) for s in samples]

    print(f"modele: {EMBEDDING_MODEL} | mails: {len(samples)} (spam={int(y.sum())})")
    X = compute_embeddings(texts)

    rows = []
    for seed in SEEDS:
        cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        r = evaluate_embeddings_logreg(X, y, groups, cv)
        rows.append((r["accuracy"], r["recall_spam"], r["f1_macro"]))
        print(f"  graine {seed}: accuracy={r['accuracy']:.3f} rappel_spam={r['recall_spam']:.3f} f1={r['f1_macro']:.3f}")

    arr = np.array(rows)
    print(f"  MOYENNE: accuracy={arr[:,0].mean():.3f}±{arr[:,0].std():.3f} "
          f"rappel_spam={arr[:,1].mean():.3f}±{arr[:,1].std():.3f} "
          f"f1={arr[:,2].mean():.3f}±{arr[:,2].std():.3f}")


if __name__ == "__main__":
    main()
