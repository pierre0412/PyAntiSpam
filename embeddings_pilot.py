#!/usr/bin/env python3
"""Première expérience embeddings (étape 4 de la feuille de route rspamd).

Compare, sur les mêmes échantillons et les mêmes folds de validation croisée :
- le pipeline actuel (FeatureExtractor + RandomForestClassifier)
- un classifieur à base d'embeddings (sentence-transformers + LogisticRegression)

Ne touche à aucun modèle de production : lecture seule de data/training_data.json.
"""

import json
import re
import sys
from email.header import decode_header
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

sys.path.insert(0, str(Path(__file__).parent / "src"))

from pyantispam.ml.feature_extractor import FeatureExtractor  # noqa: E402

from sentence_transformers import SentenceTransformer  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import StratifiedKFold, cross_validate  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

EMBEDDING_MODEL = "paraphrase-multilingual-MiniLM-L12-v2"
MAX_BODY_CHARS = 2000  # ~512 tokens, cf. doc projet
N_SPLITS = 5


def decode_mime_subject(raw_subject: str) -> str:
    try:
        parts = decode_header(raw_subject)
        return "".join(
            part.decode(enc or "utf-8", errors="ignore") if isinstance(part, bytes) else part
            for part, enc in parts
        )
    except Exception:
        return raw_subject


def strip_html(text: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def load_real_samples() -> List[Dict[str, Any]]:
    data_file = Path("data/training_data.json")
    samples = json.loads(data_file.read_text(encoding="utf-8"))

    real = []
    for s in samples:
        email_data = s.get("email_data", {})
        if email_data.get("sender_domain") == "user-feedback.local":
            continue
        body = email_data.get("body") or email_data.get("text_content") or ""
        if not body.strip() and not email_data.get("subject", "").strip():
            continue
        real.append(s)
    return real


def build_embedding_text(email_data: Dict[str, Any]) -> str:
    subject = decode_mime_subject(email_data.get("subject", ""))
    body = strip_html(email_data.get("body") or email_data.get("text_content") or "")
    return f"{subject}\n\n{body[:MAX_BODY_CHARS]}"


def evaluate_rf(samples: List[Dict[str, Any]], y: np.ndarray, cv: StratifiedKFold) -> Dict[str, float]:
    extractor = FeatureExtractor()
    feature_names = extractor.get_feature_names()

    X = []
    for s in samples:
        features = extractor.extract_features(s["email_data"])
        X.append([features.get(name, 0.0) for name in feature_names])
    X = np.array(X)

    pipeline_scores = {"accuracy": [], "precision_macro": [], "recall_macro": [], "f1_macro": []}
    for train_idx, test_idx in cv.split(X, y):
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X[train_idx])
        X_test = scaler.transform(X[test_idx])

        clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight="balanced")
        clf.fit(X_train, y[train_idx])
        _score_fold(clf, X_test, y[test_idx], pipeline_scores)

    return {k: float(np.mean(v)) for k, v in pipeline_scores.items()}


def evaluate_embeddings(texts: List[str], y: np.ndarray, cv: StratifiedKFold) -> Dict[str, float]:
    print(f"Chargement du modèle d'embeddings ({EMBEDDING_MODEL})...")
    model = SentenceTransformer(EMBEDDING_MODEL)
    X = model.encode(texts, show_progress_bar=False)

    pipeline_scores = {"accuracy": [], "precision_macro": [], "recall_macro": [], "f1_macro": []}
    for train_idx, test_idx in cv.split(X, y):
        clf = LogisticRegression(class_weight="balanced", max_iter=1000)
        clf.fit(X[train_idx], y[train_idx])
        _score_fold(clf, X[test_idx], y[test_idx], pipeline_scores)

    return {k: float(np.mean(v)) for k, v in pipeline_scores.items()}


def _score_fold(clf, X_test, y_test, pipeline_scores: Dict[str, list]):
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support

    y_pred = clf.predict(X_test)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )
    pipeline_scores["accuracy"].append(accuracy_score(y_test, y_pred))
    pipeline_scores["precision_macro"].append(precision)
    pipeline_scores["recall_macro"].append(recall)
    pipeline_scores["f1_macro"].append(f1)


def main():
    samples = load_real_samples()
    y = np.array([1 if s["is_spam"] else 0 for s in samples])
    texts = [build_embedding_text(s["email_data"]) for s in samples]

    print(f"Échantillons réels utilisables : {len(samples)} (spam={int(y.sum())}, ham={int((1 - y).sum())})")
    if len(samples) < 20:
        print("Attention : échantillon très réduit, résultats indicatifs uniquement.\n")

    cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=42)

    rf_scores = evaluate_rf(samples, y, cv)
    emb_scores = evaluate_embeddings(texts, y, cv)

    print("\n=== Résultats (moyenne sur 5 folds) ===")
    print(f"{'Métrique':<18}{'RF (features actuelles)':<26}{'Embeddings + LogReg':<22}")
    for metric in ["accuracy", "precision_macro", "recall_macro", "f1_macro"]:
        print(f"{metric:<18}{rf_scores[metric]:<26.3f}{emb_scores[metric]:<22.3f}")


if __name__ == "__main__":
    main()
