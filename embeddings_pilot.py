#!/usr/bin/env python3
"""Première expérience embeddings (étape 4 de la feuille de route rspamd).

Compare, sur les mêmes échantillons et les mêmes folds de validation croisée :
- le pipeline actuel (FeatureExtractor + RandomForestClassifier)
- un classifieur à base d'embeddings (sentence-transformers + LogisticRegression)
- le "fuzzy sémantique" de la note projet : similarité cosinus max avec les
  spams déjà connus, sans entraînement supervisé (juste un seuil)

Ne touche à aucun modèle de production : lecture seule de data/training_data.json.
"""

import json
import os
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
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support, roc_auc_score  # noqa: E402
from sklearn.metrics.pairwise import cosine_similarity  # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "paraphrase-multilingual-MiniLM-L12-v2")
MAX_BODY_CHARS = 2000  # ~512 tokens, cf. doc projet
N_SPLITS = 5

# Features dérivées de l'historique de feedback du même expéditeur : l'auto-blacklist
# s'en charge déjà, et elles sont partiellement circulaires avec le label pour un
# expéditeur déjà signalé plusieurs fois. On les exclut pour juger le contenu seul,
# qui est le seul signal utile face à un expéditeur jamais vu.
SENDER_HISTORY_FEATURES = {
    "sender_spam_ratio",
    "sender_total_feedbacks",
    "sender_days_since_first",
    "sender_is_recurring_spammer",
    "sender_is_recurring_ham",
}


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


def evaluate_rf(
    samples: List[Dict[str, Any]],
    y: np.ndarray,
    groups: np.ndarray,
    cv: StratifiedGroupKFold,
    content_only: bool = False,
) -> Dict[str, float]:
    extractor = FeatureExtractor()
    feature_names = extractor.get_feature_names()
    if content_only:
        feature_names = [n for n in feature_names if n not in SENDER_HISTORY_FEATURES]

    X = []
    for s in samples:
        features = extractor.extract_features(s["email_data"])
        X.append([features.get(name, 0.0) for name in feature_names])
    X = np.array(X)

    pipeline_scores = {"accuracy": [], "precision_macro": [], "recall_macro": [], "f1_macro": [], "recall_spam": [], "precision_spam": [], "recall_ham": []}
    for train_idx, test_idx in cv.split(X, y, groups):
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X[train_idx])
        X_test = scaler.transform(X[test_idx])

        clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight="balanced")
        clf.fit(X_train, y[train_idx])
        _score_fold(clf.predict(X_test), y[test_idx], pipeline_scores)

    return {k: float(np.mean(v)) for k, v in pipeline_scores.items()}


def compute_embeddings(texts: List[str]) -> np.ndarray:
    print(f"Chargement du modèle d'embeddings ({EMBEDDING_MODEL})...")
    model = SentenceTransformer(EMBEDDING_MODEL)
    return model.encode(texts, show_progress_bar=False)


def evaluate_embeddings_logreg(
    X: np.ndarray, y: np.ndarray, groups: np.ndarray, cv: StratifiedGroupKFold
) -> Dict[str, float]:
    pipeline_scores = {"accuracy": [], "precision_macro": [], "recall_macro": [], "f1_macro": [], "recall_spam": [], "precision_spam": [], "recall_ham": []}
    for train_idx, test_idx in cv.split(X, y, groups):
        clf = LogisticRegression(class_weight="balanced", max_iter=1000)
        clf.fit(X[train_idx], y[train_idx])
        _score_fold(clf.predict(X[test_idx]), y[test_idx], pipeline_scores)

    return {k: float(np.mean(v)) for k, v in pipeline_scores.items()}


def evaluate_semantic_fuzzy(
    X: np.ndarray, y: np.ndarray, groups: np.ndarray, cv: StratifiedGroupKFold
) -> Dict[str, float]:
    """"Fuzzy sémantique" de la note projet : pas d'entraînement supervisé, juste

    la similarité cosinus max de chaque mail avec les spams déjà connus. Le
    seuil de décision est choisi sur le fold d'entraînement (celui qui maximise
    le F1), jamais sur le test, pour ne pas tricher.
    """
    pipeline_scores = {"accuracy": [], "precision_macro": [], "recall_macro": [], "f1_macro": [], "recall_spam": [], "precision_spam": [], "recall_ham": []}
    oof_scores, oof_labels = [], []  # out-of-fold, pour un AUC global indépendant du seuil

    for train_idx, test_idx in cv.split(X, y, groups):
        spam_train_idx = train_idx[y[train_idx] == 1]
        sim_train = cosine_similarity(X[train_idx], X[spam_train_idx])
        # Un spam du train ne doit pas se comparer à lui-même (similarité triviale = 1)
        for row, global_i in enumerate(train_idx):
            for col, spam_global_i in enumerate(spam_train_idx):
                if global_i == spam_global_i:
                    sim_train[row, col] = -1.0
        train_scores = sim_train.max(axis=1)

        best_threshold, best_f1 = 0.5, -1.0
        for threshold in np.linspace(0.0, 1.0, 101):
            preds = (train_scores >= threshold).astype(int)
            f1 = f1_score(y[train_idx], preds, zero_division=0)
            if f1 > best_f1:
                best_f1, best_threshold = f1, threshold

        sim_test = cosine_similarity(X[test_idx], X[spam_train_idx])
        test_scores = sim_test.max(axis=1)
        test_preds = (test_scores >= best_threshold).astype(int)

        _score_fold(test_preds, y[test_idx], pipeline_scores)
        oof_scores.extend(test_scores.tolist())
        oof_labels.extend(y[test_idx].tolist())

    result = {k: float(np.mean(v)) for k, v in pipeline_scores.items()}
    result["auc"] = float(roc_auc_score(oof_labels, oof_scores))
    return result


def _score_fold(y_pred, y_test, pipeline_scores: Dict[str, list]):
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )
    # Par classe aussi : c'est le taux de détection du spam (recall_spam) et le taux
    # de faux positifs sur le ham (1 - recall_ham) qui comptent le plus en pratique,
    # pas la moyenne macro qui les dilue.
    precision_per_class, recall_per_class, _, _ = precision_recall_fscore_support(
        y_test, y_pred, labels=[0, 1], zero_division=0
    )
    pipeline_scores["accuracy"].append(accuracy_score(y_test, y_pred))
    pipeline_scores["precision_macro"].append(precision)
    pipeline_scores["recall_macro"].append(recall)
    pipeline_scores["f1_macro"].append(f1)
    pipeline_scores["recall_spam"].append(recall_per_class[1])
    pipeline_scores["precision_spam"].append(precision_per_class[1])
    pipeline_scores["recall_ham"].append(recall_per_class[0])


def main():
    samples = load_real_samples()
    y = np.array([1 if s["is_spam"] else 0 for s in samples])
    texts = [build_embedding_text(s["email_data"]) for s in samples]
    # Groupe par domaine expéditeur : un même domaine ne doit jamais se retrouver
    # à la fois dans le train et le test d'un même fold, sinon on ne mesure pas
    # vraiment la capacité à juger un expéditeur jamais vu (31% des 74 échantillons
    # partagent un domaine avec au moins un autre échantillon).
    groups = np.array([s["email_data"].get("sender_domain", f"__no_domain_{i}") for i, s in enumerate(samples)])

    print(f"Échantillons réels utilisables : {len(samples)} (spam={int(y.sum())}, ham={int((1 - y).sum())})")
    print(f"Domaines expéditeurs distincts : {len(set(groups))}")
    if len(samples) < 20:
        print("Attention : échantillon très réduit, résultats indicatifs uniquement.\n")

    cv = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=42)

    rf_full_scores = evaluate_rf(samples, y, groups, cv, content_only=False)
    rf_content_scores = evaluate_rf(samples, y, groups, cv, content_only=True)

    X_emb = compute_embeddings(texts)
    emb_scores = evaluate_embeddings_logreg(X_emb, y, groups, cv)
    fuzzy_scores = evaluate_semantic_fuzzy(X_emb, y, groups, cv)

    print("\n=== Résultats (moyenne sur 5 folds, groupés par domaine expéditeur) ===")
    print("Un domaine expéditeur n'apparaît jamais à la fois en train et en test :")
    print("ça mesure la capacité à juger un expéditeur jamais vu, pas à le reconnaître.\n")
    print(f"{'Métrique':<18}{'RF complet':<14}{'RF contenu seul':<18}{'Embeddings+LogReg':<20}{'Fuzzy sémantique':<18}")
    for metric in [
        "accuracy", "precision_macro", "recall_macro", "f1_macro",
        "recall_spam", "precision_spam", "recall_ham",
    ]:
        print(
            f"{metric:<18}{rf_full_scores[metric]:<14.3f}"
            f"{rf_content_scores[metric]:<18.3f}{emb_scores[metric]:<20.3f}{fuzzy_scores[metric]:<18.3f}"
        )
    print(f"\nAUC (indépendant du seuil) du fuzzy sémantique seul : {fuzzy_scores['auc']:.3f}")


if __name__ == "__main__":
    main()
