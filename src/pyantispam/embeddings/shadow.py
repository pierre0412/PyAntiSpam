"""Shadow scoring with a sentence-embedding model (mode fantôme).

Observes only: the score is logged next to the real decision and never
influences it. The model and the fitted classifier live at module level, because
EmailProcessor is recreated every daemon cycle and reloading the model each time
would cost ~15 s. Nothing here writes to disk except the caller's log.
"""

import logging
import os
import re
from email.header import decode_header
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

import numpy as np

from ..ml.training_store import read_samples_readonly

if TYPE_CHECKING:
    from ..config import ConfigManager

logger = logging.getLogger(__name__)

MAX_BODY_CHARS = 2000
TRAINING_FILE = Path("data/training_data.json")

_model: Any = None
_model_name: Optional[str] = None
_vectors: Dict[str, np.ndarray] = {}
_clf: Any = None
_fitted_mtime: float = -1.0


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


def build_text(email_data: Dict[str, Any]) -> str:
    subject = decode_mime_subject(email_data.get("subject", ""))
    body = strip_html(email_data.get("body") or email_data.get("text_content") or "")
    return f"{subject}\n\n{body[:MAX_BODY_CHARS]}"


def fingerprint(email_data: Dict[str, Any]) -> str:
    content = str(email_data.get("body", email_data.get("text_content", "")))[:200]
    return f"{email_data.get('sender_email', '')}|{email_data.get('subject', '')}|{content}"


class EmbeddingShadowClassifier:
    def __init__(self, config: "ConfigManager"):
        self.enabled = bool(config.get("embeddings.enabled", False))
        self.model_name = config.get("embeddings.model", "dangvantuan/sentence-camembert-base")

    def is_enabled(self) -> bool:
        return self.enabled

    def _get_model(self):
        global _model, _model_name
        if _model is None or _model_name != self.model_name:
            from sentence_transformers import SentenceTransformer

            _model = SentenceTransformer(self.model_name)
            _model_name = self.model_name
        return _model

    def _refit_if_changed(self) -> None:
        global _clf, _fitted_mtime
        try:
            mtime = os.stat(TRAINING_FILE).st_mtime
        except OSError:
            return
        if mtime == _fitted_mtime and _clf is not None:
            return

        samples = read_samples_readonly(TRAINING_FILE)
        if samples is None:
            return

        keys, labels, pending_keys, pending_texts = [], [], [], []
        for s in samples:
            ed = s.get("email_data")
            if not ed:
                continue
            k = fingerprint(ed)
            keys.append(k)
            labels.append(1 if s.get("is_spam") else 0)
            if k not in _vectors:
                pending_keys.append(k)
                pending_texts.append(build_text(ed))

        if pending_texts:
            vecs = self._get_model().encode(pending_texts, show_progress_bar=False)
            for k, v in zip(pending_keys, vecs):
                _vectors[k] = v

        y = np.array(labels)
        if len(set(labels)) < 2:
            return
        X = np.array([_vectors[k] for k in keys])

        from sklearn.linear_model import LogisticRegression

        _clf = LogisticRegression(class_weight="balanced", max_iter=1000).fit(X, y)
        _fitted_mtime = mtime
        logger.info(f"embedding shadow classifier fitted on {len(y)} samples ({len(pending_texts)} newly encoded)")

    def score(self, email_data: Dict[str, Any]) -> Optional[float]:
        """Probability that the email is spam, or None if unavailable. Never raises."""
        if not self.enabled:
            return None
        try:
            self._refit_if_changed()
            if _clf is None:
                return None
            vec = self._get_model().encode([build_text(email_data)], show_progress_bar=False)[0]
            return float(_clf.predict_proba(vec.reshape(1, -1))[0][1])
        except Exception as e:
            logger.debug(f"embedding shadow score failed (non-blocking): {e}")
            return None
