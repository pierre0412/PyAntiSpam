"""Sender domains that imitate a domain the recipient validated (shadow signal).

A phishing text written by an LLM is flawless, but its sender domain still
has to differ from the real one: creditagrlcole.fr, sonepar-fr.com,
sonepar.com next to sonepar.fr. Brands themselves vary the structure (other
extension, hyphen, extra word: societegenerale.com, e-ca-pca.fr), never the
letters: only altered letters (typo, homoglyph) are STRONG. The reference
list is the recipient's own validations (sender_feedback_history.json: some ham, no spam), so it grows
with every correction. A domain that only looks like itself is never flagged.
"""

import json
from pathlib import Path
from typing import Dict, Iterable, Optional, Set, Tuple

from ..llm.recipient_history import SHARED_SENDER_DOMAINS, base_domain

HISTORY_FILE = Path("data/sender_feedback_history.json")

# Look-alike characters, folded before comparing (longest sequences first).
_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("i", "l"), ("3", "e"), ("5", "s")]


def validated_domains() -> Set[str]:
    """Registrable domains the recipient marked legitimate and never spam."""
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
    except (OSError, ValueError):
        return set()
    counts: Dict[str, list] = {}
    for entry in history.values():
        dom = base_domain(entry.get("sender_domain") or (entry.get("sender_email") or "").split("@")[-1])
        c = counts.setdefault(dom, [0, 0])
        c[0] += entry.get("ham_count", 0) + entry.get("whitelist_count", 0)
        c[1] += entry.get("spam_count", 0) + entry.get("blacklist_count", 0)
    return {d for d, (ham, spam) in counts.items()
            if ham > 0 and spam == 0 and d and d not in SHARED_SENDER_DOMAINS}


def _label(domain: str) -> str:
    """The name part of a registrable domain: sonepar.fr -> sonepar."""
    return domain.split(".")[0]


# Kinds brands never use for their own domains; the others are logged as siblings.
STRONG_KINDS = {"homoglyph", "typo"}


def _fold(label: str) -> str:
    for src, dst in _HOMOGLYPHS:
        label = label.replace(src, dst)
    return label


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (adjacent swaps count 1): creditagrlcole/creditagricole = 1."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def is_typo(sender_label: str, known_label: str) -> bool:
    """True when sender_label is a near-miss spelling of known_label."""
    # One letter off is enough: a brand does not misspell its own domain. Below
    # 5 letters one letter makes another word (free/tree), not an imitation.
    return len(known_label) >= 5 and edit_distance(sender_label, known_label) == 1


def _kind(label: str, known: str) -> Optional[str]:
    """How label imitates known, structure variations checked first."""
    plain, known_plain = label.replace("-", ""), known.replace("-", "")
    if label == known:
        return "tld"
    if plain == known_plain:
        return "hyphen"
    def has_word(longer: str, shorter: str) -> bool:
        return (longer.startswith(shorter + "-") or longer.endswith("-" + shorter)
                or f"-{shorter}-" in longer or shorter.replace("-", "") in longer.split("-"))

    if has_word(label, known) or has_word(known, label):  # a word added or removed
        return "contains"
    if _fold(plain) == _fold(known_plain):
        return "homoglyph"
    if is_typo(plain, known_plain):
        return "typo"
    return None


def find_lookalike(sender_domain: str, validated: Iterable[str]) -> Optional[Tuple[str, str]]:
    """(validated domain imitated, kind) or None, a STRONG kind preferred.
    Structure kinds: "tld" (same name, other extension), "hyphen", "contains"
    (the known name plus extra words). Strong kinds: "homoglyph" (equal once
    look-alike characters are folded), "typo" (one letter off)."""
    dom = base_domain(sender_domain)
    if not dom or dom in SHARED_SENDER_DOMAINS:
        return None
    validated = set(validated)
    if dom in validated:
        return None  # the sender is itself a validated domain
    label = _label(dom)
    weak = None
    for known in sorted(validated):
        k = _label(known)
        if len(k.replace("-", "")) < 4:
            continue  # too short to tell imitation from coincidence (ca.fr, sfr.fr)
        kind = _kind(label, k)
        if kind in STRONG_KINDS:
            return known, kind
        if kind and weak is None:
            weak = (known, kind)
    return weak
