#!/usr/bin/env python3
"""Compare les décisions PyAntiSpam et les scores CamemBERT sur les mails traités.

Lecture seule. Ne nécessite aucune étiquette : montre où les deux systèmes
s'accordent, où ils divergent, et sur quels mails il faudrait une relecture.

Usage : python3 shadow_report.py [seuil_camembert]
"""

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from email.header import decode_header
from pathlib import Path

LOGS = Path("data/logs")
THRESHOLD = float(sys.argv[1]) if len(sys.argv) > 1 else 0.5


def decode_subject(raw: str) -> str:
    try:
        return "".join(
            part.decode(enc or "utf-8", errors="replace") if isinstance(part, bytes) else part
            for part, enc in decode_header(raw)
        )
    except Exception:
        return raw


def load_jsonl(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.open(encoding="utf-8")]


def main():
    pred = {}
    for r in load_jsonl(LOGS / "prediction_log.jsonl"):
        pred[r["fingerprint"]] = r

    emb = {}
    for r in load_jsonl(LOGS / "embedding_shadow_log.jsonl"):
        emb[r["fingerprint"]] = r.get("embedding_spam_proba", r.get("camembert_spam_proba"))

    joined = [(pred[k], emb[k]) for k in emb if k in pred and emb[k] is not None]
    print(f"mails traités avec score CamemBERT : {len(joined)} (seuil {THRESHOLD})")
    print()

    table = Counter()
    by_account = defaultdict(Counter)
    for p, proba in joined:
        cam = "SPAM" if proba >= THRESHOLD else "KEEP"
        table[(p["action"], cam)] += 1
        by_account[p["account"]][(p["action"], cam)] += 1

    print("PyAntiSpam \\ CamemBERT | SPAM | KEEP")
    for pa in ("SPAM", "KEEP"):
        spam_n = table[(pa, "SPAM")]
        keep_n = table[(pa, "KEEP")]
        print(f"{pa:<23} | {spam_n:>4} | {keep_n:>4}")
    print()

    for acc, c in sorted(by_account.items()):
        total = sum(c.values())
        agree = c[("SPAM", "SPAM")] + c[("KEEP", "KEEP")]
        print(f"compte {acc} : {total} mails, accord {agree / total:.0%}")
    print()

    print("Désaccords à relire, du plus confiant au moins confiant :")
    disagreements = []
    for p, proba in joined:
        cam = "SPAM" if proba >= THRESHOLD else "KEEP"
        if p["action"] != cam:
            disagreements.append((proba, p, cam))
    for proba, p, cam in sorted(disagreements, key=lambda x: -x[0]):
        subject = decode_subject(p.get("subject") or "")[:70]
        when = datetime.fromtimestamp(p["timestamp"]).strftime("%d/%m %H:%M")
        print(f"  {when} [{p['account']}] pyantispam={p['action']:<4} camembert={cam:<4} "
              f"p={proba:.2f} | {p.get('sender_email', '')} | {subject}")


if __name__ == "__main__":
    main()
