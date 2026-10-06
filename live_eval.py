#!/usr/bin/env python3
"""Évaluation continue sur le trafic réel, sans étiquetage supplémentaire.

Étiquette de référence :
- si l'utilisateur a corrigé un mail via un dossier de feedback (entrée
  `user_feedback` dans data/llm_cache.json, même empreinte), c'est sa décision ;
- sinon, la décision de PyAntiSpam est tenue pour juste.

Chaque mail compte une fois, avec sa décision d'arrivée (le journal contient
des doublons). Biais connus :
- faux positifs bien mesurés (l'utilisateur les corrige) ;
- faux négatifs sous-estimés (un spam gardé et non vu reste compté comme juste) ;
- seuls les mails plus vieux que --min-age-hours sont comptés (délai de relecture).

Lecture seule : aucun mail, aucun dossier, aucun fichier de données n'est modifié.

Usage :
  python3 live_eval.py                                  # bilan global
  python3 live_eval.py --depuis "2026-10-05 09:40"      # série par tranches
  python3 live_eval.py --depuis "2026-10-05 09:40" --pas-heures 48
"""

import argparse
import json
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

LOGS = Path("data/logs")
CACHE = Path("data/llm_cache.json")


def load_jsonl(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.open(encoding="utf-8")]


def add(c: Counter, label_spam: bool, predicted_spam: bool):
    if predicted_spam and label_spam:
        c["TP"] += 1
    elif predicted_spam:
        c["FP"] += 1
    elif label_spam:
        c["FN"] += 1
    else:
        c["TN"] += 1


def precision(c: Counter) -> float:
    return c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else float("nan")


def recall(c: Counter) -> float:
    return c["TP"] / (c["TP"] + c["FN"]) if c["TP"] + c["FN"] else float("nan")


def load_data():
    cache = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
    feedback = {fp: v["action"] for fp, v in cache.items()
                if isinstance(v, dict) and v.get("method") == "user_feedback"}
    emb = {}
    for r in load_jsonl(LOGS / "embedding_shadow_log.jsonl"):
        v = r.get("embedding_spam_proba", r.get("camembert_spam_proba"))
        if v is not None:
            emb.setdefault(r["fingerprint"], v)
    first = {}
    for r in load_jsonl(LOGS / "prediction_log.jsonl"):
        first.setdefault(r["fingerprint"], r)
    return feedback, emb, first


def global_report(args, feedback, emb, first):
    cutoff = time.time() - args.min_age_hours * 3600
    pa, cam = Counter(), Counter()
    corrected = Counter()
    for fp, r in first.items():
        if r["timestamp"] > cutoff:
            continue
        action_spam = r["action"] == "SPAM"
        if fp in feedback:
            corrected[(r["action"], feedback[fp])] += 1
            label_spam = feedback[fp] == "SPAM"
        else:
            label_spam = action_spam
        add(pa, label_spam, action_spam)
        if fp in emb:
            add(cam, label_spam, emb[fp] >= args.threshold)

    print(f"mails distincts plus vieux que {args.min_age_hours:g} h : {sum(pa.values())} "
          f"(corrigés : {sum(corrected.values())})")
    print(f"corrections (décision PyAntiSpam -> décision finale) : {dict(corrected)}")
    print(f"seuil CamemBERT : {args.threshold}")
    print()
    print(f"{'système':<12} {'n':>5} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>5} {'précision':>10} {'rappel':>8}")
    for name, c in (("PyAntiSpam", pa), ("CamemBERT", cam)):
        if not sum(c.values()):
            print(f"{name:<12} aucun mail scoré")
            continue
        print(f"{name:<12} {sum(c.values()):>5} {c['TP']:>4} {c['FN']:>4} {c['FP']:>4} {c['TN']:>5} "
              f"{precision(c):>10.2f} {recall(c):>8.2f}")


def series_report(args, feedback, first):
    start = datetime.strptime(args.depuis, "%Y-%m-%d %H:%M").timestamp()
    step = args.pas_heures * 3600
    bins = defaultdict(Counter)
    for fp, r in first.items():
        if r["timestamp"] < start:
            continue
        b = int((r["timestamp"] - start) // step)
        spam = r["action"] == "SPAM"
        bins[b]["mails"] += 1
        if spam:
            bins[b]["SPAM"] += 1
        if fp in feedback:
            bins[b]["corrections"] += 1
            if spam and feedback[fp] == "KEEP":
                bins[b]["FP"] += 1
            if not spam and feedback[fp] == "SPAM":
                bins[b]["FN"] += 1

    print(f"série depuis {args.depuis}, tranches de {args.pas_heures:g} h")
    print(f"{'tranche':<12} {'mails':>6} {'SPAM':>5} {'corr.':>6} {'FP':>4} {'FN':>4} {'précision SPAM':>15}")
    for b in sorted(bins):
        c = bins[b]
        t = datetime.fromtimestamp(start + b * step).strftime("%d/%m %Hh")
        prec = (1 - c["FP"] / c["SPAM"]) if c["SPAM"] else float("nan")
        print(f"{t:<12} {c['mails']:>6} {c['SPAM']:>5} {c['corrections']:>6} {c['FP']:>4} {c['FN']:>4} {prec:>15.2f}")
    print(f"relu à : {datetime.fromtimestamp(time.time()).strftime('%d/%m %H:%M')}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--threshold", type=float, default=0.5, help="seuil de CamemBERT")
    parser.add_argument("--min-age-hours", type=float, default=24.0, help="ignorer les mails plus récents")
    parser.add_argument("--depuis", help="série depuis cette date locale, format AAAA-MM-JJ HH:MM")
    parser.add_argument("--pas-heures", type=float, default=12.0, help="taille des tranches de la série")
    args = parser.parse_args()

    feedback, emb, first = load_data()
    if args.depuis:
        series_report(args, feedback, first)
    else:
        global_report(args, feedback, emb, first)


if __name__ == "__main__":
    main()
