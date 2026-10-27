#!/usr/bin/env python3
"""Point quotidien : ce qui s'est passé depuis le dernier point.

Sections :
- part du LLM dans les décisions, par tranches de 24 h depuis --serie ;
- décisions par méthode depuis --depuis ;
- spams LLM en attente de confirmation tacite (data/pending_llm_spam.json) ;
- corpus (training_data.json), part des mails avec l'authentification rspamd ;
- corrections de l'utilisateur (sender_feedback_history.json) ;
- erreurs du journal (data/logs/pyantispam.log) ;
- fantôme « LLM + auth + historique + exemples » : désaccords avec le vrai LLM
  (qui a l'historique), et la correction de l'utilisateur quand il y en a une
  (même empreinte, user_feedback) ; bilan de l'ancien fantôme historique ;
- fantôme « sosies » : alertes fortes et frères.

Le compteur Bayes de rspamd n'est pas dans data/ :
  docker compose exec rspamd rspamc stat | grep BAYES

Lecture seule : aucun mail, aucun dossier, aucun fichier de données n'est modifié.

Usage :
  python3 daily_report.py                               # dernières 24 h
  python3 daily_report.py --depuis "2026-10-21 07:40"   # depuis le dernier point
"""

import argparse
import json
import time
from collections import Counter, defaultdict
from datetime import datetime
from email.header import decode_header, make_header
from pathlib import Path

DATA = Path("data")
LOGS = DATA / "logs"
DAY = 86400


def load_jsonl(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.open(encoding="utf-8")]


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%d/%m %H:%M")


def subject(raw) -> str:
    """Sujet MIME décodé (=?UTF-8?B?...?=), sur une ligne."""
    try:
        text = str(make_header(decode_header(raw or "")))
    except Exception:
        text = raw or ""
    return " ".join(text.split())[:60]


def llm_share(predictions, serie: float):
    print(f"== Part du LLM par 24 h depuis {when(serie)}")
    bins = defaultdict(Counter)
    for r in predictions:
        if r["timestamp"] >= serie:
            b = bins[int((r["timestamp"] - serie) // DAY)]
            b["mails"] += 1
            if r.get("method", "").startswith("llm"):
                b["llm"] += 1
                b["llm_spam"] += r["action"] == "SPAM"
    print("jour    mails   LLM   part  LLM spam")
    for i in sorted(bins):
        b = bins[i]
        print(f"{when(serie + i * DAY)[:5]}   {b['mails']:5} {b['llm']:5} {100 * b['llm'] / b['mails']:5.0f} %  {b['llm_spam']:5}")


def decisions(predictions, since: float):
    print(f"\n== Décisions depuis {when(since)}")
    counts = Counter((r.get("method"), r["action"]) for r in predictions if r["timestamp"] >= since)
    for (method, action), n in counts.most_common():
        print(f"  {method:20} {action:5} {n}")


def pending():
    queue = load_json(DATA / "pending_llm_spam.json", {})
    print(f"\n== Confirmations tacites en attente : {len(queue)}")
    for v in sorted(queue.values(), key=lambda v: v["decided_at"]):
        e = v["email_data"]
        auth = " [auth]" if e.get("rspamd_auth") else ""
        print(f"  {when(v['decided_at'])} {v['account']:5} {e.get('sender_email')} | {subject(e.get('subject'))}{auth}")


def corpus():
    samples = load_json(DATA / "training_data.json", [])
    spams = sum(1 for s in samples if s["is_spam"])
    auth = sum(1 for s in samples if s["email_data"].get("rspamd_auth"))
    print(f"\n== Corpus : {len(samples)} mails dont {spams} spams ; avec rspamd_auth : {auth}")


def corrections(since: float):
    history = load_json(DATA / "sender_feedback_history.json", {})
    rows = []
    for sender, v in history.items():
        ts = v.get("last_updated") or v.get("last_seen")
        if ts and float(ts) >= since:
            rows.append((float(ts), sender, v))
    print(f"\n== Corrections de l'utilisateur : {len(rows)} expéditeurs (cumul légitime / spam)")
    for ts, sender, v in sorted(rows):
        ham = v.get("ham_count", 0) + v.get("whitelist_count", 0)
        spam = v.get("spam_count", 0) + v.get("blacklist_count", 0)
        print(f"  {when(ts)} {sender}  {ham} / {spam}")


def errors(since: float):
    counts = Counter()
    first = {}
    for path in sorted(LOGS.glob("pyantispam.log*"), reverse=True):
        for line in path.open(encoding="utf-8", errors="replace"):
            if " - ERROR - " not in line and " - CRITICAL - " not in line:
                continue
            try:
                ts = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                continue
            if ts >= since:
                msg = line.split(" - ", 3)[-1].strip()[:110]
                counts[msg] += 1
                first.setdefault(msg, ts)
    print(f"\n== Erreurs : {sum(counts.values())}")
    for msg, n in counts.most_common(15):
        print(f"  {n:3} × (dès {when(first[msg])}) {msg}")


def llm_shadow(title: str, log_name: str, since: float, feedback, archived: bool = False):
    rows = load_jsonl(LOGS / log_name)
    if archived and not rows:
        return
    asked = [r for r in rows if r.get("shadow_reason")]
    print(f"\n== {title} : {len(rows)} lignes, {len(asked)} jugées en fantôme")
    disagree = [r for r in asked if r["shadow_action"] != r["real_action"]]
    right = Counter()
    for r in disagree:
        user = feedback.get(r["fingerprint"])
        if user:
            right["fantôme" if user == r["shadow_action"] else "vrai LLM"] += 1
    print(f"  désaccords (depuis le début) : {len(disagree)} ; corrigés : {dict(right) or 'aucun'}")
    if archived:
        return
    for r in disagree:
        user = feedback.get(r["fingerprint"])
        verdict = "non corrigé"
        if user:
            verdict = f"utilisateur : {user} → {'fantôme' if user == r['shadow_action'] else 'vrai LLM'} a raison"
        extra = f" ({r['n_examples']} ex.)" if r.get("n_examples") else ""
        print(f"  {when(r['timestamp'])} {r['account']:5} {r['sender_email']} réel {r['real_action']}"
              f" / fantôme {r['shadow_action']}{extra} ; {verdict}")
    recent = [r for r in rows if r["timestamp"] >= since and r not in disagree]
    print(f"  accords ou non consultés depuis {when(since)} : {len(recent)}")


def lookalike_shadow(since: float):
    rows = load_jsonl(LOGS / "lookalike_shadow_log.jsonl")
    strong = [r for r in rows if r.get("strong")]
    print(f"\n== Fantôme sosies : {len(rows)} lignes, {len(strong)} alertes fortes (depuis le début)")
    for r in rows:
        if r["timestamp"] >= since or r.get("strong"):
            tag = "FORTE" if r.get("strong") else "frère"
            print(f"  {when(r['timestamp'])} {tag:5} {r['sender_email']} imite {r['imitates']} ({r['kind']})"
                  f" dkim {r.get('dkim')} dmarc {r.get('dmarc')} ; réel {r['real_action']} ({r['real_method']})")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--depuis", help="début du point, format AAAA-MM-JJ HH:MM (défaut : il y a 24 h)")
    parser.add_argument("--serie", default="2026-10-05 09:40", help="début de la série de la part du LLM")
    args = parser.parse_args()
    fmt = "%Y-%m-%d %H:%M"
    since = datetime.strptime(args.depuis, fmt).timestamp() if args.depuis else time.time() - DAY
    serie = datetime.strptime(args.serie, fmt).timestamp()

    cache = load_json(DATA / "llm_cache.json", {})
    feedback = {fp: v["action"] for fp, v in cache.items()
                if isinstance(v, dict) and v.get("method") == "user_feedback"}
    predictions = load_jsonl(LOGS / "prediction_log.jsonl")

    print(f"Point du {when(time.time())}, depuis {when(since)}\n")
    llm_share(predictions, serie)
    decisions(predictions, since)
    pending()
    corpus()
    corrections(since)
    errors(since)
    llm_shadow("Fantôme LLM + auth + historique + exemples", "llm_context_shadow_log.jsonl", since, feedback)
    llm_shadow("Ancien fantôme historique (archivé le 27/10)", "llm_history_shadow_log.jsonl", since, feedback,
               archived=True)
    lookalike_shadow(since)


if __name__ == "__main__":
    main()
