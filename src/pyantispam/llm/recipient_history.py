"""The recipient's own verdicts on a sender, as a line of context for the LLM.

Built from data/sender_feedback_history.json, which only the user's
reclassifications feed (never the RF, the LLM or tacit confirmation), so the
LLM can never talk itself into trusting a sender. Counted per registrable
domain (news.picard.fr and informations.picard.fr are both picard.fr), except
on shared sending platforms where one domain serves unrelated senders.

Given only when rspamd verified the sender's domain (aligned DMARC pass, or a
valid DKIM signature from that domain): a spoofed From inherits nothing.
Same for the examples block: earlier emails from the same sender that the user
labelled, read from data/training_data.json (read only).
"""

import hashlib
import json
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set, Tuple

HISTORY_FILE = Path("data/sender_feedback_history.json")
TRAINING_FILE = Path("data/training_data.json")

# Counts shown to the LLM are capped: it only needs the order of magnitude, and
# counters inherited from before October 2026 run into the hundreds (654 spams
# for one Klarna address) without being that many decisions.
COUNT_CAP = 10
MAX_EXAMPLES = 5

# Public suffixes with a second level (picard.co.uk -> picard.co.uk, not co.uk).
_SECOND_LEVEL = {"co", "com", "org", "net", "gouv", "asso", "ac", "gov", "edu"}

# Shared sending platforms and consumer mailboxes, counted per exact address
# instead of per domain: one domain there serves unrelated senders.
SHARED_SENDER_DOMAINS = {
    # E-mailing platforms
    "shopifyemail.com", "mjt.lu", "mailjet.com", "mailchimpapp.net", "mcsv.net", "mcdlv.net",
    "sendinblue.com", "brevo.com", "sendgrid.net", "amazonses.com", "mailgun.org",
    "hubspotemail.net", "klaviyomail.com", "sparkpostmail.com", "odoo.com",
    # Consumer mailboxes
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "hotmail.com", "hotmail.fr",
    "outlook.com", "outlook.fr", "live.com", "live.fr", "msn.com", "icloud.com", "me.com",
    "orange.fr", "wanadoo.fr", "free.fr", "sfr.fr", "neuf.fr", "laposte.net", "bbox.fr",
    "aol.com", "gmx.fr", "gmx.com", "protonmail.com", "proton.me",
}


def base_domain(domain: str) -> str:
    """Registrable domain: informations.picard.fr -> picard.fr."""
    parts = (domain or "").lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _sender_domain(email_data: Dict[str, Any]) -> str:
    return (email_data.get("sender_domain")
            or (email_data.get("sender_email") or "").split("@")[-1]).lower()


def is_verified(email_data: Dict[str, Any]) -> bool:
    """True when rspamd validated DMARC or DKIM for the From's registrable domain
    (email_data["rspamd_auth"], set by RspamdShadowClassifier.attach_auth)."""
    auth = email_data.get("rspamd_auth") or {}
    dkim_domains: Iterable[str] = auth.get("dkim_domains") or []
    dmarc_domain: Optional[str] = auth.get("dmarc_domain")
    dom = base_domain(_sender_domain(email_data))
    if not dom:
        return False
    if dmarc_domain and base_domain(dmarc_domain) == dom:
        return True
    return any(base_domain(d) == dom for d in dkim_domains)


def _sender_key(email_data: Dict[str, Any]) -> Tuple[str, bool]:
    """(registrable domain, False), or (exact address, True) on shared platforms."""
    dom = base_domain(_sender_domain(email_data))
    if dom in SHARED_SENDER_DOMAINS:
        return (email_data.get("sender_email") or "").lower(), True
    return dom, False


def history_counts(email_data: Dict[str, Any]) -> Tuple[str, int, int]:
    """(who, legitimate, spam) as the recipient marked them, uncapped."""
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
    except (OSError, ValueError):
        history = {}

    who, shared = _sender_key(email_data)
    ham = spam = 0
    for entry in history.values():
        if shared:
            match = (entry.get("sender_email") or "").lower() == who
        else:
            match = base_domain(entry.get("sender_domain")
                                or (entry.get("sender_email") or "").split("@")[-1]) == who
        if match:
            ham += entry.get("ham_count", 0) + entry.get("whitelist_count", 0)
            spam += entry.get("spam_count", 0) + entry.get("blacklist_count", 0)
    return who, ham, spam


def is_validated(email_data: Dict[str, Any]) -> bool:
    """The recipient kept emails from this domain and never marked one as spam.
    Never on shared platforms: a validated Gmail address says nothing of the next one."""
    if _sender_key(email_data)[1]:
        return False
    _, ham, spam = history_counts(email_data)
    return ham > 0 and spam == 0


def history_line(email_data: Dict[str, Any]) -> str:
    """'Recipient history for picard.fr: 4 emails marked legitimate, 0 marked spam...'
    or "" when the recipient never reviewed this sender. Caller checks is_verified first."""
    who, ham, spam = history_counts(email_data)
    if ham + spam == 0:
        return ""
    cap = lambda n: f"more than {COUNT_CAP}" if n > COUNT_CAP else str(n)
    return (f"Recipient history for {who}: {cap(ham)} emails marked legitimate, "
            f"{cap(spam)} marked spam by the recipient")


def fingerprint(email_data: Dict[str, Any]) -> str:
    """Same fingerprint as EmailProcessor._get_email_fingerprint."""
    content = (f"{email_data.get('sender_email', '')}{email_data.get('subject', '')}"
               f"{(email_data.get('body') or '')[:200]}")
    return hashlib.md5(content.encode("utf-8")).hexdigest()


def _decoded(subject: Any) -> str:
    try:
        return " ".join(str(make_header(decode_header(subject or ""))).split())
    except Exception:
        return " ".join(str(subject or "").split())


def _timestamp(email_data: Dict[str, Any]) -> Optional[float]:
    try:
        return parsedate_to_datetime(email_data.get("date")).timestamp()
    except Exception:
        return None


def examples_block(email_data: Dict[str, Any], user_fingerprints: Set[str]) -> str:
    """Up to MAX_EXAMPLES earlier emails from the same sender (domain, or exact address
    on shared platforms), each with the verdict the user gave it, most recent first.
    Only emails the user labelled (user_fingerprints: user_feedback entries of the
    LLM cache), never tacit confirmations nor the email being judged. "" if none."""
    try:
        with open(TRAINING_FILE, "r", encoding="utf-8") as f:
            samples = json.load(f)
    except (OSError, ValueError):
        return ""

    key = _sender_key(email_data)
    own = fingerprint(email_data)
    before = _timestamp(email_data) or float("inf")
    found = []
    for sample in samples:
        past = sample.get("email_data") or {}
        fp = fingerprint(past)
        t = _timestamp(past)
        if fp in user_fingerprints and fp != own and t and t < before and _sender_key(past) == key:
            found.append((t, sample))
    if not found:
        return ""

    lines = ["Previous emails from this sender, with the recipient's own verdict (most recent first):"]
    for _, sample in sorted(found, key=lambda x: x[0], reverse=True)[:MAX_EXAMPLES]:
        past = sample["email_data"]
        body = " ".join(str(past.get("body") or "").split())[:300]
        verdict = "spam" if sample.get("is_spam") else "legitimate"
        lines.append(f"- [{verdict}] Subject: {_decoded(past.get('subject'))[:120]} | Excerpt: {body}")
    return "\n".join(lines)
