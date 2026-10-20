"""The recipient's own verdicts on a sender, as a line of context for the LLM.

Built from data/sender_feedback_history.json, which only the user's
reclassifications feed (never the RF, the LLM or tacit confirmation), so the
LLM can never talk itself into trusting a sender. Counted per registrable
domain (news.picard.fr and informations.picard.fr are both picard.fr), except
on shared sending platforms where one domain serves unrelated senders.

Given only when rspamd verified the sender's domain (aligned DMARC pass, or a
valid DKIM signature from that domain): a spoofed From inherits nothing.
"""

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

HISTORY_FILE = Path("data/sender_feedback_history.json")

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


def is_verified(email_data: Dict[str, Any], dkim_domains: Iterable[str],
                dmarc_domain: Optional[str]) -> bool:
    """True when rspamd validated DMARC or DKIM for the From's registrable domain."""
    dom = base_domain(_sender_domain(email_data))
    if not dom:
        return False
    if dmarc_domain and base_domain(dmarc_domain) == dom:
        return True
    return any(base_domain(d) == dom for d in dkim_domains)


def history_line(email_data: Dict[str, Any]) -> str:
    """'Recipient history for picard.fr: 4 emails marked legitimate, 0 marked spam...'
    or "" when the recipient never reviewed this sender. Caller checks is_verified first."""
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
    except (OSError, ValueError):
        return ""

    sender = (email_data.get("sender_email") or "").lower()
    dom = base_domain(_sender_domain(email_data))
    shared = dom in SHARED_SENDER_DOMAINS
    ham = spam = 0
    for entry in history.values():
        if shared:
            match = (entry.get("sender_email") or "").lower() == sender
        else:
            match = base_domain(entry.get("sender_domain")
                                or (entry.get("sender_email") or "").split("@")[-1]) == dom
        if match:
            ham += entry.get("ham_count", 0) + entry.get("whitelist_count", 0)
            spam += entry.get("spam_count", 0) + entry.get("blacklist_count", 0)

    if ham + spam == 0:
        return ""
    who = sender if shared else dom
    return f"Recipient history for {who}: {ham} emails marked legitimate, {spam} marked spam by the recipient"
