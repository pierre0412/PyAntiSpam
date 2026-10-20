"""Shadow classifier for rspamd: observes every email's rspamd verdict
without ever influencing the real spam/keep decision.

This is "mode fantôme" from the project roadmap - rspamd scores each email
exactly like it would in production, the result is logged for future
calibration analysis, and that's it. Nothing here can move, delete, or
reclassify a message. Any failure (rspamd down, timeout, bad response) is
swallowed and simply means "no shadow verdict this time" - never an error
that could affect the real pipeline.
"""

import logging
import os
from typing import Any, Dict, Optional, TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from ..config import ConfigManager


# rspamd symbol -> verdict, per mechanism; anything else is "none" (absent or not checked).
_DKIM = {"R_DKIM_ALLOW": "pass", "R_DKIM_REJECT": "fail", "R_DKIM_PERMFAIL": "fail", "R_DKIM_TEMPFAIL": "fail"}
_DMARC = {"DMARC_POLICY_ALLOW": "pass", "DMARC_POLICY_ALLOW_WITH_FAILURES": "pass",
          "DMARC_POLICY_REJECT": "fail", "DMARC_POLICY_QUARANTINE": "fail", "DMARC_POLICY_SOFTFAIL": "fail"}
# Without the connecting IP (we post the stored message), rspamd's SPF is mostly "none".
_SPF = {"R_SPF_ALLOW": "pass", "R_SPF_FAIL": "fail", "R_SPF_SOFTFAIL": "softfail"}


def auth_summary(symbols: Dict[str, Any]) -> Dict[str, Any]:
    """What rspamd verified about the sender, small enough to store with the email:
    {"dkim", "dmarc", "spf": "pass"|"fail"|"softfail"|"none", "dkim_domains", "dmarc_domain"}.
    Options look like "picard.fr:s=selector" (DKIM) and ["picard.fr", "quarantine"] (DMARC)."""
    def verdict(table: Dict[str, str]) -> str:
        found = [v for name, v in table.items() if name in symbols]
        return "pass" if "pass" in found else (found[0] if found else "none")

    dkim = symbols.get("R_DKIM_ALLOW", {}).get("options") or []
    dmarc = symbols.get("DMARC_POLICY_ALLOW", {}).get("options") or []
    return {
        "dkim": verdict(_DKIM),
        "dmarc": verdict(_DMARC),
        "spf": verdict(_SPF),
        "dkim_domains": [str(o).split(":")[0].strip().lower() for o in dkim],
        "dmarc_domain": str(dmarc[0]).strip().lower() if dmarc else None,
    }


class RspamdShadowClassifier:
    """Calls rspamd's /checkv2 and returns its verdict, read-only."""

    def __init__(self, config: "ConfigManager"):
        self.logger = logging.getLogger(__name__)
        self.enabled = config.get("rspamd.enabled", False)
        self.url = config.get("rspamd.url", "http://rspamd:11334").rstrip("/")
        self.timeout = config.get("rspamd.timeout", 10)
        password_env = config.get("rspamd.password_env", "RSPAMD_PASSWORD")
        self.password = os.getenv(password_env)

        if self.enabled and not self.password:
            self.logger.warning(
                f"rspamd shadow mode enabled but {password_env} is not set - disabling"
            )
            self.enabled = False

    def is_enabled(self) -> bool:
        return self.enabled

    def check(self, raw_message: bytes) -> Optional[Dict[str, Any]]:
        """Return a compact rspamd verdict, or None if unavailable for any reason."""
        if not self.enabled or not raw_message:
            return None

        try:
            response = requests.post(
                f"{self.url}/checkv2",
                headers={"Password": self.password},
                data=raw_message,
                timeout=self.timeout,
            )
            response.raise_for_status()
            result = response.json()

            symbols = result.get("symbols", {})
            top_symbols = sorted(
                (
                    {"name": name, "score": s.get("metric_score", 0)}
                    for name, s in symbols.items()
                    if s.get("metric_score", 0) != 0
                ),
                key=lambda s: -abs(s["score"]),
            )[:5]

            return {
                "score": result.get("score"),
                "action": result.get("action"),
                "top_symbols": top_symbols,
                "auth": auth_summary(symbols),
            }
        except Exception as e:
            self.logger.debug(f"rspamd shadow check failed (non-blocking): {e}")
            return None

    def attach_auth(self, email_data: Dict[str, Any], raw_message: Optional[bytes]) -> Optional[Dict[str, Any]]:
        """Score the message and store rspamd's authentication verdict in
        email_data["rspamd_auth"], so it travels with the email into the
        prediction record, the tacit-confirmation queue and training_data (future
        RF features). Observation only: nothing reads it to decide. Returns the
        full verdict (reused by the shadow logs), or None if rspamd is unavailable."""
        verdict = self.check(raw_message) if raw_message else None
        if verdict:
            email_data["rspamd_auth"] = verdict["auth"]
        return verdict

    def learn_spam(self, raw_message: bytes) -> bool:
        """Teach rspamd this message is spam. Only call this from real human
        feedback (blacklist/is_spam folders) - never from an ML/LLM verdict,
        which isn't independently verified. Best-effort: returns False on any
        failure (down, timeout, already learned), never raises.
        """
        return self._learn(raw_message, "learnspam")

    def learn_ham(self, raw_message: bytes) -> bool:
        """Teach rspamd this message is ham. Same caveats as learn_spam."""
        return self._learn(raw_message, "learnham")

    def _learn(self, raw_message: bytes, endpoint: str) -> bool:
        if not self.enabled or not raw_message:
            return False
        try:
            response = requests.post(
                f"{self.url}/{endpoint}",
                headers={"Password": self.password},
                data=raw_message,
                timeout=self.timeout,
            )
            return response.ok
        except Exception as e:
            self.logger.debug(f"rspamd {endpoint} failed (non-blocking): {e}")
            return False
