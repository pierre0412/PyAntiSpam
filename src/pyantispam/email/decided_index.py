"""Inbox emails whose automatic KEEP verdict is final, indexed by IMAP UID.

An email kept by an automatic verdict is never judged again: a retrain or a
config change must not pull out of the inbox a mail that has sat there for
days. Only the user moves it afterwards, and a mail going through a feedback
folder comes back with a new UID, so it is judged afresh.

Keyed by "account/folder"; reset when the folder's UIDVALIDITY changes (UIDs
are then meaningless), pruned each cycle to the UIDs still in the folder.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Optional, Set

DECIDED_FILE = Path("data/decided_uids.json")


def _read_all() -> dict:
    try:
        with open(DECIDED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}


def load(account: str, folder: str, uidvalidity: Optional[str]) -> Set[str]:
    """UIDs already judged final; empty if unknown or UIDVALIDITY changed."""
    if not uidvalidity:
        return set()
    entry = _read_all().get(f"{account}/{folder}", {})
    if entry.get("uidvalidity") != uidvalidity:
        return set()
    return set(entry.get("uids", []))


def save(account: str, folder: str, uidvalidity: Optional[str], uids: Set[str]) -> None:
    """Atomically replace this folder's entry, leaving the other folders as they are."""
    if not uidvalidity:
        return
    data = _read_all()
    data[f"{account}/{folder}"] = {
        "uidvalidity": uidvalidity,
        "uids": sorted(uids, key=int),
    }
    DECIDED_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=DECIDED_FILE.parent, prefix=f".{DECIDED_FILE.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)  # mkstemp creates 0600, which would lock out the host user
        os.replace(tmp, DECIDED_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
