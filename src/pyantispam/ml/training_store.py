"""Safe read/write for data/training_data.json.

Two rules, both learned the hard way:
- Writes are atomic (temp file in the same directory, then os.replace), so a
  process killed mid-write can never leave a truncated file behind.
- If the existing file exists but can't be parsed, we never treat it as empty
  and overwrite it. We move it aside and refuse to write, so accumulated
  samples aren't silently replaced by whatever batch happens to be in memory.
"""

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def load_samples(path: Path) -> Optional[List[Dict[str, Any]]]:
    """Return the stored samples, [] if no file yet, or None if the file exists but is unreadable."""
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else None
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        aside = path.with_name(f"{path.name}.unreadable-{int(time.time())}")
        try:
            os.replace(path, aside)
        except OSError:
            pass
        logger.error(f"training data unreadable ({e}); moved aside to {aside.name}, not overwriting")
        return None


def write_samples_atomic(path: Path, samples: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(samples, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)  # mkstemp creates 0600, which would lock out the host user
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
