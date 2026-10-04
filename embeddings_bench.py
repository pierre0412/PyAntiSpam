#!/usr/bin/env python3
"""Mesure latence et mémoire d'inférence d'un modèle d'embeddings. Lecture seule."""

import os
import resource
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from embeddings_pilot import EMBEDDING_MODEL, build_embedding_text, load_real_samples  # noqa: E402

from sentence_transformers import SentenceTransformer  # noqa: E402


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def main():
    print(f"modele: {EMBEDDING_MODEL} | cpu_threads: {os.cpu_count()}")
    print(f"memoire avant chargement: {rss_mb():.0f} Mo")

    t0 = time.time()
    model = SentenceTransformer(EMBEDDING_MODEL)
    print(f"chargement: {time.time() - t0:.1f} s | memoire apres chargement: {rss_mb():.0f} Mo")

    texts = [build_embedding_text(s["email_data"]) for s in load_real_samples()][:60]
    model.encode(texts[:3], show_progress_bar=False)  # échauffement

    times = []
    for t in texts:
        t1 = time.time()
        model.encode([t], show_progress_bar=False)
        times.append((time.time() - t1) * 1000)
    times.sort()
    print(f"latence par mail (n={len(times)}): mediane {times[len(times)//2]:.0f} ms, "
          f"p90 {times[int(len(times)*0.9)]:.0f} ms, max {times[-1]:.0f} ms")
    print(f"memoire pic: {rss_mb():.0f} Mo")


if __name__ == "__main__":
    main()
