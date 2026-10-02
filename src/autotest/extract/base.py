"""Extractor abstraction (OCP): new secret sources plug in without touching pipeline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .mobsf_extract import extract_candidates

# {secret_type, value, preview, provenance, optional paired_secret}
ExtractorResult = dict[str, Any]


class Extractor(ABC):
    name: str = "base"

    @abstractmethod
    def extract(self, report: dict[str, Any]) -> list[ExtractorResult]: ...


class MobSFExtractor(Extractor):
    name = "mobsf"

    def extract(self, report: dict[str, Any]) -> list[ExtractorResult]:
        return extract_candidates(report)


EXTRACTORS: list[Extractor] = [MobSFExtractor()]


def run_extractors(report: dict[str, Any]) -> list[tuple[str, ExtractorResult]]:
    """Run every registered extractor; assign stable cand-NNN ids in order."""
    merged: list[ExtractorResult] = []
    seen: set[tuple[str, str]] = set()
    for extractor in EXTRACTORS:
        for cand in extractor.extract(report):
            key = (cand["secret_type"], cand["value"])
            if key not in seen:
                seen.add(key)
                merged.append(cand)
    return [(f"cand-{i + 1:03d}", cand) for i, cand in enumerate(merged)]
