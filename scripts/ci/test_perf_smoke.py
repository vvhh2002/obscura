#!/usr/bin/env python3
"""Regression tests for the PR performance threshold policy."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("perf_smoke.py")
SPEC = importlib.util.spec_from_file_location("perf_smoke", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {MODULE_PATH}")
PERF_SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PERF_SMOKE)


class PerformanceThresholdTests(unittest.TestCase):
    def test_exactly_ten_percent_is_allowed(self) -> None:
        self.assertEqual(
            PERF_SMOKE.performance_regression_failures("fixture", 1.10, 1.10),
            [],
        )

    def test_any_latency_ratio_above_ten_percent_fails(self) -> None:
        self.assertEqual(
            PERF_SMOKE.performance_regression_failures("fixture", 1.100001, 1.0),
            ["fixture latency is 1.100001x the base"],
        )

    def test_any_rss_ratio_above_ten_percent_fails(self) -> None:
        self.assertEqual(
            PERF_SMOKE.performance_regression_failures("fixture", 1.0, 1.100001),
            ["fixture RSS is 1.100001x the base"],
        )


if __name__ == "__main__":
    unittest.main()
