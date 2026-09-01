#!/usr/bin/env python3
"""Regression tests for main's PR performance threshold policy."""

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
    def test_exact_thresholds_are_allowed(self) -> None:
        self.assertEqual(
            PERF_SMOKE.performance_regression_failures(
                "fixture",
                PERF_SMOKE.LATENCY_FAILURE_RATIO,
                PERF_SMOKE.LATENCY_FAILURE_DELTA_MS + 1,
                PERF_SMOKE.RSS_FAILURE_RATIO,
                PERF_SMOKE.RSS_FAILURE_DELTA_KIB + 1,
            ),
            [],
        )

    def test_ratio_without_absolute_delta_is_allowed(self) -> None:
        self.assertEqual(
            PERF_SMOKE.performance_regression_failures(
                "fixture",
                PERF_SMOKE.LATENCY_FAILURE_RATIO + 0.01,
                PERF_SMOKE.LATENCY_FAILURE_DELTA_MS,
                PERF_SMOKE.RSS_FAILURE_RATIO + 0.01,
                PERF_SMOKE.RSS_FAILURE_DELTA_KIB,
            ),
            [],
        )

    def test_latency_above_both_guards_fails(self) -> None:
        self.assertEqual(
            PERF_SMOKE.performance_regression_failures(
                "fixture",
                PERF_SMOKE.LATENCY_FAILURE_RATIO + 0.01,
                PERF_SMOKE.LATENCY_FAILURE_DELTA_MS + 1,
                1.0,
                0.0,
            ),
            ["fixture latency is 1.21x the base"],
        )

    def test_rss_above_both_guards_fails(self) -> None:
        self.assertEqual(
            PERF_SMOKE.performance_regression_failures(
                "fixture",
                1.0,
                0.0,
                PERF_SMOKE.RSS_FAILURE_RATIO + 0.01,
                PERF_SMOKE.RSS_FAILURE_DELTA_KIB + 1,
            ),
            ["fixture RSS is 1.16x the base"],
        )


if __name__ == "__main__":
    unittest.main()
