"""
Assignment 11 — Monitoring & Alerts.

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def default_metrics_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "metrics.json")


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    def record(self, *, blocked: bool, layer: str | None = None, judge_failed: bool | None = None):
        """Cập nhật bộ đếm sau MỖI request (pipeline gọi hàm này)."""
        self.total_requests += 1
        if blocked:
            self.blocked_requests += 1
        if layer == "rate_limiter":
            self.rate_limit_hits += 1
        if judge_failed is not None:
            self.judge_checks += 1
            if judge_failed:
                self.judge_fails += 1

    def check_metrics(self) -> list[Alert]:
        """Tính lại các tỉ lệ và sinh Alert cho chỉ số vượt ngưỡng.

        Danh sách alert được tính lại từ đầu mỗi lần gọi (không cộng dồn),
        nên gọi nhiều lần cũng không bị trùng alert.
        """
        snap = self.snapshot()
        rules = [
            # (tên chỉ số, giá trị hiện tại, ngưỡng, có dữ liệu không, thông điệp)
            (
                "block_rate", snap["block_rate"], self.block_rate_threshold,
                self.total_requests > 0,
                "Tỉ lệ chặn vượt ngưỡng: có thể đang bị tấn công hàng loạt, "
                "hoặc filter đang chặn nhầm người dùng thật.",
            ),
            (
                "rate_limit_hits", self.rate_limit_hits, self.rate_limit_hit_threshold,
                True,
                "Nhiều request bị rate limit: nghi spam / tấn công tốn chi phí.",
            ),
            (
                "judge_fail_rate", snap["judge_fail_rate"], self.judge_fail_rate_threshold,
                self.judge_checks > 0,
                "LLM judge đánh UNSAFE nhiều: cần xem lại output của model.",
            ),
        ]
        self.alerts = [
            Alert(metric=name, value=round(value, 3), threshold=threshold, message=msg)
            for name, value, threshold, has_data, msg in rules
            if has_data and value >= threshold and value > 0
        ]
        return self.alerts

    def export_json(self, filepath: str | None = None):
        """Ghi metrics + alerts ra <repo>/outputs/metrics.json (mặc định)."""
        self.check_metrics()
        path = Path(filepath or default_metrics_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.snapshot(), f, ensure_ascii=False, indent=2)
        return str(path)

    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }
