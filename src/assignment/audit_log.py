"""
Assignment 11 — Audit Log.

Ghi lại MỌI tương tác để điều tra về sau. Lớp này không tự chặn gì —
các lớp khác bắt tấn công, audit log giúp xem lại được chuyện gì đã xảy ra.

Cách dùng (pipeline gọi như một "side observer"):
    audit.record_input(user_id=..., text=..., request_id=...)
    ... chạy agent ...
    audit.record_output(user_id=..., text=..., blocked=..., layer=..., request_id=...)
    audit.export_json()
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

PREVIEW_CHARS = 500  # cắt bớt output dài để file log không phình to


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _preview(text: str | None) -> str:
    text = text or ""
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS] + "…"


class AuditLogPlugin:
    """Framework-agnostic audit logger."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        # request đang mở (đã có input, chưa có output): key -> entry tạm
        self._pending: dict[str, dict] = {}
        self._seq = 0

    def _key(self, user_id: str, request_id: str | None) -> str:
        return request_id if request_id else f"user:{user_id}"

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Lưu input + mốc bắt đầu, chờ record_output ghép cặp."""
        self._pending[self._key(user_id, request_id)] = {
            "request_id": request_id,
            "user_id": user_id,
            "started_at": utc_now_iso(),
            "input": text,
            "input_chars": len(text or ""),
            "_t0": time.perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Ghép output với input tương ứng, tính latency, thêm vào self.logs."""
        entry = self._pending.pop(self._key(user_id, request_id), None)
        if entry is None:
            # output không có input đi kèm -> vẫn ghi, đánh dấu để dễ phát hiện
            entry = {
                "request_id": request_id,
                "user_id": user_id,
                "started_at": None,
                "input": None,
                "input_chars": 0,
                "_t0": None,
            }

        t0 = entry.pop("_t0")
        self._seq += 1
        entry.update(
            {
                "seq": self._seq,
                "finished_at": utc_now_iso(),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2) if t0 else None,
                "blocked": bool(blocked),
                "layer": layer,
                "output": _preview(text),
            }
        )
        self.logs.append(entry)
        return entry

    def summary(self) -> dict:
        """Thống kê nhanh: tổng request, số bị chặn theo từng lớp."""
        by_layer: dict[str, int] = {}
        for e in self.logs:
            if e["blocked"]:
                by_layer[e["layer"] or "unknown"] = by_layer.get(e["layer"] or "unknown", 0) + 1
        return {
            "total": len(self.logs),
            "blocked": sum(by_layer.values()),
            "blocked_by_layer": by_layer,
        }

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, ensure_ascii=False, indent=2)
        return str(path)
