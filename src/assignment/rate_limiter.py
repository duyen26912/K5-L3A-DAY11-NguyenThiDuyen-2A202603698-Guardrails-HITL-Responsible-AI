"""
Assignment 11 — Rate Limiter (sliding window, theo từng user).

Chặn spam / tấn công chi phí — loại lạm dụng mà các lớp guardrail nội dung
không xử lý được. Đứng ĐẦU pipeline vì đây là kiểm tra rẻ nhất.

Ý tưởng sliding window:
  - Mỗi user có một hàng đợi (deque) chứa thời điểm các request đã được cho qua.
  - Request mới tới: bỏ các mốc thời gian cũ hơn ``window_seconds`` ở đầu hàng.
  - Còn ít hơn ``max_requests`` mốc trong cửa sổ -> cho qua và ghi mốc mới.
  - Ngược lại -> chặn, báo số giây phải chờ tới khi mốc cũ nhất hết hạn.
"""
from __future__ import annotations

from collections import defaultdict, deque
import time
from typing import Callable

from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds."""

    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: int = 60,
        clock: Callable[[], float] = time.monotonic,
    ):
        super().__init__(name="rate_limiter")
        if max_requests < 1 or window_seconds <= 0:
            raise ValueError("max_requests >= 1 và window_seconds > 0")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # monotonic: không bị ảnh hưởng khi đồng hồ hệ thống bị chỉnh
        self._clock = clock
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    # ------------------------------------------------------------------ helpers
    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    def _evict_expired(self, window: deque, now: float) -> None:
        """Bỏ các mốc đã nằm ngoài cửa sổ [now - window_seconds, now]."""
        cutoff = now - self.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()

    def retry_after(self, user_id: str) -> float:
        """Số giây user phải chờ trước khi được gửi tiếp (0 nếu còn quota)."""
        window = self.user_windows[user_id]
        now = self._clock()
        self._evict_expired(window, now)
        if len(window) < self.max_requests:
            return 0.0
        return max(0.0, window[0] + self.window_seconds - now)

    def reset(self, user_id: str | None = None) -> None:
        """Xóa cửa sổ của một user (hoặc tất cả). Dùng giữa các nhóm test."""
        if user_id is None:
            self.user_windows.clear()
        else:
            self.user_windows.pop(user_id, None)

    # ----------------------------------------------------------------- callback
    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow."""
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"

        wait = self.retry_after(user_id)
        if wait > 0:
            self.blocked_count += 1
            return self._block_response(
                f"Too many requests: limit is {self.max_requests} per "
                f"{self.window_seconds}s. Please try again in {int(wait) + 1}s."
            )

        self.user_windows[user_id].append(self._clock())
        return None
