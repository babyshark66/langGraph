"""Nhà máy tạo LLM (OpenAI-compatible) — tự chuyển sang heuristic khi thiếu key.

- Có ``NETDOCTOR_LLM_API_KEY`` → dùng ``ChatOpenAI`` (hỗ trợ mọi server
  tương thích OpenAI: OpenAI, DeepSeek, vLLM, Ollama...).
- Không có key / ``offline=True`` → trả về ``None``, các node sẽ dùng
  ``analyzers.heuristic_*`` để vẫn hoạt động được (an toàn, không tốn phí).
"""

from __future__ import annotations

import logging

from .config import Settings

logger = logging.getLogger(__name__)


def build_llm(settings: Settings | None = None, offline: bool = False):
    """Trả về ChatOpenAI hoặc None (heuristic mode)."""
    settings = settings or Settings()
    if offline:
        logger.info("Chế độ offline: không dùng LLM, chỉ heuristic.")
        return None
    if not settings.llm_api_key:
        logger.warning(
            "Chưa cấu hình NETDOCTOR_LLM_API_KEY — chuyển sang chế độ heuristic."
        )
        return None
    from langchain_openai import ChatOpenAI

    kwargs: dict = {
        "model": settings.llm_model,
        "api_key": settings.llm_api_key,
        "temperature": 0,
        "timeout": 60,
        "max_retries": 2,
    }
    if settings.llm_base_url:
        kwargs["base_url"] = settings.llm_base_url
    return ChatOpenAI(**kwargs)
