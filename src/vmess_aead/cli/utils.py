import asyncio
from collections.abc import Coroutine, Iterable
from dataclasses import dataclass
from datetime import timedelta
from logging import getLogger
from secrets import compare_digest
from typing import Any, Literal

logger = getLogger(__name__)


@dataclass(frozen=True)
class TransferSpeed:
    elapsed: float
    transferred: int

    unit_format: Literal["bits", "bytes"] = "bytes"
    """display unit format, either bits or bytes per second"""
    si: bool = False
    """use SI unit (1 KB = 1000 bytes) or IEC unit (1 KiB = 1024 bytes)"""

    @staticmethod
    def _digit_scale(value: float, base: int) -> str:
        scales = ["", "K", "M", "G", "T", "P", "E", "Z", "Y"]
        scale = 0
        while value >= base:
            value /= base
            scale += 1
        return f"{value:.2f} {scales[scale]}"

    @property
    def human_readable_size(self) -> str:
        text = self._digit_scale(self.transferred, 1024 if not self.si else 1000)
        text += "B" if not self.si else "iB"
        return text

    @property
    def human_readable_rate(self) -> str:
        rate = self.transferred / self.elapsed
        text = self._digit_scale(
            rate * 8 if self.unit_format == "bits" else rate,
            1024 if not self.si else 1000,
        )
        text += (
            "bps" if self.unit_format == "bits" else "B/s" if not self.si else "iB/s"
        )
        return text

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.__str__()}>"

    def __str__(self) -> str:
        text = (
            f"in {timedelta(seconds=self.elapsed)}"
            f", {self.human_readable_size} transferred"
            f", at {self.human_readable_rate} rate"
        )
        return text


def compare_iterable(actual_iter: Iterable[str], expected_iter: Iterable[str]) -> bool:
    """Compare two iterable of strings in constant time."""
    return all(
        compare_digest(actual, expected)
        for actual, expected in zip(actual_iter, expected_iter, strict=True)
    )


def create_ref_task[T](
    coro: Coroutine[Any, Any, T], loop: asyncio.AbstractEventLoop | None = None
) -> asyncio.Task[T]:
    running_tasks: set[asyncio.Task] = create_ref_task.__dict__.setdefault(
        "_running_tasks", set()
    )
    if loop is None:
        loop = asyncio.get_running_loop()
    task = loop.create_task(coro)
    running_tasks.add(task)
    task.add_done_callback(running_tasks.discard)
    return task
