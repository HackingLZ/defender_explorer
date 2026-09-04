"""Run bounded CPU work in a disposable process without blocking the API."""

import asyncio
import multiprocessing
from pathlib import Path
import tempfile
import sys


class WorkerTimeoutError(RuntimeError):
    pass


def _worker_entry(target, args: tuple, output_path: str, max_output: int) -> None:
    if sys.platform == "linux":
        import resource
        # Bound each child independently of the containing application's limit.
        memory_limit = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_output, max_output))
    target(*args, output_path)


async def run_worker(target, args: tuple, *, timeout: float, max_output: int) -> bytes:
    """The child writes its result to the final output-path argument.

    File transport avoids pipe deadlocks with large results. Cancellation,
    timeout, and exceptions all reap the child before returning.
    """
    context = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="defender-worker-") as directory:
        output = Path(directory) / "result"
        process = context.Process(target=_worker_entry, args=(target, args, str(output), max_output))
        process.start()
        try:
            async with asyncio.timeout(timeout):
                while process.is_alive():
                    if output.exists() and output.stat().st_size > max_output:
                        raise RuntimeError("Worker output exceeded its size limit")
                    await asyncio.sleep(0.05)
            process.join(timeout=0)
            if process.exitcode != 0 or not output.exists():
                raise RuntimeError("Worker failed")
            if output.stat().st_size > max_output:
                raise RuntimeError("Worker output exceeded its size limit")
            return output.read_bytes()
        except TimeoutError as exc:
            raise WorkerTimeoutError("Worker deadline exceeded") from exc
        finally:
            if process.is_alive():
                process.terminate()
                for _ in range(20):
                    if not process.is_alive():
                        break
                    await asyncio.sleep(0.01)
                if process.is_alive():
                    process.kill()
                await asyncio.to_thread(process.join, 1)
            process.close()
