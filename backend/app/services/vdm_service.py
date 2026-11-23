"""Bounded VDM decompression for API import jobs."""

import asyncio
import hashlib

from defender_sig_extractor.vdm_parser import (
    MAX_VDM_DECOMPRESSED_SIZE, MAX_VDM_FILE_SIZE, VDMParser,
)

from .process_worker import run_worker


VDM_TIMEOUT = 120
# Keep decompression's child memory and temporary output to one job at a time.
_vdm_slot = asyncio.Semaphore(1)


def _vdm_worker(path: str, hash_only: bool, max_input: int, max_expanded: int,
                output_path: str) -> None:
    parser = VDMParser(path, max_file_size=max_input, max_decompressed_size=max_expanded)
    with open(output_path, "w+b") as output:
        parser.decompress_to(output)
        if hash_only:
            output.seek(0)
            digest = hashlib.sha256()
            while chunk := output.read(64 * 1024):
                digest.update(chunk)
            output.seek(0)
            output.truncate()
            output.write(digest.hexdigest().encode("ascii"))


async def _run_vdm(path: str, *, hash_only: bool) -> bytes:
    async with _vdm_slot:
        return await run_worker(
            _vdm_worker, (path, hash_only, MAX_VDM_FILE_SIZE, MAX_VDM_DECOMPRESSED_SIZE),
            timeout=VDM_TIMEOUT, max_output=MAX_VDM_DECOMPRESSED_SIZE,
        )


async def hash_vdm(path: str) -> str:
    """Hash expanded content without transferring it into the API process."""
    return (await _run_vdm(path, hash_only=True)).decode("ascii")


async def decompress_vdm(path: str) -> bytes:
    """Only return complete, size-checked data from the disposable worker."""
    return await _run_vdm(path, hash_only=False)


def _merge_worker(base_path, delta_path, max_input, max_output, output_path):
    from defender_sig_extractor.delta_patcher import VDMDeltaPatcher
    with open(output_path, "w+b") as output:
        VDMDeltaPatcher(base_path, delta_path).apply_to(
            output, max_input=max_input, max_output=max_output,
        )


async def merge_vdm(base_path: str, delta_path: str) -> bytes:
    """Reconstruct and verify a base/delta pair in the bounded VDM worker."""
    async with _vdm_slot:
        return await run_worker(
            _merge_worker,
            (base_path, delta_path, MAX_VDM_FILE_SIZE, MAX_VDM_DECOMPRESSED_SIZE),
            timeout=VDM_TIMEOUT, max_output=MAX_VDM_DECOMPRESSED_SIZE,
        )
