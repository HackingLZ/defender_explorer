"""Read untrusted import files without following filesystem links."""

from contextlib import ExitStack
import os
from pathlib import Path
import stat


class UnsafeImportFileError(ValueError):
    """An import entry could not be opened as a contained regular file."""


def read_import_text(root: Path, path: Path) -> str:
    """Read a regular file beneath root, refusing links in every component.

    Do not resolve dataset paths: that would discard evidence of symlinks.
    Walk from the filesystem root using directory descriptors and O_NOFOLLOW
    so replacing a checked entry cannot redirect a later open outside the tree.
    Unsupported platforms fail closed instead of falling back to Path.open.
    """
    root = Path(root).absolute()
    path = Path(path).absolute()
    if ".." in root.parts or ".." in path.parts:
        raise UnsafeImportFileError("Parent traversal is not allowed in import paths")
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise UnsafeImportFileError("Import file is outside the approved root") from exc
    if not relative.parts:
        raise UnsafeImportFileError("Import entry must be a file beneath the root")
    if (os.open not in os.supports_dir_fd
            or not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))):
        raise UnsafeImportFileError("Secure import file opening is unavailable on this platform")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        with ExitStack() as stack:
            directory_fd = os.open(root.anchor, directory_flags)
            stack.callback(os.close, directory_fd)
            for component in (*root.parts[1:], *relative.parts[:-1]):
                directory_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                stack.callback(os.close, directory_fd)

            # O_NONBLOCK prevents a supplied FIFO from hanging before fstat.
            file_fd = os.open(
                relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_fd,
            )
            stack.callback(os.close, file_fd)
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise UnsafeImportFileError("Import entry is not a regular file")
            with open(file_fd, "r", errors="replace", closefd=False) as source:
                return source.read()
    except OSError as exc:
        raise UnsafeImportFileError(f"Cannot safely open import file: {exc.strerror}") from exc
