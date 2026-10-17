"""Allow only one cooperating writer for the Phase 2 MySQL database."""
from contextlib import contextmanager
from sqlalchemy import text
from .core import digest


class WriterBusy(RuntimeError):
    """A cooperating writer owns the lock; a periodic collector may retry later."""


@contextmanager
def writer_lock(engine):
    name = "kg:" + digest(engine.url.database)[:60]
    with engine.connect() as conn:
        acquired = conn.execute(text("SELECT GET_LOCK(:name, 0)"), {"name": name}).scalar()
        if acquired != 1:
            raise WriterBusy("Another KernelGuard writer is active for this database")
        try:
            yield
        finally:
            conn.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": name})
