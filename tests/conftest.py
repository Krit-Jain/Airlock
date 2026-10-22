import pytest

from airlock.store import Store


@pytest.fixture
def store(tmp_path):
    db = Store(tmp_path / "test.db")
    yield db
    db.close()
