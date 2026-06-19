# conftest.py
import os
import pytest_asyncio
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv('.env'), override=True)

# Safety guard: never run tests against a production database.
# Set ENVIRONMENT=test in your .env.test or CI environment.
assert os.getenv("DATABASE_URL", "") == "" or os.getenv("ENVIRONMENT") == "test", (
    "\n\nDANGER: ENVIRONMENT is not set to 'test' but DATABASE_URL is set.\n"
    "Tests must not run against a production or staging database.\n"
    "Set ENVIRONMENT=test in .env.test or your CI secrets.\n"
)

db_url = os.getenv('DATABASE_URL', '')
if db_url and 'asyncpg' not in db_url:
    os.environ['DATABASE_URL'] = db_url.replace('postgresql://', 'postgresql+asyncpg://')

os.environ['ENVIRONMENT'] = 'test'

from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine
import database.session as db_session

db_session.engine = create_async_engine(
    db_session.ASYNC_DATABASE_URL,
    echo=False,
    poolclass=NullPool,
)
db_session.AsyncSessionLocal = db_session.async_sessionmaker(
    db_session.engine,
    class_=db_session.AsyncSession,
    expire_on_commit=False,
)


@pytest_asyncio.fixture(scope="function", autouse=True)
async def override_db_engine():
    """
    Per-test database engine override with NullPool.
    Ensures each test gets a fresh connection on the current event loop.
    """
    original_engine = db_session.engine
    test_engine = create_async_engine(
        db_session.ASYNC_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
    )
    db_session.engine = test_engine
    db_session.AsyncSessionLocal = db_session.async_sessionmaker(
        test_engine,
        class_=db_session.AsyncSession,
        expire_on_commit=False,
    )
    yield
    await test_engine.dispose()
    db_session.engine = original_engine
    db_session.AsyncSessionLocal = db_session.async_sessionmaker(
        original_engine,
        class_=db_session.AsyncSession,
        expire_on_commit=False,
    )
