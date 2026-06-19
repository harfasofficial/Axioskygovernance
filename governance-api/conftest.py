# conftest.py
import os
import sys

# SAFETY GUARD: Prevent running tests against a non-test database.
# Set ENVIRONMENT=test in your .env.test or pytest invocation.
assert os.getenv("ENVIRONMENT", "") == "test" or "pytest" in sys.modules, (
    "SAFETY: ENVIRONMENT must be 'test' when running pytest. "
    "Add ENVIRONMENT=test to your .env.test file or run: ENVIRONMENT=test pytest"
)

import pytest_asyncio
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv('.env'), override=True)

# Force test environment after loading .env (in case .env overrides it)
os.environ['ENVIRONMENT'] = 'test'

db_url = os.getenv('DATABASE_URL', '')
if db_url and 'asyncpg' not in db_url:
    os.environ['DATABASE_URL'] = db_url.replace('postgresql://', 'postgresql+asyncpg://')

from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine
import database.session as db_session

# Create test engine with NullPool - no connection caching between tests
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
