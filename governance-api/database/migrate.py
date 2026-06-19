# database/migrate.py
import logging
import os
import sys
import time
from pathlib import Path

import psycopg2

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://axiosky:axiosky@db:5432/axiosky"
)
MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def run():
    retries = 5
    for attempt in range(retries):
        try:
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = True
            cur = conn.cursor()

            # Create migration tracking table for idempotency
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version VARCHAR(255) PRIMARY KEY,
                    applied_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            # Run all migrations in sorted order, skip already-applied
            migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
            if not migration_files:
                logger.warning("No migration files found in %s", MIGRATIONS_DIR)
                return

            for mf in migration_files:
                cur.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = %s",
                    (mf.name,)
                )
                if cur.fetchone():
                    logger.info("Already applied: %s", mf.name)
                    continue

                logger.info("Applying: %s", mf.name)
                with open(mf, encoding="utf-8-sig") as f:
                    cur.execute(f.read())
                cur.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)",
                    (mf.name,)
                )
                logger.info("Applied: %s", mf.name)

            cur.close()
            conn.close()
            logger.info("All migrations complete")
            return

        except psycopg2.OperationalError as e:
            if attempt < retries - 1:
                logger.info(
                    "DB not ready (attempt %d/%d), retrying in 3s...",
                    attempt + 1, retries
                )
                time.sleep(3)
            else:
                logger.error("Migration failed after %d attempts: %s", retries, e)
                sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run()
