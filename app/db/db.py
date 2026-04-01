import logging

from sqlalchemy import StaticPool, create_engine, text
from sqlalchemy.orm import Session

from app.config import ConfigDatabase
from app.db.models.base import Base
from app.db.session import DbSession

logger = logging.getLogger(__name__)


class Database:
    _config_database: ConfigDatabase

    def __init__(self, config_database: ConfigDatabase):
        self._config_database = config_database

        try:
            if "sqlite://" in config_database.dsn:
                self.engine = create_engine(
                    config_database.dsn,
                    connect_args={
                        "check_same_thread": False
                    },  # This + static pool is needed for sqlite in-memory tables
                    poolclass=StaticPool,
                )
            else:
                self.engine = create_engine(
                    config_database.dsn,
                    echo=False,
                    pool_pre_ping=config_database.pool_pre_ping,
                    pool_recycle=config_database.pool_recycle,
                    pool_size=config_database.pool_size,
                    max_overflow=config_database.max_overflow,
                )
        except BaseException as e:
            logger.error("Error while connecting to database: %s", e)
            raise e

    def generate_tables(self) -> None:
        logger.info("Generating tables...")
        Base.metadata.create_all(self.engine)

    def is_healthy(self) -> bool:
        """
        Check if the database is healthy

        :return: True if the database is healthy, False otherwise
        """
        try:
            with Session(self.engine) as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.info("Database is not healthy: %s", e)
            return False

    def get_db_session(self) -> DbSession:
        return DbSession(self.engine, self._config_database.retry_backoff)
