from typing import TypeVar

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    def __repr__(self) -> str:
        props = ", ".join([f"{k}={self.__getattribute__(k)}" for k in self.__table__.columns.keys()])

        return f"<{self.__class__.__name__}=({props})>"


TBase = TypeVar("TBase", bound=Base)
