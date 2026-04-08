from typing import Any


class OinNumber:
    """
    Representation of an OIN (Organisatie-identificatienummer), consisting of:
      - prefix: 8 digits identifying the issuing authority
      - number: 12 digits identifying the organization
    Full OIN is the concatenation of prefix + number (20 digits total).
    """

    PREFIX_LENGTH = 8
    NUMBER_LENGTH = 12
    TOTAL_LENGTH = PREFIX_LENGTH + NUMBER_LENGTH

    def __init__(self, value: Any) -> None:
        if not isinstance(value, (int, str)):
            raise ValueError(f"OIN number must be a string or integer, got {type(value).__name__}")

        if isinstance(value, int) and value < 0:
            raise ValueError("OIN number must be a positive integer")

        str_value = str(value)

        if not str_value.isdigit():
            raise ValueError("OIN number must contain digits only")

        if len(str_value) != self.TOTAL_LENGTH:
            raise ValueError(
                f"OIN number must be exactly {self.TOTAL_LENGTH} digits "
                f"({self.PREFIX_LENGTH} prefix + {self.NUMBER_LENGTH} number), got {len(str_value)}"
            )

        self.prefix = str_value[: self.PREFIX_LENGTH]
        self.number = str_value[self.PREFIX_LENGTH :]

    @property
    def value(self) -> str:
        return self.prefix + self.number

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"OinNumber({self.prefix}, {self.number})"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, OinNumber):
            return self.value == other.value
        return False

    def __hash__(self) -> int:
        return hash(self.value)
