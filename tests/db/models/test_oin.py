import pytest

from app.db.models.oin import OinNumber

VALID_OIN = "00000001123456700000"


class TestOinNumberConstruction:
    def test_valid_string(self) -> None:
        oin = OinNumber(VALID_OIN)
        assert str(oin) == VALID_OIN

    def test_valid_integer(self) -> None:
        # Use an OIN without leading zeros so the integer representation stays 20 digits
        oin_str = "12345678901234567890"
        oin = OinNumber(int(oin_str))
        assert str(oin) == oin_str

    def test_prefix_and_number_split_correctly(self) -> None:
        oin = OinNumber(VALID_OIN)
        assert oin.prefix == VALID_OIN[:8]
        assert oin.number == VALID_OIN[8:]

    def test_rejects_non_string_non_integer(self) -> None:
        with pytest.raises(ValueError, match="must be a string or integer"):
            OinNumber(3.14)

    def test_rejects_negative_integer(self) -> None:
        with pytest.raises(ValueError, match="must be a positive integer"):
            OinNumber(-1)

    def test_rejects_non_digit_characters(self) -> None:
        with pytest.raises(ValueError, match="digits only"):
            OinNumber("0000000112345670000X")

    def test_rejects_wrong_length(self) -> None:
        with pytest.raises(ValueError, match="exactly 20 digits"):
            OinNumber("123")


class TestOinNumberEquality:
    def test_equal_to_same_value(self) -> None:
        assert OinNumber(VALID_OIN) == OinNumber(VALID_OIN)

    def test_not_equal_to_different_value(self) -> None:
        assert OinNumber(VALID_OIN) != OinNumber("00000002987654321000")

    def test_not_equal_to_non_oin(self) -> None:
        assert OinNumber(VALID_OIN) != VALID_OIN

    def test_hashable_and_usable_in_set(self) -> None:
        s = {OinNumber(VALID_OIN), OinNumber(VALID_OIN)}
        assert len(s) == 1

    def test_repr(self) -> None:
        oin = OinNumber(VALID_OIN)
        assert repr(oin) == f"OinNumber({oin.prefix}, {oin.number})"
