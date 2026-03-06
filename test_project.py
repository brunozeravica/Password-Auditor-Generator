from project import (
    get_password, validate_character_set, get_entropy, scan_patterns, scan_uniqueness, calculate_score, generate_password
    )
import pytest

def test_get_password_type(monkeypatch):

    monkeypatch.setattr('builtins.input', lambda _: "password")

    password, pwnd = get_password()

    assert isinstance(password, str)
    assert isinstance(pwnd, int)


def test_get_password_good(monkeypatch):


    monkeypatch.setattr('builtins.input', lambda _: "Zp/A%zVaXUq'Vb)^y:)V(Q=#eLI02[+u")

    password, pwnd = get_password()

    assert pwnd == 0


def test_get_password_bad(monkeypatch):


    monkeypatch.setattr('builtins.input', lambda _: "password")

    password, pwnd = get_password()

    assert pwnd > 0


def test_validate_character_set_valid():

    assert validate_character_set("valid-string") == None


def test_validate_character_set_invalid():

    with pytest.raises(ValueError):
        validate_character_set("invalid char đ")


def test_get_entropy_type():

    entropy = get_entropy("password")

    assert isinstance(entropy, int)


def test_get_entropy_max():

    assert get_entropy("Zp/A%zVaXUq'Vb)^y:)V(Q=#eLI02[+u") == 100


def test_get_entropy_min():

    assert get_entropy("1") == 2


def test_scan_patterns_nonzero():

    assert scan_patterns("password") != 0


def test_scan_patterns_zero():

    assert scan_patterns("Zp/A%zVaXUq'Vb)^y:)V(Q=#eLI02[+u") == 0


def test_scan_uniqueness_type():

    result = scan_uniqueness("abcdefgh")

    assert isinstance(result, float)
    assert 0 <= result <= 1


def test_scan_uniqueness_midpoint():

    assert scan_uniqueness("aaaabbbb") == pytest.approx(0.5)


def test_calculate_score_zero():

    assert calculate_score("password") == 0


def test_calculate_score_high():

    assert calculate_score("Zp/A%zVaXUq'Vb)^y:)V(Q=#eLI02[+u") > 90


def test_generate_password_type():

    password, score = generate_password("80")

    assert isinstance(password, str)
    assert isinstance(score, int)
