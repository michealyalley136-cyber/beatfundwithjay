"""
Basic fee math checks for BeatFund booking fees.
Run: python test_fee_math.py
"""
from app import (
    calc_beatfund_fee_total,
    calc_total_and_processing,
)


def assert_close(actual: int, expected: int, tolerance: int = 1) -> None:
    if abs(actual - expected) > tolerance:
        raise AssertionError(f"Expected {expected} (+/-{tolerance}), got {actual}")


def run():
    # $100 service
    fee_100 = calc_beatfund_fee_total(10000)
    if fee_100 != 517:
        raise AssertionError(f"$100 fee should be 517 cents, got {fee_100}")

    # $100 service balance (fees on top)
    total_balance_100, processing_balance_100 = calc_total_and_processing(8000, fee_100)
    assert_close(total_balance_100, 8803)
    assert_close(processing_balance_100, 286)

    # $250 service with $20 hold
    total_service = 25000
    fee_total = calc_beatfund_fee_total(total_service)
    if fee_total != 1293:
        raise AssertionError(f"$250 fee should be 1293 cents, got {fee_total}")

    # Hold fee: base only + processing
    total_deposit, processing_deposit = calc_total_and_processing(2000, 0)
    assert_close(total_deposit, 2091)
    assert_close(processing_deposit, 91)

    # Balance: remaining base + full BeatFund fee + processing
    total_balance, processing_balance = calc_total_and_processing(23000, fee_total)
    assert_close(total_balance, 25050)
    assert_close(processing_balance, 757)

    print("[OK] Fee math checks passed.")


if __name__ == "__main__":
    run()
