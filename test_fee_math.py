"""
Basic fee math checks for BeatFund booking fees.
Run: python test_fee_math.py
"""
from app import (
    calc_beatfund_fee_cents,
    calc_total_and_processing,
    allocate_fee_between_deposit_and_balance,
)


def assert_close(actual: int, expected: int, tolerance: int = 1) -> None:
    if abs(actual - expected) > tolerance:
        raise AssertionError(f"Expected {expected} (+/-{tolerance}), got {actual}")


def run():
    # $100 service
    fee_100 = calc_beatfund_fee_cents(10000)
    if fee_100 != 517:
        raise AssertionError(f"$100 fee should be 517 cents, got {fee_100}")

    # $250 service with $20 deposit
    total_service = 25000
    fee_total = calc_beatfund_fee_cents(total_service)
    if fee_total != 1293:
        raise AssertionError(f"$250 fee should be 1293 cents, got {fee_total}")

    fee_deposit, fee_balance = allocate_fee_between_deposit_and_balance(fee_total)
    if fee_deposit != 517 or fee_balance != 776:
        raise AssertionError(f"Fee split wrong: deposit {fee_deposit}, balance {fee_balance}")

    total_deposit, processing_deposit = calc_total_and_processing(2000, fee_deposit)
    assert_close(total_deposit, 2624)
    assert_close(processing_deposit, 107)

    total_balance, processing_balance = calc_total_and_processing(23000, fee_balance)
    assert_close(total_balance, 24517)
    assert_close(processing_balance, 741)

    print("[OK] Fee math checks passed.")


if __name__ == "__main__":
    run()
