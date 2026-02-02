# Stripe-Only Payouts + Affiliate Commissions

## Environment variables

```env
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
CONNECT_ONBOARDING_RETURN_URL=https://yourapp.com/connect/stripe/return
CONNECT_ONBOARDING_REFRESH_URL=https://yourapp.com/connect/stripe/start

STRIPE_PLATFORM_FEE_PCT=0.02
STRIPE_BOOKING_HOLD_FEE=5.17

AFFILIATE_DEFAULT_PCT=0.30
AFFILIATE_PAYOUT_DELAY_DAYS=14

APP_BASE_URL=https://yourapp.com
KYC_ENFORCE=1
```

Notes:
- `STRIPE_BOOKING_HOLD_FEE` is a platform-only charge applied at booking acceptance.
- `STRIPE_PLATFORM_FEE_PCT` is the percentage fee withheld from provider payouts.
- Affiliate commissions are computed from platform fees actually collected.

## Manual test checklist

1) **Booking flow (Stripe Connect destination charges)**
   - Create a booking with agreed total of **$350.00**.
   - Pay holding fee **$5.17**:
     - PaymentLedger row: `gross_amount_cents=517`, `platform_fee_collected_cents=517`, `provider_amount_routed_cents=0`.
   - Pay balance:
     - `application_fee_amount` should be **2% of 35000 = 700 cents**.
     - Provider receives `balance_due_cents - 700`.
   - BeatFund revenue total for the booking = `517 + 700 = 1217 cents` (**$12.17**).

2) **No-double-charge guard**
   - Attempt to pay balance twice.
   - Second attempt must be blocked or return an error (no additional ledger entry).

3) **Beat purchase**
   - Beat price **$100.00**.
   - Platform fee = **200 cents** (2%).
   - Provider receives **9800 cents**, BeatFund gets **200 cents**.

4) **Affiliate commission**
   - Create affiliate code and sign up a user with that code.
   - Complete a booking/beat purchase.
   - `AffiliateEarning` row created based on platform fee collected.
   - Issue a refund: `AffiliateEarning.status` becomes `reversed`.

5) **Webhook idempotency**
   - Re-deliver the same Stripe event.
   - Ensure `stripe_webhook_event` prevents double processing.
