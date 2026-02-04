# beatfundinc

## Booking + Payment Schema Patch (Postgres)
The app auto-applies safe, idempotent schema patches on boot to add missing columns.

Booking columns:
- quoted_total_cents
- deposit_base_cents
- beatfund_fee_total_cents
- beatfund_fee_collected_cents

Payment columns:
- kind
- base_amount_cents
- beatfund_fee_cents
- processing_fee_cents
- total_paid_cents
- refunded_base_cents
- nonrefundable_processing_kept_cents
- nonrefundable_beatfund_kept_cents
- idempotency_key
- external_id
- booking_request_id
- stripe_payment_intent_id
- stripe_charge_id

Verify via the admin endpoint:
- /dashboard/admin/schema-check
- /dashboard/admin/schema/booking (legacy booking-only view)

## Beats Preview + Downloads
- Requires ffmpeg to generate 30s MP3 previews on upload (Dockerfile installs it).
- Env:
  - PREVIEW_SECONDS (default 30)
  - FFMPEG_CMD (default "ffmpeg")

## Stripe Checkout + Apple Pay
- Apple Pay appears automatically in Stripe Checkout on supported devices once the domain is verified.
- Steps:
  1) Ensure APP_BASE_URL is HTTPS and matches your public domain.
  2) Verify the domain in the Stripe Dashboard (Payment Methods -> Apple Pay).
  3) Host the Apple Pay verification file at `/.well-known/apple-developer-merchantid-domain-association`.
     (If using Railway, add the file to `static/.well-known/` or `public/.well-known/` and redeploy.)

## Holding Fee (Bookings)
- HOLDING_FEE_CENTS=2000 (fixed $20 deposit)
