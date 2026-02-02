# Provider Reviews and Ratings

## Overview
Provider reviews are tied to service bookings. Each booking can have at most one review from the client, and reviews are shown on the provider public profile and summarized on provider dashboards.

## Data model
- ProviderReview fields: id, booking_id (unique), reviewer_user_id, provider_user_id, rating (1-5), title, body, status (visible/hidden), reported_count, created_at, updated_at.

## Business rules
- Only the booking client can review the booking.
- Booking must be completed (status == COMPLETED).
- One review per booking (unique booking_id).
- rating must be between 1 and 5.
- Reviews shown on public profile only when status is visible.

## Routes
- GET /bookings/<id>/review: review form (only eligible client).
- POST /bookings/<id>/review: create review.
- POST /reviews/<id>/report: increment reported_count.
- GET /admin/reviews: admin list (filter/status).
- POST /admin/reviews/<id>/hide
- POST /admin/reviews/<id>/show

## UI
- Booking detail shows "Leave a review" when eligible.
- Provider public profile shows summary and visible reviews.
- Provider dashboards include rating snippet in templates/_provider_rating_snippet.html.

## Schema notes
Schema patches for SQLite/Postgres create the provider_review table on boot if missing.
