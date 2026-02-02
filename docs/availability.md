# Provider Availability and Settings

## Overview
All provider roles use ProviderSettings plus weekly availability and date exceptions for booking validation.

## Data model
- ProviderSettings: provider_user_id (unique), accepting_new_requests, onsite, remote, travel_radius_miles, base_location, tz.
- ProviderAvailability: provider_user_id, day_of_week (0=Mon..6=Sun), start_time, end_time, tz, is_active.
- ProviderAvailabilityException: provider_user_id, date, start_time, end_time, is_unavailable.

## Rules and behavior
- If accepting_new_requests is false, booking requests are blocked.
- Weekly slots define availability windows; if no slots are configured, booking is allowed (backward compatible).
- Exceptions are evaluated first for the requested date:
  - If is_unavailable is true and the window overlaps, the request is blocked.
  - If is_unavailable is false and the window overlaps, the request is allowed even if outside weekly slots.
- Requests that cross midnight are rejected.

## Routes
- GET /provider/settings
- POST /provider/settings
- POST /provider/availability/add
- POST /provider/availability/<id>/delete
- POST /provider/availability/exception
- POST /provider/availability/exception/<id>/delete

## Booking integration
- Booking request forms show availability summary and settings.
- On submit, requested date/time is validated against settings/availability.

## UI
- Provider dashboard links to "Availability and Settings".
- Provider public profile shows accepting new requests, modes, travel radius, and availability summary.

## Schema notes
Schema patches for SQLite/Postgres create provider_settings, provider_availability, and provider_availability_exception tables on boot if missing.
