# Manual QA Script - Reviews, Availability, Support/Disputes

## Setup
- Create a provider user (any provider role) with a BookMe profile.
- Create a client user.
- Ensure you can access the admin dashboard for admin actions.

## Reviews and ratings
- Create a completed booking between the client and provider.
- Visit the booking detail as the client and confirm "Leave a review" appears.
- Submit a review with rating 5 and a short title/body.
- Verify the review appears on the provider public profile and the rating summary updates.
- Attempt to review a non-completed booking and confirm it is rejected.
- Attempt to review the booking as a non-participant and confirm 403.
- As admin, hide the review and confirm it disappears from the provider public profile.
- As admin, show the review again and confirm it returns.

## Availability and settings
- As the provider, open /provider/settings and turn off "accepting new requests".
- As the client, attempt a booking request and confirm it is blocked with a friendly message.
- Turn "accepting new requests" back on.
- Add a weekly slot (example: Monday 09:00-12:00, UTC).
- Submit a booking request inside the slot and confirm it succeeds.
- Submit a booking request outside the slot and confirm it is rejected.
- Add a date exception with is_unavailable checked for a future date/time range.
- Attempt a booking inside that exception window and confirm it is blocked.
- Add a date exception with is_unavailable unchecked and confirm it allows a request even outside weekly slots.

## Support tickets
- As the client, create a support ticket from /support/new.
- Confirm the ticket appears in /support and you can open the thread.
- Add a reply and confirm it appears in the thread.
- As a different non-admin user, attempt to access the ticket and confirm 403.
- As admin, reply and change status; confirm the user sees the update.

## Booking disputes
- Use a completed booking within 30 days of event time.
- As a participant, open a dispute and confirm it appears on the booking detail page.
- As the other participant, add a reply and confirm it appears.
- As a non-participant, attempt to access the dispute and confirm 403.
- Attempt to create a second dispute for the same booking and confirm it is rejected.
- As admin, update the dispute status and add a reply.
