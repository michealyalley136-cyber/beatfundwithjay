# Support Tickets and Booking Disputes

## Support tickets
Users can create support tickets and hold a threaded conversation. Admins can reply and update ticket status.

### Data model
- SupportTicket: user_id, created_by_admin_id, subject, type, status, description, created_at, updated_at.
- SupportTicketMessage: ticket_id, author_user_id, body, created_at.
- SupportTicketComment is still used for admin internal notes.

### Routes
- GET /support: list my tickets.
- GET /support/new: create form.
- POST /support/new: create ticket.
- GET /support/<id>: view thread.
- POST /support/<id>/reply: add message.
- Admin: GET /admin/tickets, POST /admin/tickets/<id>/status, POST /admin/tickets/<id>/reply.

### Security
- Only the ticket owner or an admin can view or reply.
- IDOR protections are enforced on ticket routes.

## Booking disputes
Booking participants can open one dispute within 30 days of the booking event time.

### Data model
- BookingDispute: booking_id, opened_by_id, reason, details, status, created_at, updated_at.
- BookingDisputeMessage: dispute_id, author_user_id, body, created_at.

### Routes
- GET /bookings/<id>/dispute: view thread or create form if none.
- POST /bookings/<id>/dispute: create dispute.
- POST /disputes/<id>/reply: add message.
- Admin: GET /admin/disputes, GET/POST /admin/disputes/<id>.

### Rules
- Only booking participants can create or view a dispute.
- One dispute per booking (unless reopened by admin).
- Status values: open, under_review, resolved, closed.

## UI
- Booking detail shows dispute status and link to the thread.
- Support area lists tickets and includes a create flow.
