# Stripe Checkout Session Error Handling Improvements

## Overview
Enhanced error handling for Stripe checkout session creation to better diagnose and report issues when `checkout_session.url` is None or the session creation fails.

## Changes Made

### 1. **Beat Purchase Checkout** (`/create-checkout-session`)
**File**: [app.py](app.py#L7761)

Added explicit validation checks after session creation:
- **Check 1**: Validates `checkout_session.id` exists
  - Logs full session object if missing
  - Returns clear error: "Stripe session creation failed: no session ID"
- **Check 2**: Validates `checkout_session.url` exists  
  - Logs session ID, status, payment_status, and full session data if URL is missing
  - Returns clear error: "Stripe session created but checkout URL is missing. This may indicate a configuration issue..."

**Benefits**:
- Catches API errors that create a session but don't generate a checkout URL
- Provides diagnostic information in logs for debugging
- Returns specific, actionable error messages to the frontend
- Prevents passing `None` URLs to the frontend

### 2. **Hold Fee Checkout** (`/create-checkout-session-hold-fee`)
**File**: [app.py](app.py#L7956)

Applied identical validation logic:
- Validates session ID and URL
- Logs comprehensive diagnostic information
- Returns specific error messages
- Includes informational log on successful session creation

### 3. **Wallet Top-Up** (wallet action in `/wallet-center`)
**File**: [app.py](app.py#L5532)

Enhanced error handling:
- Added explicit validation for `checkout_session.id` and `checkout_session.url`
- Provides user-friendly flash messages for both issues
- Prevents rendering the redirect template with a None URL
- Logs full session data for debugging

**Benefits**:
- Prevents application crashes from None URLs
- Guides users to contact support when Stripe configuration issues occur
- Server logs contain full session information for diagnostics

## Error Messages Exposed

### User-Facing (API/Flash Messages)
1. "Stripe session creation failed: no session ID. Please contact support."
2. "Stripe session created but checkout URL is missing. This may indicate a configuration issue with your Stripe account. Please contact support if the problem persists."

### Server Logs (Detailed Diagnostics)
When `checkout_session.url` is None, logs include:
```
Stripe checkout session created but has no URL.
Session ID: cs_test_xxxx...
Status: {session.status}
Payment Status: {session.payment_status}
Session data: {full session object}
```

## Possible Root Causes for Missing URL

The missing URL scenario typically indicates:

1. **Stripe API Configuration Issues**
   - Invalid or expired Stripe API key
   - Mismatched live/test keys
   - Stripe account restrictions or limits

2. **Stripe Account Issues**
   - Account not fully onboarded
   - Payment method not configured
   - Account flagged for review

3. **Rate Limiting**
   - Too many rapid session creation attempts
   - Stripe API rate limits exceeded

4. **Network/Connectivity Issues**
   - Transient Stripe API failures
   - Incomplete API response

## Testing

To verify these improvements:

1. **Normal Flow**: Session creation returns valid URL → user redirected to Stripe
2. **Missing ID**: Mock Stripe to return session without ID → error logged and user notified
3. **Missing URL**: Mock Stripe to return session without URL → diagnostic logs and user error message
4. **Stripe Error**: Network/API errors → caught by existing exception handler

## Deployment Notes

No database migrations required. No breaking changes.

These improvements:
- ✅ Are backward compatible
- ✅ Enhance error visibility without changing happy path
- ✅ Provide better UX with specific error messages
- ✅ Enable faster debugging via comprehensive logs
