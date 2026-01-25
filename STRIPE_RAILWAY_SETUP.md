# Stripe Configuration for Railway Deployment

## Overview
The BeatFund app supports Stripe for:
- **Wallet top-ups**: Users can add funds to their account via Stripe Checkout
- **Beat purchases**: Direct payment processing
- **Stripe Connect**: Artist payouts and withdrawals (Express accounts)
- **Webhook handling**: Process Stripe events for payment confirmations

## Required Stripe Environment Variables

Three environment variables must be set in your Railway deployment:

| Variable | Source | Example |
|----------|--------|---------|
| `STRIPE_SECRET_KEY` | Stripe Dashboard | `sk_live_...` or `sk_test_...` |
| `STRIPE_PUBLISHABLE_KEY` | Stripe Dashboard | `pk_live_...` or `pk_test_...` |
| `STRIPE_WEBHOOK_SECRET` | Stripe Dashboard (Webhooks section) | `whsec_...` |

## Step 1: Get Your Stripe API Keys

1. Go to [Stripe Dashboard](https://dashboard.stripe.com) and log in
2. Navigate to **Developers** → **API keys** (top right)
3. You'll see two sets of keys:
   - **Test keys** (if you're in Test Mode - toggle in top right)
   - **Live keys** (if you're in Live Mode)

### For Development/Testing:
- Use **Test Mode** keys (start with `sk_test_` and `pk_test_`)
- These don't process real payments

### For Production:
- Use **Live Mode** keys (start with `sk_live_` and `pk_live_`)
- These process real payments from customers

## Step 2: Get Your Webhook Secret

1. In Stripe Dashboard, go to **Developers** → **Webhooks**
2. Click **Add an endpoint**
3. Enter your endpoint URL:
   ```
   https://your-railway-domain.com/stripe/webhook
   ```
   Or use the alternative endpoint:
   ```
   https://your-railway-domain.com/webhooks/stripe
   ```
4. Select the following events:
   - `charge.succeeded`
   - `charge.failed`
   - `payment_intent.succeeded`
   - `payment_intent.payment_failed`
   - `checkout.session.completed`
5. Copy the **Signing secret** (starts with `whsec_`)

## Step 3: Configure Railway Environment Variables

1. Go to your Railway project dashboard
2. Click on your service (the one running BeatFund)
3. Navigate to **Variables**
4. Add these three new variables:

```
STRIPE_SECRET_KEY=sk_live_your_actual_secret_key_here
STRIPE_PUBLISHABLE_KEY=pk_live_your_actual_publishable_key_here
STRIPE_WEBHOOK_SECRET=whsec_your_actual_webhook_secret_here
```

5. Click **Save** or **Deploy** to apply changes

## Step 4: Test Stripe Configuration

After deploying with the new variables, test the configuration:

```
GET https://your-railway-domain.com/check-stripe-config
```

Expected response (if configured correctly):
```json
{
  "STRIPE_AVAILABLE": true,
  "STRIPE_SECRET_KEY_set": true,
  "STRIPE_SECRET_KEY_length": 120,
  "STRIPE_SECRET_KEY_prefix": "sk_live_...",
  "STRIPE_PUBLISHABLE_KEY_set": true,
  "stripe_api_key_set": true
}
```

## Features That Require Stripe

### 1. Wallet Top-Ups
- Route: `POST /create-checkout-session`
- Creates Stripe Checkout session for adding funds
- Requires: `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`

### 2. Beat Purchases
- Routes: `/create-checkout-session`, `/wallet/stripe/success`
- Users can purchase beats directly with Stripe
- Requires: `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`

### 3. Artist Payouts (Stripe Connect)
- Routes: `/connect/stripe/start`, `/connect/stripe/return`
- Artists can connect their Stripe account for payouts
- Requires: Valid Stripe Connect account on your platform

### 4. Webhook Processing
- Route: `POST /stripe/webhook` or `POST /webhooks/stripe`
- Handles payment confirmations, charge events, etc.
- Requires: `STRIPE_WEBHOOK_SECRET` for signature verification

## Graceful Fallback (If Stripe Not Configured)

If Stripe keys are not set:
- ✅ App continues to work
- ✅ Wallet functionality uses local wallet (if implemented)
- ❌ Stripe payment routes return error: "Stripe is not available"
- ⚠️ Check logs: "Stripe not configured: STRIPE_AVAILABLE=..."

## Debug Endpoints

Test Stripe configuration without credentials exposure:

```
GET /check-stripe-config
```
Shows high-level Stripe status

```
GET /admin/stripe/webhooks
```
Admin panel to view Stripe webhook events (if logged in as admin)

```
POST /admin/stripe/webhooks/<event_id>/retry
```
Retry failed webhook processing

## Troubleshooting

### "Stripe is not available" error
- **Cause**: Stripe package not installed or import failed
- **Fix**: `pip install stripe` in requirements.txt

### "Stripe not configured" warning in logs
- **Cause**: Environment variables not set
- **Fix**: Add `STRIPE_SECRET_KEY` and `STRIPE_PUBLISHABLE_KEY` to Railway Variables

### Webhook signature verification failed
- **Cause**: `STRIPE_WEBHOOK_SECRET` is wrong or missing
- **Fix**: Copy the correct webhook signing secret from Stripe Dashboard

### "Invalid API Key" errors
- **Cause**: Using test keys in production or live keys in test mode
- **Fix**: Match key prefixes: `sk_test_` for test, `sk_live_` for production

### Webhook events not processing
- **Cause**: Webhook endpoint not registered in Stripe Dashboard
- **Fix**: Add `https://your-domain.com/stripe/webhook` in Stripe Webhooks settings

## Security Best Practices

⚠️ **NEVER**:
- Commit API keys to GitHub
- Share webhook secrets
- Use placeholder keys in production
- Log full API keys

✅ **DO**:
- Use Railway's environment variables for secrets
- Rotate keys regularly
- Monitor webhook event logs
- Test in test mode before going live
- Use different keys for dev/staging/prod environments

## Next Steps

1. Get API keys from Stripe Dashboard
2. Add them to Railway Variables
3. Deploy and test with `/check-stripe-config`
4. Monitor webhook processing in admin panel
5. Test payment flow in your app

---

**Need Help?**
- [Stripe API Documentation](https://stripe.com/docs/api)
- [Stripe Webhooks Guide](https://stripe.com/docs/webhooks)
- [Railway Environment Variables](https://docs.railway.app/deploy/variables)
