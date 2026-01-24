# Stripe Integration Guide for BeatFund Wallet

This document outlines the Stripe integration points in the wallet system. The wallet page is designed to be Stripe-ready, with clear integration points for each feature.

## Overview

The wallet system supports four main features, all ready for Stripe integration:

1. **Add Money** - Top up wallet via Stripe Checkout
2. **P2P Transfers** - Peer-to-peer wallet transfers (no Stripe needed)
3. **Withdraw to Bank** - Withdrawal via Stripe Connect
4. **Transfer to Main Account** - Transfer via Stripe ACH or Instant Payouts

## Integration Points

### 1. Add Money (Stripe Checkout)

**Location:** `templates/wallet_center.html` - "Add Money" card

**Current Implementation:**
- Form submits to `/wallet/action` with `action=add`
- Backend creates a ledger entry (demo mode)

**Stripe Integration Steps:**
1. When form is submitted, instead of creating ledger entry directly:
   ```python
   # In wallet_action() function, when action == "add"
   if method == "stripe_card" or method == "stripe_bank":
       # Create Stripe Checkout Session
       checkout_session = stripe.checkout.Session.create(
           payment_method_types=['card'] if method == "stripe_card" else ['us_bank_account'],
           line_items=[{
               'price_data': {
                   'currency': 'usd',
                   'product_data': {'name': 'BeatFund Wallet Top-up'},
                   'unit_amount': cents,
               },
               'quantity': 1,
           }],
           mode='payment',
           success_url=url_for('wallet_stripe_success', _external=True),
           cancel_url=url_for('wallet_home', _external=True),
           metadata={'user_id': current_user.id, 'action': 'add_funds'}
       )
       return redirect(checkout_session.url)
   ```

2. Create success handler:
   ```python
   @app.route("/wallet/stripe/success")
   @login_required
   def wallet_stripe_success():
       session_id = request.args.get('session_id')
       session = stripe.checkout.Session.retrieve(session_id)
       
       if session.payment_status == 'paid':
           w = get_or_create_wallet(current_user.id)
           amount_cents = session.amount_total
           post_ledger(w, EntryType.deposit, amount_cents, 
                      meta=f"deposit via Stripe {session.payment_method_types[0]}")
           flash("Funds added successfully!", "success")
       
       return redirect(url_for("wallet_home"))
   ```

### 2. P2P Transfers

**Location:** `templates/wallet_center.html` - "Send to User" card

**Current Implementation:**
- Fully functional wallet-to-wallet transfers
- No Stripe integration needed (internal transfers)

**Note:** This feature is complete and doesn't require Stripe.

### 3. Withdraw to Bank (Stripe Connect)

**Location:** `templates/wallet_center.html` - "Withdraw to Bank" card

**Current Implementation:**
- Form submits to `/wallet/action` with `action=withdraw`
- Backend creates a ledger entry (demo mode)

**Stripe Connect Integration Steps:**

1. **Set up Stripe Connect:**
   - Create Connect account for users who want to withdraw
   - Store `stripe_account_id` in user model

2. **Update withdrawal handler:**
   ```python
   # In wallet_action() function, when action == "withdraw"
   if bank_account == "stripe_connected":
       # Verify user has Stripe Connect account
       if not current_user.stripe_account_id:
           flash("Please connect your bank account first.", "error")
           return redirect(url_for("wallet_home"))
       
       # Create Stripe Transfer
       transfer = stripe.Transfer.create(
           amount=cents,
           currency='usd',
           destination=current_user.stripe_account_id,
           metadata={'user_id': current_user.id, 'action': 'withdrawal'}
       )
       
       # Create ledger entry
       with db_txn():
           post_ledger(w, EntryType.withdrawal, cents, 
                      meta=f"withdraw to bank (Stripe Transfer: {transfer.id})")
       
       flash(f"Withdrawal initiated. Processing time: 2-5 business days.", "success")
   ```

3. **Add bank account connection flow:**
   - Create route for Stripe Connect onboarding
   - Use Stripe Connect Onboarding API

### 4. Transfer to Main Account

**Location:** `templates/wallet_center.html` - "Transfer to Main Account" card

**Current Implementation:**
- Form submits to `/wallet/action` with `action=transfer_out`
- Backend creates a ledger entry (demo mode)

**Stripe Integration Steps:**

1. **For Bank Transfers (Stripe ACH):**
   ```python
   if destination == "stripe_bank":
       # Create Stripe Payout
       payout = stripe.Payout.create(
           amount=cents,
           currency='usd',
           method='standard',  # or 'instant' for instant payouts
           metadata={'user_id': current_user.id, 'action': 'transfer_out'}
       )
       
       with db_txn():
           post_ledger(w, EntryType.withdrawal, cents, 
                      meta=f"transfer to bank (Stripe Payout: {payout.id})")
   ```

2. **For Instant Card Transfers:**
   ```python
   if destination == "stripe_card":
       # Create instant payout to debit card
       payout = stripe.Payout.create(
           amount=cents,
           currency='usd',
           method='instant',
           destination='card',  # User's connected debit card
           metadata={'user_id': current_user.id, 'action': 'transfer_out_instant'}
       )
       
       with db_txn():
           post_ledger(w, EntryType.withdrawal, cents, 
                      meta=f"transfer to card (Stripe Instant: {payout.id})")
   ```

## Payment Methods Section

**Location:** `templates/wallet_center.html` - "Payment Methods" card

**Current Implementation:**
- Placeholder UI showing "No payment methods"

**Stripe Integration Steps:**

1. **Store payment methods:**
   - Use Stripe Payment Methods API to save cards/banks
   - Store `payment_method_id` in a new `PaymentMethod` model

2. **Display saved methods:**
   ```python
   # In wallet_page() function
   payment_methods = PaymentMethod.query.filter_by(
       user_id=current_user.id,
       is_active=True
   ).all()
   
   # Retrieve details from Stripe
   for pm in payment_methods:
       stripe_pm = stripe.PaymentMethod.retrieve(pm.stripe_payment_method_id)
       pm.details = stripe_pm  # Store for template
   
   return render_template("wallet_center.html", 
                         balance=balance, 
                         txns=txns, 
                         recent=recent, 
                         tab=tab,
                         payment_methods=payment_methods)
   ```

3. **Add payment method flow:**
   - Use Stripe Elements or Checkout to collect payment method
   - Save to Stripe and store reference in database

## Environment Variables Needed

Add these to your `.env` file:

```env
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_CONNECT_CLIENT_ID=ca_...
```

## Webhook Handler

Create a webhook endpoint to handle Stripe events:

```python
@app.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET')
        )
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400
    
    # Handle events
    if event['type'] == 'checkout.session.completed':
        # Handle successful payment
        session = event['data']['object']
        # Update wallet balance
    elif event['type'] == 'payout.paid':
        # Handle successful payout
        payout = event['data']['object']
        # Update transaction status
    
    return jsonify({'status': 'success'}), 200
```

## Testing

1. Use Stripe Test Mode keys
2. Use test card numbers: `4242 4242 4242 4242`
3. Test webhook events using Stripe CLI: `stripe listen --forward-to localhost:5000/webhooks/stripe`

## Security Considerations

1. Always validate amounts server-side
2. Use CSRF tokens for all forms
3. Verify webhook signatures
4. Store Stripe keys securely (environment variables)
5. Never expose secret keys in frontend code
6. Validate user permissions before processing transactions

## Next Steps

1. Install Stripe Python SDK: `pip install stripe`
2. Add Stripe keys to environment variables
3. Implement Stripe Checkout for "Add Money"
4. Set up Stripe Connect for withdrawals
5. Implement payment method storage
6. Add webhook handlers
7. Test with Stripe test mode
8. Update UI to show real payment methods
9. Add error handling and user feedback
10. Deploy with production Stripe keys

