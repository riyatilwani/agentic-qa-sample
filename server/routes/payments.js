const express = require('express');
const router  = express.Router();

// BUG: Stripe secret key hardcoded — will appear in git history even if removed later.
//      Must be rotated immediately if this merges.
const stripe = require('stripe')('sk_live_FAKE_KEY_DO_NOT_USE_4xT9mK2nPqRsUvWxYzAbCdEf');

// BUG: No idempotency key — double-clicking "Pay" fires two intents, charges user twice.
// BUG: amount and currency come directly from the request body — client dictates price.
//      Server must look up the price from its own DB, never trust the client.
// BUG: console.log includes full paymentIntent object — card fingerprint etc. logged to stdout.
// BUG: No authentication middleware — any unauthenticated caller can create a payment intent.

// POST /api/payments/create-intent
router.post('/create-intent', async (req, res) => {
  const { amount, currency, description } = req.body;

  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency,
      description,
    });

    console.log('Payment intent created:', paymentIntent); // BUG: logs sensitive data

    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error('Stripe error:', err);
    res.status(500).json({ error: 'Payment failed' });
  }
});

// POST /api/payments/webhook
// BUG: Stripe signature not verified — anyone can POST fake webhook events.
router.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const event = JSON.parse(req.body);

  if (event.type === 'payment_intent.succeeded') {
    const intent = event.data.object;
    console.log('Payment succeeded:', intent.id);
    // TODO: fulfil the order
  }

  res.json({ received: true });
});

module.exports = router;
