const express = require('express');
const { Pool } = require('pg');
const router = express.Router();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// GET /api/orders
// Returns the authenticated user's order history with line items attached.
router.get('/', async (req, res) => {
  try {
    const userId = req.user.userId;

    const ordersResult = await pool.query(
      'SELECT id, status, total_cents, created_at FROM orders WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );

    const orders = [];
    for (const order of ordersResult.rows) {
      const itemsResult = await pool.query(
        'SELECT sku, quantity, unit_price_cents FROM order_items WHERE order_id = $1',
        [order.id]
      );
      orders.push({ ...order, items: itemsResult.rows });
    }

    res.json(orders);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load orders' });
  }
});

module.exports = router;
