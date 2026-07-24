const express = require('express');
const { Pool } = require('pg');
const router = express.Router();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// GET /api/dashboard
// Returns activity feed for the authenticated user.
//
// BUG: N+1 query — for each event we fire a separate SELECT to get the actor name.
//      At 100 events = 101 DB queries per request. Should JOIN or batch.
// BUG: No LIMIT on the events query — returns unbounded rows for old accounts.
// BUG: No DB index on user_events(user_id) — full table scan on every request.
// BUG: Cursor-based pagination not implemented — offset pagination will drift.

router.get('/', async (req, res) => {
  try {
    const userId = req.user.userId;

    // Fetch all events for this user (no LIMIT)
    const eventsResult = await pool.query(
      'SELECT * FROM user_events WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );

    const events = eventsResult.rows;

    // N+1: for each event, separately fetch actor info
    const enrichedEvents = [];
    for (const event of events) {
      const actorResult = await pool.query(
        'SELECT name, avatar_url FROM users WHERE id = $1',
        [event.actor_id]
      );
      enrichedEvents.push({
        ...event,
        actor: actorResult.rows[0] || null,
      });
    }

    res.json(enrichedEvents);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

module.exports = router;
