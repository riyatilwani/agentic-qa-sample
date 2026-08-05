const express = require('express');
const { Pool } = require('pg');
const router = express.Router();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 50;

// GET /api/notifications?cursor=<id>&pageSize=<n>
// Returns the authenticated user's most recent notifications, newest first.
// Cursor-paginated on id (indexed, monotonically increasing) rather than
// offset, so results stay stable while new notifications keep arriving.
router.get('/', async (req, res) => {
  try {
    const userId = req.user.userId;
    const pageSize = Math.min(
      Number.parseInt(req.query.pageSize, 10) || DEFAULT_PAGE_SIZE,
      MAX_PAGE_SIZE
    );
    const cursor = req.query.cursor ? Number.parseInt(req.query.cursor, 10) : null;

    const params = [userId];
    let where = 'user_id = $1';
    if (Number.isInteger(cursor)) {
      params.push(cursor);
      where += ` AND id < $${params.length}`;
    }
    params.push(pageSize);

    const result = await pool.query(
      `SELECT id, type, message, read_at, created_at
       FROM notifications
       WHERE ${where}
       ORDER BY id DESC
       LIMIT $${params.length}`,
      params
    );

    const notifications = result.rows;
    const nextCursor = notifications.length === pageSize
      ? notifications[notifications.length - 1].id
      : null;

    res.json({ notifications, nextCursor });
  } catch (err) {
    console.error('Failed to load notifications:', err.message);
    res.status(500).json({ error: 'Failed to load notifications' });
  }
});

// POST /api/notifications/:id/read
// Marks a single notification as read. Scoped to the requesting user so one
// account can't mark another account's notification as read.
router.post('/:id/read', async (req, res) => {
  try {
    const userId = req.user.userId;
    const notificationId = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(notificationId)) {
      return res.status(400).json({ error: 'Invalid notification id' });
    }

    const result = await pool.query(
      `UPDATE notifications SET read_at = now()
       WHERE id = $1 AND user_id = $2
       RETURNING id`,
      [notificationId, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    res.json({ id: notificationId, read: true });
  } catch (err) {
    console.error('Failed to mark notification as read:', err.message);
    res.status(500).json({ error: 'Failed to update notification' });
  }
});

module.exports = router;
