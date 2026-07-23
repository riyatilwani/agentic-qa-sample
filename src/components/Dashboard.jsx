import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function Dashboard({ user, onLogout }) {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    // Fetch user activity
    axios.get('/api/dashboard').then(res => setEvents(res.data));
  }, []);

  return (
    <div>
      <h2>Welcome, {user.name}</h2>
      <button onClick={onLogout}>Logout</button>
      <ul>
        {events.map(e => <li key={e.id}>{e.description}</li>)}
      </ul>
    </div>
  );
}
