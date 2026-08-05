import React, { useState, useEffect } from 'react';
import Login from '../components/Login';
import Dashboard from '../components/Dashboard';
import { loadSession, clearSession } from '../utils/session';

export default function App() {
  const [user, setUser] = useState(null);

  // Restore the session on refresh so the user isn't logged out every time
  // they reload the page.
  useEffect(() => {
    const session = loadSession();
    if (session) setUser(session.user);
  }, []);

  const handleLogout = () => {
    clearSession();
    setUser(null);
  };

  return (
    <div className="app">
      {user ? (
        <Dashboard user={user} onLogout={handleLogout} />
      ) : (
        <Login onLogin={setUser} />
      )}
    </div>
  );
}
