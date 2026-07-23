import React, { useState } from 'react';
import Login from '../components/Login';
import Dashboard from '../components/Dashboard';

export default function App() {
  const [user, setUser] = useState(null);

  return (
    <div className="app">
      {user ? (
        <Dashboard user={user} onLogout={() => setUser(null)} />
      ) : (
        <Login onLogin={setUser} />
      )}
    </div>
  );
}
