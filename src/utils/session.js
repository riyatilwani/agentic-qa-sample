// Lightweight session persistence so a page refresh doesn't force the user
// to log in again. Reads the token issued by /api/auth/login and rehydrates
// the user object from it on load.

const STORAGE_KEY = 'authToken';

export function saveSession(token) {
  localStorage.setItem(STORAGE_KEY, token);
}

export function clearSession() {
  localStorage.removeItem(STORAGE_KEY);
}

export function loadSession() {
  const token = localStorage.getItem(STORAGE_KEY);
  if (!token) return null;

  const user = decodeUser(token);
  return user ? { token, user } : null;
}

// Pulls the display fields out of the JWT payload so we can show
// "Welcome back" immediately, without waiting on a round trip.
function decodeUser(token) {
  try {
    const payload = token.split('.')[1];
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(json);
    return { id: claims.userId, email: claims.email, name: claims.name || claims.email };
  } catch {
    return null;
  }
}
