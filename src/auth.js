// BUG: JWT stored in localStorage — readable by any JS on the page (XSS attack vector).
// BUG: No token expiry check before use — an old stolen token is accepted forever.
// BUG: clearAuth() only removes from current tab; other tabs stay "authenticated".
// NOTE: The right fix is httpOnly cookies set by the server, never touching client JS.

const TOKEN_KEY = 'auth_token';
const USER_KEY  = 'current_user';

export function storeAuth(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function getCurrentUser() {
  const raw = localStorage.getItem(USER_KEY);
  return raw ? JSON.parse(raw) : null;
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function authHeader() {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}
