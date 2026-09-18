import { useState, type FormEvent } from 'react';
import { clearToken, errorMessage, getMe, login, type User } from '../services/api';
import StatusBanner from '../components/StatusBanner';

export default function LoginPage({ onLogin }: { onLogin: (user: User) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      await login(username.trim(), password);
      const user = await getMe();
      if (!user.is_active) throw new Error('This account is inactive. Contact your administrator.');
      setPassword('');
      onLogin(user);
    } catch (error) {
      clearToken();
      setError(errorMessage(error));
    } finally { setPending(false); }
  }
  return <main className="login-layout">
    <section className="login-story" aria-label="About PRAMAAN">
      <div className="brand"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 3 28 9v14l-12 6L4 23V9Z M4 9l12 7 12-7 M16 16v13" /></svg><span>PRAMAAN</span></div>
      <div className="login-thesis"><h1>Every claim.<br />Its evidence.</h1><p>Trace AI integrity from contributor to finding. Inspect what supports a decision—and what contradicts it.</p>
        <ol className="evidence-flow"><li>Evidence</li><li>Provenance</li><li>Decision</li></ol>
      </div>
      <p className="login-principle">Nothing trusted by default.<br />Assurance is scoped, verifiable, and never absolute.</p>
    </section>
    <section className="login-form-wrap"><form onSubmit={submit} className="login-form" aria-busy={pending}>
      <h2>Sign in to your workspace</h2><p className="muted">Use your PRAMAAN account to review evidence and run assessments.</p>
      {error && <StatusBanner tone="error" title="Sign-in failed">{error}</StatusBanner>}
      <label htmlFor="username">Email address</label><input id="username" name="username" type="email" autoComplete="username" required maxLength={254} value={username} onChange={(event) => setUsername(event.target.value)} disabled={pending} placeholder="you@organization.com" />
      <label htmlFor="password">Password</label><input id="password" name="password" type="password" autoComplete="current-password" required maxLength={256} value={password} onChange={(event) => setPassword(event.target.value)} disabled={pending} />
      <button type="submit" className="button primary login-submit" disabled={pending}>{pending ? 'Signing in…' : 'Sign in'}</button>
      <p className="footnote">Accounts are provisioned by your administrator. Your session token is stored in this browser; sign out on shared devices.</p>
    </form></section>
  </main>;
}
