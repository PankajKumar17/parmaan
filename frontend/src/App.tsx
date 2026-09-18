import { Component, useEffect, useState, type ReactNode } from 'react';
import { AUTH_EVENT, clearToken, getAssets, getHealth, getIntegrity, getMe, getToken, type User } from './services/api';
import { useApi } from './hooks/useApi';
import StatusBanner from './components/StatusBanner';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard/Index';
import LineageView from './pages/LineageView/Index';
import Passport from './pages/Passport/Index';

type Page = 'dashboard' | 'lineage' | 'passport';
class PageBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <StatusBanner tone="error" title="This view could not be displayed" onRetry={() => this.setState({ failed: false })}>Other pages remain available. Retry this view or refresh the application.</StatusBanner> : this.props.children;
  }
}
function NavIcon({ page }: { page: Page }) {
  return <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.6">{page === 'dashboard' ? <path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z" /> : page === 'lineage' ? <><rect x="2" y="9" width="5" height="6" rx="1" /><rect x="17" y="2" width="5" height="6" rx="1" /><rect x="17" y="16" width="5" height="6" rx="1" /><path d="M7 12h5V5h5M12 12v7h5" /></> : <><rect x="5" y="2" width="14" height="20" rx="2" /><path d="M9 7h6M9 11h6M9 15h3" /></>}</svg>;
}
function Workspace({ user }: { user: User }) {
  const [page, setPage] = useState<Page>('dashboard');
  const [chosenAsset, setChosenAsset] = useState('');
  const assets = useApi(getAssets);
  const integrity = useApi(getIntegrity, { pollInterval: 30000 });
  const health = useApi(getHealth, { pollInterval: 30000 });
  const assetId = assets.data?.some((asset) => asset.id === chosenAsset) ? chosenAsset : assets.data?.[0]?.id ?? '';
  const verified = integrity.data?.verified === true && !integrity.error;
  const nav: { page: Page; label: string }[] = [{ page: 'dashboard', label: 'Overview' }, { page: 'lineage', label: 'Lineage & provenance' }, { page: 'passport', label: 'Assurance passport' }];
  return <div className="app-shell"><a className="skip-link" href="#workspace">Skip to workspace</a><aside className="sidebar">
    <div className="brand"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 3 28 9v14l-12 6L4 23V9Z M4 9l12 7 12-7 M16 16v13" /></svg><span>PRAMAAN</span></div><p className="brand-description">Evidence-carrying AI</p>
    <nav aria-label="Workspace navigation">{nav.map((item) => <button type="button" key={item.page} className={`nav-link ${page === item.page ? 'active' : ''}`} onClick={() => setPage(item.page)} aria-current={page === item.page ? 'page' : undefined}><NavIcon page={item.page} /><span>{item.label}</span></button>)}</nav>
    <div className="sidebar-bottom"><p>Assurance, not assumption.</p><div className="user-profile"><span className="avatar" aria-hidden="true">{user.email.slice(0, 1).toUpperCase() || 'U'}</span><span className="user-email" title={user.email}>{user.email}</span></div><button type="button" className="button sign-out" onClick={clearToken}>Sign out</button></div>
  </aside><div className="workspace-shell"><header className="topbar"><span>Assurance workspace <span className="topbar-divider">/</span> {nav.find((item) => item.page === page)?.label}</span><span className={`connection ${health.error || health.data && health.data.status !== 'ok' ? 'error-text' : 'muted'}`}><span className="status-dot" />{health.error ? 'API unreachable' : health.data?.status === 'ok' ? 'API connected' : health.loading ? 'Connecting…' : 'API status unknown'}</span></header>
    <main id="workspace" className="workspace" tabIndex={-1}>
      <StatusBanner tone={integrity.loading && !integrity.data && !integrity.error ? 'info' : verified ? 'success' : 'error'} title={integrity.loading && !integrity.data ? 'Checking system self-integrity…' : verified ? 'System self-integrity verified' : 'DEGRADED / UNVERIFIED — system self-integrity'} onRetry={!verified && !integrity.loading ? integrity.reload : undefined}>
        {integrity.error || (verified ? 'Backend integrity baseline verified. This does not certify asset safety.' : 'Do not treat this workspace’s findings as verified assurance until backend integrity is restored.')}
        {integrity.data && !verified && <details><summary>Integrity details</summary><ul>{integrity.data.errors.map((error, index) => <li key={`error-${index}`}>{error}</li>)}{(['missing', 'changed', 'added'] as const).flatMap((kind) => integrity.data?.[kind].map((path, index) => <li key={`${kind}-${index}`}>{kind}: <code>{path}</code></li>) ?? [])}</ul></details>}
      </StatusBanner>
      {health.error && <StatusBanner tone="error" title="Backend health unavailable" onRetry={health.reload}>{health.error}</StatusBanner>}
      {health.data && (health.data.status !== 'ok' || health.data.self_integrity !== 'VERIFIED') && <StatusBanner tone="error" title="Backend health reports degraded assurance">Service: {health.data.status}. Self-integrity: {health.data.self_integrity}.</StatusBanner>}
      <PageBoundary key={page}>{page === 'dashboard' ? <Dashboard assets={assets} onPassport={(id) => { setChosenAsset(id); setPage('passport'); }} /> : page === 'lineage' ? <LineageView assets={assets} assetId={assetId} onAssetChange={setChosenAsset} /> : <Passport assets={assets} assetId={assetId} onAssetChange={setChosenAsset} />}</PageBoundary>
      <footer className="workspace-footer"><span>PRAMAAN · Evidence carries its limitations.</span><span>All findings require scoped interpretation.</span></footer>
    </main>
  </div></div>;
}
export default function App() {
  const [hasSession, setHasSession] = useState(() => !!getToken());
  const [user, setUser] = useState<User | null>(null);
  const session = useApi(getMe, { enabled: hasSession && !user });
  useEffect(() => {
    const expire = () => { setHasSession(false); setUser(null); };
    const storage = () => { setHasSession(!!getToken()); setUser(null); };
    window.addEventListener(AUTH_EVENT, expire); window.addEventListener('storage', storage);
    return () => { window.removeEventListener(AUTH_EVENT, expire); window.removeEventListener('storage', storage); };
  }, []);
  useEffect(() => {
    if (session.data && hasSession) {
      if (session.data.is_active) setUser(session.data);
      else clearToken();
    }
  }, [session.data, hasSession]);
  if (!hasSession) return <LoginPage onLogin={(value) => { setUser(value); setHasSession(true); }} />;
  if (!user) return <main className="session-screen"><div className="brand">PRAMAAN</div><StatusBanner tone={session.error ? 'error' : 'info'} title={session.error ? 'Session verification unavailable' : 'Verifying your session…'} onRetry={session.error ? session.reload : undefined}>{session.error || 'Loading your authenticated workspace.'}</StatusBanner><button className="button" onClick={clearToken}>Return to sign in</button></main>;
  return <Workspace user={user} />;
}
