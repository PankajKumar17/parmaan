import type { ReactNode } from 'react';
import StatusBanner from './StatusBanner';

export default function Panel({ title, subtitle, children, loading = false, error, empty = false, emptyText = 'No data available yet.', onRetry, actions, className = '' }: {
  title: string; subtitle?: string; children?: ReactNode; loading?: boolean; error?: string | null;
  empty?: boolean; emptyText?: string; onRetry?: () => void; actions?: ReactNode; className?: string;
}) {
  return <section className={`panel ${className}`} aria-label={title} aria-busy={loading}>
    <header className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div><div className="panel-actions">{loading && <span className="loading-label">Loading…</span>}{actions}</div></header>
    {error ? <StatusBanner tone="error" title="Panel degraded" onRetry={onRetry}>{error}</StatusBanner> : loading && !children ? <p className="empty-state" role="status">Fetching evidence…</p> : empty ? <p className="empty-state">{emptyText}</p> : children}
  </section>;
}
