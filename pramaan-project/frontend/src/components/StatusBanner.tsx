import type { ReactNode } from 'react';

export type StatusTone = 'success' | 'warning' | 'error' | 'info';
export default function StatusBanner({ tone = 'info', title, children, onRetry }: { tone?: StatusTone; title: string; children?: ReactNode; onRetry?: () => void }) {
  return <div className={`status-banner status-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
    <span className="status-dot" aria-hidden="true" />
    <div><strong>{title}</strong>{children && <div className="status-detail">{children}</div>}</div>
    {onRetry && <button type="button" className="button small" onClick={onRetry}>Retry</button>}
  </div>;
}
