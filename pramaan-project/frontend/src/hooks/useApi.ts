import { useCallback, useEffect, useState } from 'react';
import { errorMessage } from '../services/api';

export interface ApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  updatedAt: Date | null;
  reload: () => void;
}

export function useApi<T>(fetcher: (signal: AbortSignal) => Promise<T>, options: { enabled?: boolean; pollInterval?: number } = {}): ApiState<T> {
  const { enabled = true, pollInterval = 0 } = options;
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<{
    fetcher: typeof fetcher;
    data: T | null;
    loading: boolean;
    error: string | null;
    updatedAt: Date | null;
  }>({ fetcher, data: null, loading: enabled, error: null, updatedAt: null });
  const reload = useCallback(() => setRevision((value) => value + 1), []);

  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let active = true;
    async function run() {
      setState((previous) => ({ fetcher, data: previous.fetcher === fetcher ? previous.data : null, loading: true, error: null, updatedAt: previous.fetcher === fetcher ? previous.updatedAt : null }));
      try {
        const data = await fetcher(controller.signal);
        if (active) setState({ fetcher, data, loading: false, error: null, updatedAt: new Date() });
      } catch (error) {
        if (active) setState({ fetcher, data: null, loading: false, error: errorMessage(error), updatedAt: null });
      } finally {
        if (active && pollInterval > 0) timer = setTimeout(() => void run(), pollInterval);
      }
    }
    void run();
    return () => {
      active = false;
      controller.abort();
      clearTimeout(timer);
    };
  }, [fetcher, enabled, pollInterval, revision]);

  if (!enabled || state.fetcher !== fetcher) return { data: null, loading: enabled, error: null, updatedAt: null, reload };
  return { data: state.data, loading: state.loading, error: state.error, updatedAt: state.updatedAt, reload };
}
