import { ref, onUnmounted } from 'vue';
import type { Feed, IOCStats, McpStatus } from '../types';
import { API_URL } from './useIOCs';

export function useFeeds() {
  const feeds = ref<Feed[]>([]);
  const stats = ref<IOCStats | null>(null);
  const mcpStatus = ref<McpStatus | null>(null);
  const loading = ref(false);

  let pollInterval: ReturnType<typeof setInterval> | null = null;
  let fastPollInterval: ReturnType<typeof setInterval> | null = null;

  const fetchAll = async (): Promise<void> => {
    loading.value = true;
    try {
      const [feedsRes, statsRes, mcpRes] = await Promise.all([
        fetch(`${API_URL}/feeds`),
        fetch(`${API_URL}/stats`),
        fetch(`${API_URL}/mcp/status`),
      ]);

      if (feedsRes.ok) {
        const data = await feedsRes.json();
        feeds.value = data.feeds ?? data ?? [];
        
        // If any feed is still polling, trigger/maintain fast polling
        const anyPolling = feeds.value.some(f => f.status === 'polling');
        if (anyPolling) {
          startFastPolling();
        } else if (fastPollInterval) {
          clearInterval(fastPollInterval);
          fastPollInterval = null;
        }
      }

      if (statsRes.ok) {
        stats.value = await statsRes.json();
      }

      if (mcpRes.ok) {
        mcpStatus.value = await mcpRes.json();
      }
    } catch (err) {
      console.error('Failed to fetch feeds/stats/mcp:', err);
    } finally {
      loading.value = false;
    }
  };

  const startFastPolling = () => {
    if (fastPollInterval) return;
    fastPollInterval = setInterval(() => {
      fetchAll();
    }, 2000);
  };

  const triggerPoll = async (): Promise<void> => {
    try {
      await fetch(`${API_URL}/feeds/poll`, { method: 'POST' });
      // Set the non-manual feeds to 'polling' locally so the UI updates instantly
      feeds.value = feeds.value.map(f => f.name !== 'manual' ? { ...f, status: 'polling' } : f);
      // Immediately start fast polling
      startFastPolling();
    } catch (err) {
      console.error('Failed to trigger poll:', err);
    }
  };

  // Initial fetch
  fetchAll();

  // Poll every 30 seconds
  pollInterval = setInterval(() => {
    if (!fastPollInterval) {
      fetchAll();
    }
  }, 30_000);

  onUnmounted(() => {
    if (pollInterval) clearInterval(pollInterval);
    if (fastPollInterval) clearInterval(fastPollInterval);
  });

  return {
    feeds,
    stats,
    mcpStatus,
    loading,
    triggerPoll,
  };
}
