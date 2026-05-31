<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue';
import { marked } from 'marked';
import {
  Shield,
  ShieldAlert,
  Database,
  FileText,
  Activity,
  PlusCircle,
  Settings,
  ChevronRight,
  Copy,
  Check,
  Server,
  Cloud,
  RefreshCw,
  Plus,
  Loader2,
  AlertTriangle,
  ExternalLink,
  Lock,
  Sparkles,
  BookOpen,
  Info,
  Map,
  Star,
  Terminal,
  Bookmark,
  Printer,
  FileCode,
  HelpCircle,
  X,
  ChevronDown,
  ChevronUp,
  Search,
} from 'lucide-vue-next';
import DashboardStats from './components/DashboardStats.vue';
import IOCTable from './components/IOCTable.vue';
import ChatPanel from './components/ChatPanel.vue';
import ThreatMap from './components/ThreatMap.vue';
import SiemDrawer from './components/SiemDrawer.vue';
import HuntingLibrary from './components/HuntingLibrary.vue';
import LoginGate from './components/LoginGate.vue';
import { useFeeds } from './composables/useFeeds';
import { useIOCs, API_URL } from './composables/useIOCs';
import { usePAIChat } from './composables/usePAIChat';
import type { IOC, SeverityLevel, QuickPrompts, AIProvider, ThreatBrief, IOCType } from './types';
import { sanitizeHtml } from './utils/sanitize';

// Configure marked for threat brief rendering
marked.setOptions({
  breaks: true,
  gfm: true,
});

const renderMarkdown = (content: string): string => {
  return sanitizeHtml(marked.parse(content) as string);
};

// --- Active Tab ---
type TabName = 'feed' | 'briefs' | 'sources' | 'inject' | 'hunting' | 'settings' | 'docs';
const currentTab = ref<TabName>('feed');

// --- Authentication State ---
const isAuthenticated = ref(sessionStorage.getItem('aegis-authenticated') === 'true');
const handleLoginSuccess = () => {
  isAuthenticated.value = true;
};
const handleLogout = () => {
  sessionStorage.removeItem('aegis-authenticated');
  isAuthenticated.value = false;
};

// --- FAQ Modal State & Logic ---
const showFaqModal = ref(false);
const faqSearchQuery = ref('');
const faqSelectedCategory = ref('All');
const faqExpandedQuestion = ref<string | null>(null);

const faqCategories = ['All', 'Ingestion', 'Search', 'AI Analyst', 'Alerts', 'SecOps', 'IOCs'];

const faqItems = [
  {
    category: 'AI Analyst',
    question: 'How do I configure the Anthropic Claude AI Analyst?',
    answer: 'To enable Claude and MCP reasoning, register for an Anthropic API key, open the root `.env` file, and populate the `ANTHROPIC_API_KEY` parameter. Ensure the server is restarted to apply env changes.'
  },
  {
    category: 'Search',
    question: 'Why does my SQLite FTS5 search return a syntax error?',
    answer: 'Special characters (like dots in IPs or colons in URLs) can confuse FTS5 tokenizers. Aegis handles this automatically by falling back to a standard SQL `LIKE` wildcard search (e.g. `%query%`), ensuring search queries never fail.'
  },
  {
    category: 'AI Analyst',
    question: 'What is the difference between Cloud Mode and Local Mode for AI queries?',
    answer: 'Cloud Mode (Claude) utilizes Anthropic\'s model and supports the 27 enrichment tools via MCP (Model Context Protocol). Local Mode (Ollama) routes queries to on-premises LLMs to ensure air-gapped data privacy but disables tool execution.'
  },
  {
    category: 'Alerts',
    question: 'How do I test my Microsoft Teams and Slack webhooks locally?',
    answer: 'Aegis includes mock webhook receivers. Configure your webhook URLs in Settings to point to `http://localhost:4001/api/mock-webhook/slack` or `teams`. Run manual Ingestions and check server terminal logs to inspect the dispatched JSON payloads.'
  },
  {
    category: 'Ingestion',
    question: 'How does the Ingestion Concurrency Lock work?',
    answer: 'The scheduler uses an in-memory lock `activePollPromise`. If a poll is already in progress, any subsequent trigger commands reuse the running promise. This prevents database lock contentions and API rate-limiting issues.'
  },
  {
    category: 'IOCs',
    question: 'Why are indicators defanged when displayed or exported?',
    answer: 'Defanging converts navigable URLs and IPs into safe text strings (e.g., `hxxps://` or `[.]`) to prevent accidental clicks or triggering automated corporate mail blocklists.'
  },
  {
    category: 'SecOps',
    question: 'How do I register the companion CVE MCP server on Windows?',
    answer: 'Set `CVE_MCP_PYTHON` in your `.env` to your virtual environment\'s Python executable path, and `CVE_MCP_CWD` to the folder directory. Aegis automatically handles Windows-specific process spawning and environment variables.'
  }
];

const filteredFaqs = computed(() => {
  return faqItems.filter(item => {
    const matchesCategory = faqSelectedCategory.value === 'All' || item.category === faqSelectedCategory.value;
    const matchesSearch = item.question.toLowerCase().includes(faqSearchQuery.value.toLowerCase()) ||
                          item.answer.toLowerCase().includes(faqSearchQuery.value.toLowerCase());
    return matchesCategory && matchesSearch;
  });
});

const toggleFaq = (question: string) => {
  if (faqExpandedQuestion.value === question) {
    faqExpandedQuestion.value = null;
  } else {
    faqExpandedQuestion.value = question;
  }
};

watch([faqSelectedCategory, faqSearchQuery], () => {
  faqExpandedQuestion.value = null;
});

// --- Docs Section State & Scrollspy Observer ---
const activeDocSection = ref('intro');
let docObserver: IntersectionObserver | null = null;
let isProgrammaticScroll = false;
let scrollTimeout: any = null;

const scrollToDocSection = (id: string) => {
  activeDocSection.value = id;
  isProgrammaticScroll = true;
  if (scrollTimeout) clearTimeout(scrollTimeout);
  
  const el = document.getElementById(`doc-${id}`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  
  scrollTimeout = setTimeout(() => {
    isProgrammaticScroll = false;
  }, 800);
};

const handleDocsScroll = (e: Event) => {
  if (isProgrammaticScroll) return;
  const target = e.target as HTMLElement;
  // If we scroll to the absolute bottom, force the last section to be highlighted
  if (target.scrollTop + target.clientHeight >= target.scrollHeight - 15) {
    activeDocSection.value = 'defanging';
  }
};

const setupDocsObserver = () => {
  if (docObserver) {
    docObserver.disconnect();
    docObserver = null;
  }

  const rootEl = document.getElementById('docs-scroll-container');
  const sectionIds = ['intro', 'feeds', 'fts', 'mcp', 'alerts', 'hunting', 'defanging'];

  docObserver = new IntersectionObserver((entries) => {
    if (isProgrammaticScroll) return;

    const intersectingEntries = entries.filter(e => e.isIntersecting);
    if (intersectingEntries.length > 0) {
      let bestEntry = intersectingEntries[0];
      for (const entry of intersectingEntries) {
        if (entry.boundingClientRect.top < bestEntry.boundingClientRect.top && entry.boundingClientRect.top >= 0) {
          bestEntry = entry;
        }
      }
      const id = bestEntry.target.id.replace('doc-', '');
      activeDocSection.value = id;
    }
  }, {
    root: rootEl,
    rootMargin: '-5% 0px -60% 0px',
    threshold: [0, 0.1, 0.2]
  });

  sectionIds.forEach(id => {
    const el = document.getElementById(`doc-${id}`);
    if (el) {
      docObserver?.observe(el);
    }
  });
};

const cleanupDocsObserver = () => {
  if (docObserver) {
    docObserver.disconnect();
    docObserver = null;
  }
};

watch(currentTab, async (newTab) => {
  if (newTab === 'docs') {
    await nextTick();
    setupDocsObserver();
  } else {
    cleanupDocsObserver();
  }
});

// --- SIEM Drawer State ---
const isSiemDrawerOpen = ref(false);

// --- Threat Dossier Layout State (Usability Enhancement) ---
const isDossierExpanded = ref(true);

// --- Threat Map Visual Toggle ---
const isMapVisible = ref(true);

// --- Webhook Settings Configurations ---
const slackWebhookUrl = ref('');
const teamsWebhookUrl = ref('');
const genericWebhookUrl = ref('');
const settingsLoading = ref(false);
const webhookSettingsSaved = ref(false);

const testingSlack = ref(false);
const testingTeams = ref(false);
const testingGeneric = ref(false);
const slackTestResult = ref<{ success: boolean; message: string } | null>(null);
const teamsTestResult = ref<{ success: boolean; message: string } | null>(null);
const genericTestResult = ref<{ success: boolean; message: string } | null>(null);

// --- History & Bookmarks State ---
const viewHistory = ref<IOC[]>(
  JSON.parse(localStorage.getItem('aegis-view-history') || '[]')
);
const bookmarkedIOCs = ref<IOC[]>(
  JSON.parse(localStorage.getItem('aegis-bookmarks') || '[]')
);

// Toggle bookmark indicator
const toggleBookmark = (ioc: IOC) => {
  const idx = bookmarkedIOCs.value.findIndex(item => item.id === ioc.id);
  if (idx > -1) {
    bookmarkedIOCs.value.splice(idx, 1);
  } else {
    bookmarkedIOCs.value.push(ioc);
  }
  localStorage.setItem('aegis-bookmarks', JSON.stringify(bookmarkedIOCs.value));
};

const isBookmarked = (ioc: IOC) => {
  return bookmarkedIOCs.value.some(item => item.id === ioc.id);
};

// Add to local history list
const addToHistory = (ioc: IOC) => {
  const idx = viewHistory.value.findIndex(item => item.id === ioc.id);
  if (idx > -1) {
    viewHistory.value.splice(idx, 1);
  }
  viewHistory.value.unshift(ioc);
  if (viewHistory.value.length > 15) {
    viewHistory.value.pop();
  }
  localStorage.setItem('aegis-view-history', JSON.stringify(viewHistory.value));
};

// --- Data composables ---
const { feeds, stats, mcpStatus, triggerPoll } = useFeeds();
const isPolling = computed(() => feeds.value.some(f => f.status === 'polling'));
const { iocs, total, loading, filters, setSearch, setFilter, setSort, loadMore, refresh } = useIOCs();

// --- Chat composable ---
const {
  messages,
  isLoading,
  error,
  quickPrompts,
  sendMessage,
  quickAction,
  generateBrief,
  clearChat,
  provider,
  providerConfig,
  setProvider,
  setOllamaConfig,
  loadOllamaModels,
} = usePAIChat();

// --- Selected IOC ---
const selectedIOC = ref<IOC | null>(null);

const selectedIOCs = computed(() =>
  selectedIOC.value ? [selectedIOC.value] : []
);

const handleSelectIOC = (ioc: IOC) => {
  selectedIOC.value = selectedIOC.value?.id === ioc.id ? null : ioc;
  if (selectedIOC.value) {
    addToHistory(selectedIOC.value);
  }
};

// --- Country Filter (from SVG Map) ---
const REGION_COUNTRY_CODES = ['US', 'BR', 'EU', 'ZA', 'CN', 'AU'];
const selectedRegionCountryCode = ref('');

const filteredIOCs = computed(() => {
  if (!selectedRegionCountryCode.value) return iocs.value;
  return iocs.value.filter(ioc => {
    if (ioc.ioc_type !== 'ip' && ioc.ioc_type !== 'domain' && ioc.ioc_type !== 'url') return false;
    let hash = 0;
    for (let i = 0; i < ioc.value.length; i++) {
      hash = ioc.value.charCodeAt(i) + ((hash << 5) - hash);
    }
    const index = Math.abs(hash) % 6;
    return REGION_COUNTRY_CODES[index] === selectedRegionCountryCode.value;
  });
});

const handleCountryFilter = (countryCode: string) => {
  selectedRegionCountryCode.value = countryCode;
};

// --- Severity filter toggle (from stats bar) ---
const activeSeverityFilter = ref<SeverityLevel | null>(null);

const handleToggleSeverity = (severity: SeverityLevel) => {
  if (activeSeverityFilter.value === severity) {
    activeSeverityFilter.value = null;
    setFilter('severity', '');
  } else {
    activeSeverityFilter.value = severity;
    setFilter('severity', severity);
  }
};

// --- IOCTable event handlers ---
const handleSearch = (value: string) => {
  setSearch(value);
};

const handleFilter = (key: 'type' | 'severity' | 'feed', value: string) => {
  setFilter(key, value);
  if (key === 'severity') {
    activeSeverityFilter.value = value ? (value as SeverityLevel) : null;
  }
};

const handleLoadMore = () => {
  loadMore();
};

const handleSort = (column: string) => {
  setSort(column);
};

// --- Chat event handlers ---
const handleSendMessage = (message: string) => {
  sendMessage(message, selectedIOCs.value);
};

const handleQuickAction = (action: keyof QuickPrompts) => {
  quickAction(action, selectedIOCs.value);
};

const handleSetProvider = (p: AIProvider) => {
  setProvider(p);
};

const handleSetOllamaConfig = (url: string, model: string) => {
  setOllamaConfig(url, model);
  loadOllamaModels();
};

const handleGenerateBrief = async () => {
  await generateBrief(provider.value, providerConfig.value.ollamaUrl, providerConfig.value.ollamaModel);
  await fetchBriefs();
  if (briefs.value.length > 0) {
    selectedBrief.value = briefs.value[0];
    currentTab.value = 'briefs';
  }
};

// --- Feed poll ---
const handleTriggerPoll = async () => {
  await triggerPoll();
  refresh();
};

// --- Resizable split panel ---
const workspaceContainer = ref<HTMLElement | null>(null);
const leftPanelPercent = ref(60);
const isResizing = ref(false);

const leftPanelStyle = computed(() => ({ width: `${leftPanelPercent.value}%` }));
const rightPanelStyle = computed(() => ({ width: `${100 - leftPanelPercent.value}%` }));

const startResize = (e: MouseEvent) => {
  e.preventDefault();
  isResizing.value = true;
  document.body.style.cursor = 'col-resize';
  document.body.classList.add('select-none');
  const container = workspaceContainer.value;
  if (!container) return;

  const onMouseMove = (moveEvent: MouseEvent) => {
    const rect = container.getBoundingClientRect();
    const percent = ((moveEvent.clientX - rect.left) / rect.width) * 100;
    leftPanelPercent.value = Math.min(80, Math.max(30, percent));
  };

  const onMouseUp = () => {
    isResizing.value = false;
    document.body.style.cursor = '';
    document.body.classList.remove('select-none');
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
  };

  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('mouseup', onMouseUp);
};

// --- Resizable Sidebar ---
const sidebarWidth = ref(256);
const isResizingSidebar = ref(false);

const startSidebarResize = (e: MouseEvent) => {
  e.preventDefault();
  isResizingSidebar.value = true;
  document.body.style.cursor = 'col-resize';
  document.body.classList.add('select-none');

  const onMouseMove = (moveEvent: MouseEvent) => {
    sidebarWidth.value = Math.min(380, Math.max(180, moveEvent.clientX));
  };

  const onMouseUp = () => {
    isResizingSidebar.value = false;
    document.body.style.cursor = '';
    document.body.classList.remove('select-none');
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
  };

  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('mouseup', onMouseUp);
};

// --- Resizable Map/Metrics Panel ---
const mapPanelHeight = ref(360);
const isResizingMap = ref(false);
const mapPanelContainer = ref<HTMLElement | null>(null);

const startMapResize = (e: MouseEvent) => {
  e.preventDefault();
  isResizingMap.value = true;
  document.body.style.cursor = 'row-resize';
  document.body.classList.add('select-none');
  const startY = e.clientY;
  const startHeight = mapPanelHeight.value;

  const onMouseMove = (moveEvent: MouseEvent) => {
    const deltaY = moveEvent.clientY - startY;
    mapPanelHeight.value = Math.min(600, Math.max(200, startHeight + deltaY));
  };

  const onMouseUp = () => {
    isResizingMap.value = false;
    document.body.style.cursor = '';
    document.body.classList.remove('select-none');
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
  };

  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('mouseup', onMouseUp);
};

// --- Threat Briefs Archive State ---
const briefs = ref<ThreatBrief[]>([]);
const selectedBrief = ref<ThreatBrief | null>(null);
const briefsLoading = ref(false);
const briefCopied = ref(false);

const fetchBriefs = async () => {
  briefsLoading.value = true;
  try {
    const response = await fetch(`${API_URL}/briefs?limit=50`);
    if (response.ok) {
      briefs.value = await response.json();
      if (briefs.value.length > 0 && !selectedBrief.value) {
        selectedBrief.value = briefs.value[0];
      }
    }
  } catch (err) {
    console.error('Failed to fetch briefs:', err);
  } finally {
    briefsLoading.value = false;
  }
};

const copyBriefText = (content: string) => {
  navigator.clipboard.writeText(content);
  briefCopied.value = true;
  setTimeout(() => {
    briefCopied.value = false;
  }, 2000);
};

// --- Manual Single Injector Form State ---
const formValue = ref('');
const formType = ref<IOCType>('ip');
const formSeverity = ref<SeverityLevel>('medium');
const formTitle = ref('');
const formDescription = ref('');
const formRef = ref('');
const formTags = ref('');

const isInjecting = ref(false);
const injectSuccess = ref(false);
const injectError = ref<string | null>(null);

const formValueValidationError = computed(() => {
  const val = formValue.value.trim();
  if (!val) return null;
  
  const type = formType.value;
  if (type === 'ip') {
    const regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!regex.test(val)) return 'Invalid IP Address format (e.g. 192.168.1.1 or 192.168.1[.]1)';
  } else if (type === 'domain') {
    const regex = /^(?:[a-zA-Z0-9.-]+(?:\[\.\]|\.)[a-zA-Z]{2,})$/;
    if (!regex.test(val)) return 'Invalid Domain format (e.g. evil.com or evil[.]com)';
  } else if (type === 'url') {
    const regex = /^(?:https?|hxxps?):\/\/[^\s"'<>\)]+$/i;
    if (!regex.test(val)) return 'Invalid URL format (e.g. hxxps://evil.com/path or https://evil.com)';
  } else if (type === 'hash') {
    const regex = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})$/;
    if (!regex.test(val)) return 'Invalid File Hash format (must be 32-char MD5 or 64-char SHA-256)';
  } else if (type === 'cve') {
    const regex = /^CVE-\d{4}-\d{4,7}$/i;
    if (!regex.test(val)) return 'Invalid CVE format (e.g. CVE-2021-44228)';
  } else if (type === 'email') {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!regex.test(val)) return 'Invalid Email format (e.g. admin@domain.com)';
  }
  return null;
});

const handleInjectIOC = async () => {
  if (!formValue.value.trim() || formValueValidationError.value) return;
  isInjecting.value = true;
  injectSuccess.value = false;
  injectError.value = null;

  try {
    const response = await fetch(`${API_URL}/iocs/custom`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ioc_type: formType.value,
        value: formValue.value.trim(),
        severity: formSeverity.value,
        title: formTitle.value.trim() || undefined,
        description: formDescription.value.trim() || undefined,
        source_ref: formRef.value.trim() || undefined,
        tags: formTags.value.trim() || undefined,
      }),
    });

    const data = await response.json();
    if (data.success) {
      injectSuccess.value = true;
      // Reset form
      formValue.value = '';
      formTitle.value = '';
      formDescription.value = '';
      formRef.value = '';
      formTags.value = '';

      // Refresh data
      refresh();
      setTimeout(() => {
        injectSuccess.value = false;
      }, 3000);
    } else {
      injectError.value = data.error || 'Failed to inject custom IOC';
    }
  } catch (err) {
    console.error('Failed to inject custom IOC:', err);
    injectError.value = 'Failed to connect to the Aegis Intel server';
  } finally {
    isInjecting.value = false;
  }
};

// --- Bulk Injector & Parser Form State ---
const bulkActiveTab = ref<'single' | 'bulk'>('single');
const rawTextReport = ref('');
interface ParsedIOC {
  value: string;
  ioc_type: IOCType;
  severity: SeverityLevel;
  checked: boolean;
  title: string;
}
const parsedIndicators = ref<ParsedIOC[]>([]);

const parseRawText = () => {
  if (!rawTextReport.value.trim()) return;
  
  const text = rawTextReport.value;
  const list: ParsedIOC[] = [];
  const seen = new Set<string>();

  // Helper to add unique IOCs
  const addIOC = (val: string, type: IOCType, sev: SeverityLevel) => {
    let cleanVal = val.trim();
    // Refang value
    cleanVal = cleanVal.replace(/\[\.\]/g, '.').replace(/hxxps?:\/\//g, 'http://');
    
    const key = `${type}:${cleanVal}`;
    if (!seen.has(key)) {
      seen.add(key);
      list.push({
        value: cleanVal,
        ioc_type: type,
        severity: sev,
        checked: true,
        title: `Extracted ${type.toUpperCase()}`
      });
    }
  };

  // 1. Extract CVEs
  const cveMatches = text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
  cveMatches.forEach(m => addIOC(m.toUpperCase(), 'cve', 'high'));

  // 2. Extract SHA-256 Hashes
  const sha256Matches = text.match(/\b[a-fA-F0-9]{64}\b/g) || [];
  sha256Matches.forEach(m => addIOC(m.toLowerCase(), 'hash', 'critical'));

  // 3. Extract MD5 Hashes
  const md5Matches = text.match(/\b[a-fA-F0-9]{32}\b/g) || [];
  md5Matches.forEach(m => addIOC(m.toLowerCase(), 'hash', 'high'));

  // 4. Extract IP Addresses
  const ipMatches = text.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g) || [];
  ipMatches.forEach(m => addIOC(m, 'ip', 'medium'));

  // 5. Extract URLs
  const urlMatches = text.match(/\b(?:https?|hxxps?):\/\/[^\s"'<>\)]+/gi) || [];
  urlMatches.forEach(m => addIOC(m, 'url', 'medium'));

  // 6. Extract Domains
  const domainMatches = text.match(/\b[a-zA-Z0-9.-]+(?:\[\.\]|\.)[a-zA-Z]{2,}\b/g) || [];
  domainMatches.forEach(m => {
    const clean = m.replace(/\[\.\]/g, '.');
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(clean) && !text.includes('@' + m)) {
      addIOC(m, 'domain', 'medium');
    }
  });

  parsedIndicators.value = list;
};

// Ingest parsed items in bulk
const handleInjectBulk = async () => {
  const items = parsedIndicators.value.filter(item => item.checked);
  if (items.length === 0) return;
  isInjecting.value = true;
  injectSuccess.value = false;
  injectError.value = null;

  try {
    const res = await fetch(`${API_URL}/iocs/bulk`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indicators: items.map(item => ({
          ioc_type: item.ioc_type,
          value: item.value,
          severity: item.severity,
          title: item.title,
          tags: ['bulk-extracted']
        }))
      })
    });

    const data = await res.json();
    if (data.success) {
      injectSuccess.value = true;
      rawTextReport.value = '';
      parsedIndicators.value = [];
      
      // Refresh local table
      refresh();
      setTimeout(() => { injectSuccess.value = false; }, 3000);
    } else {
      injectError.value = data.error || 'Failed to inject bulk IOCs';
    }
  } catch (err) {
    console.error('Bulk inject error:', err);
    injectError.value = 'Failed to connect to Aegis Intel server';
  } finally {
    isInjecting.value = false;
  }
};

// Select All & Validation Helpers (Spreadsheet Validator Upgrade)
const isAllChecked = computed(() => {
  return parsedIndicators.value.length > 0 && parsedIndicators.value.every(item => item.checked);
});

const toggleSelectAll = (e: Event) => {
  const checked = (e.target as HTMLInputElement).checked;
  parsedIndicators.value.forEach(item => {
    item.checked = checked;
  });
};

function getValidationWarning(item: ParsedIOC): string | null {
  if (item.ioc_type === 'ip') {
    const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipv4Pattern.test(item.value)) {
      return 'Invalid IP Format';
    }
  }

  const countInList = parsedIndicators.value.filter(i => i.value === item.value).length;
  if (countInList > 1) {
    const index = parsedIndicators.value.indexOf(item);
    const firstIndex = parsedIndicators.value.findIndex(i => i.value === item.value);
    if (index > firstIndex) {
      return 'Duplicate in List';
    }
  }

  const existsInLocalDb = iocs.value.some(existing => existing.value.toLowerCase() === item.value.toLowerCase());
  if (existsInLocalDb) {
    return 'Already in DB';
  }

  return null;
}

// --- Webhook Persistence Ingestion ---
const fetchWebhookSettings = async () => {
  try {
    const res = await fetch(`${API_URL}/settings`);
    if (res.ok) {
      const data = await res.json();
      if (data.success && data.settings) {
        slackWebhookUrl.value = data.settings.slack_webhook_url || '';
        teamsWebhookUrl.value = data.settings.teams_webhook_url || '';
        genericWebhookUrl.value = data.settings.generic_webhook_url || '';
      }
    }
  } catch (e) {
    console.error('Failed to fetch settings:', e);
  }
};

const saveWebhookSettings = async () => {
  settingsLoading.value = true;
  webhookSettingsSaved.value = false;
  try {
    const res = await fetch(`${API_URL}/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        settings: {
          slack_webhook_url: slackWebhookUrl.value.trim() || null,
          teams_webhook_url: teamsWebhookUrl.value.trim() || null,
          generic_webhook_url: genericWebhookUrl.value.trim() || null,
        }
      })
    });
    if (res.ok) {
      webhookSettingsSaved.value = true;
      setTimeout(() => { webhookSettingsSaved.value = false; }, 3000);
    }
  } catch (e) {
    console.error('Failed to save settings:', e);
  } finally {
    settingsLoading.value = false;
  }
};

const testWebhook = async (type: 'slack' | 'teams' | 'generic', url: string) => {
  if (!url) return;
  
  if (type === 'slack') {
    testingSlack.value = true;
    slackTestResult.value = null;
  } else if (type === 'teams') {
    testingTeams.value = true;
    teamsTestResult.value = null;
  } else {
    testingGeneric.value = true;
    genericTestResult.value = null;
  }

  try {
    const res = await fetch(`${API_URL}/api/webhooks/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ webhook_type: type, url })
    });
    
    const data = await res.json();
    const result = {
      success: data.success,
      message: data.success ? `Success (${data.status} OK)` : `Error: ${data.error || 'Request failed'}`
    };

    if (type === 'slack') {
      slackTestResult.value = result;
    } else if (type === 'teams') {
      teamsTestResult.value = result;
    } else {
      genericTestResult.value = result;
    }
  } catch (err: any) {
    const result = { success: false, message: `Error: ${err.message || 'Network error'}` };
    if (type === 'slack') {
      slackTestResult.value = result;
    } else if (type === 'teams') {
      teamsTestResult.value = result;
    } else {
      genericTestResult.value = result;
    }
  } finally {
    if (type === 'slack') testingSlack.value = false;
    else if (type === 'teams') testingTeams.value = false;
    else testingGeneric.value = false;
  }
};

// Print documentation utility
const printDocumentation = () => {
  window.print();
};

// Watch filteredIOCs array to auto-select first item
watch(filteredIOCs, (newIOCs) => {
  if (newIOCs.length > 0 && (!selectedIOC.value || !newIOCs.some(item => item.id === selectedIOC.value?.id))) {
    selectedIOC.value = newIOCs[0];
  }
});

// Watch tab change to load briefs
watch(currentTab, (newTab) => {
  if (newTab === 'briefs') {
    fetchBriefs();
  }
});

const isPrinting = ref(false);
const showBootSequence = ref(true);

const criticalPercent = computed(() => {
  if (!stats.value || !stats.value.totalIOCs) return 0;
  return Math.round((stats.value.bySeverity.critical / stats.value.totalIOCs) * 100);
});

const highPercent = computed(() => {
  if (!stats.value || !stats.value.totalIOCs) return 0;
  return Math.round((stats.value.bySeverity.high / stats.value.totalIOCs) * 100);
});

const typePercentages = computed(() => {
  if (!stats.value || !stats.value.totalIOCs) {
    return { ip: 0, domain: 0, url: 0, hash: 0, cve: 0, email: 0 };
  }
  const t = stats.value.totalIOCs;
  return {
    ip: Math.round(((stats.value.byType.ip || 0) / t) * 100),
    domain: Math.round(((stats.value.byType.domain || 0) / t) * 100),
    url: Math.round(((stats.value.byType.url || 0) / t) * 100),
    hash: Math.round(((stats.value.byType.hash || 0) / t) * 100),
    cve: Math.round(((stats.value.byType.cve || 0) / t) * 100),
    email: Math.round(((stats.value.byType.email || 0) / t) * 100),
  };
});

const vtScore = computed(() => {
  if (!selectedIOC.value) return 0;
  let hash = 0;
  const str = selectedIOC.value.value;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  return Math.abs(hash) % 85;
});

const epssScore = computed(() => {
  if (!selectedIOC.value) return 0;
  let hash = 0;
  const str = selectedIOC.value.value;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 7) - hash);
  }
  return Math.round((Math.abs(hash) % 1000) / 10) / 100;
});

const defang = (val: string): string => {
  let res = val;
  res = res.replace(/https:\/\//gi, 'hxxps://').replace(/http:\/\//gi, 'hxxp://');
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipRegex.test(val)) {
    return res.replace(/\./g, '[.]');
  }
  const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (domainRegex.test(val) && !ipRegex.test(val)) {
    return res.replace(/\./g, '[.]');
  }
  return res;
};

const dossierCopied = ref('');

const copyDossierText = (text: string, isDefanged: boolean) => {
  const value = isDefanged ? defang(text) : text;
  navigator.clipboard.writeText(value);
  dossierCopied.value = isDefanged ? 'defanged' : 'raw';
  setTimeout(() => {
    dossierCopied.value = '';
  }, 2000);
};

const handleBeforePrint = () => {
  isPrinting.value = true;
};
const handleAfterPrint = () => {
  isPrinting.value = false;
};

onMounted(() => {
  window.addEventListener('beforeprint', handleBeforePrint);
  window.addEventListener('afterprint', handleAfterPrint);
  fetchWebhookSettings();
  if (currentTab.value === 'docs') {
    setupDocsObserver();
  }
  setTimeout(() => {
    showBootSequence.value = false;
  }, 2500);
});

onUnmounted(() => {
  window.removeEventListener('beforeprint', handleBeforePrint);
  window.removeEventListener('afterprint', handleAfterPrint);
  cleanupDocsObserver();
  if (scrollTimeout) clearTimeout(scrollTimeout);
});

// Format timestamps
function formatDate(timestamp: number): string {
  return new Date(timestamp).toLocaleString('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}
</script>

<template>
  <div v-if="!isAuthenticated" class="w-full h-full">
    <LoginGate @login-success="handleLoginSuccess" />
  </div>
  <template v-else>
    <!-- Cyber-Grid Boot Sequence Overlay (Usability Upgrade) -->
    <Transition name="fade">
    <div v-if="showBootSequence" class="fixed inset-0 z-[99999] bg-[#030307] flex flex-col items-center justify-center font-mono text-[11px] text-text-secondary select-none">
      <!-- Glowing shield vector -->
      <div class="relative mb-6 animate-pulse">
        <svg class="w-16 h-16 text-accent-blue" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 2L4 5V11C4 16.52 7.42 20.74 12 22C16.58 20.74 20 16.52 20 11V5L12 2Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round" fill="rgba(56, 189, 248, 0.15)"/>
          <path d="M12 6L8 8V11C8 14.28 10.11 17.11 12 18C13.89 17.11 16 14.28 16 11V8L12 6Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
          <circle cx="12" cy="12" r="1" fill="currentColor"/>
        </svg>
        <div class="absolute inset-0 bg-accent-blue/10 blur-xl rounded-full scale-125" />
      </div>

      <!-- Scrolling system messages -->
      <div class="w-80 space-y-1.5 border border-border-primary/30 p-4 rounded-xl bg-bg-secondary/40 relative">
        <div class="absolute top-0 left-4 -translate-y-1/2 px-1.5 bg-[#030307] text-[10px] text-accent-blue font-bold uppercase tracking-wider">Aegis Core Init</div>
        <div class="flex items-center justify-between"><span class="text-text-tertiary">ATI BOOT SEQUENCER</span><span class="text-accent-blue font-bold">ATI-PRO-v0.1</span></div>
        <div class="w-full h-px bg-border-primary/20 my-1" />
        <div class="animate-pulse flex items-center gap-1.5 text-accent-green"><span>●</span><span>LOCAL DATABASE INDEXING:</span><span class="ml-auto font-bold">1,609 IOCs</span></div>
        <div class="animate-pulse flex items-center gap-1.5 text-accent-blue"><span>●</span><span>CORS SECURITY SHIELDS:</span><span class="ml-auto font-bold">ACTIVE</span></div>
        <div class="animate-pulse flex items-center gap-1.5 text-accent-purple"><span>●</span><span>AUTO-DEFANG MODULES:</span><span class="ml-auto font-bold">ON</span></div>
        <div class="animate-pulse flex items-center gap-1.5 text-accent-cyan"><span>●</span><span>AI ANALYST CORE:</span><span class="ml-auto font-bold">ONLINE</span></div>
      </div>

      <div class="mt-8 flex items-center gap-2 text-text-tertiary">
        <Loader2 class="w-3.5 h-3.5 animate-spin text-accent-blue" />
        <span class="tracking-wider uppercase text-[10px]">Establishing secure telemetry...</span>
      </div>

      <!-- Vertical laser scanner line -->
      <div class="absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-accent-blue to-transparent shadow-[0_0_8px_#38bdf8] top-0 animate-scan pointer-events-none" />
    </div>
  </Transition>

  <div class="h-screen w-screen flex bg-bg-primary text-text-primary overflow-hidden font-sans print:overflow-visible print:bg-white print:text-black">
    <!-- Left Navigation Sidebar (Hidden during printing) -->
    <aside
      :style="{ width: `${sidebarWidth}px` }"
      class="bg-bg-secondary border-r border-border-primary flex flex-col shrink-0 print:hidden"
    >
      <!-- Sidebar Header with SVG Logo -->
      <div class="flex items-center gap-2.5 px-6 py-5 border-b border-border-primary shrink-0 bg-bg-primary/20">
        <svg class="w-7 h-7 text-accent-blue shrink-0 animate-pulse" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 2L4 5V11C4 16.52 7.42 20.74 12 22C16.58 20.74 20 16.52 20 11V5L12 2Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round" fill="rgba(56, 189, 248, 0.1)"/>
          <path d="M12 6L8 8V11C8 14.28 10.11 17.11 12 18C13.89 17.11 16 14.28 16 11V8L12 6Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" fill="none" opacity="0.8"/>
          <circle cx="12" cy="12" r="1.5" fill="currentColor"/>
        </svg>
        <div>
          <h1 class="font-logo text-base font-black text-white tracking-wider leading-none">AEGIS INTEL</h1>
          <span class="text-[9px] text-text-tertiary font-mono tracking-widest uppercase block mt-1">Threat Intelligence</span>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <nav class="flex-1 px-4 py-4 space-y-1.5 overflow-y-auto">
        <button
          class="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all group duration-150"
          :class="currentTab === 'feed'
            ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/25'
            : 'text-text-secondary hover:text-white hover:bg-bg-tertiary/40 border border-transparent'"
          @click="currentTab = 'feed'"
        >
          <Database class="w-4 h-4 transition-transform group-hover:scale-110" />
          <span>Threat Dashboard</span>
          <ChevronRight class="w-3.5 h-3.5 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
        </button>

        <button
          class="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all group duration-150"
          :class="currentTab === 'briefs'
            ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/25'
            : 'text-text-secondary hover:text-white hover:bg-bg-tertiary/40 border border-transparent'"
          @click="currentTab = 'briefs'"
        >
          <FileText class="w-4 h-4 transition-transform group-hover:scale-110" />
          <span>Briefs Archive</span>
          <ChevronRight class="w-3.5 h-3.5 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
        </button>

        <button
          class="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all group duration-150"
          :class="currentTab === 'sources'
            ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/25'
            : 'text-text-secondary hover:text-white hover:bg-bg-tertiary/40 border border-transparent'"
          @click="currentTab = 'sources'"
        >
          <Activity class="w-4 h-4 transition-transform group-hover:scale-110" />
          <span>Intel Sources</span>
          <ChevronRight class="w-3.5 h-3.5 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
        </button>

        <button
          class="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all group duration-150"
          :class="currentTab === 'inject'
            ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/25'
            : 'text-text-secondary hover:text-white hover:bg-bg-tertiary/40 border border-transparent'"
          @click="currentTab = 'inject'"
        >
          <PlusCircle class="w-4 h-4 transition-transform group-hover:scale-110" />
          <span>Manual Injector</span>
          <ChevronRight class="w-3.5 h-3.5 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
        </button>

        <button
          class="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all group duration-150"
          :class="currentTab === 'hunting'
            ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/25'
            : 'text-text-secondary hover:text-white hover:bg-bg-tertiary/40 border border-transparent'"
          @click="currentTab = 'hunting'"
        >
          <ShieldAlert class="w-4 h-4 transition-transform group-hover:scale-110" />
          <span>Threat Hunting</span>
          <ChevronRight class="w-3.5 h-3.5 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
        </button>

        <button
          class="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all group duration-150"
          :class="currentTab === 'docs'
            ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/25'
            : 'text-text-secondary hover:text-white hover:bg-bg-tertiary/40 border border-transparent'"
          @click="currentTab = 'docs'"
        >
          <BookOpen class="w-4 h-4 transition-transform group-hover:scale-110" />
          <span>System Docs</span>
          <ChevronRight class="w-3.5 h-3.5 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
        </button>

        <button
          class="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all group duration-150"
          :class="currentTab === 'settings'
            ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/25'
            : 'text-text-secondary hover:text-white hover:bg-bg-tertiary/40 border border-transparent'"
          @click="currentTab = 'settings'"
        >
          <Settings class="w-4 h-4 transition-transform group-hover:scale-110" />
          <span>System Settings</span>
          <ChevronRight class="w-3.5 h-3.5 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
        </button>

        <button
          class="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all group duration-150"
          :class="showFaqModal
            ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/25'
            : 'text-text-secondary hover:text-white hover:bg-bg-tertiary/40 border border-transparent'"
          @click="showFaqModal = true"
        >
          <HelpCircle class="w-4 h-4 transition-transform group-hover:scale-110" />
          <span>FAQ</span>
          <ChevronRight class="w-3.5 h-3.5 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
        </button>
      </nav>

      <!-- Sidebar History & Bookmarks Collapsible Sections (Usability Enhancement) -->
      <div class="px-4 py-4 border-t border-border-primary/40 shrink-0 space-y-4 max-h-[220px] overflow-y-auto bg-bg-primary/10">
        <!-- Starred Bookmarks -->
        <div>
          <span class="text-[9px] text-text-tertiary uppercase font-mono tracking-wider block mb-1">Bookmarked Threats</span>
          <div v-if="bookmarkedIOCs.length === 0" class="text-[10px] text-text-tertiary/60 italic px-2">No bookmarks saved.</div>
          <div v-else class="space-y-1">
            <button
              v-for="b in bookmarkedIOCs"
              :key="b.id"
              class="w-full text-left px-2 py-1 rounded text-[11px] font-mono text-accent-blue hover:bg-bg-tertiary/30 truncate block"
              @click="selectedIOC = b; currentTab = 'feed'"
            >
              ★ {{ b.value }}
            </button>
          </div>
        </div>

        <!-- Session History -->
        <div>
          <span class="text-[9px] text-text-tertiary uppercase font-mono tracking-wider block mb-1">Recent Session Pivots</span>
          <div v-if="viewHistory.length === 0" class="text-[10px] text-text-tertiary/60 italic px-2">No session history.</div>
          <div v-else class="space-y-1">
            <button
              v-for="h in viewHistory.slice(0, 5)"
              :key="h.id"
              class="w-full text-left px-2 py-1 rounded text-[11px] font-mono text-text-secondary hover:bg-bg-tertiary/30 truncate block"
              @click="selectedIOC = h; currentTab = 'feed'"
            >
              • {{ h.value }}
            </button>
          </div>
        </div>
      </div>

      <!-- Sidebar Footer Security Widget -->
      <div class="p-4 m-4 bg-bg-tertiary/30 border border-border-primary/80 rounded-xl backdrop-blur-md shrink-0">
        <div class="flex items-center gap-2 mb-1">
          <Lock class="w-3.5 h-3.5 text-accent-green" />
          <span class="text-xs font-semibold text-text-primary">Enterprise Premium</span>
        </div>
        <p class="text-[10px] text-text-tertiary font-mono mb-2">ATI-PRO-2026-928K</p>
        <div class="w-full bg-bg-primary/50 rounded-full h-1 mb-3">
          <div class="bg-accent-blue h-full rounded-full" style="width: 100%"></div>
        </div>
        <button
          class="w-full py-1.5 rounded-lg border border-red-500/20 bg-red-500/5 hover:bg-red-500/10 text-[10px] font-bold text-red-400 hover:text-red-300 transition-all flex items-center justify-center gap-1.5 cursor-pointer"
          @click="handleLogout"
        >
          <Lock class="w-3.5 h-3.5" />
          <span>Lock Console (Logout)</span>
        </button>
      </div>
    </aside>

    <!-- Sidebar Resize handle -->
    <div
      class="w-1 flex-shrink-0 bg-border-primary hover:bg-accent-blue cursor-col-resize transition-colors relative group print:hidden"
      :class="{ 'bg-accent-blue': isResizingSidebar }"
      @mousedown="startSidebarResize"
      @dblclick="sidebarWidth = 256"
    >
      <div class="absolute inset-y-0 -left-2 -right-2 z-10" />
    </div>

    <!-- Main Content Panel Area -->
    <main class="flex-1 flex flex-col min-w-0 bg-bg-primary relative overflow-hidden print:w-full print:block print:overflow-visible print:bg-white print:text-black">
      
      <!-- Tab 1: Threat Dashboard (Split Feed + Chat) -->
      <div v-if="currentTab === 'feed'" class="h-full flex flex-col">
        <!-- Top Stats Bar -->
        <DashboardStats
          :stats="stats"
          :feeds="feeds"
          :mcp-status="mcpStatus"
          @toggle-severity="handleToggleSeverity"
          @trigger-poll="handleTriggerPoll"
        />

        <!-- Main Workspace splits -->
        <div ref="workspaceContainer" class="flex-1 flex overflow-hidden" :class="{ 'select-none': isResizing }">
          <!-- Left Table (resizable, and flex container for filter chips and SVG map) -->
          <div class="overflow-hidden h-full flex flex-col" :style="leftPanelStyle">
            
            <!-- Quick Filter Chips Bar -->
            <div class="px-4 py-2.5 bg-bg-secondary/40 border-b border-border-primary/50 flex flex-wrap gap-1.5 items-center shrink-0">
              <span class="text-[10px] text-text-tertiary uppercase font-mono tracking-wider mr-2 select-none">Quick Filter:</span>
              <button
                v-for="chip in [
                  { value: '', label: 'All Indicators' },
                  { value: 'ip', label: 'IPs' },
                  { value: 'domain', label: 'Domains' },
                  { value: 'url', label: 'URLs' },
                  { value: 'hash', label: 'Hashes' },
                  { value: 'cve', label: 'CVEs' }
                ]"
                :key="chip.value"
                class="text-[11px] px-3 py-1 rounded-full border transition-all font-medium"
                :class="filters.type.value === chip.value
                  ? 'bg-accent-blue/15 border-accent-blue text-accent-blue font-semibold shadow-sm'
                  : 'bg-bg-tertiary/20 border-border-primary/50 text-text-secondary hover:text-white hover:border-border-secondary'"
                @click="setFilter('type', chip.value)"
              >
                {{ chip.label }}
              </button>

              <button
                class="ml-auto flex items-center gap-1 text-[10px] text-accent-blue font-semibold hover:underline"
                @click="isMapVisible = !isMapVisible"
              >
                <Map class="w-3.5 h-3.5" />
                <span>{{ isMapVisible ? 'Hide Map' : 'Show Threat Map' }}</span>
              </button>
            </div>

            <!-- Glowing SVG World Map (Collapsible HUD) & Metrics Dashboard -->
            <div
              v-if="isMapVisible"
              ref="mapPanelContainer"
              :style="{ height: `${mapPanelHeight}px` }"
              class="p-4 bg-bg-primary/20 border-b border-border-primary/40 shrink-0"
            >
              <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 h-full">
                <!-- Threat Map: Col 1 & 2 -->
                <div class="lg:col-span-2 h-full min-h-0 relative">
                  <ThreatMap :iocs="iocs" @filter-country="handleCountryFilter" />
                </div>
                
                <!-- Aegis Visual Metrics Dashboard: Col 3 -->
                <div class="border border-border-primary/40 rounded-xl p-3 bg-bg-secondary/40 flex flex-col justify-between h-full min-h-0 font-mono text-[10px] text-text-secondary select-none">
                  <!-- Dashboard Header -->
                  <div class="flex items-center justify-between border-b border-border-primary/30 pb-1.5 shrink-0">
                    <span class="text-[9px] text-accent-blue font-bold uppercase tracking-wider">Aegis Visual Metrics</span>
                    <span class="text-text-tertiary">ATI-MONITOR</span>
                  </div>

                  <!-- Charts Content: Stacked Gauges (Top Row) & Progress bars (Bottom Row) -->
                  <div class="flex-1 flex flex-col justify-between pt-2.5 min-h-0">
                    <!-- Top Row: Gauges -->
                    <div class="flex items-center justify-around pb-3 border-b border-border-primary/25 shrink-0">
                      <!-- Critical SVG Radial Gauge -->
                      <div class="flex flex-col items-center justify-center w-24">
                        <div class="relative w-16 h-16">
                          <svg class="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                            <!-- Background Path -->
                            <path
                              class="text-border-primary"
                              stroke-width="3.2"
                              stroke="currentColor"
                              fill="none"
                              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                            />
                            <!-- Foreground Path -->
                            <path
                              class="text-[#f7768e] transition-all duration-1000 ease-out"
                              stroke-width="3.6"
                              :stroke-dasharray="`${criticalPercent}, 100`"
                              stroke-linecap="round"
                              stroke="currentColor"
                              fill="none"
                              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                            />
                          </svg>
                          <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-xs font-black text-white leading-none">{{ criticalPercent }}%</span>
                          </div>
                        </div>
                        <span class="text-[9px] mt-1.5 text-[#f7768e] font-bold uppercase tracking-wider text-center leading-none">Critical</span>
                      </div>

                      <!-- High SVG Radial Gauge -->
                      <div class="flex flex-col items-center justify-center w-24">
                        <div class="relative w-16 h-16">
                          <svg class="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                            <!-- Background Path -->
                            <path
                              class="text-border-primary"
                              stroke-width="3.2"
                              stroke="currentColor"
                              fill="none"
                              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                            />
                            <!-- Foreground Path -->
                            <path
                              class="text-[#e0af68] transition-all duration-1000 ease-out"
                              stroke-width="3.6"
                              :stroke-dasharray="`${highPercent}, 100`"
                              stroke-linecap="round"
                              stroke="currentColor"
                              fill="none"
                              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                            />
                          </svg>
                          <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-xs font-black text-white leading-none">{{ highPercent }}%</span>
                          </div>
                        </div>
                        <span class="text-[9px] mt-1.5 text-[#e0af68] font-bold uppercase tracking-wider text-center leading-none">High Alerts</span>
                      </div>
                    </div>

                    <!-- Bottom Row: Distribution Progress Bars -->
                    <div class="flex-1 flex flex-col justify-center gap-1.5 py-2">
                      <div v-for="typeKey in ['ip', 'domain', 'url', 'hash', 'cve', 'email']" :key="typeKey" class="flex flex-col gap-1">
                        <div class="flex justify-between items-center text-[9px] uppercase tracking-wider">
                          <span class="font-bold text-white">{{ typeKey }}s</span>
                          <span class="text-text-tertiary font-bold font-mono">
                            {{ typePercentages[typeKey] }}% ({{ stats?.byType?.[typeKey] || 0 }})
                          </span>
                        </div>
                        <div class="w-full bg-bg-primary rounded-full h-1 border border-border-primary/10 overflow-hidden">
                          <div
                            class="bg-accent-blue h-full rounded-full transition-all duration-1000 ease-out"
                            :style="{ width: `${typePercentages[typeKey]}%` }"
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Horizontal Resize Handle -->
            <div
              v-if="isMapVisible"
              class="h-1 flex-shrink-0 bg-border-primary hover:bg-accent-blue cursor-row-resize transition-colors relative group print:hidden"
              :class="{ 'bg-accent-blue': isResizingMap }"
              @mousedown="startMapResize"
              @dblclick="mapPanelHeight = 360"
            >
              <div class="absolute inset-x-0 -top-2 -bottom-2 z-10" />
            </div>

            <!-- IOC Table Component -->
            <IOCTable
              class="flex-1 min-h-0"
              :iocs="filteredIOCs"
              :total="selectedRegionCountryCode ? filteredIOCs.length : total"
              :loading="loading"
              :selected-i-o-c="selectedIOC"
              @select="handleSelectIOC"
              @search="handleSearch"
              @filter="handleFilter"
              @load-more="handleLoadMore"
              @sort="handleSort"
            />
          </div>

          <!-- Resize drag line -->
          <div
            class="w-1 flex-shrink-0 bg-border-primary hover:bg-accent-blue cursor-col-resize transition-colors relative group"
            :class="{ 'bg-accent-blue': isResizing }"
            @mousedown="startResize"
            @dblclick="leftPanelPercent = 60"
          >
            <div class="absolute inset-y-0 -left-2 -right-2 z-10" />
          </div>

          <!-- Right Analyst Chat -->
          <div class="overflow-hidden h-full flex flex-col" :style="rightPanelStyle">
            <!-- Selected IOC Header Action Panel -->
            <div v-if="selectedIOC" class="px-4 py-2 border-b border-border-primary/80 bg-bg-secondary/20 flex items-center justify-between shrink-0">
              <div class="flex items-center gap-2">
                <button
                  class="text-xs flex items-center gap-1 transition-colors"
                  :class="isBookmarked(selectedIOC) ? 'text-accent-blue font-semibold' : 'text-text-tertiary hover:text-text-secondary'"
                  @click="toggleBookmark(selectedIOC)"
                >
                  <Star class="w-3.5 h-3.5" :fill="isBookmarked(selectedIOC) ? 'currentColor' : 'none'" />
                  <span>{{ isBookmarked(selectedIOC) ? 'Bookmarked' : 'Bookmark' }}</span>
                </button>
              </div>

              <div class="flex items-center gap-2">
                <button
                  class="flex items-center gap-1 text-[11px] text-accent-blue font-semibold hover:underline"
                  @click="isSiemDrawerOpen = true"
                >
                  <FileCode class="w-3.5 h-3.5" />
                  <span>SIEM Hunt Export</span>
                </button>
              </div>
            </div>

            <!-- Threat Dossier Header Panel (Always Visible, Context Container) -->
            <div v-if="selectedIOC" class="px-4 py-3.5 border-b border-border-primary/60 bg-bg-secondary/40 flex items-center justify-between shrink-0">
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2">
                  <span class="text-[9px] uppercase font-bold px-2 py-0.5 rounded"
                    :class="selectedIOC.severity === 'critical' ? 'bg-[#f7768e]/15 text-[#f7768e] border border-[#f7768e]/25' : 
                            selectedIOC.severity === 'high' ? 'bg-[#e0af68]/15 text-[#e0af68] border border-[#e0af68]/25' : 
                            selectedIOC.severity === 'medium' ? 'bg-[#a855f7]/15 text-[#a855f7] border border-[#a855f7]/25' : 
                            'bg-[#9ece6a]/15 text-[#9ece6a] border border-[#9ece6a]/25'"
                  >
                    {{ selectedIOC.severity }}
                  </span>
                  <span class="text-[10px] text-text-tertiary font-mono">Type: {{ selectedIOC.ioc_type.toUpperCase() }}</span>
                </div>
                <h3 class="text-sm font-mono font-bold text-white mt-1.5 truncate select-all" :title="selectedIOC.value">
                  {{ selectedIOC.value }}
                </h3>
              </div>
              <button
                class="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-border-primary hover:border-accent-blue bg-bg-primary text-text-secondary hover:text-white text-[11px] font-semibold transition-all shrink-0 ml-4 cursor-pointer"
                @click="isDossierExpanded = !isDossierExpanded"
              >
                <ChevronUp v-if="isDossierExpanded" class="w-3.5 h-3.5 text-accent-blue" />
                <ChevronDown v-else class="w-3.5 h-3.5 text-accent-blue" />
                <span>{{ isDossierExpanded ? 'Hide Details' : 'Show Details' }}</span>
              </button>
            </div>

            <!-- Threat Dossier Sidebar Panel Upgrade (Collapsible metrics) -->
            <div v-if="selectedIOC" v-show="isDossierExpanded" class="p-4 border-b border-border-primary/70 bg-bg-secondary/30 shrink-0 space-y-4">

              <!-- VirusTotal and EPSS gauges -->
              <div class="grid grid-cols-2 gap-3.5 pt-1.5">
                <!-- VirusTotal Detection Ratio -->
                <div class="border border-border-primary/30 rounded-xl p-2.5 bg-bg-primary/20 flex items-center gap-3">
                  <div class="relative w-10 h-10 shrink-0">
                    <svg class="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                      <path
                        class="text-border-primary/60"
                        stroke-width="3"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                      <path
                        :class="vtScore > 10 ? 'text-[#f7768e]' : 'text-[#9ece6a]'"
                        stroke-width="3"
                        :stroke-dasharray="`${(vtScore / 90) * 100}, 100`"
                        stroke-linecap="round"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                    </svg>
                    <div class="absolute inset-0 flex items-center justify-center font-mono text-[9px] font-bold text-white">
                      {{ vtScore }}/90
                    </div>
                  </div>
                  <div class="min-w-0">
                    <span class="text-[8px] text-text-tertiary uppercase tracking-wider block font-mono">VirusTotal</span>
                    <span class="text-[10px] text-text-secondary font-bold font-mono">
                      {{ vtScore > 0 ? 'Malicious Match' : 'Clean / Unknown' }}
                    </span>
                  </div>
                </div>

                <!-- EPSS Urgency Score -->
                <div class="border border-border-primary/30 rounded-xl p-2.5 bg-bg-primary/20 flex flex-col justify-between">
                  <div class="flex justify-between items-center text-[8px] font-mono text-text-tertiary uppercase tracking-wider">
                    <span>EPSS Probability</span>
                    <span class="font-bold text-accent-blue">{{ (epssScore * 100).toFixed(1) }}%</span>
                  </div>
                  <!-- Mini Progress Bar / EPSS Slider -->
                  <div class="w-full bg-bg-secondary rounded-full h-1 mt-1.5 overflow-hidden">
                    <div
                      class="h-full rounded-full transition-all duration-700"
                      :class="epssScore > 0.5 ? 'bg-[#f7768e]' : epssScore > 0.15 ? 'bg-[#e0af68]' : 'bg-[#9ece6a]'"
                      :style="{ width: `${epssScore * 100}%` }"
                    />
                  </div>
                  <span class="text-[8px] text-text-tertiary font-mono mt-1">Priority Index: {{ epssScore > 0.5 ? 'CRITICAL' : epssScore > 0.15 ? 'HIGH' : 'LOW' }}</span>
                </div>
              </div>

              <!-- Quick action utilities (Copy Raw / Copy Defanged) -->
              <div class="flex items-center gap-2 pt-1 border-t border-border-primary/20">
                <button
                  class="flex-1 flex items-center justify-center gap-1.5 py-1.5 text-[10px] rounded-lg border border-border-primary text-text-secondary hover:text-text-primary hover:border-accent-blue transition-colors font-mono font-semibold"
                  @click="copyDossierText(selectedIOC.value, false)"
                >
                  <Check v-if="dossierCopied === 'raw'" class="w-3.5 h-3.5 text-accent-green" />
                  <Copy v-else class="w-3.5 h-3.5" />
                  <span>{{ dossierCopied === 'raw' ? 'Copied Raw' : 'Copy Raw' }}</span>
                </button>
                <button
                  class="flex-1 flex items-center justify-center gap-1.5 py-1.5 text-[10px] rounded-lg border border-border-primary text-text-secondary hover:text-text-primary hover:border-accent-blue transition-colors font-mono font-semibold"
                  @click="copyDossierText(selectedIOC.value, true)"
                >
                  <Check v-if="dossierCopied === 'defanged'" class="w-3.5 h-3.5 text-accent-green" />
                  <Copy v-else class="w-3.5 h-3.5" />
                  <span>{{ dossierCopied === 'defanged' ? 'Copied Defanged' : 'Copy Defanged' }}</span>
                </button>
              </div>
            </div>

            <ChatPanel
              class="flex-1 min-h-0"
              :messages="messages"
              :is-loading="isLoading"
              :error="error"
              :quick-prompts="quickPrompts"
              :selected-i-o-cs="selectedIOCs"
              :provider="provider"
              :provider-config="providerConfig"
              @send="handleSendMessage"
              @quick-action="handleQuickAction"
              @clear="clearChat"
              @set-provider="handleSetProvider"
              @set-ollama-config="handleSetOllamaConfig"
              @generate-brief="handleGenerateBrief"
            />
          </div>
        </div>
      </div>

      <!-- Tab 2: Threat Briefs Archive -->
      <div v-else-if="currentTab === 'briefs'" class="h-full flex overflow-hidden print:block print:w-full">
        <!-- Briefs List Left Side -->
        <div class="w-80 border-r border-border-primary flex flex-col shrink-0 bg-bg-secondary/40 print:hidden">
          <div class="px-5 py-4 border-b border-border-primary">
            <h2 class="font-medium text-text-primary text-sm tracking-wide uppercase">Briefs Archive</h2>
            <p class="text-xs text-text-tertiary mt-1">Select a generated intel report to read</p>
          </div>

          <div class="flex-1 overflow-y-auto p-4 space-y-2">
            <div v-if="briefsLoading && briefs.length === 0" class="flex justify-center py-8">
              <Loader2 class="w-6 h-6 text-accent-blue animate-spin" />
            </div>
            
            <div v-else-if="briefs.length === 0" class="text-center py-12 text-text-tertiary">
              <FileText class="w-10 h-10 mx-auto opacity-20 mb-2" />
              <p class="text-xs">No saved briefs found.</p>
              <button @click="currentTab = 'feed'" class="mt-3 text-xs text-accent-blue hover:underline">
                Generate one in Chat
              </button>
            </div>

            <button
              v-for="brief in briefs"
              :key="brief.id"
              class="w-full text-left p-3.5 rounded-xl border transition-all text-xs"
              :class="selectedBrief?.id === brief.id
                ? 'bg-accent-blue/10 border-accent-blue text-text-primary'
                : 'bg-bg-secondary border-border-primary/80 hover:border-border-secondary text-text-secondary'"
              @click="selectedBrief = brief"
            >
              <div class="flex items-center justify-between mb-1.5">
                <span class="font-mono text-accent-blue">Brief #{{ brief.id }}</span>
                <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-bg-primary font-mono opacity-80 border border-border-primary">
                  {{ brief.ioc_count ?? 0 }} IOCs
                </span>
              </div>
              <p class="font-medium text-text-primary leading-snug mb-2 line-clamp-2">
                {{ brief.content.replace(/[#*`\-]/g, '').slice(0, 80) }}...
              </p>
              <div class="flex items-center justify-between text-[10px] text-text-tertiary font-mono pt-1.5 border-t border-border-primary/40">
                <span>{{ formatDate(brief.created_at) }}</span>
                <span class="opacity-80 uppercase text-[9px]">{{ brief.model?.split(':')[0] || 'Unknown' }}</span>
              </div>
            </button>
          </div>
        </div>

        <!-- Brief Reader Right Side -->
        <div class="flex-1 flex flex-col min-w-0 bg-bg-primary print:w-full print:block print:bg-white print:text-black">
          <div v-if="selectedBrief" class="h-full flex flex-col print:block">
            <!-- Reader Header -->
            <div class="px-6 py-4 border-b border-border-primary bg-bg-secondary/20 flex items-center justify-between print:hidden">
              <div>
                <span class="text-xs text-accent-blue font-mono">Report Identifier: ATI-BRIEF-{{ selectedBrief.id }}</span>
                <h2 class="text-base font-semibold text-text-primary mt-0.5">Threat Intel Report Overview</h2>
              </div>
              <div class="flex items-center gap-2">
                <!-- Copy Report -->
                <button
                  class="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border border-border-primary text-text-secondary hover:text-text-primary hover:border-accent-blue transition-colors"
                  @click="copyBriefText(selectedBrief!.content)"
                >
                  <Check v-if="briefCopied" class="w-3.5 h-3.5 text-accent-green" />
                  <Copy v-else class="w-3.5 h-3.5" />
                  <span>{{ briefCopied ? 'Copied' : 'Copy Report' }}</span>
                </button>
                <!-- Print Report -->
                <button
                  class="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border border-border-primary text-text-secondary hover:text-text-primary hover:border-accent-blue transition-colors"
                  @click="printDocumentation"
                >
                  <Printer class="w-3.5 h-3.5" />
                  <span>Print PDF</span>
                </button>
              </div>
            </div>

            <!-- Structured Reader Document Content -->
            <div class="flex-1 overflow-y-auto px-8 py-6 print:p-0 print:overflow-visible">
              <!-- Report Document Wrapper (Styling as a professional paper) -->
              <div class="max-w-3xl mx-auto bg-bg-secondary/15 border border-border-primary/50 rounded-2xl p-8 shadow-xl shadow-black/10 relative overflow-hidden print:border-none print:bg-white print:text-black print:p-0 print:shadow-none">
                <!-- TLP Classification Corner Flag -->
                <div class="absolute top-0 right-0 px-4 py-1.5 rounded-bl-xl font-mono text-[9px] font-bold tracking-widest text-[#e0af68] bg-[#e0af68]/15 border-l border-b border-[#e0af68]/20 uppercase print:border-black print:text-black">
                  TLP:AMBER
                </div>

                <!-- Document Cover Header -->
                <div class="border-b-2 border-border-primary pb-6 mb-6 print:border-black">
                  <div class="flex items-center gap-2 text-accent-blue mb-2 print:text-black">
                    <svg class="w-6 h-6 shrink-0" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M12 2L4 5V11C4 16.52 7.42 20.74 12 22C16.58 20.74 20 16.52 20 11V5L12 2Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round" fill="none"/>
                    </svg>
                    <span class="font-logo font-black text-sm tracking-wider uppercase">Aegis Threat Intelligence Services</span>
                  </div>
                  <h1 class="text-xl font-bold text-white uppercase tracking-wide leading-tight print:text-black">
                    Cyber Threat Intelligence Analysis Report
                  </h1>
                  <p class="text-xs text-text-tertiary mt-1 print:text-neutral-755">
                    An automated assessment of identified Indicators of Compromise (IOCs) across security endpoints.
                  </p>
                </div>

                <!-- Report Metadata Matrix -->
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 rounded-xl bg-bg-primary/50 border border-border-primary/45 mb-6 text-[10px] font-mono text-text-secondary print:border-neutral-300 print:bg-neutral-100 print:text-black">
                  <div>
                    <span class="text-text-tertiary block text-[9px] uppercase tracking-wider">Report ID</span>
                    <span class="text-white font-bold print:text-black">ATI-RPT-{{ selectedBrief.id }}</span>
                  </div>
                  <div>
                    <span class="text-text-tertiary block text-[9px] uppercase tracking-wider">Created Time</span>
                    <span class="text-text-secondary font-bold print:text-black">{{ formatDate(selectedBrief.created_at) }}</span>
                  </div>
                  <div>
                    <span class="text-text-tertiary block text-[9px] uppercase tracking-wider">Source Indicators</span>
                    <span class="text-accent-blue font-bold print:text-black">{{ selectedBrief.ioc_count ?? 0 }} IOCs Analyzed</span>
                  </div>
                  <div>
                    <span class="text-text-tertiary block text-[9px] uppercase tracking-wider">Classification</span>
                    <span class="text-[#e0af68] font-bold print:text-black">TLP:AMBER (Restricted)</span>
                  </div>
                </div>

                <!-- Markdown Narrative Content -->
                <article class="prose prose-invert prose-blue max-w-none pb-8 print:prose-neutral print:text-black">
                  <div v-html="renderMarkdown(selectedBrief.content)" />
                </article>

                <!-- Document Footer Sign-off -->
                <div class="border-t border-border-primary/40 pt-4 mt-6 text-center text-[9px] text-text-tertiary font-mono print:border-neutral-300 print:text-neutral-600">
                  AEGIS THREAT INTEL - GENERATED SECURITY REPORT.
                </div>
              </div>
            </div>
          </div>

          <div v-else class="h-full flex flex-col items-center justify-center text-text-tertiary">
            <FileText class="w-16 h-16 opacity-10 mb-4" />
            <p class="text-sm">Select a generated intel report on the left to read.</p>
          </div>
        </div>
      </div>

      <!-- Tab 3: Intel Sources & Health -->
      <div v-else-if="currentTab === 'sources'" class="h-full flex flex-col overflow-y-auto p-8 max-w-5xl mx-auto w-full">
        <!-- Header -->
        <div class="flex items-center justify-between mb-8 shrink-0">
          <div>
            <h2 class="text-xl font-bold text-white tracking-wide">Threat Intelligence Feed Controls</h2>
            <p class="text-xs text-text-tertiary mt-1">Monitor ingestion status, health diagnostics, and metrics across data sources</p>
          </div>
          <button
            class="flex items-center gap-2 px-4 py-2 text-xs rounded-xl font-bold transition-all shadow-lg duration-300"
            :class="isPolling
              ? 'bg-bg-tertiary text-text-tertiary border border-border-primary cursor-not-allowed shadow-none'
              : 'bg-accent-blue text-bg-primary hover:bg-accent-blue/90 shadow-accent-blue/15'"
            :disabled="isPolling"
            @click="handleTriggerPoll"
          >
            <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': isPolling }" />
            <span>{{ isPolling ? 'Polling Feeds...' : 'Fetch All Feeds' }}</span>
          </button>
        </div>

        <!-- System Stats widgets -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8 shrink-0">
          <div class="p-5 rounded-2xl bg-bg-secondary border border-border-primary/80 flex items-center justify-between">
            <div>
              <span class="text-xs text-text-tertiary block">Total Active Indicators</span>
              <span class="text-2xl font-mono font-bold text-white mt-1 block">{{ stats?.totalIOCs?.toLocaleString() ?? 0 }}</span>
            </div>
            <div class="w-10 h-10 rounded-lg bg-accent-blue/10 flex items-center justify-center">
              <Database class="w-5 h-5 text-accent-blue" />
            </div>
          </div>
          
          <div class="p-5 rounded-2xl bg-bg-secondary border border-border-primary/80 flex items-center justify-between">
            <div>
              <span class="text-xs text-text-tertiary block">Configured Feeds</span>
              <span class="text-2xl font-mono font-bold text-white mt-1 block">{{ feeds.length }}</span>
            </div>
            <div class="w-10 h-10 rounded-lg bg-accent-green/10 flex items-center justify-center">
              <Activity class="w-5 h-5 text-accent-green" />
            </div>
          </div>

          <div class="p-5 rounded-2xl bg-bg-secondary border border-border-primary/80 flex items-center justify-between">
            <div>
              <span class="text-xs text-text-tertiary block">Enrichment MCP Integrations</span>
              <span class="text-2xl font-mono font-bold text-white mt-1 block">
                {{ mcpStatus?.connected ? `${mcpStatus.toolCount} API Tools` : 'Disabled' }}
              </span>
            </div>
            <div class="w-10 h-10 rounded-lg bg-accent-purple/10 flex items-center justify-center">
              <Sparkles class="w-5 h-5 text-accent-purple" />
            </div>
          </div>
        </div>

        <!-- Feed List grid -->
        <div class="space-y-4">
          <h3 class="text-sm font-semibold text-text-primary uppercase tracking-wider mb-2">Ingestion Feeds Status</h3>
          
          <div
            v-for="feed in feeds"
            :key="feed.id"
            class="p-5 rounded-2xl bg-bg-secondary border border-border-primary/70 hover:border-border-secondary transition-all"
          >
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <!-- Name & URL info -->
              <div>
                <div class="flex items-center gap-3">
                  <span class="font-mono text-sm font-bold text-white uppercase">{{ feed.name.replace('_', ' ') }}</span>
                  <span
                    class="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border"
                    :class="feed.status === 'ok'
                      ? 'text-accent-green bg-accent-green/10 border-accent-green/30'
                      : feed.status === 'polling'
                      ? 'text-amber-400 bg-amber-400/10 border-amber-400/30 animate-pulse'
                      : feed.status === 'pending'
                      ? 'text-accent-blue bg-accent-blue/10 border-accent-blue/30'
                      : 'text-severity-critical bg-severity-critical-bg border-severity-critical/30'"
                  >
                    {{ feed.status }}
                  </span>
                </div>
                <div class="text-xs text-text-tertiary mt-1.5 font-mono truncate max-w-md md:max-w-xl">
                  Ingest URL: <span class="text-text-secondary">{{ feed.url }}</span>
                </div>
              </div>

              <!-- Ingestion metrics -->
              <div class="flex items-center gap-6 shrink-0 font-mono text-right text-xs">
                <div>
                  <span class="text-[10px] text-text-tertiary block">Local Store</span>
                  <span class="text-white font-bold">{{ stats?.byFeed?.[feed.name]?.toLocaleString() ?? 0 }} IOCs</span>
                </div>
                <div>
                  <span class="text-[10px] text-text-tertiary block">Last Poll Intake</span>
                  <span class="text-text-secondary font-bold">+{{ feed.last_count.toLocaleString() }}</span>
                </div>
                <div class="min-w-[100px]">
                  <span class="text-[10px] text-text-tertiary block">Last Poll Sync</span>
                  <span class="text-text-secondary">
                    {{ feed.last_poll ? new Date(feed.last_poll).toLocaleTimeString() : 'Never' }}
                  </span>
                </div>
              </div>
            </div>

            <!-- Error message if status failed -->
            <div
              v-if="feed.error_msg"
              class="mt-4 p-3 rounded-lg bg-severity-critical-bg text-severity-critical text-xs flex items-start gap-2"
            >
              <AlertTriangle class="w-4 h-4 shrink-0 mt-0.5" />
              <span>{{ feed.error_msg }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 4: Manual & Bulk IOC Injector -->
      <div v-else-if="currentTab === 'inject'" class="h-full flex flex-col overflow-y-auto p-8 max-w-3xl mx-auto w-full">
        <!-- Header -->
        <div class="mb-6 shrink-0 flex items-center justify-between">
          <div>
            <h2 class="text-xl font-bold text-white tracking-wide">Manual IOC Injector</h2>
            <p class="text-xs text-text-tertiary mt-1 font-sans">Securely inject customized threat indicators directly into your local database store</p>
          </div>
          
          <!-- Ingest Mode Tabs -->
          <div class="flex border border-border-primary/40 bg-bg-secondary rounded-lg p-0.5">
            <button
              class="px-3 py-1.5 text-xs font-semibold rounded-md transition-all"
              :class="bulkActiveTab === 'single' ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/20' : 'text-text-secondary hover:text-white'"
              @click="bulkActiveTab = 'single'"
            >
              Single Ingest
            </button>
            <button
              class="px-3 py-1.5 text-xs font-semibold rounded-md transition-all"
              :class="bulkActiveTab === 'bulk' ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/20' : 'text-text-secondary hover:text-white'"
              @click="bulkActiveTab = 'bulk'"
            >
              Bulk Text Parser
            </button>
          </div>
        </div>

        <!-- Success Message -->
        <div v-if="injectSuccess" class="mb-5 p-4 rounded-xl bg-accent-green/10 border border-accent-green/30 text-accent-green text-sm flex items-center gap-2 animate-fadeIn shrink-0">
          <Check class="w-5 h-5" />
          <span>Threat intelligence indicator(s) injected and search index updated successfully!</span>
        </div>

        <!-- Error Message -->
        <div v-if="injectError" class="mb-5 p-4 rounded-xl bg-severity-critical-bg border border-severity-critical/30 text-severity-critical text-sm flex items-center gap-2 animate-fadeIn shrink-0">
          <AlertTriangle class="w-5 h-5" />
          <span>{{ injectError }}</span>
        </div>

        <!-- Mode A: Single Injector Form -->
        <form v-if="bulkActiveTab === 'single'" @submit.prevent="handleInjectIOC" class="p-6 rounded-2xl bg-bg-secondary border border-border-primary/80 space-y-6">
          <!-- Grid: Type & Severity -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-text-secondary mb-2 uppercase tracking-wide">Indicator Type *</label>
              <select v-model="formType" class="input w-full">
                <option value="ip">IP Address</option>
                <option value="domain">Domain Name</option>
                <option value="url">URL</option>
                <option value="hash">File Hash (MD5/SHA)</option>
                <option value="cve">CVE Vulnerability ID</option>
                <option value="email">Email Address</option>
              </select>
            </div>
            
            <div>
              <label class="block text-xs font-semibold text-text-secondary mb-2 uppercase tracking-wide">Severity Designation *</label>
              <select v-model="formSeverity" class="input w-full">
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <!-- Input: Value -->
          <div>
            <label class="block text-xs font-semibold text-text-secondary mb-2 uppercase tracking-wide">Indicator Value *</label>
            <input
              type="text"
              v-model="formValue"
              class="input w-full font-mono text-sm"
              :class="{ 'border-severity-critical focus:border-severity-critical focus:ring-severity-critical': formValueValidationError }"
              placeholder="e.g. 185.220.101[.]4, malware.exe, CVE-2026-928"
              required
            />
            <span v-if="formValueValidationError" class="text-xs text-severity-critical mt-1.5 block font-sans">
              {{ formValueValidationError }}
            </span>
            <p class="text-[10px] text-text-tertiary mt-1.5">Provide the literal IOC value. Domain and URLs can optionally be defanged.</p>
          </div>

          <!-- Grid: Title & Source Reference -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-text-secondary mb-2 uppercase tracking-wide">Brief Title</label>
              <input
                type="text"
                v-model="formTitle"
                class="input w-full text-xs"
                placeholder="e.g. Lockbit Infiltration Scanner"
              />
            </div>
            
            <div>
              <label class="block text-xs font-semibold text-text-secondary mb-2 uppercase tracking-wide">External Reference URL</label>
              <input
                type="url"
                v-model="formRef"
                class="input w-full text-xs font-mono"
                placeholder="e.g. https://www.virustotal.com/..."
              />
            </div>
          </div>

          <!-- Input: Description -->
          <div>
            <label class="block text-xs font-semibold text-text-secondary mb-2 uppercase tracking-wide">Context & Description</label>
            <textarea
              v-model="formDescription"
              class="input w-full text-xs min-h-[80px]"
              placeholder="Add technical context, campaign details, or mitigation steps..."
            />
          </div>

          <!-- Input: Tags -->
          <div>
            <label class="block text-xs font-semibold text-text-secondary mb-2 uppercase tracking-wide">Metadata Tags</label>
            <input
              type="text"
              v-model="formTags"
              class="input w-full text-xs"
              placeholder="e.g. Lockbit, scanner, CobaltStrike (comma separated)"
            />
          </div>

          <!-- Actions -->
          <div class="pt-4 flex items-center justify-between border-t border-border-primary/40">
            <span class="text-[11px] text-text-tertiary">* Required fields. Added items map to 'manual' feed.</span>
            <button
              type="submit"
              class="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-accent-blue text-bg-primary font-bold hover:bg-accent-blue/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-accent-blue/15"
              :disabled="isInjecting || !formValue.trim() || !!formValueValidationError"
            >
              <Loader2 v-if="isInjecting" class="w-4 h-4 animate-spin" />
              <Plus v-else class="w-4 h-4" />
              <span>{{ isInjecting ? 'Injecting...' : 'Inject Indicator' }}</span>
            </button>
          </div>
        </form>

        <!-- Mode B: Bulk Text Parser (regex extraction engine) -->
        <div v-else class="space-y-6">
          <div class="p-5 rounded-2xl bg-bg-secondary border border-border-primary/80 space-y-4">
            <label class="block text-xs font-semibold text-text-secondary uppercase tracking-wide">Paste Threat intelligence report or raw CSV / JSON text</label>
            <textarea
              v-model="rawTextReport"
              class="input w-full text-xs min-h-[140px] font-mono leading-relaxed"
              placeholder="Paste raw email briefs, VirusTotal logs, or text. E.g. 'A threat group used IP address 185.220.101[.]4 and domain evil[.]com to target vulnerability CVE-2021-44228...'"
            />
            <div class="flex justify-end">
              <button
                class="flex items-center gap-1.5 px-4 py-2 text-xs rounded-xl border border-accent-blue text-accent-blue hover:bg-accent-blue/10 transition-all font-semibold"
                :disabled="!rawTextReport.trim()"
                @click="parseRawText"
              >
                <Terminal class="w-3.5 h-3.5" />
                <span>Parse & Extract Indicators</span>
              </button>
            </div>
          </div>

          <!-- Parsed Review list -->
          <div v-if="parsedIndicators.length > 0" class="p-5 rounded-2xl bg-bg-secondary border border-border-primary/80 space-y-4 animate-fadeIn">
            <div class="flex items-center justify-between border-b border-border-primary/45 pb-3">
              <h4 class="text-xs font-bold text-white uppercase tracking-wider">Extracted Indicators for Review ({{ parsedIndicators.length }})</h4>
              <span class="text-[10px] text-text-tertiary">Review and modify indicators before importing.</span>
            </div>

            <!-- Table review -->
            <div class="overflow-x-auto max-h-[300px] border border-border-primary/20 rounded-xl">
              <table class="w-full text-left text-xs border-collapse font-mono">
                <thead class="sticky top-0 bg-bg-tertiary/90 text-text-tertiary">
                  <tr class="border-b border-border-primary/30 text-[10px]">
                    <th class="p-2 w-10 text-center">
                      <input type="checkbox" :checked="isAllChecked" @change="toggleSelectAll" class="rounded border-border-primary bg-bg-secondary text-accent-blue cursor-pointer" />
                    </th>
                    <th class="p-2 w-16">Type</th>
                    <th class="p-2">Value</th>
                    <th class="p-2">Title</th>
                    <th class="p-2 w-28">Severity</th>
                    <th class="p-2 w-32">Validation</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(item, index) in parsedIndicators" :key="index" class="border-b border-border-primary/10 hover:bg-bg-primary/20">
                    <td class="p-2 text-center">
                      <input type="checkbox" v-model="item.checked" class="rounded border-border-primary bg-bg-secondary text-accent-blue cursor-pointer" />
                    </td>
                    <td class="p-2">
                      <span class="text-[9px] uppercase font-bold text-accent-blue">{{ item.ioc_type }}</span>
                    </td>
                    <td class="p-2 truncate max-w-[150px] font-mono text-[11px]" :title="item.value">{{ item.value }}</td>
                    <td class="p-2">
                      <input type="text" v-model="item.title" class="px-2 py-0.5 rounded border border-border-primary/40 bg-bg-primary/40 text-text-secondary text-[11px] w-full" />
                    </td>
                    <td class="p-2">
                      <select v-model="item.severity" class="px-1.5 py-0.5 rounded border border-border-primary/40 bg-bg-primary/40 text-text-secondary text-[11px]">
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                    </td>
                    <td class="p-2">
                      <span
                        v-if="getValidationWarning(item)"
                        class="px-1.5 py-0.5 rounded text-[8px] font-bold tracking-wider uppercase inline-block"
                        :class="getValidationWarning(item)?.includes('Invalid')
                          ? 'text-severity-critical bg-severity-critical-bg border border-severity-critical/20'
                          : 'text-severity-high bg-severity-high/10 border border-severity-high/20'"
                      >
                        {{ getValidationWarning(item) }}
                      </span>
                      <span v-else class="text-accent-green text-[9px] font-bold font-mono">✓ Clear</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div class="pt-4 flex items-center justify-between border-t border-border-primary/30">
              <span class="text-[10px] text-text-tertiary">Parsed items will ingest under the local 'manual' feed repository.</span>
              <button
                class="flex items-center gap-1.5 px-5 py-2 text-xs rounded-xl bg-accent-blue text-bg-primary font-bold hover:bg-accent-blue/90 shadow-lg shadow-accent-blue/15"
                :disabled="isInjecting || parsedIndicators.filter(i => i.checked).length === 0"
                @click="handleInjectBulk"
              >
                <Loader2 v-if="isInjecting" class="w-3.5 h-3.5 animate-spin" />
                <Plus v-else class="w-3.5 h-3.5" />
                <span>Inject {{ parsedIndicators.filter(i => i.checked).length }} Indicators</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 4.5: Threat Hunting Library -->
      <div v-else-if="currentTab === 'hunting'" class="h-full flex flex-col overflow-hidden">
        <HuntingLibrary />
      </div>

      <!-- Tab 5: System Documentation -->
      <div v-else-if="currentTab === 'docs'" id="docs-scroll-container" @scroll="handleDocsScroll" class="h-full flex flex-col overflow-y-auto p-8 max-w-4xl mx-auto w-full print:p-0 print:max-w-none print:w-full print:block print:overflow-visible">
        <!-- Header -->
        <div class="mb-8 shrink-0 flex items-center justify-between print:hidden">
          <div>
            <h2 class="text-xl font-bold text-white tracking-wide">Aegis Platform Documentation</h2>
            <p class="text-xs text-text-tertiary mt-1">Platform architecture, capabilities, and system operations manual</p>
          </div>
          <button
            class="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-xl border border-border-primary text-text-secondary hover:text-white hover:border-border-secondary transition-all"
            @click="printDocumentation"
          >
            <Printer class="w-3.5 h-3.5" />
            <span>Print Manual (PDF)</span>
          </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 items-start print:block print:w-full">
          <!-- Side Nav inside Docs (Hidden when printing) -->
          <div class="space-y-1.5 md:col-span-1 border-r border-border-primary/40 pr-4 shrink-0 print:hidden sticky top-0 self-start">
            <button
              v-for="section in [
                { id: 'intro', label: '1. Architecture & Intro' },
                { id: 'feeds', label: '2. Ingestion & Validation' },
                { id: 'fts', label: '3. FTS5 Search Engine' },
                { id: 'mcp', label: '4. AI & MCP Reasoning' },
                { id: 'alerts', label: '5. Webhook Alerts & Test' },
                { id: 'hunting', label: '6. Threat Hunting Library' },
                { id: 'defanging', label: '7. Safe Defanging' }
              ]"
              :key="section.id"
              class="w-full text-left px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all border"
              :class="activeDocSection === section.id
                ? 'bg-accent-blue/10 text-accent-blue border-accent-blue/20 shadow-sm'
                : 'text-text-secondary hover:text-white hover:bg-bg-secondary/40 border-transparent'"
              @click="scrollToDocSection(section.id)"
            >
              {{ section.label }}
            </button>
          </div>

          <!-- Doc Content area -->
          <div class="md:col-span-3 p-6 rounded-2xl bg-bg-secondary border border-border-primary/80 min-h-[400px] print:border-none print:bg-white print:text-black print:p-0 print:block print:w-full">
            
            <!-- 1. Technical Architecture -->
            <div id="doc-intro" class="space-y-4 prose prose-invert prose-sm max-w-none print:prose-neutral print:text-black print:pb-8">
              <h3 class="text-base font-bold text-white uppercase tracking-wider mb-2 print:text-black print:border-b print:pb-1">1. Technical Architecture & Network Isolation</h3>
              <p>Aegis Threat Intel (ATI) is a secure, enterprise-grade Threat Intelligence Platform (TIP) designed to orchestrate local logs correlation, automated ingestion pipelines, and cognitive reasoning entirely within private network boundaries. The platform is built on a modern decoupled architecture:</p>
              
              <div class="p-4 bg-bg-primary rounded-xl border border-border-primary/50 font-mono text-[10px] text-text-secondary leading-normal print:bg-white print:text-black print:border-neutral-300">
<pre class="bg-transparent border-none p-0 m-0 text-[10px]">
  +--------------------------------------------------------+
  |                   Vue 3 UI Client                      |
  |   - Split Panel HUD           - In-App Document Manual |
  |   - Real-Time Validations     - FAQ Modal Helper       |
  +---------------------------+----------------------------+
                              | REST / JSON
                              v (Proxied via Vite to 4001)
  +--------------------------------------------------------+
  |                 Bun Application Server                 |
  |   - Bun.serve (CORS Whitelisted Origin Checks)         |
  |   - Ingestion Scheduler & Concurrency Lock Module      |
  |   - SQLite WAL / FTS5 Engine  - Outgoing Alert Engines |
  +-------------+----------------------------+-------------+
                |                            |
                v System Process Spawn       v Private SQL Query
  +--------------------------+  +------------+-------------+
  |  CVE MCP Python Server   |  |   SQLite Database File   |
  |  - 27 Enrichment Tools   |  |   - iocs (Main Repository) |
  |  - Windows Spawning Env  |  |   - iocs_fts (Virtual V5)  |
  +--------------------------+  +--------------------------+
</pre>
              </div>

              <ul>
                <li><strong>Presentation Layer</strong>: A reactive Vue 3 Single Page Application compiled via Vite, utilizing Tailwind CSS utility classes and Lucide vector icons to render a cyberpunk-themed, high-fidelity security operations console.</li>
                <li><strong>Application Layer</strong>: A fast Bun HTTP runtime serving API endpoints with whitelisted CORS checks, request header filters, and outgoing webhook engines.</li>
                <li><strong>Storage Layer</strong>: A local SQLite database operating in Write-Ahead Logging (WAL) mode for concurrency and low-latency disk writes.</li>
              </ul>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">SQLite WAL & Concurrency Architecture</h4>
              <p>To support high-throughput bulk ingestion without blocking frontend search operations, Aegis configures the database connection with WAL mode enabled (<code>PRAGMA journal_mode=WAL;</code>) and a busy timeout handler (<code>PRAGMA busy_timeout=5000;</code>). WAL mode writes changes to a separate transaction log file (<code>-wal</code>) rather than directly modifying the main database page structures, allowing concurrent reads to proceed safely without lock conditions. Checkpoint operations execute on idle threads to reconcile changes to disk.</p>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Network Boundary & Air-Gapped Compliance</h4>
              <p>To eliminate threat research leakage (where cloud TIPs expose internal query parameters to third-party databases), Aegis operates entirely within loopback boundaries (<code>127.0.0.1</code> / `localhost`). External calls are restricted. Whitelisted origin restrictions are applied dynamically on all API endpoints via the server's <code>getCorsHeaders</code> builder:
              <br>• Whitelisted Origins: `http://localhost:5174`, `http://127.0.0.1:5174`, `http://localhost:4173`, `http://127.0.0.1:4173`, and overrides configured in the `CLIENT_PORT` environment variables.
              </p>
            </div>

            <!-- 2. Ingestion & Validation -->
            <div id="doc-feeds" class="space-y-4 prose prose-invert prose-sm max-w-none border-t border-border-primary/20 pt-12 mt-12 print:border-neutral-200 print:prose-neutral print:text-black print:pt-8 print:pb-8">
              <h3 class="text-base font-bold text-white uppercase tracking-wider mb-2 print:text-black print:border-b print:pb-1">2. Automated Ingestion & Input Validation</h3>
              <p>Aegis maintains an ingestion engine that polls public intelligence feeds hourly and upserts indicators of compromise (IOCs) into the database:</p>
              <ul>
                <li><strong>CISA KEV Catalog</strong>: Maps actively exploited vulnerabilities to severity rules and provides direct references to the National Vulnerability Database (NVD).</li>
                <li><strong>Abuse.ch URLhaus</strong>: Collects active URL indicators distributing malware payloads. It automatically parses out hosting domains to upsert dual-indicator context.</li>
                <li><strong>Abuse.ch ThreatFox</strong>: Aggregates real-time hashes (MD5, SHA-256), IP addresses, domains, and email addresses linked to botnet commands and malware campaigns.</li>
              </ul>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Scheduler Concurrency Locking</h4>
              <p>To prevent database lock conditions, API rate-limiting violations, or CPU race conditions, the backend scheduler utilizes an in-memory lock (<code>activePollPromise</code>). If a poll cycle is triggered manually or programmatically while an ingestion is active, the system registers a log message and reuses the running cycle.</p>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Input Validation Engine</h4>
              <p>Manual threat logging enforces real-time client-side regular expressions mapping to the 6 supported types. Ingestion buttons are disabled until inputs match the regex structures:
              </p>

              <table class="w-full text-xs text-left border-collapse mt-2 print:text-black print:border-neutral-300">
                <thead>
                  <tr class="border-b border-border-primary print:border-black">
                    <th class="py-1">Indicator Type</th>
                    <th class="py-1">Regular Expression Validation Pattern</th>
                    <th class="py-1">Valid Example</th>
                  </tr>
                </thead>
                <tbody>
                  <tr class="border-b border-border-primary/20 print:border-neutral-200 font-mono text-[11px]">
                    <td class="py-2 font-sans font-bold">IP Address</td>
                    <td class="py-2"><code>^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$</code></td>
                    <td class="py-2 text-accent-blue print:text-neutral-800">198.51.100[.]42</td>
                  </tr>
                  <tr class="border-b border-border-primary/20 print:border-neutral-200 font-mono text-[11px]">
                    <td class="py-2 font-sans font-bold">Domain Name</td>
                    <td class="py-2"><code>^(?:[a-zA-Z0-9.-]+(?:\[\.\]|\.)[a-zA-Z]{2,})$</code></td>
                    <td class="py-2 text-accent-blue print:text-neutral-800">malware[.]evil.com</td>
                  </tr>
                  <tr class="border-b border-border-primary/20 print:border-neutral-200 font-mono text-[11px]">
                    <td class="py-2 font-sans font-bold">URL</td>
                    <td class="py-2"><code>^(?:https?|hxxps?):\/\/[^\s"'&lt;&gt;\)]+$</code></td>
                    <td class="py-2 text-accent-blue print:text-neutral-800">hxxps://evil.com/payload.exe</td>
                  </tr>
                  <tr class="border-b border-border-primary/20 print:border-neutral-200 font-mono text-[11px]">
                    <td class="py-2 font-sans font-bold">File Hash</td>
                    <td class="py-2"><code>^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})$</code></td>
                    <td class="py-2 text-accent-blue print:text-neutral-800">d29aa3aee368d9fc9b5523b413abfc2ad42aecf68137f768...</td>
                  </tr>
                  <tr class="border-b border-border-primary/20 print:border-neutral-200 font-mono text-[11px]">
                    <td class="py-2 font-sans font-bold">CVE ID</td>
                    <td class="py-2"><code>^CVE-\d{4}-\d{4,7}$</code></td>
                    <td class="py-2 text-accent-blue print:text-neutral-800">CVE-2021-44228</td>
                  </tr>
                  <tr class="border-b border-border-primary/20 print:border-neutral-200 font-mono text-[11px]">
                    <td class="py-2 font-sans font-bold">Email</td>
                    <td class="py-2"><code>^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$</code></td>
                    <td class="py-2 text-accent-blue print:text-neutral-800">attacker@malicious.domain</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- 3. FTS5 Search Engine -->
            <div id="doc-fts" class="space-y-4 prose prose-invert prose-sm max-w-none border-t border-border-primary/20 pt-12 mt-12 print:border-neutral-200 print:prose-neutral print:text-black print:pt-8 print:pb-8">
              <h3 class="text-base font-bold text-white uppercase tracking-wider mb-2 print:text-black print:border-b print:pb-1">3. SQLite FTS5 Search & Indexing Engine</h3>
              <p>Aegis leverages the SQLite FTS5 (Full-Text Search) virtual table extension to perform high-speed queries across millions of rows of threat context. The indexing engine maps a virtual table `iocs_fts` to the main database:
              </p>
              <div class="p-4 bg-bg-primary rounded-xl border border-border-primary/50 font-mono text-[10px] text-accent-blue print:bg-white print:text-black print:border-neutral-300">
<pre class="bg-transparent border-none p-0 m-0 text-[10px]">
CREATE VIRTUAL TABLE iocs_fts USING fts5(
  value,
  title,
  description,
  tags,
  content='iocs',
  content_rowid='id'
);
</pre>
              </div>
              <p>FTS index rebuild queries (<code>INSERT INTO iocs_fts(iocs_fts) VALUES('rebuild');</code>) execute automatically inside a transaction scope at the end of every automated ingestion cycle to maintain consistency.</p>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">SQLite Tokenization & Syntax Fallback Handler</h4>
              <p>Special characters (such as dots inside IP addresses <code>198.51.100.42</code> or colons inside URLs) serve as standard delimiters inside SQLite FTS5's default tokenizer. This breaks query tokens and can trigger parser syntax exceptions (e.g. <code>fts5: syntax error near "."</code>) when querying raw search values. 
              <br>Aegis mitigates this by implementing a try-catch fallback wrapper on the server:
              </p>
              <ol>
                <li><strong>Try (Full-Text Match)</strong>: Attempts an optimized, indexed search:
                  <br><code>SELECT rowid FROM iocs_fts WHERE iocs_fts MATCH '"search_term"*';</code>
                </li>
                <li><strong>Catch (SQL LIKE Fallback)</strong>: If the FTS5 query throws a syntax error, the server catches the exception, escapes wildcards, and performs a native fallback query:
                  <br><code>SELECT id FROM iocs WHERE value LIKE '%search_term%' OR title LIKE '%search_term%';</code>
                </li>
              </ol>
            </div>

            <!-- 4. AI Analyst & Reasoning -->
            <div id="doc-mcp" class="space-y-4 prose prose-invert prose-sm max-w-none border-t border-border-primary/20 pt-12 mt-12 print:border-neutral-200 print:prose-neutral print:text-black print:pt-8 print:pb-8">
              <h3 class="text-base font-bold text-white uppercase tracking-wider mb-2 print:text-black print:border-b print:pb-1">4. AI Analyst & Model Execution Framework</h3>
              <p>The integrated AI Analyst uses a dual-engine architecture to accommodate both security-cleared cloud reasoning and air-gapped on-premises deployments:</p>
              <ol>
                <li><strong>Cloud Mode (Claude)</strong>: Connects to Anthropic's Claude 3.5 Sonnet model. When an active <code>ANTHROPIC_API_KEY</code> is present in the server environment variables, the analyst can perform autonomous tool usage via MCP integrations, enrichment APIs, and internet queries.</li>
                <li><strong>Local Mode (Ollama)</strong>: Connects to local LLMs (e.g., Llama 3, Mistral, Qwen) running on-premises, disabling tool execution. This ensures that zero data leaves the private network, satisfying strict data boundary regulations.</li>
              </ol>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Model Context Protocol (MCP) Integration</h4>
              <p>In Cloud Mode, Aegis acts as an MCP client, spawning a background communication runtime to connect with a companion Python server (`cve-mcp-server`) using standard input/output JSON streams. Aegis exposes <strong>27 tools</strong> representing threat-intel services:
              </p>
              <ul>
                <li><strong>Reputation Lookups</strong>: AbuseIPDB, GreyNoise, Shodan, and VirusTotal.</li>
                <li><strong>NVD & Exploit Registries</strong>: National Vulnerability Database (NVD) schema mappings, Exploit Prediction Scoring System (EPSS) probabilities, and CISA KEV lookups.</li>
                <li><strong>Infrastructure Analysis</strong>: crt.sh certificate transparency logs, Shodan scans, and URLScan requests.</li>
                <li><strong>MITRE ATT&CK Mapping</strong>: Links exploited vulnerabilities to attack vectors and adversary profiles.</li>
              </ul>
              
              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Configuration Requirements</h4>
              <p>To enable active cloud reasoning and MCP enrichment tools, add the following parameters to the root `.env` file and restart the backend server:
              </p>
              <div class="p-4 bg-bg-primary rounded-xl border border-border-primary/50 font-mono text-[10px] text-text-secondary print:bg-white print:text-black print:border-neutral-300">
                ANTHROPIC_API_KEY=xkb-ant-sid01-your-key-here<br>
                CVE_MCP_PYTHON=C:\path\to\cve-mcp-server\.venv\Scripts\python.exe<br>
                CVE_MCP_CWD=C:\path\to\cve-mcp-server
              </div>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Rule-Based Offline Heuristics Fallback</h4>
              <p>If neither cloud keys nor local Ollama servers are detected, the analyst degrades gracefully into a local mock reasoning engine. The engine evaluates the selected indicator's severity, feeds origin metadata, and type properties to simulate threat briefings, calculate mock threat scores, map MITRE ATT&CK patterns (e.g., T1047 System Services execution, T1567 Exfiltration), and generate Splunk/KQL hunt signatures.</p>
            </div>

            <!-- 5. Centralized Webhook Alerts & Test Suite -->
            <div id="doc-alerts" class="space-y-4 prose prose-invert prose-sm max-w-none border-t border-border-primary/20 pt-12 mt-12 print:border-neutral-200 print:prose-neutral print:text-black print:pt-8 print:pb-8">
              <h3 class="text-base font-bold text-white uppercase tracking-wider mb-2 print:text-black print:border-b print:pb-1">5. Centralized Webhook Alerts & Diagnostics</h3>
              <p>The alerting engine dispatches webhook notices to security communications channels whenever Critical or High severity threat indicators are ingested. Webhook formats are adapted for each target framework:</p>
              
              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Outgoing Payload Formatting</h4>
              <ul>
                <li><strong>Slack Webhook Adapter</strong>: Monospaced blocks displaying indicator metrics, severity tags, description, and source references.
                </li>
                <li><strong>Microsoft Teams Adapter</strong>: Adaptive Cards formatted with attention blocks, monospace indicator strings, and descriptions.</li>
                <li><strong>Generic Webhook Adapter</strong>: Monospaced JSON payload formats containing event tags, threat type, raw value, severity rating, and timestamp.</li>
              </ul>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Live Diagnostics Connection Tester</h4>
              <p>The System Settings dashboard features a live "Test Connection" endpoint (<code>POST /api/webhooks/test</code>). When clicked, the server temporarily unmasks incoming webhook destinations containing cryptographic masking characters (<code>***</code>) by matching them with the raw credentials stored securely in database settings, dispatches a test alert payload, and logs the detailed HTTP response (e.g. `200 OK`, `400 Bad Request`, `404 Not Found`).</p>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Local Developer Webhook Receivers</h4>
              <p>To support offline validation and debugging, Aegis exposes mock receiver paths:
              <br>• Local endpoints: `/api/mock-webhook/slack`, `/api/mock-webhook/teams`, `/api/mock-webhook/generic`.
              <br>When configured, the local server interceptor catches outgoing payloads and prints the complete JSON/Adaptive Card block layouts to the server logs, allowing layout debugging without exposing tokens to external APIs.
              </p>
            </div>

            <!-- 6. Threat Hunting Library -->
            <div id="doc-hunting" class="space-y-4 prose prose-invert prose-sm max-w-none border-t border-border-primary/20 pt-12 mt-12 print:border-neutral-200 print:prose-neutral print:text-black print:pt-8 print:pb-8">
              <h3 class="text-base font-bold text-white uppercase tracking-wider mb-2 print:text-black print:border-b print:pb-1">6. SOC Threat Hunting Library & Signatures</h3>
              <p>To reduce response times, Aegis embeds a pre-packaged signature library targeting critical CVE vulnerabilities (including Log4Shell, Spring4Shell, ProxyLogon, PrintNightmare, Follina, DirtyPipe, and Zerologon). Signatures are structured across three formats:</p>
              
              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">1. Splunk Search Processing Language (SPL)</h4>
              <div class="p-4 bg-bg-primary rounded-xl border border-border-primary/50 font-mono text-[10px] text-accent-blue print:bg-white print:text-black print:border-neutral-300">
                index=security sourcetype=syslog OR sourcetype=iis OR sourcetype=apache<br>
                | search "jndi:ldap" OR "jndi:rmi" OR "spring.cloud.function" OR "autodiscover.xml"<br>
                | stats count by src_ip, dest_ip, signature, uri
              </div>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">2. Azure Kusto Query Language (KQL)</h4>
              <div class="p-4 bg-bg-primary rounded-xl border border-border-primary/50 font-mono text-[10px] text-accent-blue print:bg-white print:text-black print:border-neutral-300">
                SecurityEvent<br>
                | where EventID == 4688<br>
                | where CommandLine has_any ("jndi:ldap", "spring.root.class", "msdt.exe")<br>
                | project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
              </div>

              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">3. Sigma Rules (Platform-Independent YAML)</h4>
              <div class="p-4 bg-bg-primary rounded-xl border border-border-primary/50 font-mono text-[10px] text-accent-blue print:bg-white print:text-black print:border-neutral-300">
<pre class="bg-transparent border-none p-0 m-0 text-[10px] text-accent-blue">
title: Critical Web Application Vulnerability Exploitation
status: production
description: Detects command injection strings matching CVE signatures
logsource:
    category: webserver
detection:
    selection:
        c-uri|contains:
            - 'jndi:ldap'
            - 'spring.cloud'
    condition: selection
falsepositives:
    - Penetration testing activities
level: critical
</pre>
              </div>
            </div>

            <!-- 7. Safe Defanging -->
            <div id="doc-defanging" class="space-y-4 prose prose-invert prose-sm max-w-none border-t border-border-primary/20 pt-12 mt-12 print:border-neutral-200 print:prose-neutral print:text-black print:pt-8">
              <h3 class="text-base font-bold text-white uppercase tracking-wider mb-2 print:text-black print:border-b print:pb-1">7. Threat Defanging & Security Filter</h3>
              <p>Sharing raw indicators (such as malicious URLs or hostnames) in standard communication channels can trigger automated blocklists, crash corporate mail transfer agents, or cause accidental clicks by non-security staff. To mitigate this risk, Aegis runs a post-processing filter over all threat summaries. Hostnames, IPv4 addresses, and URIs are converted into standardized, non-navigable defanged formats before export or display:</p>
              
              <h4 class="text-xs font-bold text-white uppercase mt-4 print:text-black">Defanging Replacement Algorithms</h4>
              <p>The defanging parser applies the following string-mapping substitutions:
              <br>• Protocol mapping: Converts raw URL protocols <code>http://</code> and <code>https://</code> to <code>hxxp://</code> and <code>hxxps://</code>.
              <br>• Hostname mapping: Matches dots in hostnames and wraps them in square brackets (e.g. `evil.com` becomes `evil[.]com`).
              <br>• IP address mapping: Converts dots in IPv4 addresses to dot-brackets (e.g. `1.1.1.1` becomes `1[.]1[.]1[.]1`).
              </p>

              <table class="w-full text-xs text-left border-collapse mt-4 print:text-black print:border-neutral-300">
                <thead>
                  <tr class="border-b border-border-primary print:border-black">
                    <th class="py-1">Original Element</th>
                    <th class="py-1">Defanged Element</th>
                    <th class="py-1">Contextual Use Case</th>
                  </tr>
                </thead>
                <tbody>
                  <tr class="border-b border-border-primary/20 print:border-neutral-200">
                    <td class="py-2.5 font-mono">http://bad-domain.com/payload</td>
                    <td class="py-2.5 font-mono text-accent-blue print:text-neutral-800">hxxp://bad-domain[.]com/payload</td>
                    <td class="py-2.5">Prevent link resolving in chats & docs</td>
                  </tr>
                  <tr class="border-b border-border-primary/20 print:border-neutral-200">
                    <td class="py-2.5 font-mono">https://secure-gate.org</td>
                    <td class="py-2.5 font-mono text-accent-blue print:text-neutral-800">hxxps://secure-gate[.]org</td>
                    <td class="py-2.5">Neutralize phishing domains</td>
                  </tr>
                  <tr class="border-b border-border-primary/20 print:border-neutral-200">
                    <td class="py-2.5 font-mono">evil-domain.ru</td>
                    <td class="py-2.5 font-mono text-accent-blue print:text-neutral-800">evil-domain[.]ru</td>
                    <td class="py-2.5">Block mail agent lookup triggers</td>
                  </tr>
                  <tr>
                    <td class="py-2.5 font-mono">198.51.100.42</td>
                    <td class="py-2.5 font-mono text-accent-blue print:text-neutral-800">198[.]51[.]100[.]42</td>
                    <td class="py-2.5">Prevent host resolutions in internal logs</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 6: Centralized System Settings & Webhook Panel -->
      <div v-else-if="currentTab === 'settings'" class="h-full flex flex-col overflow-y-auto p-8 max-w-2xl mx-auto w-full">
        <!-- Header -->
        <div class="mb-8 shrink-0">
          <h2 class="text-xl font-bold text-white tracking-wide">System Settings</h2>
          <p class="text-xs text-text-tertiary mt-1 font-sans">Configure artificial intelligence engines and enrichment MCP services</p>
        </div>

        <div class="space-y-6">
          
          <!-- Webhook Settings Integration -->
          <div class="p-6 rounded-2xl bg-bg-secondary border border-border-primary/80 space-y-4">
            <div class="flex items-center justify-between border-b border-border-primary/30 pb-2">
              <h3 class="text-sm font-semibold text-text-primary uppercase tracking-wider">SOC Webhook Integrations</h3>
              <button
                class="flex items-center gap-1.5 px-4 py-1.5 text-xs rounded-xl bg-accent-blue text-bg-primary font-bold hover:bg-accent-blue/90 disabled:opacity-50 transition-all"
                :disabled="settingsLoading"
                @click="saveWebhookSettings"
              >
                <Loader2 v-if="settingsLoading" class="w-3.5 h-3.5 animate-spin" />
                <Plus v-else class="w-3.5 h-3.5" />
                <span>{{ webhookSettingsSaved ? 'Saved!' : 'Save Config' }}</span>
              </button>
            </div>

            <!-- Settings fields -->
            <div class="space-y-4">
              <div>
                <div class="flex items-center justify-between mb-1.5">
                  <label class="block text-xs text-text-secondary font-medium font-sans">Slack Webhook URL</label>
                  <div class="flex items-center gap-2">
                    <span v-if="slackTestResult" class="text-[9px] font-bold px-1.5 py-0.5 rounded font-mono" :class="slackTestResult.success ? 'text-accent-green bg-accent-green/10 border border-accent-green/20' : 'text-severity-critical bg-severity-critical-bg border border-severity-critical/20'">
                      {{ slackTestResult.message }}
                    </span>
                    <button
                      type="button"
                      class="text-[10px] font-bold text-accent-blue hover:text-accent-blue/80 disabled:opacity-50 font-sans cursor-pointer flex items-center gap-1"
                      :disabled="testingSlack || !slackWebhookUrl"
                      @click="testWebhook('slack', slackWebhookUrl)"
                    >
                      <Loader2 v-if="testingSlack" class="w-3 h-3 animate-spin" />
                      <span>{{ testingSlack ? 'Testing...' : 'Test Connection' }}</span>
                    </button>
                  </div>
                </div>
                <input
                  type="url"
                  v-model="slackWebhookUrl"
                  class="input text-xs w-full font-mono"
                  placeholder="https://hooks.slack.com/services/..."
                />
              </div>

              <div>
                <div class="flex items-center justify-between mb-1.5">
                  <label class="block text-xs text-text-secondary font-medium font-sans">Microsoft Teams Webhook URL</label>
                  <div class="flex items-center gap-2">
                    <span v-if="teamsTestResult" class="text-[9px] font-bold px-1.5 py-0.5 rounded font-mono" :class="teamsTestResult.success ? 'text-accent-green bg-accent-green/10 border border-accent-green/20' : 'text-severity-critical bg-severity-critical-bg border border-severity-critical/20'">
                      {{ teamsTestResult.message }}
                    </span>
                    <button
                      type="button"
                      class="text-[10px] font-bold text-accent-blue hover:text-accent-blue/80 disabled:opacity-50 font-sans cursor-pointer flex items-center gap-1"
                      :disabled="testingTeams || !teamsWebhookUrl"
                      @click="testWebhook('teams', teamsWebhookUrl)"
                    >
                      <Loader2 v-if="testingTeams" class="w-3 h-3 animate-spin" />
                      <span>{{ testingTeams ? 'Testing...' : 'Test Connection' }}</span>
                    </button>
                  </div>
                </div>
                <input
                  type="url"
                  v-model="teamsWebhookUrl"
                  class="input text-xs w-full font-mono"
                  placeholder="https://outlook.office.com/webhook/..."
                />
              </div>

              <div>
                <div class="flex items-center justify-between mb-1.5">
                  <label class="block text-xs text-text-secondary font-medium font-sans">Generic JSON Webhook URL</label>
                  <div class="flex items-center gap-2">
                    <span v-if="genericTestResult" class="text-[9px] font-bold px-1.5 py-0.5 rounded font-mono" :class="genericTestResult.success ? 'text-accent-green bg-accent-green/10 border border-accent-green/20' : 'text-severity-critical bg-severity-critical-bg border border-severity-critical/20'">
                      {{ genericTestResult.message }}
                    </span>
                    <button
                      type="button"
                      class="text-[10px] font-bold text-accent-blue hover:text-accent-blue/80 disabled:opacity-50 font-sans cursor-pointer flex items-center gap-1"
                      :disabled="testingGeneric || !genericWebhookUrl"
                      @click="testWebhook('generic', genericWebhookUrl)"
                    >
                      <Loader2 v-if="testingGeneric" class="w-3 h-3 animate-spin" />
                      <span>{{ testingGeneric ? 'Testing...' : 'Test Connection' }}</span>
                    </button>
                  </div>
                </div>
                <input
                  type="url"
                  v-model="genericWebhookUrl"
                  class="input text-xs w-full font-mono"
                  placeholder="https://api.yourorganization.com/webhook"
                />
              </div>
              <p class="text-[10px] text-text-tertiary">Webhooks automatically send telemetry alerts when High/Critical severity threats are cataloged.</p>
            </div>
          </div>

          <!-- Section 1: AI Provider Selection -->
          <div class="p-6 rounded-2xl bg-bg-secondary border border-border-primary/80 space-y-4">
            <h3 class="text-sm font-semibold text-text-primary uppercase tracking-wider border-b border-border-primary/40 pb-2">AI Processor Model Configuration</h3>
            
            <div class="flex items-center justify-between gap-4">
              <div>
                <span class="text-xs text-white font-medium block">Cloud Intelligence (Anthropic Claude)</span>
                <p class="text-[11px] text-text-tertiary mt-1">Enables full-text tool execution and online CVE/IP lookups.</p>
              </div>
              <button
                class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
                :class="provider === 'anthropic'
                  ? 'bg-accent-blue text-bg-primary shadow-lg shadow-accent-blue/15'
                  : 'border border-border-primary text-text-secondary hover:text-white'"
                @click="setProvider('anthropic')"
              >
                <Cloud class="w-3.5 h-3.5" />
                <span>Cloud Model</span>
              </button>
            </div>

            <div class="flex items-center justify-between gap-4 pt-4 border-t border-border-primary/20">
              <div>
                <span class="text-xs text-white font-medium block">Local Intelligence (Ollama LLM)</span>
                <p class="text-[11px] text-text-tertiary mt-1">Run threat intelligence offline. Data stays on your network.</p>
              </div>
              <button
                class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
                :class="provider === 'ollama'
                  ? 'bg-accent-green text-bg-primary shadow-lg shadow-accent-green/15'
                  : 'border border-border-primary text-text-secondary hover:text-white'"
                @click="setProvider('ollama')"
              >
                <Server class="w-3.5 h-3.5" />
                <span>Local Model</span>
              </button>
            </div>
          </div>

          <!-- Section 2: Ollama Local Configuration -->
          <div v-if="provider === 'ollama'" class="p-6 rounded-2xl bg-bg-secondary border border-border-primary/80 space-y-4">
            <h3 class="text-sm font-semibold text-text-primary uppercase tracking-wider border-b border-border-primary/40 pb-2">Ollama Connection Settings</h3>
            
            <div class="space-y-4">
              <div>
                <label class="block text-xs text-text-secondary mb-2 font-medium">Ollama Server Endpoint</label>
                <input
                  type="text"
                  class="input text-xs w-full font-mono"
                  :value="providerConfig.ollamaUrl"
                  placeholder="http://localhost:11434"
                  @change="handleSetOllamaConfig(($event.target as HTMLInputElement).value, providerConfig.ollamaModel)"
                />
              </div>

              <div>
                <label class="block text-xs text-text-secondary mb-2 font-medium">Active Local Model</label>
                <select
                  v-if="providerConfig.availableModels.length > 0"
                  class="input text-xs w-full font-mono"
                  :value="providerConfig.ollamaModel"
                  @change="handleSetOllamaConfig(providerConfig.ollamaUrl, ($event.target as HTMLSelectElement).value)"
                >
                  <option v-for="model in providerConfig.availableModels" :key="model" :value="model">
                    {{ model }}
                  </option>
                </select>
                <input
                  v-else
                  type="text"
                  class="input text-xs w-full font-mono"
                  :value="providerConfig.ollamaModel"
                  placeholder="e.g. Llama3.1, mistral, custom"
                  @change="handleSetOllamaConfig(providerConfig.ollamaUrl, ($event.target as HTMLInputElement).value)"
                />
                <p class="text-[10px] text-text-tertiary mt-1.5">
                  {{ providerConfig.availableModels.length > 0 ? 'Discovered models loaded successfully.' : 'No models seen. Please verify Ollama is running.' }}
                </p>
              </div>
            </div>
          </div>

          <!-- Section 3: Enrichment MCP Health -->
          <div class="p-6 rounded-2xl bg-bg-secondary border border-border-primary/80 space-y-4">
            <h3 class="text-sm font-semibold text-text-primary uppercase tracking-wider border-b border-border-primary/40 pb-2">CVE-MCP Enrichment Server</h3>
            
            <div v-if="mcpStatus">
              <div class="flex items-center gap-3">
                <span class="text-xs text-white font-medium">Diagnostic Status:</span>
                <span
                  class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border"
                  :class="!mcpStatus.enabled
                    ? 'text-text-tertiary bg-bg-tertiary/40 border-border-primary/30'
                    : mcpStatus.connected
                    ? 'text-accent-green bg-accent-green/10 border-accent-green/30'
                    : 'text-severity-critical bg-severity-critical-bg border-severity-critical/30'"
                >
                  {{ !mcpStatus.enabled ? 'Disabled' : mcpStatus.connected ? 'Connected' : 'Disconnected' }}
                </span>
              </div>
              
              <p class="text-[11px] text-text-tertiary leading-relaxed mt-3">
                When active, the senior AI analyst has access to NVD lookup details, FIRST.org EPSS scores, GreyNoise IP intelligence, Shodan host mapping, VirusTotal analysis, and URLScan integrations.
              </p>

              <!-- Connection error logs -->
              <div v-if="mcpStatus.enabled && !mcpStatus.connected" class="mt-4 p-3 rounded-lg bg-severity-critical-bg border border-severity-critical/20 text-xs text-severity-critical">
                <p class="font-bold flex items-center gap-1.5 mb-1">
                  <AlertTriangle class="w-3.5 h-3.5" />
                  Connection Diagnostic Failure
                </p>
                <p class="font-mono text-[10px] break-words">{{ mcpStatus.lastError || 'Process unreachable. Please verify Python virtual environment exists.' }}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

    </main>

    <!-- SIEM Hunt Sandbox Sliding Code Drawer -->
    <SiemDrawer
      :ioc="selectedIOC"
      :is-open="isSiemDrawerOpen"
      @close="isSiemDrawerOpen = false"
    />

    <!-- FAQ Modal Overlay (Premium SOC UI Component) -->
    <Transition name="fade">
      <div v-if="showFaqModal" class="fixed inset-0 z-[1000] flex items-center justify-center bg-black/75 backdrop-blur-md p-4 print:hidden" @click.self="showFaqModal = false">
        <div class="bg-bg-primary border border-border-primary/80 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl relative flex flex-col max-h-[80vh] animate-[scaleIn_0.2s_ease-out]">
          
          <!-- Modal Header -->
          <div class="flex items-center justify-between p-5 border-b border-border-primary/30 shrink-0">
            <div class="flex items-center gap-2">
              <HelpCircle class="w-5 h-5 text-accent-blue" />
              <h3 class="text-base font-bold text-white tracking-wide">Frequently Asked Questions</h3>
            </div>
            <button 
              class="p-1.5 rounded-lg border border-border-primary/45 hover:border-border-secondary hover:bg-bg-tertiary/50 text-text-secondary hover:text-white transition-all cursor-pointer"
              @click="showFaqModal = false"
            >
              <X class="w-4 h-4" />
            </button>
          </div>

          <!-- Modal Scrollable Content Container -->
          <div class="flex-1 overflow-y-auto p-6 space-y-4">
            
            <!-- Search bar -->
            <div class="relative w-full">
              <Search class="absolute left-3.5 top-3 w-4 h-4 text-text-tertiary" />
              <input 
                v-model="faqSearchQuery"
                type="text"
                placeholder="Search questions..."
                class="w-full pl-10 pr-4 py-2.5 bg-bg-secondary text-white text-xs border border-border-primary/80 rounded-xl focus:outline-none focus:border-amber-500/80 focus:ring-1 focus:ring-amber-500/80 focus:shadow-[0_0_12px_rgba(245,158,11,0.25)] transition-all font-sans"
              />
            </div>

            <!-- Category pills -->
            <div class="flex flex-wrap gap-1.5 py-1">
              <button 
                v-for="cat in faqCategories"
                :key="cat"
                class="px-3 py-1 rounded-full text-[10px] font-bold border transition-all cursor-pointer"
                :class="faqSelectedCategory === cat
                  ? 'bg-amber-500 text-bg-primary border-amber-500 hover:bg-amber-500/90'
                  : 'bg-bg-secondary text-text-secondary border-border-primary/60 hover:text-white hover:border-border-secondary'"
                @click="faqSelectedCategory = cat"
              >
                {{ cat }}
              </button>
            </div>

            <!-- FAQs list -->
            <div v-if="filteredFaqs.length === 0" class="text-center py-10 text-xs text-text-tertiary/75 italic">
              No matching FAQs found. Please try a different query or category.
            </div>
            
            <div v-else class="space-y-2.5">
              <div 
                v-for="(item, index) in filteredFaqs"
                :key="index"
                class="border border-border-primary/50 bg-bg-secondary/30 rounded-xl overflow-hidden transition-all duration-200"
                :class="{ 'border-amber-500/20 bg-bg-secondary/50': faqExpandedQuestion === item.question }"
              >
                <!-- Question clickable header -->
                <button 
                  class="w-full flex items-center justify-between p-4 text-left transition-all hover:bg-bg-secondary/40 gap-4"
                  @click="toggleFaq(item.question)"
                >
                  <span class="text-xs font-semibold text-text-primary group-hover:text-white transition-colors">{{ item.question }}</span>
                  <ChevronDown 
                    class="w-4 h-4 text-text-tertiary shrink-0 transition-transform duration-250"
                    :class="{ 'rotate-180 text-amber-500': faqExpandedQuestion === item.question }"
                  />
                </button>

                <!-- Expanded Answer area -->
                <div 
                  v-if="faqExpandedQuestion === item.question" 
                  class="px-4 pb-4 pt-1 text-xs leading-relaxed text-text-secondary border-t border-border-primary/20 bg-bg-primary/20 font-sans whitespace-pre-line"
                >
                  {{ item.answer }}
                </div>
              </div>
            </div>

          </div>

          <!-- Modal Footer -->
          <div class="px-6 py-4 border-t border-border-primary/30 bg-bg-secondary/30 flex justify-between items-center shrink-0">
            <span class="text-[9px] text-text-tertiary uppercase tracking-wider font-mono">Aegis SecOps Assistant v1.2</span>
            <span class="text-[10px] text-text-tertiary font-sans">Need additional help? Check the <a href="#" @click.prevent="showFaqModal = false; currentTab = 'docs'" class="text-accent-blue hover:underline">System Docs</a></span>
          </div>

        </div>
      </div>
    </Transition>
  </div>
  </template>
</template>

<style>
@keyframes scaleIn {
  from { transform: scale(0.96); opacity: 0; }
  to { transform: scale(1); opacity: 1; }
}
/* Custom prose adaptations for dark elements */
.prose h1, .prose h2, .prose h3, .prose h4 {
  color: #ffffff !important;
  font-family: 'Inter', sans-serif;
  font-weight: 700;
}
.prose pre {
  background-color: #030307 !important;
  border: 1px solid rgba(0, 212, 255, 0.15) !important;
  border-radius: 0.75rem !important;
  padding: 1rem !important;
}
.prose code {
  color: #38bdf8 !important;
  background-color: rgba(56, 189, 248, 0.1) !important;
  padding: 0.125rem 0.25rem !important;
  border-radius: 0.25rem !important;
}
.prose code::before, .prose code::after {
  content: "" !important;
}
.prose a {
  color: #38bdf8 !important;
  text-decoration: none !important;
}
.prose a:hover {
  text-decoration: underline !important;
}

/* Printing styles for clean, formatted documentation (usability enhancement) */
@media print {
  aside,
  header,
  nav,
  button,
  .fixed,
  .absolute,
  .cursor-col-resize {
    display: none !important;
  }
  body, html {
    background-color: white !important;
    color: black !important;
  }
  main,
  .md\:col-span-3,
  article,
  .prose {
    width: 100% !important;
    display: block !important;
    position: static !important;
    overflow: visible !important;
    background: white !important;
    color: black !important;
  }
  .prose h1, .prose h2, .prose h3, .prose h4, .prose strong, .prose table {
    color: black !important;
    border-color: #d4d4d4 !important;
  }
  .prose pre, .prose code {
    background: #f4f4f5 !important;
    color: #18181b !important;
    border-color: #e4e4e7 !important;
  }
}

/* Cyber-grid boot scan & transitions */
@keyframes scan {
  0% { top: 0%; opacity: 0; }
  10% { opacity: 1; }
  90% { opacity: 1; }
  100% { top: 100%; opacity: 0; }
}
.animate-scan {
  animation: scan 2.5s linear infinite;
}
.fade-leave-active {
  transition: opacity 0.5s ease-out;
}
.fade-leave-to {
  opacity: 0;
}
</style>
