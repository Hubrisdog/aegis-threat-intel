/**
 * Aegis Threat Intelligence Server
 * HTTP API for IOC management, feed polling, and AI-powered analysis
 */

import { initDB, getStats, getFeeds, queryIOCs, getIOCById, getBriefs, getBriefById, upsertIOC, rebuildFTS, updateFeedStatus, getSystemSetting, setSystemSetting } from './db';
import { startFeedScheduler, pollAllFeeds } from './feeds';
import { sendChatMessage, generateThreatBrief, getOllamaModels, QUICK_PROMPTS } from './ai-client';
import { getCveMcpStatus } from './mcp-client';

// Initialize database
const db = initDB();

// Start feed polling
startFeedScheduler();

async function dispatchWebhookAlert(ioc: { value: string; ioc_type: string; severity: string; title?: string; description?: string }) {
  // Only trigger for high and critical
  if (ioc.severity !== 'critical' && ioc.severity !== 'high') return;

  const slackUrl = getSystemSetting('slack_webhook_url');
  const teamsUrl = getSystemSetting('teams_webhook_url');
  const genericUrl = getSystemSetting('generic_webhook_url');

  const titleText = ioc.title ? ` — *${ioc.title}*` : '';
  const descriptionText = ioc.description ? `\n> ${ioc.description}` : '';
  
  // Format defanged text representation
  const defangedValue = ioc.value.replace(/\./g, '[.]');

  // Slack Format
  if (slackUrl) {
    try {
      await fetch(slackUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: `🚨 *AEGIS INTEL ALERT* 🚨\n*Severity*: \`${ioc.severity.toUpperCase()}\` | *Type*: \`${ioc.ioc_type.toUpperCase()}\`\n*Indicator*: \`${defangedValue}\`${titleText}${descriptionText}`
        })
      });
      console.log('[webhook] Sent Slack alert for', defangedValue);
    } catch (e) {
      console.error('[webhook] Failed to send Slack alert:', e);
    }
  }

  // MS Teams Format
  if (teamsUrl) {
    try {
      await fetch(teamsUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'message',
          attachments: [{
            contentType: 'application/vnd.microsoft.card.adaptive',
            content: {
              type: 'AdaptiveCard',
              body: [
                { type: 'TextBlock', text: '🚨 AEGIS INTEL ALERT 🚨', weight: 'bolder', size: 'medium', color: 'attention' },
                { type: 'TextBlock', text: `Severity: ${ioc.severity.toUpperCase()} | Type: ${ioc.ioc_type.toUpperCase()}`, weight: 'bold' },
                { type: 'TextBlock', text: `Indicator: ${defangedValue}${titleText}`, fontType: 'monospace' },
                { type: 'TextBlock', text: ioc.description || 'No description provided.', wrap: true, italic: true }
              ],
              $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
              version: '1.2'
            }
          }]
        })
      });
      console.log('[webhook] Sent Teams alert for', defangedValue);
    } catch (e) {
      console.error('[webhook] Failed to send Teams alert:', e);
    }
  }

  // Generic JSON Webhook Format
  if (genericUrl) {
    try {
      await fetch(genericUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event: 'ioc_alert',
          timestamp: Date.now(),
          indicator: {
            value: defangedValue,
            raw_value: ioc.value,
            type: ioc.ioc_type,
            severity: ioc.severity,
            title: ioc.title,
            description: ioc.description
          }
        })
      });
      console.log('[webhook] Sent Generic alert for', defangedValue);
    } catch (e) {
      console.error('[webhook] Failed to send Generic alert:', e);
    }
  }
}

// CORS Whitelist & Header Builder
function getCorsHeaders(requestHeaders: Headers): Record<string, string> {
  const origin = requestHeaders.get('origin');
  
  const allowedOrigins = [
    'http://localhost:5174',
    'http://127.0.0.1:5174',
    'http://localhost:4173',
    'http://127.0.0.1:4173',
  ];
  
  const customClientPort = process.env.CLIENT_PORT;
  if (customClientPort) {
    allowedOrigins.push(`http://localhost:${customClientPort}`);
    allowedOrigins.push(`http://127.0.0.1:${customClientPort}`);
  }

  const isAllowed = origin && (allowedOrigins.includes(origin) || allowedOrigins.includes(origin.replace(/\/$/, '')));
  
  return {
    'Access-Control-Allow-Origin': isAllowed ? origin : allowedOrigins[0],
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
}

// Webhook Secret Redaction Masker
function maskWebhookUrl(url: string | null): string | null {
  if (!url) return null;
  if (url.includes('localhost') || url.includes('127.0.0.1')) {
    return url;
  }
  try {
    const parsed = new URL(url);
    const host = parsed.host;
    const protocol = parsed.protocol;
    return `${protocol}//${host}/services/T***/***/******`;
  } catch {
    return 'https://***.***/***';
  }
}

const server = Bun.serve({
  port: parseInt(process.env.PORT || '4001'),

  async fetch(req: Request) {
    const url = new URL(req.url);
    const path = url.pathname;

    const requestCorsHeaders = getCorsHeaders(req.headers);
    function json(data: unknown, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: { ...requestCorsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Preflight
    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: requestCorsHeaders });
    }

    // GET /health
    if (path === '/health' && req.method === 'GET') {
      const stats = getStats();
      return json({
        status: 'ok',
        timestamp: Date.now(),
        iocCount: stats.totalIOCs,
        feedCount: getFeeds().length,
      });
    }

    // GET /stats
    if (path === '/stats' && req.method === 'GET') {
      return json(getStats());
    }

    // GET /feeds
    if (path === '/feeds' && req.method === 'GET') {
      return json(getFeeds());
    }

    // POST /feeds/poll
    if (path === '/feeds/poll' && req.method === 'POST') {
      pollAllFeeds(); // fire and forget
      return json({ triggered: true, message: 'Poll started' });
    }

    // GET /mcp/status — cve-mcp threat-intel enrichment health
    if (path === '/mcp/status' && req.method === 'GET') {
      const status = await getCveMcpStatus();
      return json(status);
    }

    // GET /iocs
    if (path === '/iocs' && req.method === 'GET') {
      const params = {
        search: url.searchParams.get('search') || undefined,
        type: (url.searchParams.get('type') || undefined) as any,
        severity: (url.searchParams.get('severity') || undefined) as any,
        feed: (url.searchParams.get('feed') || undefined) as any,
        sort: (url.searchParams.get('sort') || 'last_seen') as any,
        sortDir: (url.searchParams.get('sortDir') || 'desc') as 'asc' | 'desc',
        limit: Math.min(parseInt(url.searchParams.get('limit') || '50'), 200),
        offset: parseInt(url.searchParams.get('offset') || '0'),
      };
      const result = queryIOCs(params);
      return json({ ...result, limit: params.limit, offset: params.offset });
    }

    // GET /iocs/:id
    if (path.startsWith('/iocs/') && req.method === 'GET') {
      const id = parseInt(path.split('/')[2]);
      if (isNaN(id)) return json({ error: 'Invalid ID' }, 400);
      const ioc = getIOCById(id);
      if (!ioc) return json({ error: 'Not found' }, 404);
      return json(ioc);
    }

    // POST /iocs/search
    if (path === '/iocs/search' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const result = queryIOCs({
          search: body.query,
          type: body.type,
          severity: body.severity,
          feed: body.feed,
          limit: Math.min(body.limit || 20, 100),
        });
        return json(result);
      } catch {
        return json({ error: 'Invalid request' }, 400);
      }
    }

    // POST /iocs/custom
    if (path === '/iocs/custom' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const { ioc_type, value, severity, title, description, source_ref, tags } = body;

        if (!ioc_type || !value || !severity) {
          return json({ success: false, error: 'ioc_type, value, and severity are required' }, 400);
        }

        // Get feed ID for 'manual'
        const feeds = getFeeds();
        const manualFeed = feeds.find(f => f.name === 'manual');
        if (!manualFeed) {
          return json({ success: false, error: 'Manual feed database entry not found' }, 500);
        }

        const now = Date.now();
        const parsedTags = Array.isArray(tags)
          ? tags
          : typeof tags === 'string'
          ? tags.split(',').map(t => t.trim()).filter(Boolean)
          : [];

        upsertIOC(manualFeed.id, {
          ioc_type,
          value,
          severity,
          title: title || undefined,
          description: description || undefined,
          source_ref: source_ref || undefined,
          tags: parsedTags,
          first_seen: now,
          last_seen: now,
        });

        // Rebuild FTS
        rebuildFTS();

        // Increment count in feeds table for the 'manual' feed
        const totalManualIOCsQuery = queryIOCs({ feed: 'manual', limit: 1 });
        const manualCount = totalManualIOCsQuery.total;
        
        // Update feed count
        updateFeedStatus('manual', 'ok', { lastCount: manualCount });

        // Dispatch Webhook Alert asynchronously
        dispatchWebhookAlert({
          value,
          ioc_type,
          severity,
          title: title || undefined,
          description: description || undefined
        });

        return json({ success: true, message: 'IOC added successfully' });
      } catch (error: any) {
        console.error('Custom IOC insert error:', error);
        return json({ success: false, error: error?.message || 'Invalid request' }, 400);
      }
    }

    // POST /iocs/bulk
    if (path === '/iocs/bulk' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const { indicators } = body;

        if (!Array.isArray(indicators) || indicators.length === 0) {
          return json({ success: false, error: 'indicators array is required' }, 400);
        }

        // Get feed ID for 'manual'
        const feeds = getFeeds();
        const manualFeed = feeds.find(f => f.name === 'manual');
        if (!manualFeed) {
          return json({ success: false, error: 'Manual feed database entry not found' }, 500);
        }

        const now = Date.now();
        let addedCount = 0;

        for (const ind of indicators) {
          const { ioc_type, value, severity, title, description, source_ref, tags } = ind;
          if (!ioc_type || !value || !severity) continue;

          const parsedTags = Array.isArray(tags)
            ? tags
            : typeof tags === 'string'
            ? tags.split(',').map(t => t.trim()).filter(Boolean)
            : [];

          upsertIOC(manualFeed.id, {
            ioc_type,
            value,
            severity,
            title: title || undefined,
            description: description || undefined,
            source_ref: source_ref || undefined,
            tags: parsedTags,
            first_seen: now,
            last_seen: now,
          });

          // Dispatch Webhook Alert asynchronously
          dispatchWebhookAlert({
            value,
            ioc_type,
            severity,
            title: title || undefined,
            description: description || undefined
          });

          addedCount++;
        }

        if (addedCount > 0) {
          rebuildFTS();
          const totalManualIOCsQuery = queryIOCs({ feed: 'manual', limit: 1 });
          const manualCount = totalManualIOCsQuery.total;
          updateFeedStatus('manual', 'ok', { lastCount: manualCount });
        }

        return json({ success: true, count: addedCount, message: `Successfully injected ${addedCount} indicators` });
      } catch (error: any) {
        console.error('Bulk IOC insert error:', error);
        return json({ success: false, error: error?.message || 'Invalid request' }, 400);
      }
    }

    // GET /settings
    if (path === '/settings' && req.method === 'GET') {
      const keys = ['slack_webhook_url', 'teams_webhook_url', 'generic_webhook_url'];
      const settings: Record<string, string | null> = {};
      for (const k of keys) {
        settings[k] = maskWebhookUrl(getSystemSetting(k));
      }
      return json({ success: true, settings });
    }

    // POST /settings
    if (path === '/settings' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const { settings } = body;
        if (typeof settings !== 'object' || !settings) {
          return json({ success: false, error: 'settings object is required' }, 400);
        }

        for (const [k, v] of Object.entries(settings)) {
          if (typeof v === 'string') {
            if (v.includes('***') || v.includes('******')) {
              continue; // Do not overwrite with masked placeholders
            }
            setSystemSetting(k, v);
          } else if (v === null) {
            setSystemSetting(k, ''); // save empty string to clear
          }
        }

        return json({ success: true, message: 'Settings saved successfully' });
      } catch (error: any) {
        return json({ success: false, error: error?.message || 'Invalid request' }, 400);
      }
    }

    // POST /api/webhooks/test
    if (path === '/api/webhooks/test' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const { webhook_type, url } = body;

        if (!webhook_type || !url) {
          return json({ success: false, error: 'webhook_type and url are required' }, 400);
        }

        let targetUrl = url;
        if (url.includes('***') || url.includes('******')) {
          const settingKey = `${webhook_type}_webhook_url`;
          targetUrl = getSystemSetting(settingKey);
        }

        if (!targetUrl) {
          return json({ success: false, error: `No unmasked URL stored for ${webhook_type}` }, 400);
        }

        let payload: any;
        if (webhook_type === 'slack') {
          payload = {
            text: `🛡️ *AEGIS THREAT INTEL - INTEGRATION TEST* 🛡️\nThis is a secure connection test payload dispatched from the Aegis SOC dashboard.\n*Timestamp*: \`${new Date().toISOString()}\` | *Status*: \`ACTIVE\``
          };
        } else if (webhook_type === 'teams') {
          payload = {
            type: 'message',
            attachments: [{
              contentType: 'application/vnd.microsoft.card.adaptive',
              content: {
                type: 'AdaptiveCard',
                body: [
                  { type: 'TextBlock', text: '🛡️ AEGIS THREAT INTEL - INTEGRATION TEST 🛡️', weight: 'bolder', size: 'medium', color: 'good' },
                  { type: 'TextBlock', text: `This is a secure connection test payload dispatched from the Aegis SOC dashboard.`, wrap: true },
                  { type: 'TextBlock', text: `Timestamp: ${new Date().toISOString()} | Status: ACTIVE`, fontType: 'monospace' }
                ],
                $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
                version: '1.2'
              }
            }]
          };
        } else {
          payload = {
            event: 'webhook_test',
            timestamp: Date.now(),
            message: 'This is a secure connection test payload dispatched from the Aegis SOC dashboard.',
            status: 'ACTIVE'
          };
        }

        const response = await fetch(targetUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        if (response.ok) {
          return json({ success: true, status: response.status, statusText: response.statusText });
        } else {
          const text = await response.text();
          return json({
            success: false,
            status: response.status,
            error: text || response.statusText || `HTTP error ${response.status}`,
          }, 400);
        }
      } catch (error: any) {
        console.error('Webhook testing error:', error);
        return json({ success: false, error: error?.message || 'Network request failed' }, 500);
      }
    }

    // GET /chat/prompts
    if (path === '/chat/prompts' && req.method === 'GET') {
      return json(QUICK_PROMPTS);
    }

    // POST /chat
    if (path === '/chat' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const { message, history = [], iocContext, provider, ollamaUrl, ollamaModel, sessionId } = body;

        if (!message) {
          return json({ success: false, error: 'Message required' }, 400);
        }

        const response = await sendChatMessage(
          message, history, iocContext, sessionId,
          provider, ollamaUrl, ollamaModel
        );
        return json(response);
      } catch (error) {
        console.error('Chat error:', error);
        return json({ success: false, error: 'Internal error' }, 500);
      }
    }

    // POST /briefs/generate
    if (path === '/briefs/generate' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const { provider, ollamaUrl, ollamaModel } = body || {};
        const response = await generateThreatBrief(provider, ollamaUrl, ollamaModel);
        return json(response);
      } catch (error) {
        console.error('Brief generation error:', error);
        return json({ success: false, error: 'Internal error' }, 500);
      }
    }

    // GET /briefs
    if (path === '/briefs' && req.method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '10');
      return json(getBriefs(limit));
    }

    // GET /briefs/:id
    if (path.startsWith('/briefs/') && req.method === 'GET') {
      const id = parseInt(path.split('/')[2]);
      if (isNaN(id)) return json({ error: 'Invalid ID' }, 400);
      const brief = getBriefById(id);
      if (!brief) return json({ error: 'Not found' }, 404);
      return json(brief);
    }

    // GET /settings/ollama-models
    if (path === '/settings/ollama-models' && req.method === 'GET') {
      const ollamaUrl = url.searchParams.get('ollamaUrl') || 'http://localhost:11434';
      const models = await getOllamaModels(ollamaUrl);
      return json({ models });
    }

    // POST /api/mock-webhook/slack
    if (path === '/api/mock-webhook/slack' && req.method === 'POST') {
      try {
        const body = await req.json();
        console.log('\n[MOCK SLACK WEBHOOK RECEIVED]');
        console.log(JSON.stringify(body, null, 2));
        console.log('-------------------------------\n');
        return json({ success: true, receiver: 'slack' });
      } catch (err) {
        return json({ success: false, error: 'Invalid body' }, 400);
      }
    }

    // POST /api/mock-webhook/teams
    if (path === '/api/mock-webhook/teams' && req.method === 'POST') {
      try {
        const body = await req.json();
        console.log('\n[MOCK TEAMS WEBHOOK RECEIVED]');
        console.log(JSON.stringify(body, null, 2));
        console.log('-------------------------------\n');
        return json({ success: true, receiver: 'teams' });
      } catch (err) {
        return json({ success: false, error: 'Invalid body' }, 400);
      }
    }

    // POST /api/mock-webhook/generic
    if (path === '/api/mock-webhook/generic' && req.method === 'POST') {
      try {
        const body = await req.json();
        console.log('\n[MOCK GENERIC WEBHOOK RECEIVED]');
        console.log(JSON.stringify(body, null, 2));
        console.log('-------------------------------\n');
        return json({ success: true, receiver: 'generic' });
      } catch (err) {
        return json({ success: false, error: 'Invalid body' }, 400);
      }
    }

    // Default
    return new Response('Aegis Threat Intelligence Server', {
      headers: { ...requestCorsHeaders, 'Content-Type': 'text/plain' },
    });
  },
});

console.log(`Aegis Threat Intel Server running on http://localhost:${server.port}`);
console.log(`Health check: http://localhost:${server.port}/health`);
console.log(`Feeds: ${getFeeds().length} configured`);
