/**
 * chatbot-integration.js
 * ─────────────────────────────────────────────────────────────
 * Drop-in module for integrating Nexus Scanner into any chatbot.
 *
 * Works with: Claude API, OpenAI, Dialogflow, Rasa, custom bots.
 *
 * Usage:
 *   import { scanForBot, formatBotReply } from './chatbot-integration.js';
 *
 *   const report = await scanForBot('https://suspicious-link.com');
 *   const reply  = formatBotReply(report);
 *   bot.sendMessage(reply);
 * ─────────────────────────────────────────────────────────────
 */

// ── Config ──────────────────────────────────────────────────
// Set NEXUS_API_URL in your chatbot's environment,
// or it defaults to localhost (local dev).
const NEXUS_API_URL = process.env.NEXUS_API_URL || 'http://localhost:3000';

// ── URL Extraction ───────────────────────────────────────────

const URL_REGEX = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;

/**
 * Extract all URLs from a message string.
 * @param {string} message
 * @returns {string[]}
 */
export function extractURLs(message) {
  return [...(message.match(URL_REGEX) || [])];
}

/**
 * Detect if a message is asking to check / scan a URL.
 * @param {string} message
 * @returns {boolean}
 */
export function isURLCheckRequest(message) {
  const lower = message.toLowerCase();
  const triggerWords = [
    'check', 'scan', 'safe', 'legit', 'legitimate', 'trust',
    'phishing', 'malware', 'virus', 'dangerous', 'suspicious',
    'analyse', 'analyze', 'verify', 'inspect', 'threat',
  ];
  const hasURL = URL_REGEX.test(message);
  URL_REGEX.lastIndex = 0; // reset global regex
  const hasTrigger = triggerWords.some(w => lower.includes(w));
  return hasURL && hasTrigger;
}

// ── API Call ─────────────────────────────────────────────────

/**
 * Scan a URL using the Nexus backend.
 * @param {string} url
 * @returns {Promise<NexusReport>}
 */
export async function scanForBot(url) {
  const res = await fetch(`${NEXUS_API_URL}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || `Nexus scan failed (${res.status})`);
  }

  return data;
}

// ── Reply Formatters ─────────────────────────────────────────

/**
 * Format a scan report as a plain-text chatbot reply.
 * @param {NexusReport} report
 * @returns {string}
 */
export function formatBotReply(report) {
  const emoji = {
    clean:      '✅',
    suspicious: '⚠️',
    malicious:  '🚨',
    unknown:    '❔',
  }[report.verdict] || '❔';

  const lines = [
    `${emoji} **${report.verdict.toUpperCase()}** — ${report.summary}`,
    ``,
    `🔗 URL: ${report.url}`,
    `🛡 Engines checked: ${report.stats.total}`,
    `⚡ Threats found: ${report.threat_count} (${report.threat_percent}%)`,
    `👍 Harmless: ${report.stats.harmless}  |  ❓ Undetected: ${report.stats.undetected}`,
  ];

  if (report.threat_count > 0) {
    lines.push('');
    lines.push('**Flagged by:**');
    report.threats_detected.slice(0, 5).forEach(t => {
      lines.push(`  • ${t.engine}: ${t.result || t.category}`);
    });
    if (report.threats_detected.length > 5) {
      lines.push(`  … and ${report.threats_detected.length - 5} more engines.`);
    }
  }

  if (report.metadata?.title) {
    lines.push('');
    lines.push(`📄 Page title: "${report.metadata.title}"`);
  }

  lines.push('');
  lines.push(`_Scanned at ${new Date(report.scanned_at).toUTCString()}_`);

  return lines.join('\n');
}

/**
 * Format a scan report as a structured JSON object
 * (for passing directly to an LLM as tool output).
 * @param {NexusReport} report
 * @returns {object}
 */
export function formatForLLM(report) {
  return {
    url: report.url,
    verdict: report.verdict,
    safe: report.verdict === 'clean',
    summary: report.summary,
    threat_count: report.threat_count,
    threat_percent: report.threat_percent,
    engines_checked: report.stats.total,
    top_threats: report.threats_detected.slice(0, 5).map(t => ({
      engine: t.engine,
      finding: t.result || t.category,
    })),
    reputation: report.reputation,
    categories: report.categories,
    scanned_at: report.scanned_at,
  };
}

/**
 * Format as a Slack Block Kit message (for Slack bots).
 * @param {NexusReport} report
 * @returns {object[]} Slack blocks array
 */
export function formatForSlack(report) {
  const colour = {
    clean: '#4ade80', suspicious: '#fb923c', malicious: '#f87171', unknown: '#6b7280',
  }[report.verdict] || '#6b7280';

  const emoji = {
    clean: ':white_check_mark:', suspicious: ':warning:', malicious: ':rotating_light:', unknown: ':grey_question:',
  }[report.verdict];

  return {
    attachments: [{
      color: colour,
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `${emoji} *${report.verdict.toUpperCase()}* — ${report.summary}`,
          },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*URL*\n${report.url}` },
            { type: 'mrkdwn', text: `*Threats*\n${report.threat_count} / ${report.stats.total} engines` },
            { type: 'mrkdwn', text: `*Threat Score*\n${report.threat_percent}%` },
            { type: 'mrkdwn', text: `*Reputation*\n${report.reputation ?? 'N/A'}` },
          ],
        },
        {
          type: 'context',
          elements: [{
            type: 'mrkdwn',
            text: `Scanned by Nexus · ${new Date(report.scanned_at).toUTCString()}`,
          }],
        },
      ],
    }],
  };
}

// ── High-level Handler ───────────────────────────────────────

/**
 * handleBotMessage(message)
 *
 * Pass in any incoming bot message.
 * If it contains a URL and seems to be asking about safety,
 * this scans all URLs and returns formatted replies.
 *
 * @param {string} message  - The user's raw message
 * @param {'text'|'llm'|'slack'} format - Output format
 * @returns {Promise<{handled: boolean, replies: string[]}>}
 */
export async function handleBotMessage(message, format = 'text') {
  if (!isURLCheckRequest(message)) {
    return { handled: false, replies: [] };
  }

  const urls = extractURLs(message);
  if (urls.length === 0) {
    return { handled: false, replies: [] };
  }

  const replies = [];

  for (const url of urls.slice(0, 3)) { // cap at 3 URLs per message
    try {
      const report = await scanForBot(url);
      switch (format) {
        case 'llm':   replies.push(JSON.stringify(formatForLLM(report))); break;
        case 'slack': replies.push(JSON.stringify(formatForSlack(report))); break;
        default:      replies.push(formatBotReply(report));
      }
    } catch (err) {
      replies.push(`❌ Could not scan ${url}: ${err.message}`);
    }
  }

  return { handled: true, replies };
}

// ── Claude Tool Definition ───────────────────────────────────
// Add this to your Anthropic API tools array to let Claude
// call the scanner autonomously.

export const CLAUDE_TOOL_DEFINITION = {
  name: 'scan_url',
  description: 'Scans a URL for malware, phishing, and other threats using VirusTotal. Returns a detailed threat intelligence report. Use this whenever a user asks if a link is safe, suspicious, or malicious.',
  input_schema: {
    type: 'object',
    properties: {
      url: {
        type: 'string',
        description: 'The full URL to scan, including the https:// scheme.',
      },
    },
    required: ['url'],
  },
};

/**
 * Handler for when Claude calls the scan_url tool.
 * @param {object} toolInput  - The input Claude passed to the tool
 * @returns {string}          - Tool result string (passed back to Claude)
 */
export async function handleClaudeToolCall(toolInput) {
  try {
    const report = await scanForBot(toolInput.url);
    return JSON.stringify(formatForLLM(report), null, 2);
  } catch (err) {
    return JSON.stringify({ error: err.message });
  }
}
