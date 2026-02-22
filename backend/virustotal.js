/**
 * virustotal.js
 * ─────────────────────────────────────────────────────────────
 * All VirusTotal API interactions live here.
 * The server.js never touches the API directly.
 * ─────────────────────────────────────────────────────────────
 */

const VT_BASE = 'https://www.virustotal.com/api/v3';
const POLL_INTERVAL_MS = 2500;
const MAX_POLLS = 15;

function getKey() {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) throw apiError('VIRUSTOTAL_API_KEY is not set in environment.', 500);
  return key;
}

function apiError(message, statusCode = 502) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function headers() {
  return { 'x-apikey': getKey(), 'Accept': 'application/json' };
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

/** Convert a URL string to VirusTotal's base64url ID */
function urlToVTId(url) {
  return Buffer.from(url).toString('base64url');
}

// ── Submit & Poll ───────────────────────────────────────────

async function submitURL(url) {
  const body = new URLSearchParams({ url });
  const res = await fetch(`${VT_BASE}/urls`, {
    method: 'POST',
    headers: { ...headers(), 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    if (res.status === 401) throw apiError('Invalid VirusTotal API key.', 401);
    if (res.status === 429) throw apiError('VirusTotal rate limit exceeded. Try again in a minute.', 429);
    throw apiError(data?.error?.message || `VirusTotal submit failed (${res.status})`, res.status);
  }

  const data = await res.json();
  return data?.data?.id;
}

async function pollAnalysis(analysisId) {
  for (let i = 0; i < MAX_POLLS; i++) {
    await sleep(POLL_INTERVAL_MS);

    const res = await fetch(`${VT_BASE}/analyses/${analysisId}`, { headers: headers() });
    if (!res.ok) throw apiError(`Analysis poll failed (${res.status})`);

    const data = await res.json();
    const status = data?.data?.attributes?.status;

    if (status === 'completed') return data;
    if (i === MAX_POLLS - 1) return data; // return partial if timeout
  }
}

async function fetchURLReport(url) {
  const id = urlToVTId(url);
  const res = await fetch(`${VT_BASE}/urls/${id}`, { headers: headers() });
  if (!res.ok) return null;
  return res.json();
}

// ── Build Unified Report ────────────────────────────────────

function buildReport(url, analysis, urlReport) {
  const attrs   = analysis?.data?.attributes || {};
  const stats   = attrs?.stats || {};
  const engines = attrs?.results || {};

  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const undetected = stats.undetected || 0;
  const harmless   = stats.harmless   || 0;
  const total      = malicious + suspicious + undetected + harmless || 1;
  const threatCount = malicious + suspicious;
  const threatPercent = Math.round((threatCount / total) * 100);

  // Verdict
  let verdict;
  if      (malicious >= 3)                      verdict = 'malicious';
  else if (malicious > 0 || suspicious >= 2)    verdict = 'suspicious';
  else if (threatCount === 0 && total > 1)       verdict = 'clean';
  else                                           verdict = 'unknown';

  // URL metadata from full report
  const ua = urlReport?.data?.attributes || {};

  // Engine breakdown
  const engineResults = Object.entries(engines).map(([name, d]) => ({
    engine: name,
    category: d.category || 'unrated',
    result: d.result || null,
    method: d.method || null,
  }));

  const threats = engineResults.filter(e =>
    e.category === 'malicious' || e.category === 'suspicious'
  );

  return {
    url,
    verdict,
    summary: verdictSummary(verdict, threatCount, total),
    stats: { malicious, suspicious, harmless, undetected, total },
    threat_percent: threatPercent,
    threat_count: threatCount,
    reputation: ua.reputation ?? null,
    categories: ua.categories ? Object.values(ua.categories) : [],
    metadata: {
      title: ua.title || null,
      final_url: ua.last_final_url || url,
      http_status: ua.last_http_response_code || null,
      content_type: ua.last_http_response_content_type || null,
      first_submitted: ua.first_submission_date
        ? new Date(ua.first_submission_date * 1000).toISOString()
        : null,
      last_analysed: ua.last_analysis_date
        ? new Date(ua.last_analysis_date * 1000).toISOString()
        : null,
    },
    threats_detected: threats,
    engine_count: engineResults.length,
    scanned_at: new Date().toISOString(),
  };
}

function verdictSummary(verdict, threatCount, total) {
  switch (verdict) {
    case 'clean':      return `No threats detected across ${total} security engines.`;
    case 'suspicious': return `${threatCount} engine(s) flagged this URL as suspicious. Proceed with caution.`;
    case 'malicious':  return `${threatCount} engine(s) identified this URL as malicious. Do not visit.`;
    default:           return 'Insufficient data to make a determination.';
  }
}

// ── Public API ──────────────────────────────────────────────

/**
 * scanURL(url) → full report object
 * Main function — submit, poll, enrich, return.
 */
export async function scanURL(url) {
  const analysisId = await submitURL(url);
  const [analysis, urlReport] = await Promise.allSettled([
    pollAnalysis(analysisId),
    fetchURLReport(url),
  ]);

  return buildReport(
    url,
    analysis.status === 'fulfilled' ? analysis.value : null,
    urlReport.status === 'fulfilled' ? urlReport.value : null,
  );
}

/**
 * getReport(url) → latest cached report (no new scan)
 */
export async function getReport(url) {
  const urlReport = await fetchURLReport(url);
  if (!urlReport) throw apiError('No existing report found for this URL. Use POST /api/scan first.', 404);

  const attrs  = urlReport?.data?.attributes || {};
  const stats  = attrs?.last_analysis_stats || {};
  // Build a minimal analysis-shaped object from the URL report
  const fakeAnalysis = {
    data: { attributes: { stats, results: attrs?.last_analysis_results || {} } }
  };
  return buildReport(url, fakeAnalysis, urlReport);
}
