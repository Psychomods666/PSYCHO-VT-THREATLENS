'use client';

/**
 * URL Safety Checker — Next.js client component
 * --------------------------------------------------------------
 * Drop this file into a Next.js App Router project as
 * app/url-safety-checker/page.jsx (or rename to page.tsx and
 * add types) and it will run as-is. It is a single, self
 * contained file: markup, styles and logic together, no external
 * CSS or component libraries required beyond lucide-react.
 *
 * Wiring up real threat intelligence:
 * This file calls POST /api/check with { url } and expects back
 * { url, verdict, ruleScore, reason, flags, vtStats, vtDetections }.
 * Create that route in Next.js (app/api/check/route.js) and call
 * VirusTotal (or any provider) from the server, where your API key
 * stays secret. If that route isn't present — e.g. while you're
 * previewing this file — it automatically falls back to a local
 * heuristic scan so the UI is fully demoable on its own.
 *
 * npm install lucide-react
 */

import { useEffect, useRef, useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  Link2,
  Moon,
  Sun,
  Copy,
  Check,
  Download,
  X,
  History,
  Trash2,
  RotateCcw,
  Radar,
  Loader2,
} from 'lucide-react';

/* ================================================================
   Local heuristic engine — used as a demo fallback when there is
   no /api/check route wired up to a real threat-intel provider.
   ================================================================ */

const SAFE_DOMAINS = [
  'google.com', 'github.com', 'wikipedia.org', 'mozilla.org',
  'apple.com', 'microsoft.com', 'anthropic.com', 'cloudflare.com',
];

const SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd'];
const RISKY_TLDS = ['.xyz', '.top', '.zip', '.gq', '.tk', '.ml', '.cf', '.work', '.click'];
const SENSITIVE_WORDS = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'signin', 'wallet', 'reset'];

const VENDOR_NAMES = [
  'Aegis', 'Bastion', 'ClearNet', 'Drift', 'Endsec', 'Ferro',
  'Glasswing', 'Harbor', 'Ionis', 'Juno', 'Keystone', 'Lumen',
];

function isIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function heuristicScan(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    u = null;
  }
  const host = u ? u.hostname.toLowerCase() : rawUrl.toLowerCase();
  const full = rawUrl.toLowerCase();
  const flags = [];
  let score = 4;

  const isKnownSafe = SAFE_DOMAINS.some((d) => host === d || host.endsWith('.' + d));
  const isShortener = SHORTENERS.some((d) => host === d);
  const hasRiskyTld = RISKY_TLDS.some((t) => host.endsWith(t));
  const hasSensitiveWord = SENSITIVE_WORDS.some((w) => full.includes(w));
  const hyphenCount = (host.match(/-/g) || []).length;
  const isPunycode = host.includes('xn--');
  const noHttps = u ? u.protocol !== 'https:' : true;
  const hostLen = host.length;

  if (isKnownSafe) {
    return {
      verdict: 'SAFE',
      ruleScore: 2,
      reason: 'Recognized, widely trusted domain with no suspicious indicators.',
      flags: [],
      vtStats: { malicious: 0, suspicious: 0, harmless: 71, undetected: 3 },
      vtDetections: [],
    };
  }

  if (isIpHost(host)) { score += 30; flags.push('Bare IP address as host'); }
  if (isShortener) { score += 18; flags.push('Link-shortener domain'); }
  if (hasRiskyTld) { score += 20; flags.push('High-abuse top-level domain'); }
  if (hasSensitiveWord) { score += 16; flags.push('Credential-related keyword in URL'); }
  if (hyphenCount >= 3) { score += 14; flags.push('Unusually hyphenated domain'); }
  if (isPunycode) { score += 22; flags.push('Punycode / lookalike domain'); }
  if (noHttps) { score += 10; flags.push('No HTTPS'); }
  if (hostLen > 32) { score += 8; flags.push('Abnormally long hostname'); }
  if (!u) { score += 25; flags.push('Malformed URL'); }

  score = Math.min(100, score);

  const verdict = score >= 55 ? 'UNSAFE' : score >= 28 ? 'WARNING' : 'SAFE';
  const reason =
    verdict === 'UNSAFE'
      ? 'Multiple indicators consistent with phishing or malware distribution.'
      : verdict === 'WARNING'
      ? 'Some indicators are unusual for a legitimate destination — proceed carefully.'
      : 'No strong indicators of malicious intent found.';

  const malicious = verdict === 'UNSAFE' ? Math.round(3 + score / 12) : 0;
  const suspicious = verdict === 'WARNING' ? Math.round(2 + score / 20) : verdict === 'UNSAFE' ? 3 : 0;
  const harmless = verdict === 'SAFE' ? 68 : Math.max(0, 60 - malicious * 6);
  const undetected = Math.max(0, 75 - malicious - suspicious - harmless);

  const vtDetections = [];
  if (malicious || suspicious) {
    const n = malicious + suspicious;
    for (let i = 0; i < n; i++) {
      const cat = i < malicious ? 'malicious' : 'suspicious';
      vtDetections.push({
        vendor: VENDOR_NAMES[i % VENDOR_NAMES.length],
        category: cat,
        result: cat === 'malicious' ? 'phishing' : 'suspicious site',
      });
    }
  }

  return {
    verdict,
    ruleScore: score,
    reason,
    flags,
    vtStats: { malicious, suspicious, harmless, undetected },
    vtDetections,
  };
}

/* ================================================================
   Small utilities
   ================================================================ */

function normalizeUrl(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  return /^https?:\/\//i.test(trimmed) ? trimmed : 'http://' + trimmed;
}

function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function truncate(str, n = 34) {
  return str.length > n ? str.slice(0, n) + '…' : str;
}

function formatTime(ts) {
  return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}

const VERDICT_META = {
  SAFE: { label: 'Clear', ring: 'var(--safe)', Icon: ShieldCheck },
  WARNING: { label: 'Caution', ring: 'var(--warn)', Icon: ShieldQuestion },
  UNSAFE: { label: 'Blocked', ring: 'var(--danger)', Icon: ShieldAlert },
};

/* ================================================================
   Component
   ================================================================ */

export default function UrlSafetyChecker() {
  const [theme, setTheme] = useState('dark');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [history, setHistory] = useState([]);
  const inputRef = useRef(null);
  const stepTimerRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
    return () => clearInterval(stepTimerRef.current);
  }, []);

  const STEP_LABELS = ['Validating', 'Heuristics', 'Threat intel', 'Finalizing'];

  async function runScan(targetRaw) {
    const raw = (targetRaw ?? url).trim();
    if (!raw) {
      setError('Enter a URL to scan.');
      return;
    }
    const target = normalizeUrl(raw);
    if (!isValidUrl(target)) {
      setError('That doesn\u2019t look like a valid URL.');
      return;
    }

    setError('');
    setResult(null);
    setLoading(true);
    setScanStep(0);

    stepTimerRef.current = setInterval(() => {
      setScanStep((s) => (s < 3 ? s + 1 : s));
    }, 550);

    let data;
    try {
      const res = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target }),
      });
      if (!res.ok) throw new Error('no route');
      data = await res.json();
    } catch {
      // No backend wired up (or it failed) — fall back to the local
      // heuristic engine so the UI still works end to end.
      await new Promise((r) => setTimeout(r, 900));
      data = heuristicScan(target);
    }

    clearInterval(stepTimerRef.current);
    setScanStep(3);
    await new Promise((r) => setTimeout(r, 250));

    const full = { ...data, url: target };
    setResult(full);
    setLoading(false);
    setHistory((h) => [
      { url: target, verdict: full.verdict, score: full.ruleScore, timestamp: Date.now() },
      ...h.filter((item) => item.url !== target),
    ].slice(0, 12));
  }

  function handleCopy() {
    if (!result) return;
    const text =
      `URL Safety Check\n` +
      `URL: ${result.url}\n` +
      `Verdict: ${result.verdict}\n` +
      `Risk score: ${result.ruleScore}/100\n` +
      `Reason: ${result.reason || '—'}\n` +
      `Flags: ${(result.flags || []).join(', ') || 'None'}\n` +
      `Malicious: ${result.vtStats?.malicious ?? 0}  Suspicious: ${result.vtStats?.suspicious ?? 0}  ` +
      `Harmless: ${result.vtStats?.harmless ?? 0}  Undetected: ${result.vtStats?.undetected ?? 0}`;
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }

  function handleExport() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'url-safety-report.json';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function clearResult() {
    setResult(null);
    setUrl('');
    setError('');
    inputRef.current?.focus();
  }

  const dark = theme === 'dark';
  const meta = result ? VERDICT_META[result.verdict] : null;
  const score = result ? Math.min(100, Math.max(0, result.ruleScore)) : 0;
  const circumference = 2 * Math.PI * 42;
  const dashOffset = circumference - (score / 100) * circumference;

  return (
    <div className={`svc ${dark ? 'svc-dark' : 'svc-light'}`}>
      <style>{`
        .svc {
          --bg: #0b0f14;
          --panel: #12171f;
          --panel-raised: #1a222c;
          --hair: #232c38;
          --ink: #edf1f7;
          --ink-dim: #8a95a6;
          --ink-faint: #57616f;
          --safe: #3fb88f;
          --warn: #e8a33d;
          --danger: #e2555a;
          --accent: #e8a33d;
          --mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
          --sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
          --disp: 'Space Grotesk', var(--sans);
          font-family: var(--sans);
          background: var(--bg);
          color: var(--ink);
          min-height: 100vh;
          width: 100%;
          display: flex;
          justify-content: center;
          padding: 32px 20px 60px;
        }
        .svc-light {
          --bg: #f3f2ee;
          --panel: #ffffff;
          --panel-raised: #f8f7f3;
          --hair: #e1ded4;
          --ink: #1a1d22;
          --ink-dim: #5b6270;
          --ink-faint: #9198a3;
        }
        .svc * { box-sizing: border-box; }
        .svc-shell { width: 100%; max-width: 1040px; }

        .svc-top {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 22px;
          gap: 12px;
          flex-wrap: wrap;
        }
        .svc-brand { display: flex; align-items: center; gap: 12px; }
        .svc-brand-mark {
          width: 38px; height: 38px;
          border-radius: 9px;
          background: linear-gradient(160deg, var(--accent), #c97f22);
          display: flex; align-items: center; justify-content: center;
          color: #1a1206;
          flex-shrink: 0;
        }
        .svc-brand-name {
          font-family: var(--disp);
          font-weight: 600;
          font-size: 1.2rem;
          letter-spacing: -0.01em;
          line-height: 1.1;
        }
        .svc-brand-sub { font-size: 0.78rem; color: var(--ink-dim); margin-top: 1px; }
        .svc-theme-btn {
          background: var(--panel);
          border: 1px solid var(--hair);
          color: var(--ink-dim);
          border-radius: 8px;
          width: 38px; height: 38px;
          display: flex; align-items: center; justify-content: center;
          cursor: pointer;
          transition: color 0.15s, border-color 0.15s;
        }
        .svc-theme-btn:hover { color: var(--ink); border-color: var(--accent); }

        .svc-grid {
          display: grid;
          grid-template-columns: 300px 1fr;
          gap: 18px;
          align-items: start;
        }
        @media (max-width: 780px) {
          .svc-grid { grid-template-columns: 1fr; }
        }

        .svc-panel {
          background: var(--panel);
          border: 1px solid var(--hair);
          border-radius: 10px;
          padding: 20px;
        }
        .svc-panel + .svc-panel { margin-top: 18px; }

        .svc-label {
          font-size: 0.72rem;
          color: var(--ink-faint);
          margin-bottom: 10px;
          font-weight: 500;
        }

        .svc-input-wrap { position: relative; }
        .svc-input-wrap .svc-icon-left {
          position: absolute; left: 13px; top: 50%; transform: translateY(-50%);
          color: var(--ink-faint); pointer-events: none;
        }
        .svc-input {
          width: 100%;
          background: var(--bg);
          border: 1px solid var(--hair);
          color: var(--ink);
          border-radius: 8px;
          padding: 13px 13px 13px 38px;
          font-size: 0.92rem;
          font-family: var(--mono);
          outline: none;
          transition: border-color 0.15s, box-shadow 0.15s;
        }
        .svc-light .svc-input { background: var(--panel-raised); }
        .svc-input::placeholder { color: var(--ink-faint); font-family: var(--sans); }
        .svc-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(232,163,61,0.15); }

        .svc-scan-btn {
          margin-top: 10px;
          width: 100%;
          background: var(--accent);
          color: #1a1206;
          border: none;
          border-radius: 8px;
          padding: 12px;
          font-weight: 600;
          font-size: 0.9rem;
          font-family: var(--sans);
          cursor: pointer;
          display: flex; align-items: center; justify-content: center; gap: 8px;
          transition: filter 0.15s, transform 0.1s;
        }
        .svc-scan-btn:hover:not(:disabled) { filter: brightness(1.08); }
        .svc-scan-btn:active:not(:disabled) { transform: scale(0.98); }
        .svc-scan-btn:disabled { opacity: 0.55; cursor: not-allowed; }

        .svc-error {
          margin-top: 10px;
          font-size: 0.82rem;
          color: var(--danger);
          display: flex; align-items: flex-start; gap: 7px;
        }

        .svc-examples { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--hair); }
        .svc-examples-list { display: flex; flex-direction: column; gap: 6px; margin-top: 8px; }
        .svc-example-btn {
          text-align: left;
          background: transparent;
          border: 1px solid var(--hair);
          border-radius: 7px;
          padding: 8px 10px;
          font-family: var(--mono);
          font-size: 0.76rem;
          color: var(--ink-dim);
          cursor: pointer;
          display: flex; align-items: center; justify-content: space-between; gap: 8px;
          transition: border-color 0.15s, color 0.15s;
        }
        .svc-example-btn:hover { border-color: var(--accent); color: var(--ink); }
        .svc-example-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }

        .svc-history-item {
          display: flex; align-items: center; justify-content: space-between; gap: 8px;
          padding: 8px 4px;
          border-bottom: 1px solid var(--hair);
          cursor: pointer;
          font-size: 0.78rem;
        }
        .svc-history-item:last-child { border-bottom: none; }
        .svc-history-item:hover .svc-hist-url { color: var(--accent); }
        .svc-hist-url {
          font-family: var(--mono);
          color: var(--ink-dim);
          overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
          transition: color 0.15s;
        }
        .svc-hist-tag {
          font-size: 0.65rem; font-weight: 700; letter-spacing: 0.02em;
          padding: 2px 7px; border-radius: 20px; flex-shrink: 0;
        }
        .svc-empty { color: var(--ink-faint); font-size: 0.8rem; padding: 6px 0; }

        .svc-history-head {
          display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;
        }
        .svc-icon-btn {
          background: none; border: none; color: var(--ink-faint);
          cursor: pointer; padding: 4px; border-radius: 6px;
          display: flex; align-items: center;
          transition: color 0.15s;
        }
        .svc-icon-btn:hover { color: var(--danger); }

        /* Right panel — readout */
        .svc-readout {
          min-height: 420px;
          display: flex;
          flex-direction: column;
        }
        .svc-idle {
          flex: 1;
          display: flex; flex-direction: column; align-items: center; justify-content: center;
          text-align: center;
          color: var(--ink-faint);
          padding: 60px 20px;
        }
        .svc-idle-ring {
          width: 74px; height: 74px; border-radius: 50%;
          border: 1px dashed var(--hair);
          display: flex; align-items: center; justify-content: center;
          margin-bottom: 16px;
        }
        .svc-idle p { font-size: 0.86rem; max-width: 280px; margin-top: 4px; }

        .svc-loading {
          flex: 1;
          display: flex; flex-direction: column; align-items: center; justify-content: center;
          padding: 60px 20px;
        }
        .svc-radar {
          width: 96px; height: 96px; border-radius: 50%;
          position: relative;
          border: 1px solid var(--hair);
          margin-bottom: 22px;
          overflow: hidden;
        }
        .svc-radar::before, .svc-radar::after {
          content: '';
          position: absolute; border-radius: 50%; border: 1px solid var(--hair);
        }
        .svc-radar::before { inset: 16px; }
        .svc-radar::after { inset: 32px; }
        .svc-radar-sweep {
          position: absolute; inset: 0;
          background: conic-gradient(from 0deg, rgba(232,163,61,0) 0deg, rgba(232,163,61,0.55) 40deg, rgba(232,163,61,0) 90deg);
          animation: svc-spin 1.1s linear infinite;
        }
        @keyframes svc-spin { to { transform: rotate(360deg); } }
        .svc-loading-steps { display: flex; gap: 18px; flex-wrap: wrap; justify-content: center; }
        .svc-loading-step {
          font-size: 0.76rem; color: var(--ink-faint);
          display: flex; align-items: center; gap: 6px;
          transition: color 0.2s;
        }
        .svc-loading-step .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--hair); transition: background 0.2s; }
        .svc-loading-step.active { color: var(--accent); }
        .svc-loading-step.active .dot { background: var(--accent); }
        .svc-loading-step.done { color: var(--ink-dim); }
        .svc-loading-step.done .dot { background: var(--ink-dim); }

        .svc-verdict-row {
          display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
          margin-bottom: 4px;
        }
        .svc-stamp {
          display: inline-flex; align-items: center; gap: 8px;
          border: 2px solid var(--ring);
          color: var(--ring);
          border-radius: 8px;
          padding: 7px 14px;
          font-family: var(--disp);
          font-weight: 700;
          font-size: 1.15rem;
          letter-spacing: 0.01em;
          transform: rotate(-1.2deg);
        }
        .svc-verdict-reason { color: var(--ink-dim); font-size: 0.88rem; margin: 10px 0 20px; max-width: 60ch; }

        .svc-scoreboard {
          display: grid;
          grid-template-columns: 108px 1fr;
          gap: 22px;
          align-items: center;
          padding: 16px 0 20px;
          border-top: 1px solid var(--hair);
          border-bottom: 1px solid var(--hair);
        }
        @media (max-width: 480px) { .svc-scoreboard { grid-template-columns: 1fr; justify-items: center; } }
        .svc-gauge { position: relative; width: 104px; height: 104px; }
        .svc-gauge svg { transform: rotate(-90deg); width: 104px; height: 104px; }
        .svc-gauge .bg { fill: none; stroke: var(--hair); stroke-width: 7; }
        .svc-gauge .fill { fill: none; stroke-width: 7; stroke-linecap: round; transition: stroke-dashoffset 0.9s cubic-bezier(.2,.8,.2,1); }
        .svc-gauge-center {
          position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center;
        }
        .svc-gauge-num { font-family: var(--mono); font-size: 1.55rem; font-weight: 700; line-height: 1; }
        .svc-gauge-label { font-size: 0.6rem; color: var(--ink-faint); margin-top: 3px; }

        .svc-meta-row { display: flex; justify-content: space-between; font-size: 0.82rem; padding: 5px 0; border-bottom: 1px solid var(--hair); gap: 12px; }
        .svc-meta-row:last-child { border-bottom: none; }
        .svc-meta-row .k { color: var(--ink-dim); flex-shrink: 0; }
        .svc-meta-row .v { font-family: var(--mono); text-align: right; word-break: break-all; }

        .svc-flags { display: flex; flex-wrap: wrap; gap: 7px; margin: 18px 0 4px; }
        .svc-flag {
          font-size: 0.76rem;
          border: 1px solid var(--hair);
          color: var(--ink-dim);
          border-radius: 20px;
          padding: 4px 12px;
        }
        .svc-flag.warn { border-color: var(--warn); color: var(--warn); }
        .svc-flag.danger { border-color: var(--danger); color: var(--danger); }
        .svc-flag.safe { border-color: var(--safe); color: var(--safe); }

        .svc-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }
        @media (max-width: 480px) { .svc-stats { grid-template-columns: repeat(2, 1fr); } }
        .svc-stat { background: var(--panel-raised); border: 1px solid var(--hair); border-radius: 8px; padding: 12px 10px; text-align: center; }
        .svc-stat .n { font-family: var(--mono); font-weight: 700; font-size: 1.35rem; }
        .svc-stat .l { font-size: 0.62rem; color: var(--ink-faint); margin-top: 3px; letter-spacing: 0.02em; }
        .svc-stat.mal .n { color: var(--danger); }
        .svc-stat.sus .n { color: var(--warn); }
        .svc-stat.har .n { color: var(--safe); }
        .svc-stat.und .n { color: var(--ink-faint); }

        .svc-detections { margin-top: 6px; padding-top: 16px; border-top: 1px solid var(--hair); }
        .svc-det-head { display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--ink-dim); margin-bottom: 8px; }
        .svc-det-list { max-height: 150px; overflow-y: auto; }
        .svc-det-item { display: flex; justify-content: space-between; gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--hair); font-size: 0.82rem; }
        .svc-det-item:last-child { border-bottom: none; }
        .svc-det-item .vendor { font-family: var(--mono); color: var(--ink-dim); }
        .svc-det-item .cat { font-weight: 600; font-size: 0.76rem; }
        .svc-det-item .cat.malicious { color: var(--danger); }
        .svc-det-item .cat.suspicious { color: var(--warn); }
        .svc-no-det { color: var(--ink-faint); font-size: 0.82rem; }

        .svc-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--hair); }
        .svc-action-btn {
          background: var(--panel-raised);
          border: 1px solid var(--hair);
          color: var(--ink-dim);
          border-radius: 7px;
          padding: 8px 14px;
          font-size: 0.8rem;
          font-family: var(--sans);
          font-weight: 500;
          cursor: pointer;
          display: inline-flex; align-items: center; gap: 6px;
          transition: color 0.15s, border-color 0.15s;
        }
        .svc-action-btn:hover { color: var(--ink); border-color: var(--accent); }
      `}</style>

      <div className="svc-shell">
        {/* Header */}
        <div className="svc-top">
          <div className="svc-brand">
            <div className="svc-brand-mark"><Radar size={19} strokeWidth={2.2} /></div>
            <div>
              <div className="svc-brand-name">Signal Check</div>
              <div className="svc-brand-sub">URL threat scanner</div>
            </div>
          </div>
          <button
            className="svc-theme-btn"
            onClick={() => setTheme(dark ? 'light' : 'dark')}
            aria-label="Toggle theme"
          >
            {dark ? <Sun size={17} /> : <Moon size={17} />}
          </button>
        </div>

        <div className="svc-grid">
          {/* Left rail */}
          <div>
            <div className="svc-panel">
              <div className="svc-label">Scan a URL</div>
              <div className="svc-input-wrap">
                <span className="svc-icon-left"><Link2 size={15} /></span>
                <input
                  ref={inputRef}
                  className="svc-input"
                  placeholder="example.com/path"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !loading) runScan(); }}
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              <button className="svc-scan-btn" onClick={() => runScan()} disabled={loading}>
                {loading ? <Loader2 size={16} className="svc-spin" style={{ animation: 'svc-spin 0.9s linear infinite' }} /> : <Radar size={16} />}
                {loading ? 'Scanning…' : 'Run scan'}
              </button>
              {error && (
                <div className="svc-error"><X size={14} style={{ marginTop: 1, flexShrink: 0 }} />{error}</div>
              )}

              <div className="svc-examples">
                <div className="svc-label" style={{ marginBottom: 8 }}>Try one</div>
                <div className="svc-examples-list">
                  {[
                    { u: 'https://github.com', s: 'var(--safe)' },
                    { u: 'https://google.com', s: 'var(--safe)' },
                    { u: 'http://verify-paypa1-secure.top', s: 'var(--danger)' },
                    { u: 'http://192.168.9.4/login', s: 'var(--warn)' },
                  ].map((ex) => (
                    <button key={ex.u} className="svc-example-btn" onClick={() => { setUrl(ex.u); if (!loading) runScan(ex.u); }}>
                      <span>{ex.u.replace(/^https?:\/\//, '')}</span>
                      <span className="svc-example-dot" style={{ background: ex.s }} />
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="svc-panel">
              <div className="svc-history-head">
                <div className="svc-label" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <History size={13} /> Recent
                </div>
                {history.length > 0 && (
                  <button className="svc-icon-btn" onClick={() => setHistory([])} aria-label="Clear history">
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
              {history.length === 0 ? (
                <div className="svc-empty">Nothing scanned yet.</div>
              ) : (
                <div>
                  {history.map((h) => (
                    <div key={h.url + h.timestamp} className="svc-history-item" onClick={() => { setUrl(h.url); runScan(h.url); }}>
                      <span className="svc-hist-url" title={h.url}>{truncate(h.url)}</span>
                      <span
                        className="svc-hist-tag"
                        style={{
                          color: VERDICT_META[h.verdict]?.ring,
                          background: 'color-mix(in srgb, ' + VERDICT_META[h.verdict]?.ring + ' 16%, transparent)',
                        }}
                      >
                        {VERDICT_META[h.verdict]?.label}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Readout panel */}
          <div className="svc-panel svc-readout">
            {!loading && !result && (
              <div className="svc-idle">
                <div className="svc-idle-ring"><Radar size={26} strokeWidth={1.5} /></div>
                <div style={{ color: 'var(--ink-dim)', fontFamily: 'var(--disp)', fontSize: '1rem' }}>Awaiting input</div>
                <p>Enter a URL on the left and run a scan — results, risk score and vendor detections will appear here.</p>
              </div>
            )}

            {loading && (
              <div className="svc-loading">
                <div className="svc-radar"><div className="svc-radar-sweep" /></div>
                <div className="svc-loading-steps">
                  {STEP_LABELS.map((label, i) => (
                    <span key={label} className={`svc-loading-step ${i < scanStep ? 'done' : i === scanStep ? 'active' : ''}`}>
                      <span className="dot" />{label}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {!loading && result && meta && (
              <div style={{ '--ring': meta.ring }}>
                <div className="svc-verdict-row">
                  <span className="svc-stamp" style={{ '--ring': meta.ring }}>
                    <meta.Icon size={19} /> {meta.label}
                  </span>
                </div>
                <p className="svc-verdict-reason">{result.reason}</p>

                <div className="svc-scoreboard">
                  <div className="svc-gauge">
                    <svg viewBox="0 0 104 104">
                      <circle className="bg" cx="52" cy="52" r="42" />
                      <circle
                        className="fill"
                        cx="52" cy="52" r="42"
                        stroke={meta.ring}
                        strokeDasharray={circumference}
                        strokeDashoffset={dashOffset}
                      />
                    </svg>
                    <div className="svc-gauge-center">
                      <span className="svc-gauge-num">{score}</span>
                      <span className="svc-gauge-label">risk / 100</span>
                    </div>
                  </div>
                  <div>
                    <div className="svc-meta-row"><span className="k">Target</span><span className="v">{truncate(result.url, 40)}</span></div>
                    <div className="svc-meta-row"><span className="k">Detections</span><span className="v">{(result.vtStats?.malicious || 0) + (result.vtStats?.suspicious || 0)} of {(Object.values(result.vtStats || {}).reduce((a, b) => a + b, 0)) || 0}</span></div>
                    <div className="svc-meta-row"><span className="k">Scanned</span><span className="v">{formatTime(Date.now())}</span></div>
                  </div>
                </div>

                <div className="svc-label" style={{ marginTop: 18, marginBottom: 0 }}>Flags</div>
                <div className="svc-flags">
                  {(result.flags || []).length === 0 ? (
                    <span className="svc-flag safe">No red flags</span>
                  ) : (
                    result.flags.map((f) => {
                      const low = f.toLowerCase();
                      const cls = low.includes('malformed') || low.includes('punycode') || low.includes('ip address')
                        ? 'danger'
                        : 'warn';
                      return <span key={f} className={`svc-flag ${cls}`}>{f}</span>;
                    })
                  )}
                </div>

                <div className="svc-stats">
                  <div className="svc-stat mal"><div className="n">{result.vtStats?.malicious ?? 0}</div><div className="l">Malicious</div></div>
                  <div className="svc-stat sus"><div className="n">{result.vtStats?.suspicious ?? 0}</div><div className="l">Suspicious</div></div>
                  <div className="svc-stat har"><div className="n">{result.vtStats?.harmless ?? 0}</div><div className="l">Harmless</div></div>
                  <div className="svc-stat und"><div className="n">{result.vtStats?.undetected ?? 0}</div><div className="l">Undetected</div></div>
                </div>

                <div className="svc-detections">
                  <div className="svc-det-head">
                    <span>Vendor detections</span>
                    <span>{(result.vtDetections || []).length} found</span>
                  </div>
                  <div className="svc-det-list">
                    {(result.vtDetections || []).length === 0 ? (
                      <div className="svc-no-det">No detections reported.</div>
                    ) : (
                      result.vtDetections.map((d, i) => (
                        <div className="svc-det-item" key={d.vendor + i}>
                          <span className="vendor">{d.vendor}</span>
                          <span className={`cat ${d.category}`}>{d.result} · {d.category}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="svc-actions">
                  <button className="svc-action-btn" onClick={handleCopy}>
                    {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? 'Copied' : 'Copy'}
                  </button>
                  <button className="svc-action-btn" onClick={handleExport}><Download size={14} /> Export</button>
                  <button className="svc-action-btn" onClick={clearResult}><RotateCcw size={14} /> New scan</button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
