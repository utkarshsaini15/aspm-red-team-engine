import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  RadialLinearScale,
  PointElement,
  LineElement,
  BarElement,
  Filler,
  Title,
  Tooltip,
  Legend,
  ChartOptions,
} from 'chart.js';
import { Line, Bar, Radar } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  RadialLinearScale,
  PointElement,
  LineElement,
  BarElement,
  Filler,
  Title,
  Tooltip,
  Legend
);

const API = 'http://localhost:8000';

interface Metrics {
  vulnerability_score: number;
  scan_progress: number;
  response_time: number;
  success_rate: number;
  anomaly_count: number;
}

interface ScanRecord {
  job_id: string;
  target_model: string;
  completed_at: string;
  results?: {
    score: number;
    vulnerabilities?: Array<{ owasp_id: string; status: string }>;
  };
}

interface ModelStat {
  model: string;
  provider: string;
  color: string;
  avgScore: number;
  scanCount: number;
  scores: number[];
  owaspPass: Record<string, number>; // owasp_id -> pass rate 0-100
}

// Stable constants
const PHASES = ['initialization', 'scanning', 'analysis', 'reporting', 'completed'];
const OWASP_IDS = ['LLM01','LLM02','LLM03','LLM04','LLM05','LLM06','LLM07','LLM08','LLM09','LLM10'];
const PROVIDER_COLORS: Record<string, string> = {
  Gemini: '#3fb950',
  GPT: '#58a6ff',
  Claude: '#a371f7',
  Unknown: '#e3b341',
};

function detectProvider(model: string): string {
  const m = model.toLowerCase().replace(' [hardened]', '');
  if (m.includes('gemini')) return 'Gemini';
  if (m.includes('claude') || m.includes('anthropic')) return 'Claude';
  if (m.includes('gpt') || m.includes('openai')) return 'GPT';
  return 'Unknown';
}

function calcScore(vulns?: Array<{ status: string }>): number {
  if (!vulns?.length) return 0;
  return Math.round(vulns.filter(v => v.status === 'Passed').length / vulns.length * 100);
}

// ── Model Comparison Panel ────────────────────────────────────────────────────
const ModelComparisonPanel: React.FC = () => {
  const [history, setHistory] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'bar'|'radar'|'timeline'>('bar');

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/scans/history`);
      if (!res.ok) throw new Error(`HTTP ${res.status} — ${res.statusText}`);
      const data = await res.json();
      setHistory(Array.isArray(data) ? data : []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load history');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHistory();
    const id = setInterval(fetchHistory, 15000);
    return () => clearInterval(id);
  }, [fetchHistory]);

  // Build per-model stats
  const modelMap: Record<string, ModelStat> = {};
  history.forEach(h => {
    const provider = detectProvider(h.target_model);
    const key = provider; // group by provider
    if (!modelMap[key]) {
      modelMap[key] = {
        model: h.target_model,
        provider,
        color: PROVIDER_COLORS[provider] || '#8b949e',
        avgScore: 0,
        scanCount: 0,
        scores: [],
        owaspPass: Object.fromEntries(OWASP_IDS.map(id => [id, 0])),
      };
    }
    const score = calcScore(h.results?.vulnerabilities);
    modelMap[key].scores.push(score);
    modelMap[key].scanCount++;
    // Accumulate OWASP pass counts
    h.results?.vulnerabilities?.forEach(v => {
      if (v.status === 'Passed') {
        modelMap[key].owaspPass[v.owasp_id] = (modelMap[key].owaspPass[v.owasp_id] || 0) + 1;
      }
    });
  });

  // Compute averages
  const stats: ModelStat[] = Object.values(modelMap).map(s => ({
    ...s,
    avgScore: s.scores.length ? Math.round(s.scores.reduce((a, b) => a + b, 0) / s.scores.length) : 0,
    owaspPass: Object.fromEntries(
      OWASP_IDS.map(id => [id, s.scanCount ? Math.round((s.owaspPass[id] / s.scanCount) * 100) : 0])
    ),
  }));
  stats.sort((a, b) => b.avgScore - a.avgScore);

  // Timeline: all scans ordered by time
  const timelineLabels = [...history].reverse().map((h, i) => `#${i + 1}`);
  const timelineByProvider: Record<string, (number | null)[]> = {};
  const reversedHistory = [...history].reverse();
  reversedHistory.forEach((h, i) => {
    const provider = detectProvider(h.target_model);
    if (!timelineByProvider[provider]) {
      timelineByProvider[provider] = new Array(reversedHistory.length).fill(null);
    }
    timelineByProvider[provider][i] = calcScore(h.results?.vulnerabilities);
  });

  // ── Chart configs ──────────────────────────────────────────────────────────
  const barData = {
    labels: stats.map(s => s.provider),
    datasets: [{
      label: 'Avg Security Score',
      data: stats.map(s => s.avgScore),
      backgroundColor: stats.map(s => s.color + 'cc'),
      borderColor: stats.map(s => s.color),
      borderWidth: 2,
      borderRadius: 8,
    }],
  };

  const barOptions: ChartOptions<'bar'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          label: ctx => ` Score: ${ctx.raw}/100 (${stats[ctx.dataIndex]?.scanCount} scan${stats[ctx.dataIndex]?.scanCount !== 1 ? 's' : ''})`,
        },
      },
    },
    scales: {
      y: { beginAtZero: true, max: 100, grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#8b949e' } },
      x: { grid: { display: false }, ticks: { color: '#8b949e', font: { weight: 'bold' } } },
    },
    animation: { duration: 600 },
  };

  const radarData = {
    labels: OWASP_IDS,
    datasets: stats.map(s => ({
      label: s.provider,
      data: OWASP_IDS.map(id => s.owaspPass[id] ?? 0),
      borderColor: s.color,
      backgroundColor: s.color + '33',
      pointBackgroundColor: s.color,
      borderWidth: 2,
    })),
  };

  const radarOptions: ChartOptions<'radar'> = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      r: {
        min: 0, max: 100,
        ticks: { display: false },
        grid: { color: 'rgba(255,255,255,0.1)' },
        pointLabels: { color: '#8b949e', font: { size: 10 } },
      },
    },
    plugins: { legend: { labels: { color: '#8b949e', font: { size: 11 } } } },
  };

  const timelineData = {
    labels: timelineLabels,
    datasets: Object.entries(timelineByProvider).map(([provider, scores]) => ({
      label: provider,
      data: scores,
      borderColor: PROVIDER_COLORS[provider] || '#8b949e',
      backgroundColor: (PROVIDER_COLORS[provider] || '#8b949e') + '22',
      pointBackgroundColor: PROVIDER_COLORS[provider] || '#8b949e',
      borderWidth: 2.5,
      tension: 0.35,
      fill: false,
      spanGaps: false,
      pointRadius: 5,
    })),
  };

  const timelineOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: '#8b949e', font: { size: 11 } } },
      tooltip: { callbacks: { label: ctx => ` ${ctx.dataset.label}: ${ctx.raw}/100` } },
    },
    scales: {
      y: { min: 0, max: 100, grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#8b949e' } },
      x: { grid: { display: false }, ticks: { color: '#8b949e' } },
    },
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, color: '#8b949e', gap: 10 }}>
        <div style={{ width: 18, height: 18, border: '2px solid #30363d', borderTopColor: '#58a6ff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
        Loading model data...
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ textAlign: 'center', padding: '36px 0', color: '#8b949e' }}>
        <div style={{ fontSize: 32, marginBottom: 10 }}>⚠️</div>
        <div style={{ fontSize: '0.85rem', color: '#f85149', marginBottom: 6 }}>Could not load model data</div>
        <div style={{ fontSize: '0.72rem', marginBottom: 14 }}>{error}</div>
        <button onClick={fetchHistory} style={{
          padding: '6px 18px', borderRadius: 6, fontSize: '0.75rem', cursor: 'pointer',
          background: 'rgba(88,166,255,0.1)', color: '#58a6ff',
          border: '1px solid rgba(88,166,255,0.3)',
        }}>⟳ Retry</button>
      </div>
    );
  }

  if (!stats.length) {
    return (
      <div style={{ textAlign: 'center', padding: '48px 0', color: '#8b949e' }}>
        <div style={{ fontSize: 40, marginBottom: 12 }}>📊</div>
        <div style={{ fontSize: '1rem', fontWeight: 600, color: '#c9d1d9', marginBottom: 8 }}>No model data yet</div>
        <div style={{ fontSize: '0.82rem' }}>Run scans on GPT, Gemini, or Claude to see comparisons here.</div>
      </div>
    );
  }

  return (
    <div>
      {/* KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.min(stats.length, 4)}, 1fr)`, gap: 12, marginBottom: 20 }}>
        {stats.map((s, rank) => (
          <div key={s.provider} style={{
            padding: '16px 18px', borderRadius: 12,
            background: `${s.color}10`,
            border: `1px solid ${s.color}33`,
            position: 'relative', overflow: 'hidden',
          }}>
            {rank === 0 && (
              <div style={{ position: 'absolute', top: 8, right: 10, fontSize: '0.6rem', fontWeight: 700, color: s.color, letterSpacing: 1 }}>
                🏆 BEST
              </div>
            )}
            <div style={{ fontSize: '0.7rem', color: s.color, fontWeight: 700, letterSpacing: '0.05em', marginBottom: 4 }}>{s.provider}</div>
            <div style={{ fontSize: '2rem', fontWeight: 900, color: s.color, fontFamily: 'monospace', lineHeight: 1 }}>{s.avgScore}</div>
            <div style={{ fontSize: '0.65rem', color: '#8b949e', marginTop: 4 }}>/100 avg · {s.scanCount} scan{s.scanCount !== 1 ? 's' : ''}</div>
            {/* Mini score bar */}
            <div style={{ height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 2, marginTop: 8 }}>
              <div style={{ height: '100%', width: `${s.avgScore}%`, background: s.color, borderRadius: 2, transition: 'width 0.8s ease' }} />
            </div>
          </div>
        ))}
      </div>

      {/* Tab switcher */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {(['bar', 'radar', 'timeline'] as const).map(t => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            padding: '5px 14px', borderRadius: 6, fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer',
            background: activeTab === t ? '#58a6ff' : 'transparent',
            color: activeTab === t ? '#fff' : '#8b949e',
            border: `1px solid ${activeTab === t ? '#58a6ff' : '#30363d'}`,
            transition: 'all 0.2s',
          }}>
            {t === 'bar' ? '📊 Avg Score' : t === 'radar' ? '🕸 OWASP Radar' : '📈 Timeline'}
          </button>
        ))}
        <button onClick={fetchHistory} style={{
          marginLeft: 'auto', padding: '5px 12px', borderRadius: 6, fontSize: '0.72rem',
          background: 'transparent', color: '#8b949e', border: '1px solid #30363d', cursor: 'pointer',
        }}>⟳ Refresh</button>
      </div>

      {/* Charts */}
      {activeTab === 'bar' && (
        <div style={{ height: 260 }}>
          <Bar data={barData} options={barOptions} />
        </div>
      )}
      {activeTab === 'radar' && (
        <div style={{ height: 300 }}>
          <Radar data={radarData} options={radarOptions} />
        </div>
      )}
      {activeTab === 'timeline' && (
        <div style={{ height: 260 }}>
          <Line data={timelineData} options={timelineOptions} />
        </div>
      )}

      {/* Scan count footer */}
      <div style={{ marginTop: 10, fontSize: '0.68rem', color: '#484f58', textAlign: 'right' }}>
        {history.length} total scan{history.length !== 1 ? 's' : ''} · auto-refreshes every 15s
      </div>
    </div>
  );
};

// ── Main LiveChart Component ──────────────────────────────────────────────────
const LiveChart: React.FC = () => {
  const [isConnected, setIsConnected] = useState(false);
  const [currentPhase, setCurrentPhase] = useState('initialization');
  const [currentPhaseIndex, setCurrentPhaseIndex] = useState(0);
  const [phaseProgress, setPhaseProgress] = useState(0);
  const [metrics, setMetrics] = useState<Metrics>({
    vulnerability_score: 0,
    scan_progress: 0,
    response_time: 0,
    success_rate: 100,
    anomaly_count: 0,
  });

  const [chartData, setChartData] = useState({
    vulnerability: [] as number[],
    response: [] as number[],
    success: [] as number[],
    anomaly: [] as number[],
  });

  const [chartLabels, setChartLabels] = useState<string[]>([]);
  const websocket = useRef<WebSocket | null>(null);

  const updateChartData = useCallback((newMetrics: Metrics) => {
    const timestamp = new Date().toLocaleTimeString();
    setChartData(prev => ({
      vulnerability: [...prev.vulnerability, newMetrics.vulnerability_score].slice(-20),
      response:      [...prev.response, newMetrics.response_time].slice(-20),
      success:       [...prev.success, newMetrics.success_rate].slice(-20),
      anomaly:       [...prev.anomaly, newMetrics.anomaly_count].slice(-20),
    }));
    setChartLabels(prev => [...prev, timestamp].slice(-20));
  }, []);

  const connectWebSocket = useCallback(() => {
    const wsUrl = `ws://localhost:8000/ws/live-chart`;
    websocket.current = new WebSocket(wsUrl);

    websocket.current.onopen = () => { setIsConnected(true); };
    websocket.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'metrics_update') {
          setMetrics(data.data);
          setCurrentPhase(data.phase);
          setPhaseProgress(data.phase_progress);
          setCurrentPhaseIndex(PHASES.indexOf(data.phase));
          updateChartData(data.data);
        }
      } catch {}
    };
    websocket.current.onclose = () => { setIsConnected(false); };
    websocket.current.onerror = () => { setIsConnected(false); };
  }, [updateChartData]);

  const disconnectWebSocket = useCallback(() => {
    websocket.current?.close();
    websocket.current = null;
    setIsConnected(false);
  }, []);

  const toggleConnection = useCallback(() => {
    isConnected ? disconnectWebSocket() : connectWebSocket();
  }, [isConnected, connectWebSocket, disconnectWebSocket]);

  const clearCharts = useCallback(() => {
    setChartData({ vulnerability: [], response: [], success: [], anomaly: [] });
    setChartLabels([]);
  }, []);

  useEffect(() => {
    connectWebSocket();
    return () => { disconnectWebSocket(); };
  }, [connectWebSocket, disconnectWebSocket]);

  // Shared chart options
  const lineOpts = (max: number): ChartOptions<'line'> => ({
    responsive: true, maintainAspectRatio: false,
    scales: {
      x: { display: true, ticks: { color: '#8b949e', maxTicksLimit: 6 }, grid: { color: 'rgba(255,255,255,0.04)' } },
      y: { display: true, beginAtZero: true, max, ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.06)' } },
    },
    plugins: { legend: { display: false } },
    animation: { duration: 0 },
  });

  const barOpts: ChartOptions<'bar'> = {
    responsive: true, maintainAspectRatio: false,
    scales: {
      x: { display: true, ticks: { color: '#8b949e', maxTicksLimit: 6 }, grid: { display: false } },
      y: { display: true, beginAtZero: true, max: 10, ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.06)' } },
    },
    plugins: { legend: { display: false } },
    animation: { duration: 0 },
  };

  const mkLine = (data: number[], color: string, bg: string) => ({
    labels: chartLabels,
    datasets: [{ data, borderColor: color, backgroundColor: bg, tension: 0.4, fill: true, pointRadius: 2 }],
  });

  return (
    <div style={{ padding: '24px 28px', minHeight: '100vh', color: '#c9d1d9' }}>

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 700, color: '#e6edf3' }}>
            📡 Live Security Metrics
          </h2>
          <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: '#8b949e' }}>
            Real-time WebSocket stream from the red-team engine
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 7,
            padding: '5px 12px', borderRadius: 20, fontSize: '0.75rem', fontWeight: 600,
            background: isConnected ? 'rgba(63,185,80,0.12)' : 'rgba(255,255,255,0.05)',
            border: `1px solid ${isConnected ? 'rgba(63,185,80,0.3)' : '#30363d'}`,
            color: isConnected ? '#3fb950' : '#8b949e',
          }}>
            <span style={{
              width: 7, height: 7, borderRadius: '50%',
              background: isConnected ? '#3fb950' : '#484f58',
              boxShadow: isConnected ? '0 0 6px #3fb950' : 'none',
              animation: isConnected ? 'pulse 1.5s ease infinite' : 'none',
              display: 'inline-block',
            }} />
            {isConnected ? 'Live' : 'Offline'}
          </div>
          <div style={{
            padding: '5px 12px', borderRadius: 20, fontSize: '0.72rem',
            background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.25)', color: '#58a6ff',
          }}>
            Phase: {currentPhase}
          </div>
        </div>
      </div>

      {/* ── KPI row ────────────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12, marginBottom: 24 }}>
        {[
          { label: 'Vuln Score', value: `${metrics.vulnerability_score.toFixed(1)}%`, color: metrics.vulnerability_score < 30 ? '#3fb950' : metrics.vulnerability_score < 70 ? '#e3b341' : '#f85149' },
          { label: 'Scan Progress', value: `${metrics.scan_progress.toFixed(1)}%`, color: '#58a6ff' },
          { label: 'Response Time', value: `${metrics.response_time.toFixed(0)}ms`, color: metrics.response_time < 200 ? '#3fb950' : metrics.response_time < 400 ? '#e3b341' : '#f85149' },
          { label: 'Success Rate', value: `${metrics.success_rate.toFixed(1)}%`, color: metrics.success_rate > 90 ? '#3fb950' : metrics.success_rate > 80 ? '#58a6ff' : '#f85149' },
          { label: 'Anomalies', value: String(metrics.anomaly_count), color: metrics.anomaly_count === 0 ? '#3fb950' : metrics.anomaly_count < 3 ? '#e3b341' : '#f85149' },
        ].map(k => (
          <div key={k.label} style={{
            padding: '14px 16px', borderRadius: 10,
            background: 'rgba(22,27,34,0.8)', border: '1px solid #21262d',
          }}>
            <div style={{ fontSize: '0.68rem', color: '#8b949e', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{k.label}</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: k.color, fontFamily: 'monospace' }}>{k.value}</div>
          </div>
        ))}
      </div>

      {/* ── Real-time mini charts ───────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 14, marginBottom: 28 }}>
        <div style={{ background: 'rgba(22,27,34,0.8)', border: '1px solid #21262d', borderRadius: 10, padding: '14px 16px' }}>
          <div style={{ fontSize: '0.72rem', color: '#8b949e', marginBottom: 10, fontWeight: 600 }}>⚠ Vulnerability Score (live)</div>
          <div style={{ height: 110 }}>
            <Line data={mkLine(chartData.vulnerability,'#f85149','rgba(248,81,73,0.08)')} options={lineOpts(100)} />
          </div>
        </div>
        <div style={{ background: 'rgba(22,27,34,0.8)', border: '1px solid #21262d', borderRadius: 10, padding: '14px 16px' }}>
          <div style={{ fontSize: '0.72rem', color: '#8b949e', marginBottom: 10, fontWeight: 600 }}>✓ Success Rate (live)</div>
          <div style={{ height: 110 }}>
            <Line data={mkLine(chartData.success,'#3fb950','rgba(63,185,80,0.08)')} options={lineOpts(100)} />
          </div>
        </div>
        <div style={{ background: 'rgba(22,27,34,0.8)', border: '1px solid #21262d', borderRadius: 10, padding: '14px 16px' }}>
          <div style={{ fontSize: '0.72rem', color: '#8b949e', marginBottom: 10, fontWeight: 600 }}>⏱ Response Time ms (live)</div>
          <div style={{ height: 110 }}>
            <Line data={mkLine(chartData.response,'#58a6ff','rgba(88,166,255,0.08)')} options={lineOpts(500)} />
          </div>
        </div>
        <div style={{ background: 'rgba(22,27,34,0.8)', border: '1px solid #21262d', borderRadius: 10, padding: '14px 16px' }}>
          <div style={{ fontSize: '0.72rem', color: '#8b949e', marginBottom: 10, fontWeight: 600 }}>🔔 Anomaly Count (live)</div>
          <div style={{ height: 110 }}>
            <Bar data={{ labels: chartLabels, datasets: [{ data: chartData.anomaly, backgroundColor: 'rgba(227,179,65,0.7)', borderColor: '#e3b341', borderWidth: 1, borderRadius: 4 }] }} options={barOpts} />
          </div>
        </div>
      </div>

      {/* ── Phase tracker ──────────────────────────────────────────────────── */}
      <div style={{ background: 'rgba(22,27,34,0.8)', border: '1px solid #21262d', borderRadius: 10, padding: '14px 18px', marginBottom: 28 }}>
        <div style={{ fontSize: '0.72rem', color: '#8b949e', fontWeight: 600, marginBottom: 12 }}>SCAN PHASE TRACKER</div>
        <div style={{ display: 'flex', gap: 8 }}>
          {PHASES.map((phase, i) => (
            <div key={phase} style={{ flex: 1, textAlign: 'center' }}>
              <div style={{
                padding: '6px 0', borderRadius: 6, fontSize: '0.68rem', fontWeight: 600,
                background: i === currentPhaseIndex ? 'rgba(88,166,255,0.15)'
                          : i < currentPhaseIndex  ? 'rgba(63,185,80,0.12)'
                          : 'rgba(255,255,255,0.03)',
                color: i === currentPhaseIndex ? '#58a6ff'
                     : i < currentPhaseIndex  ? '#3fb950'
                     : '#484f58',
                border: `1px solid ${i === currentPhaseIndex ? 'rgba(88,166,255,0.35)' : i < currentPhaseIndex ? 'rgba(63,185,80,0.25)' : '#21262d'}`,
                transition: 'all 0.3s',
              }}>
                {i < currentPhaseIndex ? '✓ ' : i === currentPhaseIndex ? '▶ ' : ''}{phase}
              </div>
              {i < PHASES.length - 1 && (
                <div style={{ height: 2, background: i < currentPhaseIndex ? '#3fb950' : '#21262d', marginTop: 4, transition: 'background 0.5s' }} />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════════════════ */}
      {/* MODEL COMPARISON GRAPH                                                */}
      {/* ══════════════════════════════════════════════════════════════════════ */}
      <div style={{ background: 'rgba(22,27,34,0.8)', border: '1px solid #21262d', borderRadius: 12, padding: '20px 22px', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#58a6ff', boxShadow: '0 0 8px #58a6ff' }} />
          <span style={{ fontSize: '0.95rem', fontWeight: 700, color: '#e6edf3' }}>
            Model Security Comparison
          </span>
          <span style={{ fontSize: '0.68rem', color: '#8b949e', marginLeft: 4 }}>
            GPT · Gemini · Claude — from scan history
          </span>
        </div>
        <ModelComparisonPanel />
      </div>

      {/* Controls */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 18 }}>
        <button onClick={toggleConnection} style={{
          padding: '9px 20px', borderRadius: 8, fontWeight: 600, fontSize: '0.82rem', cursor: 'pointer',
          background: isConnected ? 'rgba(248,81,73,0.15)' : 'rgba(88,166,255,0.15)',
          color: isConnected ? '#f85149' : '#58a6ff',
          border: `1px solid ${isConnected ? 'rgba(248,81,73,0.35)' : 'rgba(88,166,255,0.35)'}`,
          transition: 'all 0.2s',
        }}>
          {isConnected ? '⏹ Stop Live' : '▶ Start Live'}
        </button>
        <button onClick={clearCharts} style={{
          padding: '9px 20px', borderRadius: 8, fontWeight: 600, fontSize: '0.82rem', cursor: 'pointer',
          background: 'transparent', color: '#8b949e', border: '1px solid #30363d',
        }}>
          🗑 Clear Charts
        </button>
      </div>

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes spin  { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
};

export default LiveChart;
