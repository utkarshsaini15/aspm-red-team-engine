import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import {
  ShieldAlert, Activity, History, BarChart3, Server,
  ChevronRight, Zap, AlertTriangle, CheckCircle2,
  XCircle, Copy, Check, Trash2, RefreshCw, Terminal,
  TrendingUp, Clock, Cpu, Brain, GitBranch,
  Network, Layers, Bug, Shield, Play, Repeat
} from 'lucide-react';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  Tooltip, CartesianGrid, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, BarChart, Bar, Cell,
  LineChart, Line, Legend, ScatterChart, Scatter,
} from 'recharts';

const API = 'http://localhost:8000';

const THREATS = [
  '🔥 CRITICAL: New RAG Poisoning technique bypassing standard vector filters.',
  '⚠️ HIGH: Prompt Injection via indirect plugin orchestration observed.',
  '🚨 ALERT: PII leakage from untethered embedding cache in prod.',
  '🛡️ INTEL: Cloud provider patches indirect prompt injection in API gateway.',
  '💀 ZERO-DAY: Model inversion attack leaking training corpora via embeddings.',
  '🧬 RL AGENT: Adversarial suffix triggers toxicity at T>0.65 on GPT-4 class models.',
];

// ── Log colorizer ─────────────────────────────────────────────────────────────
function renderLog(raw) {
  return raw.split('\n').map((line, i) => {
    let cls = 'log-line log-intel';
    if (/INIT|Bootstrap|Booting/.test(line))     cls = 'log-line log-init';
    if (/━|VECTOR|Agent.*→/.test(line))          cls = 'log-line log-vector';
    if (/EPOCH|Epoch|RL ε|action:/.test(line))   cls = 'log-line log-epoch';
    if (/BREACH|COMPROMISE|EXPLOIT/.test(line))  cls = 'log-line log-breach';
    if (/DEFENSE|BLOCK|DENY|Guardrail/.test(line)) cls = 'log-line log-defense';
    if (/RESULT|PASSED|FAILED/.test(line))       cls = 'log-line log-result';
    if (/═|SCAN COMPLETE|Score|Q-Table/.test(line)) cls = 'log-line log-final';
    if (/PAYLOAD|→/.test(line))                  cls = 'log-line log-payload';
    if (/ANOMALY|XAI|RL\]/.test(line))           cls = 'log-line log-xai';
    if (/Mutator|Gen |evolution/.test(line))     cls = 'log-line log-mutator';
    return <span key={i} className={cls}>{line}{'\n'}</span>;
  });
}

// ── Score Ring ────────────────────────────────────────────────────────────────
function ScoreRing({ score, size = 120 }) {
  const r = size * 0.42;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 75 ? '#3fb950' : score >= 50 ? '#e3b341' : '#f85149';
  const cx = size / 2, cy = size / 2;
  return (
    <div className="score-ring" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="9" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="9"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition: 'stroke-dashoffset 1.4s cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 8px ${color})` }}
        />
      </svg>
      <div className="score-ring-text">
        <span className="score-num" style={{ color, fontSize: size * 0.28 }}>{score}</span>
        <span className="score-denom">/100</span>
      </div>
    </div>
  );
}

// ── Copy Button ───────────────────────────────────────────────────────────────
function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button className="copy-btn" onClick={() => {
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }}>
      {copied ? <><Check size={11} /> Copied!</> : <><Copy size={11} /> Copy</>}
    </button>
  );
}

// ── Vuln Table ────────────────────────────────────────────────────────────────
function VulnTable({ vulns }) {
  const [open, setOpen] = useState(null);
  const risk = r => ({ Critical: 'risk-critical', High: 'risk-high', Medium: 'risk-medium', Low: 'risk-low' }[r] || '');
  return (
    <div className="table-scroll">
      <table className="vuln-table">
        <thead><tr>
          <th>OWASP</th><th>Vector</th><th>Agent</th><th>Status</th><th>Risk</th><th>Epochs</th><th></th>
        </tr></thead>
        <tbody>
          {vulns.map((v, i) => (<React.Fragment key={i}>
            <tr>
              <td><span className="owasp-tag">{v.owasp_id}</span></td>
              <td className="vuln-name">{v.type.split(': ')[1] || v.type}</td>
              <td><span className="agent-tag">{v.agent || '—'}</span></td>
              <td>{v.status === 'Passed'
                ? <span className="chip chip-green"><CheckCircle2 size={11} style={{marginRight:4,verticalAlign:'middle'}}/>Passed</span>
                : <span className="chip chip-red"><XCircle size={11} style={{marginRight:4,verticalAlign:'middle'}}/>Failed</span>}
              </td>
              <td><span className={`risk-dot ${risk(v.risk_level)}`}>{v.risk_level}</span></td>
              <td className="text-xs text-muted font-mono">{v.epochs || 1}</td>
              <td>{v.code_snippet && (
                <button className="btn btn-ghost" style={{padding:'3px 10px',fontSize:'0.72rem'}}
                  onClick={() => setOpen(open === i ? null : i)}>
                  {open === i ? 'Close' : 'Fix →'}
                </button>
              )}</td>
            </tr>
            {open === i && (
              <tr className="expand-row">
                <td colSpan={7} className="expand-content">
                  <p className="text-xs text-muted" style={{marginBottom:8}}>
                    <strong style={{color:'var(--yellow)'}}>Mitigation:</strong> {v.mitigation}
                  </p>
                  <div className="code-block" style={{position:'relative'}}>
                    {v.code_snippet}<CopyBtn text={v.code_snippet} />
                  </div>
                </td>
              </tr>
            )}
          </React.Fragment>))}
        </tbody>
      </table>
    </div>
  );
}

// ── XAI Contribution Chart ────────────────────────────────────────────────────
function XAIPanel({ xai }) {
  if (!xai) return null;
  const max = Math.max(...xai.contributions.map(c => Math.abs(c.impact)), 1);
  return (
    <div className="xai-panel">
      <div className="panel-title"><Brain size={14}/> XAI Score Breakdown <span className="chip chip-blue" style={{marginLeft:8}}>{xai.risk_tier}</span></div>
      <div className="xai-bars">
        {xai.contributions.map((c, i) => {
          const pct = (Math.abs(c.impact) / max) * 100;
          return (
            <div key={i} className="xai-row">
              <div className="xai-label" title={c.reason}>{c.feature}</div>
              <div className="xai-bar-wrap">
                <div className="xai-bar" style={{
                  width: `${pct}%`,
                  background: c.impact >= 0 ? 'var(--green)' : 'var(--red)',
                  opacity: 0.8,
                }}/>
              </div>
              <div className="xai-impact" style={{color: c.impact >= 0 ? 'var(--green)' : 'var(--red)'}}>
                {c.impact >= 0 ? '+' : ''}{c.impact}
              </div>
            </div>
          );
        })}
      </div>
      <div className="text-xs text-muted" style={{marginTop:8}}>
        Base: 100 &nbsp;|&nbsp; Δ: {xai.total_impact > 0 ? '+':''}{xai.total_impact} &nbsp;|&nbsp;
        Final: <strong style={{color:'var(--blue)'}}>{xai.final_score}</strong>
      </div>
    </div>
  );
}

// ── Q-Learning Panel ──────────────────────────────────────────────────────────
function QLPanel({ rl }) {
  if (!rl) return null;
  const hist = rl.history || [];
  const freq = Object.entries(rl.action_frequency || {})
    .sort((a,b) => b[1]-a[1]).slice(0,8)
    .map(([k,v]) => ({ action: k.replace('_',' '), count: v }));
  const rewardHistory = hist.map((h, i) => ({ step: h.step, reward: h.reward, q: h.new_q }));

  return (
    <div className="ql-panel">
      <div className="panel-title"><Cpu size={14}/> Q-Learning Engine Stats</div>
      <div className="ql-stats-row">
        <div className="ql-stat"><div className="ql-stat-val">{rl.total_steps}</div><div className="ql-stat-lbl">Total Steps</div></div>
        <div className="ql-stat"><div className="ql-stat-val">{rl.epsilon_final?.toFixed(3)}</div><div className="ql-stat-lbl">Final ε</div></div>
        <div className="ql-stat"><div className="ql-stat-val">{rl.cumulative_reward}</div><div className="ql-stat-lbl">Σ Reward</div></div>
        <div className="ql-stat"><div className="ql-stat-val">{Object.keys(rl.q_table || {}).length}</div><div className="ql-stat-lbl">States</div></div>
      </div>
      {rewardHistory.length > 0 && (
        <div style={{height:120,marginTop:12}}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={rewardHistory}>
              <XAxis dataKey="step" stroke="#484f58" tick={{fontSize:9}} />
              <YAxis stroke="#484f58" tick={{fontSize:9}} />
              <Tooltip contentStyle={{background:'var(--bg-2)',border:'1px solid var(--border)',fontSize:11}}/>
              <Line type="monotone" dataKey="reward" stroke="#58a6ff" dot={false} strokeWidth={1.5} name="Reward"/>
              <Line type="monotone" dataKey="q" stroke="#a371f7" dot={false} strokeWidth={1.5} name="Q-Value"/>
              <Legend wrapperStyle={{fontSize:10,color:'var(--text-2)'}}/>
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
      {freq.length > 0 && (
        <div style={{height:110,marginTop:8}}>
          <div className="text-xs text-muted" style={{marginBottom:4}}>Most Played Actions</div>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={freq} layout="vertical">
              <XAxis type="number" stroke="#484f58" tick={{fontSize:9}}/>
              <YAxis type="category" dataKey="action" stroke="#484f58" tick={{fontSize:9}} width={100}/>
              <Tooltip contentStyle={{background:'var(--bg-2)',border:'1px solid var(--border)',fontSize:11}}/>
              <Bar dataKey="count" fill="#1f6feb" radius={[0,3,3,0]}/>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

// ── Agent Activity Panel ──────────────────────────────────────────────────────
function AgentPanel({ agents }) {
  if (!agents?.length) return null;
  const colors = ['#58a6ff','#3fb950','#e3b341','#f85149','#a371f7'];
  return (
    <div className="agent-panel">
      <div className="panel-title"><Network size={14}/> Multi-Agent Activity</div>
      {agents.map((a, i) => (
        <div key={i} className="agent-row" style={{borderLeftColor: colors[i % colors.length]}}>
          <div className="agent-name" style={{color: colors[i % colors.length]}}>{a.agent}</div>
          <div className="agent-targets">{a.targets?.join(' • ')}</div>
          <div className="agent-score">
            <span className="chip chip-green">{a.passed} ✓</span>
            {a.failed > 0 && <span className="chip chip-red" style={{marginLeft:4}}>{a.failed} ✗</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Anomaly Panel ─────────────────────────────────────────────────────────────
function AnomalyPanel({ anomalies }) {
  if (!anomalies?.length) return null;
  const detected = anomalies.filter(a => a.anomaly_detected);
  const allAnomalies = anomalies.flatMap(a => (a.anomalies || []).map(x => ({...x, vuln: a.vuln_type})));
  const chartData = anomalies.map(a => ({
    name: a.vuln_type?.split(':')[0] || '?',
    latency: a.metrics?.response_time || 0,
    tokens: (a.metrics?.token_count || 0) / 10,
    zscore: a.max_zscore || 0,
  }));
  return (
    <div className="anomaly-panel">
      <div className="panel-title"><Activity size={14}/> Behavioral Anomaly Detection
        <span className="chip chip-red" style={{marginLeft:8}}>{detected.length} Anomalies</span>
      </div>
      <div style={{height:130,marginTop:8}}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3"/>
            <XAxis dataKey="name" stroke="#484f58" tick={{fontSize:9}}/>
            <YAxis stroke="#484f58" tick={{fontSize:9}}/>
            <Tooltip contentStyle={{background:'var(--bg-2)',border:'1px solid var(--border)',fontSize:11}}/>
            <Bar dataKey="latency" name="Latency (s)" fill="#58a6ff" radius={[3,3,0,0]}/>
            <Bar dataKey="zscore" name="Max Z-Score" fill="#f85149" radius={[3,3,0,0]}/>
            <Legend wrapperStyle={{fontSize:10,color:'var(--text-2)'}}/>
          </BarChart>
        </ResponsiveContainer>
      </div>
      {allAnomalies.length > 0 && (
        <div className="anomaly-list">
          {allAnomalies.slice(0,4).map((a, i) => (
            <div key={i} className={`anomaly-item severity-${a.severity?.toLowerCase()}`}>
              <span className="anomaly-metric">{a.metric}</span>
              <span className="anomaly-val">{a.value}</span>
              <span className="anomaly-z">Z={a.zscore}</span>
              <span className={`chip chip-${a.severity === 'Critical' ? 'red' : a.severity === 'High' ? 'yellow' : 'blue'}`} style={{fontSize:'0.65rem'}}>{a.severity}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Toast ──────────────────────────────────────────────────────────────────────
function Toast({ message, type = 'success', onClose }) {
  useEffect(() => { const t = setTimeout(onClose, 3500); return () => clearTimeout(t); }, []);
  const icon = type === 'success' ? <CheckCircle2 size={15} color="var(--green)"/> : <AlertTriangle size={15} color="var(--yellow)"/>;
  return <div className="toast">{icon} {message}</div>;
}

// ════════════════════════════════════════════════════════════════════════════╗
//  MAIN APP
// ════════════════════════════════════════════════════════════════════════════╝
export default function App() {
  const [tab, setTab]             = useState('audit');
  const [apiOnline, setApiOnline] = useState(false);
  const [threatIdx, setThreatIdx] = useState(0);
  const [toast, setToast]         = useState(null);

  // Scan config
  const [targetModel,   setTargetModel]   = useState('gpt-4o-customer-bot');
  const [temperature,   setTemperature]   = useState(0.5);
  const [systemPrompt,  setSystemPrompt]  = useState('');

  // Primary scan
  const [scanId,     setScanId]     = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [logs,       setLogs]       = useState('');
  const [results,    setResults]    = useState(null);

  // Autonomous hardening
  const [hardenJobId,     setHardenJobId]     = useState(null);
  const [hardenStatus,    setHardenStatus]    = useState(null);
  const [hardenResults,   setHardenResults]   = useState(null);
  const [hardenLogs,      setHardenLogs]      = useState('');

  // History
  const [history, setHistory] = useState([]);
  const consoleRef = useRef(null);
  const hardenRef  = useRef(null);

  const showToast = (msg, type='success') => setToast({msg, type});

  // ── API Health ──────────────────────────────────────────────────────────────
  useEffect(() => {
    const check = async () => {
      try { await axios.get(`${API}/health`); setApiOnline(true); }
      catch { setApiOnline(false); }
    };
    check();
    const id = setInterval(check, 10000);
    return () => clearInterval(id);
  }, []);

  // ── Rotating Threats ────────────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => setThreatIdx(i => (i + 1) % THREATS.length), 5500);
    return () => clearInterval(id);
  }, []);

  // ── Primary Scan Polling ────────────────────────────────────────────────────
  useEffect(() => {
    if (!scanId || (scanStatus !== 'PENDING' && scanStatus !== 'IN_PROGRESS')) return;
    const id = setInterval(async () => {
      try {
        const { data } = await axios.get(`${API}/scan/status/${scanId}`);
        setLogs(data.logs || '');
        setScanStatus(data.status);
        if (data.status === 'COMPLETED') {
          setResults(data.results);
          fetchHistory();
          showToast('Scan completed! Vulnerabilities identified.', 'success');
        }
        if (data.status === 'FAILED') showToast('Scan failed — check backend logs.', 'warn');
      } catch {}
    }, 900);
    return () => clearInterval(id);
  }, [scanId, scanStatus]);

  // ── Hardened Scan Polling ───────────────────────────────────────────────────
  useEffect(() => {
    if (!hardenJobId || (hardenStatus !== 'PENDING' && hardenStatus !== 'IN_PROGRESS')) return;
    const id = setInterval(async () => {
      try {
        const { data } = await axios.get(`${API}/scan/status/${hardenJobId}`);
        setHardenLogs(data.logs || '');
        setHardenStatus(data.status);
        if (data.status === 'COMPLETED') {
          setHardenResults(data.results);
          fetchHistory();
          showToast('Hardened scan complete! Compare scores below.', 'success');
        }
      } catch {}
    }, 900);
    return () => clearInterval(id);
  }, [hardenJobId, hardenStatus]);

  // ── Auto Scroll ─────────────────────────────────────────────────────────────
  useEffect(() => { if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight; }, [logs]);
  useEffect(() => { if (hardenRef.current)  hardenRef.current.scrollTop  = hardenRef.current.scrollHeight;  }, [hardenLogs]);

  // ── History ─────────────────────────────────────────────────────────────────
  const fetchHistory = useCallback(async () => {
    try { const {data} = await axios.get(`${API}/scans/history`); setHistory(data); } catch {}
  }, []);
  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  const calcScore = v => v?.length ? Math.round(v.filter(x=>x.status==='Passed').length/v.length*100) : 0;

  // ── Start Scan ──────────────────────────────────────────────────────────────
  const startScan = async () => {
    if (!apiOnline) { showToast('API offline. Run: uvicorn src.server:app --reload', 'warn'); return; }
    setResults(null); setLogs(''); setScanId(null); setScanStatus('PENDING');
    setHardenJobId(null); setHardenResults(null); setHardenStatus(null); setHardenLogs('');
    try {
      const { data } = await axios.post(`${API}/scan/start`, {
        target_model: targetModel,
        system_prompt: systemPrompt,
        temperature: parseFloat(temperature),
      });
      setScanId(data.job_id);
    } catch { setScanStatus(null); showToast('Cannot connect to backend API.', 'warn'); }
  };

  // ── Harden & Verify ─────────────────────────────────────────────────────────
  const hardenAndVerify = async () => {
    if (!scanId) return;
    setHardenStatus('PENDING'); setHardenLogs(''); setHardenResults(null);
    try {
      const { data } = await axios.post(`${API}/scan/harden-and-verify/${scanId}`);
      setHardenJobId(data.job_id);
      showToast('Auto-Hardening loop launched!', 'success');
    } catch { showToast('Harden scan failed.', 'warn'); }
  };

  const clearHistory = async () => {
    try { await axios.delete(`${API}/scans/history`); setHistory([]); showToast('History cleared.'); } catch {}
  };

  const isScanning = scanStatus === 'PENDING' || scanStatus === 'IN_PROGRESS';
  const isHardening = hardenStatus === 'PENDING' || hardenStatus === 'IN_PROGRESS';

  // ── Analytics ───────────────────────────────────────────────────────────────
  const trendData = [...history].reverse().map(h => ({
    time: new Date(h.completed_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}),
    score: calcScore(h.results?.vulnerabilities),
    model: h.target_model,
  }));
  const avgScore = history.length ? Math.round(history.reduce((s,h)=>s+calcScore(h.results?.vulnerabilities),0)/history.length) : 0;
  const critScans = history.filter(h=>calcScore(h.results?.vulnerabilities)<50).length;
  const vectorMap = {};
  history.forEach(h => h.results?.vulnerabilities?.forEach(v => {
    if (v.status==='Failed') vectorMap[v.owasp_id]=(vectorMap[v.owasp_id]||0)+1;
  }));
  const heatData = Object.entries(vectorMap).map(([k,v])=>({id:k,failures:v})).sort((a,b)=>b.failures-a.failures);

  // ── RENDER ──────────────────────────────────────────────────────────────────
  return (
    <div className="app-shell">

      {/* ─── SIDEBAR ─────────────────────────────────────────────────────── */}
      <nav className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon"><ShieldAlert size={20} color="white"/></div>
          <div className="logo-text">
            <strong>ASPM</strong>
            <span>Red Team Engine v3</span>
          </div>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-section-label">Modules</div>
          {[
            { id:'audit',     label:'Live Red Team',      Icon:Activity },
            { id:'history',   label:'Posture History',    Icon:History },
            { id:'analytics', label:'Executive Analytics',Icon:BarChart3 },
          ].map(({id,label,Icon}) => (
            <div key={id} className={`nav-item ${tab===id?'active':''}`} onClick={()=>setTab(id)}>
              <Icon size={15} className="nav-icon"/> {label}
              {id==='history' && history.length>0 && <span className="nav-badge">{history.length}</span>}
            </div>
          ))}
        </div>

        <div className="sidebar-section">
          <div className="sidebar-section-label">ML Engine</div>
          <div className="ml-badge-list">
            <div className="ml-badge"><Brain size={11}/> Q-Learning RL</div>
            <div className="ml-badge"><Network size={11}/> Multi-Agent</div>
            <div className="ml-badge"><GitBranch size={11}/> Genetic Mutator</div>
            <div className="ml-badge"><Layers size={11}/> Z-Score Anomaly</div>
            <div className="ml-badge"><Zap size={11}/> XAI Explainer</div>
          </div>
        </div>

        <div className="sidebar-footer">
          <div className="api-status">
            <div className={`api-dot ${apiOnline ? '' : 'offline'}`}/>
            API: {apiOnline ? 'Online ✓' : 'Offline ✗'}
          </div>
          <div className="threat-ticker">
            <div className="threat-ticker-label"><Zap size={10}/> Live Threat Intel</div>
            <div className="threat-ticker-msg">{THREATS[threatIdx]}</div>
          </div>
        </div>
      </nav>

      {/* ─── MAIN ────────────────────────────────────────────────────────── */}
      <main className="main">

        {/* ═══ AUDIT TAB ═══════════════════════════════════════════════════ */}
        {tab === 'audit' && (
          <div className="page fade-in">
            <div className="page-header">
              <h1 className="page-title">Autonomous <span className="accent">Red Team</span></h1>
              <p className="page-subtitle">
                OWASP LLM Top 10 · Q-Learning RL · Multi-Agent · Genetic Mutations · XAI · Auto-Hardening
              </p>
            </div>

            {/* Config + Execution Grid */}
            <div className="audit-grid">
              {/* Config Panel */}
              <div className="card slide-up">
                <div className="card-header">
                  <div className="card-title"><Server size={14}/> Target Configuration</div>
                </div>
                <div className="card-body">
                  <div className="form-group">
                    <label className="form-label">Target Model URI</label>
                    <input className="form-input" value={targetModel} onChange={e=>setTargetModel(e.target.value)} placeholder="gpt-4o-customer-bot"/>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Model Temperature (Physics)</label>
                    <div className="slider-row">
                      <input className="form-range" type="range" min="0" max="1" step="0.05"
                        value={temperature} onChange={e=>setTemperature(parseFloat(e.target.value))}/>
                      <span className="range-value" style={{color: temperature>0.7 ? 'var(--red)' : 'var(--blue)'}}>{temperature.toFixed(2)}</span>
                    </div>
                    <div className="form-hint">
                      {temperature > 0.7 ? '⚠ HIGH — triggers LLM08 Toxicity & Agency failures' : '✓ Safe range — production ready'}
                    </div>
                  </div>
                  <div className="form-group">
                    <label className="form-label">System Prompt <span className="form-hint-inline">(Defensive Layer)</span></label>
                    <textarea className="form-textarea" rows={6} value={systemPrompt}
                      onChange={e=>setSystemPrompt(e.target.value)}
                      placeholder={"Defense keywords to pass each vector:\n\"filter\", \"reject\" → LLM01\n\"sanitize\", \"escape\" → LLM02\n\"timeout\", \"rate_limit\" → LLM04\n\"mask\", \"pii\", \"redact\" → LLM06\n\"cite\", \"source\" → LLM09"}
                    />
                    <div className="form-hint">{systemPrompt.length} chars — {systemPrompt.length<30?'⚠ Too short for injection defense':'✓ Length sufficient'}</div>
                  </div>
                  <button className="btn btn-launch" disabled={isScanning} onClick={startScan}>
                    {isScanning ? <><div className="spinner"/> Scanning...</> : <><Play size={15}/> Initiate Scan</>}
                  </button>
                </div>
                {isScanning && <div className="scan-progress-bar"><div className="scan-progress-fill"/></div>}
              </div>

              {/* Execution Panel */}
              <div>
                {!scanId && !results && (
                  <div className="card slide-up delay-1" style={{minHeight:500}}>
                    <div className="empty-state">
                      <Terminal size={52} className="empty-icon"/>
                      <h4>Awaiting Scan Initiation</h4>
                      <p>Q-Learning RL Agent + 5 Specialist Agents will spawn<br/>and stream attacks live here.</p>
                    </div>
                  </div>
                )}

                {(isScanning || (scanId && !results)) && (
                  <div className="card slide-up delay-1">
                    <div className="card-header">
                      <div className="card-title"><Activity size={14}/> Live RL Attack Console</div>
                      <span className="chip chip-yellow" style={{fontSize:'0.7rem'}}>
                        <div className="spinner" style={{width:8,height:8,borderWidth:1.5}}/>&nbsp;IN PROGRESS
                      </span>
                    </div>
                    <div className="terminal-wrapper">
                      <div className="terminal-topbar">
                        <div className="terminal-dot red"/><div className="terminal-dot yellow"/><div className="terminal-dot green"/>
                        <span className="terminal-title">aspm-redteam — q-learning-engine — zsh</span>
                      </div>
                      <div className="terminal-body" ref={consoleRef}>
                        {logs ? renderLog(logs) : <span className="log-line log-init">Initializing ML Agent Fleet...</span>}
                      </div>
                    </div>
                  </div>
                )}

                {results && !isScanning && (
                  <div className="card slide-up delay-1">
                    <div className="card-header">
                      <div className="card-title"><Shield size={14}/> Cyber Hygiene Report</div>
                      <span className="chip chip-blue" style={{fontSize:'0.7rem'}}>{results.scan_engine}</span>
                    </div>
                    <div className="card-body">
                      {/* Score + Radar */}
                      <div className="score-ring-container">
                        <ScoreRing score={results.score}/>
                        <div className="score-meta">
                          <h3 style={{marginBottom:8}}>Security Score</h3>
                          <div className="score-badges">
                            <span className="chip chip-green"><CheckCircle2 size={10} style={{marginRight:3,verticalAlign:'middle'}}/>{results.summary.passed} Passed</span>
                            <span className="chip chip-red"><XCircle size={10} style={{marginRight:3,verticalAlign:'middle'}}/>{results.summary.failed} Failed</span>
                            {results.summary.critical_count>0 && <span className="chip chip-red">{results.summary.critical_count} Critical</span>}
                          </div>
                          <div className="text-xs text-muted font-mono" style={{marginTop:10}}>
                            T={results.temperature?.toFixed(2)} | {new Date(results.completed_at).toLocaleString()}
                          </div>
                          {/* Autonomous Hardening Button */}
                          {results.summary.failed > 0 && !hardenJobId && (
                            <button className="btn btn-harden" onClick={hardenAndVerify} style={{marginTop:12}}>
                              <Repeat size={13}/> Auto-Harden & Verify
                            </button>
                          )}
                        </div>
                        <div style={{flex:1, height:190}}>
                          <ResponsiveContainer width="100%" height="100%">
                            <RadarChart data={results.vulnerabilities.map(v=>({s:v.owasp_id,A:v.status==='Passed'?100:15}))}>
                              <PolarGrid stroke="rgba(255,255,255,0.07)"/>
                              <PolarAngleAxis dataKey="s" tick={{fill:'#8b949e',fontSize:10}}/>
                              <PolarRadiusAxis domain={[0,100]} tick={false} axisLine={false}/>
                              <Radar dataKey="A" stroke="var(--blue)" fill="var(--blue)" fillOpacity={0.3} strokeWidth={2}/>
                            </RadarChart>
                          </ResponsiveContainer>
                        </div>
                      </div>

                      {/* Auto-Remediator */}
                      {results.summary.failed > 0 && (
                        <div className="remediator-panel">
                          <div className="remediator-title"><Zap size={13}/> AI Auto-Remediator</div>
                          <div className="remediator-desc">
                            {results.summary.failed} vector(s) breached. Apply this system prompt to patch all failures:
                          </div>
                          <div className="code-block" style={{position:'relative',color:'#a8d8a8'}}>
                            {results.hardened_prompt}<CopyBtn text={results.hardened_prompt}/>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* ── ML Intelligence Panels ─────────────────────────────────── */}
            {results && !isScanning && (
              <>
                <div className="three-col mt-6">
                  <div className="slide-up delay-1"><XAIPanel xai={results.xai_explanation}/></div>
                  <div className="slide-up delay-2"><AgentPanel agents={results.agent_activity}/></div>
                  <div className="slide-up delay-3"><AnomalyPanel anomalies={results.anomaly_report}/></div>
                </div>

                <div className="card mt-6 slide-up delay-2">
                  <div className="card-header">
                    <div className="card-title"><Cpu size={14}/> Q-Learning Engine — Reward History & Action Frequency</div>
                  </div>
                  <div className="card-body"><QLPanel rl={results.rl_data}/></div>
                </div>

                {/* Vulnerability Table */}
                <div className="card mt-6 slide-up delay-3">
                  <div className="card-header">
                    <div className="card-title"><Bug size={14}/> Full Vulnerability Breakdown</div>
                    <span className="text-xs text-muted">Click "Fix →" for remediation code</span>
                  </div>
                  <VulnTable vulns={results.vulnerabilities}/>
                </div>
              </>
            )}

            {/* ── Autonomous Hardening Section ────────────────────────────── */}
            {(hardenJobId || hardenResults) && (
              <div className="card mt-6 slide-up">
                <div className="card-header">
                  <div className="card-title"><Repeat size={14}/> Autonomous Hardening Loop — Verification Scan</div>
                  {isHardening && <span className="chip chip-yellow" style={{fontSize:'0.7rem'}}><div className="spinner" style={{width:8,height:8,borderWidth:1.5}}/>&nbsp;RUNNING</span>}
                  {hardenResults && <span className="chip chip-green" style={{fontSize:'0.7rem'}}>COMPLETE</span>}
                </div>
                <div className="card-body">
                  {isHardening && (
                    <div className="terminal-wrapper">
                      <div className="terminal-body" ref={hardenRef} style={{height:200}}>
                        {hardenLogs ? renderLog(hardenLogs) : <span className="log-init">Applying hardened prompt and re-scanning...</span>}
                      </div>
                    </div>
                  )}
                  {hardenResults && results && (
                    <div className="harden-compare">
                      <div className="compare-col">
                        <div className="compare-label">🔴 Before Hardening</div>
                        <ScoreRing score={results.score} size={90}/>
                        <div className="text-xs text-muted" style={{marginTop:8}}>{results.target}</div>
                      </div>
                      <div className="compare-arrow">→</div>
                      <div className="compare-col">
                        <div className="compare-label">🟢 After Hardening</div>
                        <ScoreRing score={hardenResults.score} size={90}/>
                        <div className="text-xs text-muted" style={{marginTop:8}}>{hardenResults.target}</div>
                      </div>
                      <div className="compare-col">
                        <div className="compare-label">📈 Improvement</div>
                        <div className="improvement-score" style={{color: hardenResults.score>results.score?'var(--green)':'var(--red)'}}>
                          {hardenResults.score-results.score > 0 ? '+' : ''}{hardenResults.score-results.score}
                        </div>
                        <div className="text-xs text-muted">Security Score Points</div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ═══ HISTORY TAB ══════════════════════════════════════════════════ */}
        {tab === 'history' && (
          <div className="page fade-in">
            <div className="page-header">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="page-title">Posture <span className="accent">History</span></h1>
                  <p className="page-subtitle">Track regression across model versions and prompt hardening iterations.</p>
                </div>
                <div className="flex gap-8">
                  <button className="btn btn-ghost" onClick={fetchHistory}><RefreshCw size={13}/> Refresh</button>
                  {history.length>0 && <button className="btn btn-danger" onClick={clearHistory}><Trash2 size={13}/> Clear</button>}
                </div>
              </div>
            </div>
            <div className="card">
              <div className="card-header"><div className="card-title"><History size={14}/> Completed Scans ({history.length})</div></div>
              {history.length===0 ? (
                <div className="empty-state"><History size={40} className="empty-icon"/><h4>No scans yet</h4><p>Run your first scan.</p></div>
              ) : history.map((h,i)=>{
                const score=calcScore(h.results?.vulnerabilities);
                const pillCls=score>=75?'score-pill-high':score>=50?'score-pill-mid':'score-pill-low';
                const barColor=score>=75?'var(--green)':score>=50?'var(--yellow)':'var(--red)';
                const failed=h.results?.vulnerabilities?.filter(v=>v.status==='Failed').length||0;
                const isHardened=h.target_model?.includes('[HARDENED]');
                return (
                  <div key={h.job_id} className="history-item slide-up" style={{animationDelay:`${i*0.04}s`}}>
                    <div style={{width:36,height:36,borderRadius:8,background:isHardened?'rgba(63,185,80,0.1)':'var(--bg-3)',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0,border:isHardened?'1px solid var(--green)':'none'}}>
                      {isHardened?<Shield size={16} color="var(--green)"/>:<Server size={16} color="var(--blue)"/>}
                    </div>
                    <div>
                      <div className="history-model">{h.target_model}{isHardened && <span className="chip chip-green" style={{marginLeft:6,fontSize:'0.65rem'}}>Hardened</span>}</div>
                      <div className="history-time"><Clock size={10} style={{verticalAlign:'middle',marginRight:3}}/>{new Date(h.completed_at).toLocaleString()}</div>
                    </div>
                    <div style={{marginLeft:'auto',display:'flex',alignItems:'center',gap:16}}>
                      <div>
                        <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}>
                          <div className="bar-bg"><div className="bar-fill" style={{width:`${score}%`,background:barColor}}/></div>
                        </div>
                        <div className="text-xs text-muted">{failed} vuln{failed!==1?'s':''} found</div>
                      </div>
                      <span className={`history-score-pill ${pillCls}`}>{score}/100</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ═══ ANALYTICS TAB ════════════════════════════════════════════════ */}
        {tab === 'analytics' && (
          <div className="page fade-in">
            <div className="page-header">
              <h1 className="page-title">Executive <span className="accent">Analytics</span></h1>
              <p className="page-subtitle">Macro-level AI security posture trends and ML attack intelligence.</p>
            </div>
            {history.length===0 ? (
              <div className="card"><div className="empty-state"><BarChart3 size={40} className="empty-icon"/><h4>No data yet</h4><p>Run scans to populate analytics.</p></div></div>
            ) : (<>
              <div className="analytics-kpi-grid slide-up">
                <div className="kpi-card"><div className="kpi-label"><TrendingUp size={10} style={{marginRight:4}}/>Avg Score</div><div className="kpi-value">{avgScore}</div><div className="kpi-delta">across {history.length} scans</div></div>
                <div className="kpi-card"><div className="kpi-label"><AlertTriangle size={10} style={{marginRight:4}}/>Critical Scans</div><div className="kpi-value" style={{color:'var(--red)'}}>{critScans}</div><div className="kpi-delta" style={{color:'var(--text-2)'}}>score below 50</div></div>
                <div className="kpi-card"><div className="kpi-label"><Cpu size={10} style={{marginRight:4}}/>Total Scans</div><div className="kpi-value">{history.length}</div><div className="kpi-delta">historical records</div></div>
              </div>
              <div className="two-col slide-up delay-1">
                <div className="card">
                  <div className="card-header"><div className="card-title"><TrendingUp size={13}/> Security Score Trend</div></div>
                  <div className="card-body" style={{height:260}}>
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={trendData}>
                        <defs>
                          <linearGradient id="sg" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%"  stopColor="#58a6ff" stopOpacity={0.4}/>
                            <stop offset="95%" stopColor="#58a6ff" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3"/>
                        <XAxis dataKey="time" stroke="#484f58" tick={{fontSize:10}}/>
                        <YAxis domain={[0,100]} stroke="#484f58" tick={{fontSize:10}}/>
                        <Tooltip contentStyle={{background:'var(--bg-2)',border:'1px solid var(--border)',borderRadius:6,fontSize:11}}/>
                        <Area type="monotone" dataKey="score" stroke="#58a6ff" fill="url(#sg)" strokeWidth={2} dot={{fill:'#58a6ff',r:4}}/>
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div className="card">
                  <div className="card-header"><div className="card-title"><Bug size={13}/> Most Exploited Vectors</div></div>
                  <div className="card-body" style={{height:260}}>
                    {heatData.length>0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={heatData} layout="vertical">
                          <CartesianGrid strokeDasharray="3 3" horizontal={false}/>
                          <XAxis type="number" stroke="#484f58" tick={{fontSize:10}}/>
                          <YAxis type="category" dataKey="id" stroke="#484f58" tick={{fontSize:10,fontFamily:'Fira Code'}} width={55}/>
                          <Tooltip contentStyle={{background:'var(--bg-2)',border:'1px solid var(--border)',fontSize:11}} formatter={v=>[v,'Failures']}/>
                          <Bar dataKey="failures" radius={[0,4,4,0]}>
                            {heatData.map((_,i)=><Cell key={i} fill={i===0?'#f85149':i===1?'#f97316':'#e3b341'} fillOpacity={0.8}/>)}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    ) : <div className="empty-state" style={{padding:'40px 0'}}><p>No failures recorded.</p></div>}
                  </div>
                </div>
              </div>
            </>)}
          </div>
        )}
      </main>

      {toast && <Toast message={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
    </div>
  );
}
