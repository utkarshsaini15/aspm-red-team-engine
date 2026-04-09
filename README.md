# 🛡️ ASPM Red Team Engine v3.0

> **Autonomous AI Security Posture Management — OWASP LLM Top 10 Red Teaming Platform**

An enterprise-grade, autonomous security auditing tool that red-teams LLM deployments against the **OWASP LLM Top 10** vulnerability framework — combining Reinforcement Learning, Genetic Algorithms, Multi-Agent orchestration, Behavioral Anomaly Detection, and Explainable AI into a single real-time dashboard.

---

## 🚀 Live Demo

```
Backend  → http://localhost:8000
Frontend → http://localhost:5173
API Docs → http://localhost:8000/docs
```

---

## 🧠 ML Architecture

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Q-Learning RL Engine** | Custom Q-Table (α=0.15, γ=0.9) | Learns optimal attack strategies per vector |
| **Multi-Agent System** | 5 Specialist Agents | Parallel OWASP vector coverage |
| **Genetic Payload Mutator** | Evolutionary Algorithm | Evolves adversarial prompts across generations |
| **Z-Score Anomaly Detector** | Statistical Baseline | Detects behavioral deviations in LLM responses |
| **XAI Risk Explainer** | SHAP-inspired contributions | Breaks down *why* a score is what it is |

---

## 🔍 OWASP LLM Top 10 Coverage

| ID | Vulnerability | Agent |
|----|--------------|-------|
| LLM01 | Prompt Injection | InjectorAgent |
| LLM02 | Insecure Output Handling | InjectorAgent |
| LLM03 | Training Data Poisoning | SupplyChainAgent |
| LLM04 | Model Denial of Service | DoSAgent |
| LLM05 | Supply Chain Vulnerabilities | SupplyChainAgent |
| LLM06 | Sensitive Information Disclosure | ExtractionAgent |
| LLM07 | Insecure Plugin Design | SupplyChainAgent |
| LLM08 | Excessive Agency / Toxicity | ToxicityAgent |
| LLM09 | Overreliance / Hallucination | ExtractionAgent |
| LLM10 | Model Theft | SupplyChainAgent |

---

## ⚡ Key Features

- **🤖 Autonomous Red Teaming** — No human intervention needed
- **📡 Live Streaming Console** — Real-time attack logs with color-coded RL epochs
- **🔄 Auto-Harden & Verify Loop** — AI generates a hardened system prompt and re-scans automatically
- **📊 Executive Analytics Dashboard** — Score trends, most exploited vectors, KPI cards
- **🧬 Genetic Payload Evolution** — Attack prompts mutate across generations to bypass defenses
- **🧠 XAI Score Breakdown** — Every risk score explained feature-by-feature
- **📈 Before vs After Comparison** — Visual proof of security improvement post-hardening

---

## 🏗️ Tech Stack

**Backend**
- FastAPI + Uvicorn (async API server)
- SQLModel + SQLite (scan job persistence)
- LiteLLM (multi-provider LLM gateway)
- NumPy (statistical anomaly detection)

**Frontend**
- React 18 + Vite
- Recharts (radar, area, bar, line charts)
- Lucide React (icons)
- Axios (API calls)

---

## 🛠️ Setup & Run

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend
```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Start server
uvicorn src.server:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

---

## 🎮 How to Use

1. Open **http://localhost:5173**
2. Enter a **Target Model URI** (e.g. `gpt-4o-customer-bot`)
3. Set **Temperature** (≥ 0.8 = high risk demo)
4. Leave **System Prompt empty** to simulate an unprotected deployment
5. Click **"Initiate Scan"** — watch the RL agents attack live
6. After completion, click **"Auto-Harden & Verify"** to see AI fix itself

---

## 📁 Project Structure

```
├── src/
│   ├── server.py          # FastAPI endpoints
│   ├── models.py          # ScanJob DB model
│   ├── database.py        # SQLite connection
│   ├── scanners.py        # Master scan orchestrator
│   ├── agents.py          # Multi-agent red team system
│   ├── rl_engine.py       # Q-Learning engine
│   ├── payload_mutator.py # Genetic algorithm mutator
│   ├── anomaly.py         # Z-Score anomaly detector
│   └── xai.py             # XAI risk score explainer
├── frontend/
│   └── src/
│       ├── App.jsx        # Main React app
│       └── index.css      # Dark theme design system
└── requirements.txt
```

---

## 🔗 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | API status |
| POST | `/scan/start` | Start a new security scan |
| GET | `/scan/status/{job_id}` | Poll scan progress & results |
| POST | `/scan/harden-and-verify/{job_id}` | Auto-hardening loop |
| GET | `/scans/history` | All completed scans |
| DELETE | `/scans/history` | Clear history |

---

## 👨‍💻 Built For

> **Hackathon 2026** — *AI Security Track*

Demonstrating that **LLM security can and should be automated** — every AI deployment deserves an autonomous red team before going to production.

---

## 📄 License

MIT License — feel free to fork, extend, and build on top of this.
