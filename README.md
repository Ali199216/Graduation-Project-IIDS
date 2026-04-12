# 🛡️ Intelligent Intrusion Detection System (IIDS)

<div align="center">
  <p><strong>Advanced System Operations Center (SOC) Dashboard & AI-Powered Threat Analysis</strong></p>
</div>

## 📌 Project Overview
The **Intelligent Intrusion Detection System (IIDS)** is a modern, production-grade cybersecurity platform. It combines a rigorous multi-stage Machine Learning pipeline with an advanced Agentic AI system (powered by LangGraph and Groq) to provide real-time threat intelligence, network anomaly detection, and automated incident response within a professional SIEM/SOC interface.

## ✨ Key Features

### 1. 🤖 AI Security Analyst (LangGraph Agent)
- **Conversational Interface:** Interact with an AI Analyst (Llama 3.3 70B via Groq) to investigate network behavior.
- **Custom Cyber Tools:** The AI autonomously uses integrated tools to scan flow data, analyze packet properties, and enact firewall-level blocking.
- **Explainable AI:** Agent's reasoning, tool execution, and context logs are fully transparent to the operator.

### 2. 🧠 Multi-Stage Machine Learning Pipeline
The detection engine operates across three distinct AI layers:
- **Stage 0: Unsupervised Anomaly Detection:** (Isolation Forest) trained purely on benign traffic to flag previously unseen anomalous network payloads.
- **Stage 1: Binary Threat Classification:** (XGBoost/Random Forest) discriminates strictly between **Benign** and **Malicious** telemetry.
- **Stage 2: Multiclass Attack Profiling:** If malicious traffic is identified, this model isolates the exact attack vector (e.g., Exploits, Backdoor, DoS, Worms).

### 3. 🖥️ Professional SOC Command Dashboard
- **Live Security Alerts:** High-contrast, severity-coded (CRITICAL, HIGH, NORMAL) scrolling event feed.
- **Control Center Panel:** Fast action controls for batch analysis, IP un-blocking, and Emergency Mode isolation.
- **Threat Analytics:** Modern Plotly & Altair-based visual analysis of attack signatures and predictive heuristic feature importance.
- **Dark Neon Cyber Theme:** Modern aesthetic UI modeled after enterprise SIEM platforms.

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Ali199216/IIDS.git
cd IIDS
```

### 2. Configure Environment Variables
You must provide a `GROQ_API_KEY` to utilize the AI Agent. Create a `.env` file in the root directory:
```env
GROQ_API_KEY=your_groq_api_key_here
```

### 3. Install Dependencies
Ensure you have Python 3.10+ installed.
```bash
pip install -r requirements.txt
```

### 4. Setup Data (Optional / For full evaluation)
Download the `NF-UNSW-NB15-v2` dataset and place it inside the `data/` directory. If missing, the app defaults to a generated sample pool.

### 5. Launch the Command Dashboard
Start the modernized Streamlit architecture:
```bash
streamlit run src/agent_app.py
```

---

## 📁 Architecture & Directory Structure
```
IIDS/
│
├─ data/                   # Dataset & telemetry payloads (.csv)
├─ evaluation/             # Model validation & benchmarking logic
├─ models/                 # Pre-compiled AI weights (.pkl)
├─ results/                # Post-analysis results & hyperparameters
├─ src/
│   ├─ agent/
│   │   ├─ agent.py        # LangGraph AI Architect & ReAct Pipeline
│   │   ├─ tools.py        # Network toolkit accessible by the LLM
│   │   └─ models_loader.py# Singleton ML Model loader for performance
│   │
│   ├─ agent_app.py        # 🚀 Main entry point - Streamlit SOC Interface
│   ├─ config.py           # Network features & global constants
│   ├─ preprocessing.py    # Pipeline sanitization mapping
│   └─ train_stage*.py     # Autonomous training scripts for Stage 0-2
│
├─ .env                    # Secrets & API Keys
├─ requirements.txt        # Backend dependencies
└─ README.md               # Architecture documentation
```

---

## 🔐 Disclaimer
This project is an academic simulation of a mature Intrusion Detection framework. The ML predictions and autonomous AI routing should not be used defensively on production networks without secondary vetting.