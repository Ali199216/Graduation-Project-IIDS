# Intelligent Intrusion Detection System (IIDS) - Technical Implementation Report

## 1. Project Overview
The IIDS is an advanced network security terminal designed to detect, analyze, and mitigate cyber threats in real-time. It combines a multi-stage Machine Learning pipeline with a Generative AI security analyst to provide automated response and human-readable insights.

---

## 2. Core Architecture
The system is built on a **Modular Micro-Services Architecture** using Python:
- **Frontend**: Streamlit (Obsidian Black & Neon Cyan Theme).
- **Backend**: Python 3.13.
- **Intelligence**: 3-Stage ML Pipeline + LangChain ReAct Agent.
- **Database**: SQLite (Data isolation per operator).

---

## 3. The 3-Stage Machine Learning Pipeline
This is the heart of the detection system:
1. **Stage 0 (Anomaly Detection)**: Uses an **Isolation Forest** model to detect statistical deviations in network traffic. It flags "Unseen" patterns that might be zero-day attacks.
2. **Stage 1 (Binary Classification)**: An **XGBoost** model trained to distinguish between Benign (Normal) and Malicious traffic with high precision.
3. **Stage 2 (Attack Classification)**: A multi-class **XGBoost** model that identifies the specific type of attack (e.g., DoS, Exploits, Reconnaissance, Fuzzers, etc.).

---

## 4. AI Security Agent (CyberGuard AI)
Instead of static rules, the system uses an **AI Agent** built with **LangChain & LangGraph**:
- **LLM**: Groq (Llama 3.3 70B) for sub-second reasoning.
- **Reasoning Loop**: Uses the ReAct (Reasoning + Acting) pattern.
- **Capabilities**: The agent can autonomously call Python functions (Tools) to analyze data, block IPs, or search history based on natural language commands.

---

## 5. API Integration Details
The system integrates 4 external APIs to enhance its intelligence:

| API | Implementation Detail | Purpose |
| :--- | :--- | :--- |
| **Groq Cloud API** | Integrated via `ChatGroq` (LangChain). | Powers the AI Analyst's brain and decision-making. |
| **IP-API (REST)** | HTTP JSON requests to `ip-api.com`. | Converts attacker IPs into Geolocation data (Map coordinates). |
| **Telegram Bot API** | Secure POST requests via `requests` library. | Sends instant mobile alerts to security personnel. |
| **Google TTS (gTTS)** | Speech synthesis engine integration. | Provides audible Arabic alerts for eyes-busy environments. |

---

## 6. Key Features & Functionality
### A. Real-Time CSV Monitoring
- Operators can upload network traffic logs (NetFlow/IPFIX).
- The system processes rows sequentially, simulating a live wire-speed feed.
- Visual feedback is provided via progress bars and tactical logs.

### B. Automated Mitigation (Active Shielding)
- When a threat is detected during analysis, the system automatically triggers an **IP Ban**.
- The blocked IP is saved to a persistent "Deny List" in the database.

### C. Threat Visualization & Forensics
- **Global Threat Radar**: An interactive 3D map (PyDeck) showing attack origins.
- **XAI (Explainable AI)**: Uses **SHAP** values to explain *why* the AI flagged a specific flow (e.g., "High Packet Rate").
- **Forensic PDF Generator**: Generates professional executive reports with attack distribution and security recommendations.

### D. Multi-Tenant Security
- Data isolation is enforced at the database level using `user_email`.
- Operators only see alerts and logs associated with their own accounts.

---

## 7. Technical Stack Summary
- **Language**: Python.
- **ML Frameworks**: Scikit-learn, XGBoost.
- **AI Frameworks**: LangChain, LangGraph, Groq.
- **Visualization**: Plotly, PyDeck, Streamlit.
- **Audio/TTS**: gTTS, Pygame.
- **Reporting**: FPDF2.
