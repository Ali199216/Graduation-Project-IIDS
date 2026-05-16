# Intelligent Intrusion Detection System (IIDS) - Complete Project Documentation
## Graduation Project Report | Academic Year 2023-2024

---

## 1. Abstract
The Intelligent Intrusion Detection System (IIDS) is a state-of-the-art cybersecurity platform that merges advanced Machine Learning (ML) techniques with Large Language Models (LLMs) to detect and mitigate network threats. By utilizing a three-stage ML pipeline alongside an autonomous AI agent, the system provides high-precision detection, real-time mitigation, and human-readable forensic insights.

---

## 2. Introduction
### 2.1 Problem Statement
Modern cyber threats are evolving beyond the capabilities of traditional rule-based Intrusion Detection Systems (IDS). Zero-day attacks and complex multi-vector threats require a more adaptive and intelligent approach.
### 2.2 Objectives
*   Develop a multi-layer ML pipeline for anomaly and attack detection.
*   Integrate a Generative AI agent for autonomous threat analysis.
*   Provide a high-fidelity Security Operations Center (SOC) dashboard.
*   Implement real-time mitigation and forensic reporting.

---

## 3. System Architecture
The system follows a modular architecture consisting of the following layers:

### 3.1 Data Acquisition Layer
Supports ingestion of network flow data in CSV format (NetFlow/IPFIX). Features are cleaned and preprocessed using a standardized pipeline defined in `preprocessing.py`.

### 3.2 The 3-Stage Machine Learning Pipeline
1.  **Stage 0: Anomaly Detection (Isolation Forest):** Detects deviations from baseline benign traffic.
2.  **Stage 1: Binary Classification (XGBoost):** Classifies traffic as Benign or Malicious.
3.  **Stage 2: Multi-class Classification (XGBoost):** Identifies the specific attack type (e.g., DoS, Exploits, Backdoor).

### 3.3 Intelligence Layer (CyberGuard AI Agent)
The agent is built using **LangGraph** and **LangChain**, utilizing the **Llama 3.3 70B** model. It uses the **ReAct** (Reasoning + Acting) loop to:
*   Analyze network flows via ML tools.
*   Execute security commands (Blocking/Unblocking IPs).
*   Search historical attack logs for patterns.

---

## 4. Technical Implementation

### 4.1 Feature Selection
The system utilizes 10 primary network features for real-time analysis:
*   `L4_SRC_PORT`, `L4_DST_PORT`, `PROTOCOL`, `L7_PROTO`
*   `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`
*   `TCP_FLAGS`, `FLOW_DURATION_MILLISECONDS`

### 4.2 Database Schema
The system uses a unified database layer supporting both **SQLite** and **PostgreSQL**.
*   **attack_logs:** Stores detailed information about every detected threat.
*   **blocked_ips:** Maintains a persistent list of banned source addresses.
*   **users:** Manages multi-tenant authentication and profile settings.
*   **analysis_sessions:** Tracks historical data analysis sessions for playback.

### 4.3 External API Integrations
*   **Groq Cloud:** LLM inference for the AI Agent.
*   **IP-API:** Geolocation lookup for attacker IP addresses.
*   **Telegram Bot API:** Mobile push notifications for critical alerts.
*   **Google Text-to-Speech (gTTS):** Audible security alerts.

---

## 5. Advanced System Features

### 5.1 Real-Time 3D Threat Visualization
The system features a **Global Threat Radar** built with **PyDeck**. 
*   **Geolocation Logic:** When a threat is detected, the system extracts the source IP and queries the **IP-API** service to obtain city, country, and GPS coordinates (Latitude/Longitude).
*   **3D Visualization:** An interactive map displays arcs or scatter points representing attack origins. This allows operators to visualize attack clusters and identify geographical threat hotspots.

### 5.2 Multichannel Alerting System
To ensure zero-latency response, the IIDS implements a redundant alerting strategy:

#### 5.2.1 Telegram Bot Integration
The system is integrated with the **Telegram Bot API** to provide mobile push notifications.
*   **Persistence:** Operator bot credentials (Token and Chat ID) are stored securely in the database per user account.
*   **Content:** Alerts include the attack type, source IP, severity level, and a link to the dashboard for immediate action.

#### 5.2.2 Arabic Voice Notification System
Designed for "eyes-busy" environments, the system features a voice alert module:
*   **Synthesis:** Uses **gTTS (Google Text-to-Speech)** to generate natural-sounding Arabic alerts.
*   **Playback:** Integrated with **Pygame** to play alerts in a non-blocking background thread.
*   **Example Alert:** "Warning: Critical threat detected from IP address 192.168.1.10. Action: Source IP has been automatically blocked."

### 5.3 Explainable AI (XAI) with SHAP
To bridge the gap between black-box ML models and human operators, IIDS utilizes **SHAP (SHapley Additive exPlanations)**.
*   **Logic:** For every malicious detection, the system calculates feature importance values.
*   **Utility:** Operators can see exactly which parameters (e.g., high packet rate or specific TCP flags) led the AI to flag the traffic, increasing trust and forensic accuracy.

---

## 6. Security Operations Center (SOC) Terminal
The dashboard is built with **Streamlit** and serves as the central command hub:
*   **Tactical Live Log:** A real-time scrolling feed with color-coded severity markers (Critical=Red, High=Orange, Normal=Green).
*   **Automated Mitigation (Active Shielding):** A toggleable feature that automatically updates the firewall/database deny-list when Stage 1 or 2 models confirm a high-probability threat.
*   **Session Playback:** Allows operators to reload historical analysis sessions to review past incidents and model performance.

---

## 7. Database & Multi-Tenancy Architecture
The IIDS is designed as a **Multi-Tenant System**, ensuring high-level security for enterprise environments:
*   **Row-Level Isolation:** All attack logs, blocked IPs, and session data are indexed by `user_email`. Operators can only access and manage data associated with their own authenticated session.
*   **Unified Driver:** The `db_utils.py` module implements a wrapper that allows the system to switch between **SQLite** (for local development) and **PostgreSQL** (for production/cloud deployment) without code changes.

---

## 8. Evaluation & Results
### 8.1 Performance Metrics
The models were evaluated on the **UNSW-NB15** dataset, achieving the following:
*   **Stage 1 Accuracy:** > 98% (Binary classification).
*   **Stage 2 F1-Score:** > 92% (Multi-class attack profiling).
*   **Detection Latency:** < 50ms per flow, enabling wire-speed simulation.

---

## 9. Installation & User Manual
1.  **Authentication:** Login with authorized credentials to access the SOC terminal.
2.  **Configuration:** Configure your Telegram Bot Token and Chat ID in the "Account Profile" section for persistent mobile alerts.
3.  **Monitoring:** Upload a CSV file to start the real-time detection simulation.
4.  **AI Chat:** Use the "CyberGuard Chat" sidebar to ask the AI about network health or to request manual IP blocks.
5.  **Reporting:** Generate an executive forensic PDF summary after each analysis session.

---

## 10. Conclusion & Future Work
The IIDS project successfully demonstrates the synergy between traditional ML and modern Generative AI. Future enhancements include:
*   Integration with live Linux/Windows kernel packet sniffing.
*   Support for automated Firewall rule generation (iptables/uwp).
*   Distributed multi-node detection support.

---
*Developed by: IIDS Engineering Team*
