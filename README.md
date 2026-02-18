# Web Vulnerability Scanner

A professional, high-performance web security scanner integrated with Gemini AI for deep vulnerability analysis. This tool automates the process of finding security flaws and provides AI-driven remediation steps, business impact analysis, and verification guides.

## Key Features

### 1. Smart Vulnerability Scanning
- **Automated Discovery**: Scans for common web vulnerabilities including XSS, SQL Injection, Security Headers, and Sensitive File Exposure.
- **Fast Execution**: Optimized core for rapid scanning without compromising depth.
- **Real-time Streaming**: Watch findings appear instantly via Server-Sent Events (SSE).

### 2. Advanced AI Analysis (powered by Gemini)
- **Multi-Model Support**: Automatically cycles through Gemini 2.5 Flash, 1.5 Flash, and Pro models for maximum reliability.
- **API Key Rotation**: Robust logic to manage up to 10+ API keys with auto-rotation on quota exhaustion (429) or failures.
- **Detailed Reporting**: AI-generated reports including:
    - Severity & Risk Rating
    - Exploit Summary
    - Business Impact Analysis
    - Remediation & Fix Steps
    - Verification Guides

### 3. Modern & Flexible UI
- **Premium Dark Theme**: Sleek Indigo-Violet aesthetic with glassmorphism effects.
- **Dynamic AI Window**: A movable and resizable analysis window that stays pinned while you browse results.
- **Professional Mobile UI**: Optimized "Bottom-Sheet" interface for mobile devices with focused reading mode.
- **Interactive Charts**: Visual breakdown of findings by severity using Chart.js.

## Tech Stack
- **Backend**: Python (Flask)
- **AI**: Google Generative AI (Gemini)
- **Frontend**: HTML5, Vanilla CSS3, JavaScript (ES6+)
- **Analysis**: Marked.js (Markdown), Chart.js (Visualization)

## Setup Instructions

### 1. Prerequisites
- Python 3.8+
- One or more [Google AI Studio API Keys](https://aistudio.google.com/)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/Gourav1612/WebScanner
cd web-scanner

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration
Create a `.env` file in the root directory and add your API keys:
```env
API_KEY=your_key_here
API_KEY1=your_key_2
API_KEY2=your_key_3
# ... add up to API_KEY10
```

### 4. Running the App
```bash
python application.py
```
Open your browser and navigate to `http://127.0.0.1:5000`.

## Security Disclaimer
This tool is for educational and authorized security testing purposes only. Usage against targets without prior written consent is illegal. The developers assume no liability for misuse or damage caused by this program.
