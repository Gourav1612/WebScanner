# Web Scanner (Flask + Gemini AI)

A powerful web vulnerability scanner with AI-powered analysis, built with Flask and Google Gemini.

## Features
- **AI Analysis**: Uses Gemini AI to explain vulnerabilities and suggest fixes.
- **Advanced Scanning**: Checks for SQL Injection, WAFs, and common misconfigurations.
- **Modern UI**: Dark theme, responsive design, charts, and filtering.
- **Reporting**: Export results to CSV and HTML.

## Setup Locally
1. Clone the repo.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file with your Gemini API key:
   ```
   API_KEY=your_gemini_api_key_here
   ```
4. Run the app:
   ```bash
   python application.py
   ```

## Deploy to Render.com
1. Push this code to GitHub.
2. Create a new **Web Service** on Render.
3. Connect your GitHub repository.
4. Use the following settings:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn application:application`
5. **Important**: Add your `API_KEY` in the **Environment Variables** section on Render.

## Project Structure
```
📂 gaurav
│
├── 📜 application.py       # Main Flask Application (Backend)
├── 📜 scanner_core.py      # Core Scanning Logic & Checks
├── 📜 requirements.txt     # Dependencies
├── 📜 Procfile             # Render Deployment Config
├── 📜 .env                 # API Keys (Not in Repo)
│
├── 📂 templates
│   └── 📜 index.html       # Frontend UI
│
└── 📂 static
    └── 📜 style.css        # Frontend Styles
```
