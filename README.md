# Email Header Analyzer

A full-stack web application that analyzes raw email headers to detect spoofing and phishing attempts. It independently verifies SPF, DKIM, and DMARC authentication (rather than trusting header claims alone), reconstructs the delivery path with IP geolocation, and produces an explainable risk score.

**Live demo:** https://email-header-analyzer-five.vercel.app

## Features

- Paste raw headers or upload a `.eml` file
- Full `Received:` chain reconstruction with hop-by-hop delay analysis
- Independent SPF, DKIM, and DMARC verification via live DNS lookups and cryptographic signature checking (not just trusting the `Authentication-Results` header, which can itself be forged)
- IP geolocation for each hop, with an interactive map view
- Weighted, explainable risk scoring (0-100) with a transparent breakdown of every signal that contributed to the score
- Brand impersonation detection (display-name spoofing of well-known services)
- Return-Path / Reply-To / From domain mismatch detection

## Tech Stack

**Backend:** Python, FastAPI, `dnspython`, `dkimpy`
**Frontend:** React (Vite), Leaflet for maps
**Deployment:** Render (backend), Vercel (frontend)

## Project Structure
email-header-analyzer/
├── backend/
│ ├── app/
│ │ ├── parsers/ # Raw header parsing, Received-chain reconstruction
│ │ ├── analyzers/ # SPF/DKIM/DMARC verification, risk scoring
│ │ ├── models/ # Pydantic schemas (API contract)
│ │ ├── utils/ # IP geolocation
│ │ └── main.py # FastAPI app and endpoints
│ └── tests/
│ ├── samples/ # Labeled legit/phishing email samples
│ └── test_accuracy.py # Accuracy/precision/recall test harness
└── frontend/
└── src/
├── App.jsx
└── components/ # ResultsDashboard, HopMap


## Running Locally

**Backend:**
```bash
cd backend
python -m venv venv
venv\Scripts\Activate.ps1   # Windows; use `source venv/bin/activate` on Mac/Linux
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173`.

## Accuracy

Run the labeled test suite:
```bash
cd backend
python -m tests.test_accuracy
```

This validates the risk-scoring logic against a labeled set of legitimate and phishing email samples, reporting accuracy, precision, recall, and F1 score.

## Methodology Note

DKIM/SPF/DMARC results are verified independently rather than trusted from the `Authentication-Results` header alone, since that header can itself be forged by a malicious relay. The risk scoring engine is intentionally rule-based rather than a black-box ML model, so every point in the final score is traceable to a specific, human-readable signal.