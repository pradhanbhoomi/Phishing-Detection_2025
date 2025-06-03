# phishing-detector


 🛡️ Phishing Detection System

This is a backend-powered phishing detection system built using **FastAPI** and **DNSTwist**, designed to help detect typosquatted (phishing) domains and identify hosting providers using **WHOIS lookup**.


🚀 Features

- 🔍 Typosquatting detection using `dnstwist`
- 🌐 WHOIS lookup to identify registrar and abuse contacts
- 📦 REST API built with FastAPI
- 📄 JSON output for frontend or integrations
  

 🛠 Tech Stack

| Tool          | Purpose                          |
|---------------|----------------------------------|
| Python        | Backend logic                    |
| FastAPI       | Web framework (API)              |
| dnstwist      | Typosquatting detection          |
| python-whois  | WHOIS lookup for domain info     |
| Uvicorn       | ASGI server for FastAPI          |


**⚙️ Backend Setup (FastAPI)**

cd backend
python -m venv venv
# Activate virtual environment:
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn main3:app --reload

The API will be available at: http://127.0.0.1:8000

Test endpoints at: http://127.0.0.1:8000/docs



**🌐 Frontend Setup (React)**

cd phishing-frontend
npm install
npm start

The React app will run at: http://localhost:3000

⚠️ Make sure your backend is running on port 8000 while the frontend runs on 3000.


**
🧠 Risk Scoring Logic**

Each malicious vote = +10 points
Each suspicious vote = +5 points
Risk Level:
HIGH ≥ 50
MEDIUM ≥ 20
LOW > 0
MINIMAL = 0



**📤 API Summary**

POST /scan
Scan a URL and return full risk assessment.
**Request Body:**
{ "url": "http://example.com" }

**Response Example:**
{
  "domain": "example.com",
  "risk_assessment": {
    "risk_level": "LOW",
    "risk_score": 10
  },
  "typosquatting": { "count": 2, "examples": [...] },
  "whois": { "registrar": "...", "country": "..." },
  "virustotal": { "malicious_votes": 1, ... }
}



**🔐 VirusTotal API**

You’ll need a VirusTotal API key. Set it using an environment variable:
set VIRUSTOTAL_API_KEY=your_api_key_here

Or hardcode it inside main3.py (not recommended for production).


📚 References

FastAPI
dnstwist
VirusTotal API

