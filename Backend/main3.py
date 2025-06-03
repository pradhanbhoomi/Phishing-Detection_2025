from fastapi import FastAPI
from pydantic import BaseModel
import subprocess
import json
import whois
import requests
import logging
import asyncio
import sys
import re
import urllib3
from concurrent.futures import ThreadPoolExecutor
import os
from fastapi.middleware.cors import CORSMiddleware
import smtplib
from email.message import EmailMessage

# Disable SSL warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React dev server origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor()

class URLInput(BaseModel):
    url: str

# Load API keys from environment variables for security
# Ensure VIRUSTOTAL_API_KEY and EMAIL_PASSWORD are set in your environment
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "d21878a64a53832f6ef77c4dc4585ba7e2cfb298a022b837af33d1b4381db949")
CA_BUNDLE_PATH = os.getenv("REQUESTS_CA_BUNDLE", None)
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "bhoomi.pradhan@somaiya.edu")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "cgua kqiu yxvv mbux") # Consider using app-specific passwords for security

# Initialize session with SSL configuration
def create_session():
    session = requests.Session()
    
    if CA_BUNDLE_PATH and os.path.exists(CA_BUNDLE_PATH):
        session.verify = CA_BUNDLE_PATH
        logging.info(f"Requests session configured to use CA bundle: {CA_BUNDLE_PATH}")
    else:
        session.verify = True  # Use default verification
        logging.info("Requests session using default SSL verification.")
    
    return session

session = create_session()

# Async wrapper for sync calls
async def run_in_thread(func, *args):
    """
    Runs a synchronous function in a separate thread to avoid blocking the FastAPI event loop.
    """
    return await asyncio.get_event_loop().run_in_executor(executor, lambda: func(*args))

def parse_dnstwist_output(output):
    """
    Parses the text output from dnstwist and converts it into a structured list of dictionaries.
    Filters out irrelevant lines and extracts fuzzer, domain name, and resolved IP addresses.
    """
    lines = output.strip().split('\n')
    domains = []
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines, headers, and separators
        if not line or line.startswith('*') or line.startswith('-') or 'original' in line.lower():
            continue
            
        if any(header in line.lower() for header in ['fuzzer', 'domain-name', 'dns-a', 'dns-aaaa', 'mx', 'country']):
            continue
            
        parts = line.split()
        if len(parts) >= 2:
            try:
                fuzzer = parts[0]
                domain_name = parts[1]
                dns_a = None
                dns_aaaa = None
                
                # Iterate through parts to find IP addresses
                for part in parts[2:]:
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', part):
                        dns_a = part
                        break
                    elif ':' in part and len(part) > 7: # Basic check for IPv6
                        dns_aaaa = part
                        break
                
                if dns_a or dns_aaaa: # Only include domains that resolved to an IP
                    domains.append({
                        "fuzzer": fuzzer,
                        "domain-name": domain_name,
                        "dns-a": dns_a,
                        "dns-aaaa": dns_aaaa
                    })
                    
            except Exception as e:
                logging.debug(f"Failed to parse line: '{line}' - {e}")
                continue
    
    logging.info(f"Parsed {len(domains)} domains from dnstwist output")
    return domains

def detect_typosquats(domain):
    """
    Executes dnstwist to detect typosquatting domains for a given domain.
    This is the comprehensive (and potentially slower) version.
    """
    try:
        logging.info(f"Running dnstwist for: {domain}")
        # Ensure dnstwist_path points to your actual dnstwist.py location
        # It's better to have dnstwist installed globally or in a virtual env path
        dnstwist_path = "c:\\users\\bhoomi\\appdata\\local\\programs\\python\\python312\\lib\\site-packages\\dnstwist.py"
        
        if not os.path.exists(dnstwist_path):
            logging.error(f"dnstwist script not found at: {dnstwist_path}. Please verify the path.")
            return [{"error": f"dnstwist script not found at: {dnstwist_path}"}]

        # Optimized dnstwist command with faster options
        cmd = [
            sys.executable, dnstwist_path, 
            "--threads", "10",  # Use more threads for faster execution
            "--format", "cli",  # Ensure consistent output format
            "--registered",      # Only check registered domains (faster)
            domain
        ]
        
        logging.info(f"Running command: {' '.join(cmd)}")
        
        # Increased timeout and added better process handling
        result = subprocess.run(
            cmd,
            capture_output=True, 
            text=True, 
            check=True,
            timeout=300,  # Increased to 5 minutes
            env=dict(os.environ, PYTHONUNBUFFERED='1')  # Ensure unbuffered output
        )
        
        output = result.stdout.strip()
        if not output:
            logging.warning("dnstwist returned empty output")
            return []
            
        parsed = parse_dnstwist_output(output)
        
        live = [
            {"domain": d["domain-name"], "resolved_to": d.get("dns-a") or d.get("dns-aaaa"), "fuzzer": d["fuzzer"]}
            for d in parsed
        ]
        logging.info(f"Found {len(live)} live typosquat domains")
        return live

    except subprocess.CalledProcessError as e:
        logging.error(f"dnstwist failed. Return code: {e.returncode}")
        logging.error(f"STDOUT: {e.stdout}")
        logging.error(f"STDERR: {e.stderr}")
        return [{"error": f"dnstwist failed: {e.stderr or str(e)}"}]
    except subprocess.TimeoutExpired:
        logging.error(f"dnstwist timed out for domain: {domain} (5 minute limit)")
        return [{"error": "dnstwist timed out - domain analysis took too long"}]
    except Exception as e:
        logging.error(f"Unexpected error in dnstwist for {domain}: {e}", exc_info=True)
        return [{"error": f"dnstwist failed: {str(e)}"}]

def detect_typosquats_fast(domain):
    """
    A faster version of dnstwist execution with a limited set of fuzzing algorithms.
    """
    try:
        logging.info(f"Running fast dnstwist for: {domain}")
        dnstwist_path = "c:\\users\\bhoomi\\appdata\\local\\programs\\python\\python312\\lib\\site-packages\\dnstwist.py"
        
        if not os.path.exists(dnstwist_path):
            logging.error(f"dnstwist script not found at: {dnstwist_path}. Please verify the path.")
            return [{"error": f"dnstwist script not found at: {dnstwist_path}"}]

        # Use only the fastest fuzzing algorithms
        cmd = [
            sys.executable, dnstwist_path,
            "--fuzzers", "addition,omission,repetition,replacement,transposition",  # Limited set
            "--threads", "15",
            "--format", "cli",
            "--registered",
            domain
        ]
        
        logging.info(f"Running fast command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True, 
            text=True, 
            check=True,
            timeout=200,  # 2 minute timeout for fast version
            env=dict(os.environ, PYTHONUNBUFFERED='1')
        )
        
        output = result.stdout.strip()
        if not output:
            logging.warning("Fast dnstwist returned empty output")
            return []
            
        parsed = parse_dnstwist_output(output)
        
        live = [
            {"domain": d["domain-name"], "resolved_to": d.get("dns-a") or d.get("dns-aaaa"), "fuzzer": d["fuzzer"]}
            for d in parsed
        ]
        logging.info(f"Fast scan found {len(live)} live typosquat domains")
        return live

    except subprocess.TimeoutExpired:
        logging.error(f"Fast dnstwist timed out for domain: {domain}")
        return [{"error": "Fast dnstwist scan timed out"}]
    except Exception as e:
        logging.error(f"Error in fast dnstwist for {domain}: {e}", exc_info=True)
        return [{"error": f"Fast dnstwist failed: {str(e)}"}]

def get_whois_info(domain):
    """
    Fetches WHOIS information for a given domain.
    Normalizes the 'emails' field to always be a list.
    """
    try:
        logging.info(f"Fetching WHOIS for: {domain}")
        w = whois.whois(domain)

        # Normalize emails to always be a list
        emails_raw = getattr(w, 'emails', [])
        if isinstance(emails_raw, str):
            emails = [emails_raw]
        else:
            emails = emails_raw if emails_raw is not None else []
        
        return {
            "domain_name": getattr(w, 'domain_name', None),
            "registrar": getattr(w, 'registrar', None),
            "org": getattr(w, 'org', None),
            "country": getattr(w, 'country', None),
            "emails": emails,
            "creation_date": str(getattr(w, 'creation_date', None)),
            "expiration_date": str(getattr(w, 'expiration_date', None)),
            "name_servers": getattr(w, 'name_servers', None)
        }
    except Exception as e:
        logging.error(f"WHOIS error for {domain}: {e}", exc_info=True)
        return {"error": f"whois failed: {str(e)}"}

def check_virustotal(domain):
    """
    Checks the domain's reputation using the VirusTotal API.
    """
    try:
        logging.info(f"Checking VirusTotal for: {domain}")
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        try:
            response = session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
        except requests.exceptions.SSLError:
            logging.warning(f"SSL error for {domain} with default verification. Retrying with verify=False.")
            response = requests.get(url, headers=headers, timeout=10, verify=False) # Fallback for SSL issues
            response.raise_for_status()
        
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        return {
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "undetected_votes": stats.get("undetected", 0),
            "total_votes": sum(stats.values()) if stats else 0,
            "last_analysis_date": attrs.get("last_analysis_date", None)
            # NOTE: threat_names intentionally omitted to keep response concise
        }
        
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code
        if code == 404:
            return {"error": "Domain not found in VirusTotal", "status_code": 404}
        if code == 429:
            return {"error": "VirusTotal rate limit exceeded", "status_code": 429}
        logging.error(f"VirusTotal HTTP error {code} for {domain}: {e.response.text}")
        return {"error": f"HTTP error {code}", "details": e.response.text}
    except requests.exceptions.RequestException as e:
        logging.error(f"VirusTotal connection error for {domain}: {e}")
        return {"error": f"Connection error: {str(e)}"}
    except json.JSONDecodeError as e:
        logging.error(f"VirusTotal invalid JSON response for {domain}: {e}")
        return {"error": f"Invalid JSON response: {str(e)}"}
    except Exception as e:
        logging.error(f"Unexpected error in VirusTotal check for {domain}: {e}", exc_info=True)
        return {"error": f"Unexpected error: {str(e)}"}

def extract_domain(url):
    """
    Extracts the base domain from a given URL.
    """
    domain = url.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    domain = domain.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower()

def compose_abuse_email(domain, whois_info, virustotal_info, risk_level):
    """
    Composes an abuse report email with details about the suspicious domain.
    """
    subject = f"Phishing Alert: Suspicious activity on {domain}"
    body = f"""
Dear Domain Registrar/Abuse Contact,

We are writing to report potential phishing or malicious activity associated with the following domain:

Domain: {domain}
Registrar: {whois_info.get('registrar', 'N/A')}
Organization: {whois_info.get('org', 'N/A')}
Country: {whois_info.get('country', 'N/A')}
Creation Date: {whois_info.get('creation_date', 'N/A')}
Expiration Date: {whois_info.get('expiration_date', 'N/A')}
Name Servers: {', '.join(whois_info.get('name_servers', ['N/A']))}

Risk Assessment:
  Risk Level: {risk_level}
  VirusTotal Malicious Detections: {virustotal_info.get('malicious_votes', 0)}
  VirusTotal Suspicious Detections: {virustotal_info.get('suspicious_votes', 0)}
  Last Analysis Date (VirusTotal): {virustotal_info.get('last_analysis_date', 'N/A')}

We urge you to investigate this domain promptly in accordance with your abuse policies and take appropriate action to mitigate any threats.

Thank you for your cooperation.

Regards,  
Automated Phishing Detection System
Contact: {SENDER_EMAIL}
"""
    return subject, body

def send_email(recipient, subject, body):
    """
    Sends an email using SMTP_SSL.
    Requires SENDER_EMAIL and EMAIL_PASSWORD environment variables to be set.
    """
    msg = EmailMessage()
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, EMAIL_PASSWORD)
            smtp.send_message(msg)
        logging.info(f"✅ Abuse email successfully sent to {recipient}")
    except Exception as e:
        logging.error(f"❌ Failed to send email to {recipient}: {e}", exc_info=True)

@app.get("/")
async def root():
    """Root endpoint for API health check and version info."""
    return {"message": "Domain Security Scanner API", "version": "1.0", "status": "active"}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"}

@app.post("/scan")
async def scan_url(data: URLInput):
    """
    Performs a domain security scan including typosquatting, WHOIS, and VirusTotal checks.
    Automatically sends an abuse email if a high-risk domain is detected.
    """
    url = data.url.strip()
    domain = extract_domain(url)
    if not domain:
        logging.error(f"Invalid URL or domain provided: {url}")
        return {"error": "Invalid URL or domain"}

    logging.info(f"Starting scan for {domain}")

    # Run all checks concurrently
    typos_task = run_in_thread(detect_typosquats_fast, domain) # Start with fast scan
    whois_task = run_in_thread(get_whois_info, domain)
    vt_task = run_in_thread(check_virustotal, domain)

    typos, whois_info, vt_info = await asyncio.gather(typos_task, whois_task, vt_task)
    
    # If fast scan failed with timeout, log and indicate to user
    if isinstance(typos, list) and len(typos) == 1 and "error" in typos[0] and "timed out" in typos[0]["error"]:
        logging.warning(f"Fast scan timed out for {domain}. This domain might have too many variations.")
        # Keep the error message for the client
    
    # Simple risk scoring
    risk_score = vt_info.get("malicious_votes", 0) * 10 + vt_info.get("suspicious_votes", 0) * 5
    risk_level = (
        "HIGH" if risk_score >= 50 else
        "MEDIUM" if risk_score >= 20 else
        "LOW" if risk_score > 0 else
        "MINIMAL"
    )

    # Automatic email sending for high-risk domains
    if risk_level == "HIGH":
        recipient_email = None
        if whois_info and whois_info.get('emails'):
            # Iterate through emails to find a valid one, prioritizing abuse contacts if logic was added
            for email in whois_info['emails']:
                if isinstance(email, str) and re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    recipient_email = email
                    break # Take the first valid email found
        
        if recipient_email:
            logging.info(f"High risk detected for {domain}. Attempting to send abuse email to {recipient_email}")
            subject, body = compose_abuse_email(domain, whois_info, vt_info, risk_level)
            try:
                await run_in_thread(send_email, recipient_email, subject, body)
                logging.info(f"Abuse email successfully triggered for {domain} to {recipient_email}")
            except Exception as email_e:
                logging.error(f"Failed to send abuse email for {domain} to {recipient_email}: {email_e}")
        else:
            logging.warning(f"High risk detected for {domain}, but no valid recipient email found in WHOIS info to send abuse report.")
    else:
        logging.info(f"Risk level for {domain} is {risk_level}. No abuse email triggered.")

    return {
        "message": "Scan complete",
        "url": url,
        "domain": domain,
        "risk_assessment": {"risk_level": risk_level, "risk_score": risk_score},
        "typosquatting": {"count": len(typos) if not (isinstance(typos, list) and len(typos) == 1 and "error" in typos[0]) else 0, "examples": typos[:10]},
        "whois": whois_info,
        "virustotal": vt_info
    }

@app.post("/scan/full")
async def scan_url_full(data: URLInput):
    """
    Full comprehensive scan - may take longer due to broader dnstwist fuzzing.
    """
    url = data.url.strip()
    domain = extract_domain(url)
    if not domain:
        logging.error(f"Invalid URL or domain provided for full scan: {url}")
        return {"error": "Invalid URL or domain"}

    logging.info(f"Starting full scan for {domain}")

    typos_task = run_in_thread(detect_typosquats, domain)  # Use full version
    whois_task = run_in_thread(get_whois_info, domain)
    vt_task = run_in_thread(check_virustotal, domain)

    typos, whois_info, vt_info = await asyncio.gather(typos_task, whois_task, vt_task)

    risk_score = vt_info.get("malicious_votes", 0) * 10 + vt_info.get("suspicious_votes", 0) * 5
    risk_level = (
        "HIGH" if risk_score >= 50 else
        "MEDIUM" if risk_score >= 20 else
        "LOW" if risk_score > 0 else
        "MINIMAL"
    )
    
    # Automatic email sending for high-risk domains (same logic as /scan)
    if risk_level == "HIGH":
        recipient_email = None
        if whois_info and whois_info.get('emails'):
            for email in whois_info['emails']:
                if isinstance(email, str) and re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    recipient_email = email
                    break
        
        if recipient_email:
            logging.info(f"High risk detected (full scan) for {domain}. Attempting to send abuse email to {recipient_email}")
            subject, body = compose_abuse_email(domain, whois_info, vt_info, risk_level)
            try:
                await run_in_thread(send_email, recipient_email, subject, body)
                logging.info(f"Abuse email successfully triggered (full scan) for {domain} to {recipient_email}")
            except Exception as email_e:
                logging.error(f"Failed to send abuse email (full scan) for {domain} to {recipient_email}: {email_e}")
        else:
            logging.warning(f"High risk detected (full scan) for {domain}, but no valid recipient email found in WHOIS info to send abuse report.")
    else:
        logging.info(f"Risk level for {domain} (full scan) is {risk_level}. No abuse email triggered.")

    return {
        "message": "Full scan complete",
        "url": url,
        "domain": domain,
        "risk_assessment": {"risk_level": risk_level, "risk_score": risk_score},
        "typosquatting": {"count": len(typos) if not (isinstance(typos, list) and len(typos) == 1 and "error" in typos[0]) else 0, "examples": typos[:10]},
        "whois": whois_info,
        "virustotal": vt_info
    }

@app.post("/test/{component}")
async def test_component(component: str, data: URLInput):
    """
    Endpoint to test individual components of the scanner (dnstwist, whois, virustotal).
    """
    domain = extract_domain(data.url.strip())
    if not domain:
        return {"error": "Invalid URL or domain"}

    result = {"error": "Invalid component. Use: dnstwist, whois, or virustotal"}
    if component == "dnstwist":
        result = await run_in_thread(detect_typosquats, domain)
    elif component == "whois":
        result = await run_in_thread(get_whois_info, domain)
    elif component == "virustotal":
        result = await run_in_thread(check_virustotal, domain)
    
    return {"component": component, "domain": domain, "result": result}

if __name__ == "__main__":
    import uvicorn
    # Ensure your environment variables VIRUSTOTAL_API_KEY, SENDER_EMAIL, and EMAIL_PASSWORD are set
    # Example:
    # export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
    # export SENDER_EMAIL="your_email@gmail.com"
    # export EMAIL_PASSWORD="your_app_password" # For Gmail, use an App Password, not your regular password
    uvicorn.run(app, host="0.0.0.0", port=8000)
