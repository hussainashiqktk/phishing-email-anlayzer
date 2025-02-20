from flask import Flask, request, render_template, jsonify
import email
import re
import os
import requests
from email import policy
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# API keys from environment variables
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Check if API keys are loaded
if not VIRUSTOTAL_API_KEY or not ABUSEIPDB_API_KEY:
    raise ValueError("API keys not found in .env file. Please set VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY.")

# Directory to store uploaded email files temporarily
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to extract domain from an email address
def extract_domain(email_address):
    match = re.search(r'@([\w.-]+)', email_address)
    return match.group(1) if match else None

# Function to extract IPs from Received headers
def extract_ips_from_headers(headers):
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = []
    for received in headers.get_all("Received", []):
        matches = ip_pattern.findall(received)
        for ip in matches:
            if not (ip.startswith('192.168.') or ip.startswith('10.') or 
                    ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
                ips.append(ip)
    return list(set(ips))

# Function to check URL with VirusTotal
def check_virustotal(url):
    try:
        vt_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        payload = {"url": url}
        response = requests.post(vt_url, headers=headers, data=payload)
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                result = analysis_response.json()["data"]["attributes"]["stats"]
                return {
                    "malicious": result.get("malicious", 0),
                    "suspicious": result.get("suspicious", 0),
                    "harmless": result.get("harmless", 0)
                }
        return {"error": "VirusTotal scan failed"}
    except Exception as e:
        return {"error": str(e)}

# Function to check URL with ThreatCrowd
def check_threatcrowd(url):
    try:
        tc_url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={urlparse(url).netloc}"
        response = requests.get(tc_url)
        if response.status_code == 200:
            data = response.json()
            return {
                "votes": data.get("votes", 0),
                "malicious": "Reported" if data.get("votes", 0) < 0 else "Not reported"
            }
        return {"error": "ThreatCrowd scan failed"}
    except Exception as e:
        return {"error": str(e)}

# Function to check IP with AbuseIPDB
def check_abuseipdb(ip):
    try:
        abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        response = requests.get(abuse_url, headers=headers)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "is_whitelisted": data.get("isWhitelisted", False)
            }
        return {"error": "AbuseIPDB scan failed"}
    except Exception as e:
        return {"error": str(e)}

# Function to parse and analyze the raw email file
def parse_email(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f, policy=policy.default)
    except Exception as e:
        return {"error": f"Failed to parse email: {str(e)}"}

    # Extract headers
    headers = {
        "From": msg.get("From", "Not found"),
        "Header.From": msg.get("header.from", "Not found"),
        "X-Original-Sender": msg.get("X-Original-Sender", "Not found"),
        "X-Original-From": msg.get("X-Original-From", "Not found"),
        "Received": msg.get_all("Received", ["Not found"])[-1],
        "Received-SPF": msg.get("Received-SPF", "Not found"),
        "Authentication-Results": msg.get("Authentication-Results", "Not found")
    }

    # Extract IPs from all Received headers
    received_ips = extract_ips_from_headers(msg)

    # Extract body and URLs
    body = ""
    urls = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    urls = url_pattern.findall(body)

    # Extract attachments
    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)

    # Analysis dictionary
    analysis = {}

    # Header Analysis for Spoofing
    from_field = headers["From"]
    from_domain = extract_domain(from_field) if from_field != "Not found" else None
    from_match = (
        (from_field == headers["Header.From"] or headers["Header.From"] == "Not found") and
        (from_field == headers["X-Original-Sender"] or headers["X-Original-Sender"] == "Not found")
    )
    analysis["from_match"] = "Matches" if from_match else "Mismatch detected (potential spoofing)"

    x_original_from_domain = extract_domain(headers["X-Original-From"]) if headers["X-Original-From"] != "Not found" else None
    received_domain = re.search(r'from\s+[\w.-]+\s+\((.*?)\)', headers["Received"])
    received_domain = received_domain.group(1) if received_domain else None
    domain_match = True
    if from_domain:
        if x_original_from_domain and from_domain != x_original_from_domain:
            domain_match = False
        if received_domain and from_domain not in received_domain:
            domain_match = False
    analysis["domain_match"] = "Matches" if domain_match else "Mismatch detected (potential spoofing)"

    spf_status = headers["Received-SPF"]
    auth_results = headers["Authentication-Results"]
    spf_pass = "pass" in spf_status.lower() if spf_status != "Not found" else False
    dmarc_pass = "dmarc=pass" in auth_results.lower() if auth_results != "Not found" else False
    analysis["spf_status"] = "PASS" if spf_pass else "FAIL or Not found"
    analysis["dmarc_status"] = "PASS" if dmarc_pass else "FAIL or Not found"
    analysis["spoofing_verdict"] = (
        "Likely spoofed" if not (from_match and domain_match and spf_pass and dmarc_pass)
        else "No spoofing detected"
    )

    # URL Analysis
    url_analysis = {}
    suspicious_urls = 0
    for url in urls:
        vt_result = check_virustotal(url)
        tc_result = check_threatcrowd(url)
        is_suspicious = (
            vt_result.get("malicious", 0) > 0 or
            vt_result.get("suspicious", 0) > 0 or
            tc_result.get("votes", 0) < 0
        )
        if is_suspicious:
            suspicious_urls += 1
        url_analysis[url] = {
            "VirusTotal": vt_result,
            "ThreatCrowd": tc_result,
            "suspicious": is_suspicious
        }
    analysis["suspicious_url_count"] = suspicious_urls

    # IP Analysis with AbuseIPDB
    ip_analysis = {}
    suspicious_ips = 0
    for ip in received_ips:
        abuse_result = check_abuseipdb(ip)
        is_suspicious = abuse_result.get("abuse_confidence_score", 0) > 25
        if is_suspicious:
            suspicious_ips += 1
        ip_analysis[ip] = {
            "AbuseIPDB": abuse_result,
            "suspicious": is_suspicious
        }
    analysis["suspicious_ip_count"] = suspicious_ips

    # Basic Phishing Indicators
    analysis["suspicious_headers"] = "Reply-To differs from From" if msg.get("Reply-To") != from_field and msg.get("Reply-To") else "No header anomalies"
    analysis["url_count"] = len(urls)
    analysis["attachment_count"] = len(attachments)
    analysis["potential_phishing"] = "Possible phishing" if urls or attachments or suspicious_urls > 0 or suspicious_ips > 0 else "No obvious phishing signs"

    return {
        "headers": headers,
        "body_preview": body[:500] + "..." if len(body) > 500 else body,
        "urls": urls,
        "url_analysis": url_analysis,
        "received_ips": received_ips,
        "ip_analysis": ip_analysis,
        "attachments": attachments,
        "analysis": analysis
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if file and file.filename.endswith('.eml'):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        result = parse_email(file_path)
        
        os.remove(file_path)
        return jsonify(result)
    else:
        return jsonify({"error": "Invalid file format. Please upload a .eml file"}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)