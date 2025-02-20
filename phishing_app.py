from flask import Flask, request, render_template, jsonify
import email
import re
import os
from email import policy
from urllib.parse import urlparse

app = Flask(__name__)

# Directory to store uploaded email files temporarily
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to extract domain from an email address
def extract_domain(email_address):
    match = re.search(r'@([\w.-]+)', email_address)
    return match.group(1) if match else None

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
        "Header.From": msg.get("header.from", "Not found"),  # Rarely used, but included for completeness
        "X-Original-Sender": msg.get("X-Original-Sender", "Not found"),
        "X-Original-From": msg.get("X-Original-From", "Not found"),
        "Received": msg.get_all("Received", ["Not found"])[-1],  # Last Received header
        "Received-SPF": msg.get("Received-SPF", "Not found"),
        "Authentication-Results": msg.get("Authentication-Results", "Not found")
    }

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

    # Header Analysis for Spoofing
    analysis = {}
    
    # 1. Check if "From" matches "Header.From" or "X-Original-Sender"
    from_field = headers["From"]
    header_from = headers["Header.From"]
    x_original_sender = headers["X-Original-Sender"]
    from_domain = extract_domain(from_field) if from_field != "Not found" else None
    
    from_match = (
        (from_field == header_from or header_from == "Not found") and
        (from_field == x_original_sender or x_original_sender == "Not found")
    )
    analysis["from_match"] = "Matches" if from_match else "Mismatch detected (potential spoofing)"

    # 2. Check domain of "From" against "X-Original-From" and "Received: from"
    x_original_from = headers["X-Original-From"]
    received = headers["Received"]
    x_original_from_domain = extract_domain(x_original_from) if x_original_from != "Not found" else None
    received_domain = re.search(r'from\s+[\w.-]+\s+\((.*?)\)', received)
    received_domain = received_domain.group(1) if received_domain else None

    domain_match = True
    if from_domain:
        if x_original_from_domain and from_domain != x_original_from_domain:
            domain_match = False
        if received_domain and from_domain not in received_domain:
            domain_match = False
    analysis["domain_match"] = "Matches" if domain_match else "Mismatch detected (potential spoofing)"

    # 3. Check SPF and DMARC
    spf_status = headers["Received-SPF"]
    auth_results = headers["Authentication-Results"]
    spf_pass = "pass" in spf_status.lower() if spf_status != "Not found" else False
    dmarc_pass = "dmarc=pass" in auth_results.lower() if auth_results != "Not found" else False
    
    analysis["spf_status"] = "PASS" if spf_pass else "FAIL or Not found"
    analysis["dmarc_status"] = "PASS" if dmarc_pass else "FAIL or Not found"

    # 4. Spoofing conclusion
    analysis["spoofing_verdict"] = (
        "Likely spoofed" if not (from_match and domain_match and spf_pass and dmarc_pass)
        else "No spoofing detected"
    )

    # Basic phishing indicators
    analysis["suspicious_headers"] = "Reply-To differs from From" if msg.get("Reply-To") != from_field and msg.get("Reply-To") else "No header anomalies"
    analysis["url_count"] = len(urls)
    analysis["attachment_count"] = len(attachments)
    analysis["potential_phishing"] = "Possible phishing" if urls or attachments else "No obvious phishing signs"

    return {
        "headers": headers,
        "body_preview": body[:500] + "..." if len(body) > 500 else body,
        "urls": urls,
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
