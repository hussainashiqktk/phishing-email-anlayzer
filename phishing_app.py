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

# Function to parse the raw email file
def parse_email(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f, policy=policy.default)
    except Exception as e:
        return {"error": f"Failed to parse email: {str(e)}"}
    
    # Extract headers
    headers = {
        "From": msg.get("From", "Not found"),
        "To": msg.get("To", "Not found"),
        "Subject": msg.get("Subject", "Not found"),
        "Reply-To": msg.get("Reply-To", "Not found"),
        "Received": msg.get("Received", "Not found").splitlines()[-1] if msg.get("Received") else "Not found"
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
    
    # Find URLs in the body
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
    
    # Basic analysis
    analysis = {
        "suspicious_headers": "Reply-To differs from From" if headers["Reply-To"] != headers["From"] and headers["Reply-To"] != "Not found" else "No header anomalies",
        "url_count": len(urls),
        "attachment_count": len(attachments),
        "potential_phishing": "Possible phishing" if urls or attachments else "No obvious phishing signs"
    }
    
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
        
        # Clean up the uploaded file
        os.remove(file_path)
        
        return jsonify(result)
    else:
        return jsonify({"error": "Invalid file format. Please upload a .eml file"}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)