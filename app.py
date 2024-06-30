import email
import re
import os
import hashlib
from email.header import decode_header
import argparse
import requests
import json
from flask import Flask, render_template, request, redirect, url_for, flash

Result = {}
api_key = '0cb4957d7d16fc57a4fd90679ecd0ce5d78587024854601f77ff67936a358a27'


def analyze_file(file_path):
    with open(file_path,"rb") as f:
        bytes = f.read() # read entire file as bytes
        md5 = hashlib.md5(bytes).hexdigest()

        # output['MD5 Hash of email:']=md5
        sha1 = hashlib.sha1(bytes).hexdigest()

        # output['SHA1 Hash of email:']=sha1
        sha256 = hashlib.sha256(bytes).hexdigest()

        # output['SHA256 Hash of email']=sha256
        Result['SHA256-Hash-email']=sha256

        analyze_email(file_path)


def analyze_email(file_path):
    with open(file_path, 'r') as f:
        email_message = email.message_from_file(f)
        headers = {}
        for header in email_message.items():
            decoded_header = decode_header(header[1])[0]
            header_name = header[0]
            header_value = decoded_header[0]
            charset = decoded_header[1]
            if charset:
                header_value = header_value.decode(charset)
            
            headers[header_name] = header_value

        Result['Headers'] = headers     

        # Extract the email's body
        email_body = email_message.get_payload()
        # Use regular expressions to find all links in the email's body
        try:
            email_body = email_body[0].as_string()
        except:
            email_body = email_body

        links = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', email_body)
        Result['Links'] = list(set(links.copy()))

        urlsFound = re.findall(r'https?://\S+', email_body)

        # Replace 'YOUR_API_KEY' with your actual VirusTotal API key
        url_to_scan = urlsFound  # Replace with the URL you want to scan

        response = scan_url(api_key, url_to_scan)
        urls = {"clean": 0, "harm": 0, "harmWebsites": [], "ratio": 0}
        Result['URLs'] = urls
        correct_urls = []

        if not response:
            for url in urls:
                response = scan_url(api_key, url)
                if not response:
                    continue
                correct_urls.append(url)

        if len(correct_urls) > 0:
            response = scan_url(api_key, correct_urls)

        if response:
            result = get_url_report(api_key, response)
            clean = 0
            harm = 0
            urls = {}
            sayHarm = []
            if result:
                for key , value in result.items():
                    if value == 'clean site':
                        clean += 1
                    elif value == 'unrated site':
                        pass
                    else:
                        harm += 1
                        sayHarm.append(key)
                urls['clean'] = clean
                urls['harm'] = harm
                urls['harmWebsites'] = sayHarm
                urls['ratio'] = clean / (clean + harm) * 100
                print('Url is safe')

            else:
                print('No Result Found')
            print("Script Finisihed Sucessfully")
        else:
            print('Script Finishing With Failure')
        Result['URLs'] = urls

        HandleEmailMessage(email_body, email_message)


def scan_url(api_key, urls):
    url_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': api_key, 'url': urls}
    try:
        response = requests.post(url_scan, params=params)
        if response.status_code == 200:
            json_response = response.json()
            if json_response['response_code'] == 1:
                print("URL scan successfully initiated. Resource ID:", json_response['scan_id'])
                return json_response['scan_id']
            else:
                print("Scan initiation failed. Response code:", json_response['response_code'])
                return False 
        else:
            print("Error:", response.status_code, response.text)

    except Exception as e:
       print("An error occurred:", e)

    
def get_url_report(api_key, scan_id):
    url_report = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': scan_id}
    result = {}
    try:
        response = requests.get(url_report, params=params)
        if response.status_code == 200:
            json_response = response.json()
            if json_response['response_code'] == 1:
                print("Scan report retrieved successfully:")
                for scan_result in json_response['scans']:
                    result[scan_result] = json_response['scans'][scan_result]['result']
                return result
            else:
                print("Report retrieval failed. Response code:", json_response['response_code'])
        else:
            print("Error:", response.status_code, response.text)
    except Exception as e:
        print("An error occurred:", e)


def HandleEmailMessage(email_body, email_message):
    # Use regular expressions to find all IP addresses in the email's body
    ip_addresses = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', email_body)
    Result['IPs'] = list(set(ip_addresses.copy()))

    email_addresses = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', email_body)
    Result['Emails'] = list(set(email_addresses.copy()))

    emailInfo = {}
    if 'subject' in email_message:
        emailInfo['Subject'] = email_message["subject"]

    sender = email_message.get('From')
    emailInfo['Sender'] = sender

    # Extract the email's recipient
    recipient = email_message.get('To')
    emailInfo['Recipient'] = recipient

    # Extract the email's delivery information
    delivery_information = email_message.get('Delivery-date')
    emailInfo['Delivery-date'] = delivery_information

    print('\n')
    # Extract the email's DMARC information
    dmarc = email_message.get('DMARC-Filter')
    emailInfo['DMARC'] = dmarc

    # Extract the email's SRF information
    spf = email_message.get('Authentication-Results')
    emailInfo['Authentication-Results'] = spf

    # Extract the email's DKIM information
    dkim = email_message.get('DKIM-Signature')
    emailInfo['DKIM'] = dkim
    # Extract the email's SPF information

    spf = email_message.get('Received-SPF')
    emailInfo['Received-SPF'] = spf

    Result['EmailInfo'] = emailInfo

    # Check if the email has attachments
    if email_message.get_content_maintype() == 'multipart':
        sha256_hash = None
        for part in email_message.get_payload():
            # Check if the attachment is a file
            if part.get_content_maintype() == 'application':
                # Extract the attachment's data
                attachment_data = part.get_payload(decode=True)

                # Calculate the attachment's MD5 hash
                md5_hash = hashlib.md5(attachment_data).hexdigest()

                # Calculate the attachment's SHA1 hash
                sha1_hash = hashlib.sha1(attachment_data).hexdigest()

                # Calculate the attachment's SHA256 hash
                sha256_hash = hashlib.sha256(attachment_data).hexdigest()
        if sha256_hash:
            HandleAttachment(sha256_hash)
    else:
        print("No attachments found in provided email.")
        print('\n')

def get_virustotal_report(api_key, file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        'x-apikey': api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print("Error:", response.status_code, response.text)
        return None


def format_report(report):
    # Extract and format relevant information from the report
    formatted_report = {
        'file_hash': report.get('data', {}).get('id'),
        'first_submission_date': report.get('data', {}).get('attributes', {}).get('first_submission_date'),
        'last_analysis_date': report.get('data', {}).get('attributes', {}).get('last_analysis_date'),
        'positives': report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious'),
        'total': sum(report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).values()),
        'scan_results': report.get('data', {}).get('attributes', {}).get('last_analysis_results')
    }
    return formatted_report

def HandleAttachment(file_hash):
    report = get_virustotal_report(api_key, file_hash)
    if report:
        formatted_report = format_report(report)
        print('                    Hash is maliciuos')
        Result['Attachment'] = 'Malicious'
    else:
        print("Could not retrieve the report from VirusTotal.")
        print("                    Hash is safe")
        Result['Attachment'] = 'Safe'
   



from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/result', methods=['GET'], strict_slashes=False)
def result():
    
    return jsonify({'result': Result})


@app.route('/analyze', methods=['POST'])
def upload_file():
    Result.clear()
    if 'file' not in request.files:
        flash('No file part')
        return {"error" : "no file found "}
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        # Process the file using the imported analyze_file function
        
        result = analyze_file(file_path)
        return 'Success'
        

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
