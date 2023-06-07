from flask import Flask, request, render_template, send_from_directory
import requests
import os
import json
from datetime import datetime, timedelta
import time
import threading
from jinja2 import Environment, FileSystemLoader
from werkzeug.serving import run_simple
import subprocess
import os.path

app = Flask(__name__)
API_KEYS = os.environ.get('VT_API_KEY', 'your_default_virustotal_public_api_key').split(',')
key_index = 0
BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
UPLOAD_DIR = 'uploads'
WAIT_TIME = 15  # 15 seconds total wait time, will be divided by the number of API keys

os.makedirs(UPLOAD_DIR, exist_ok=True)

env = Environment(loader=FileSystemLoader('templates'))

background_task_running = False

# Check if SSL certificates exist or not
if not os.path.isfile('/app/cert.pem') or not os.path.isfile('/app/key.pem'):
    # Generate self-signed SSL certificate
    subprocess.call(['openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-nodes', '-out', '/app/cert.pem', '-keyout', '/app/key.pem', '-days', '365', '-subj', '/CN=localhost'])

def check_hash(hash_value, results):
    global key_index
    params = {'apikey': API_KEYS[key_index], 'resource': hash_value}
    response = requests.get(BASE_URL, params=params)
    key_index = (key_index + 1) % len(API_KEYS)  # move to the next key
    time.sleep(WAIT_TIME / len(API_KEYS))  # divide wait time by number of API keys
    result = response.json()
    if result.get('response_code'):
        results.append((hash_value, result.get('positives', 'Not found'), result.get('total', 'Not found')))
    else:
        results.append((hash_value, 'Not found', 'Not found'))

def process_hashes(hashes):
    global background_task_running
    background_task_running = True
    results = []
    for hash_value in hashes:
        check_hash(hash_value, results)
    timestamp = datetime.now().strftime('%d.%m.%Y%H%M%S') # Ändert das Format des Datums
    filename = f'{timestamp}.html'
    with open(os.path.join(UPLOAD_DIR, filename), 'w') as f:
        result_template = env.get_template('result.html')
        html = result_template.render(results=results)
        f.write(html)
    background_task_running = False


@app.route('/', methods=['GET', 'POST'])
def index():
    global background_task_running
    if request.method == 'POST':
        hashes = request.form['hashes'].splitlines()
        estimated_time = len(hashes) * WAIT_TIME / 60 / len(API_KEYS)  # adjust estimated time based on number of API keys
        threading.Thread(target=process_hashes, args=(hashes,)).start()
        return f"Your hashes are being processed. Please check back in approximately {estimated_time} Minutes."
    files = sorted(os.listdir(UPLOAD_DIR), reverse=True)  # Sortiert die Dateien absteigend
    return render_template('index.html', files=files, task_running=background_task_running)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == '__main__':
    context = ('/app/cert.pem', '/app/key.pem')  # Certificate and key
    run_simple('0.0.0.0', 5000, app, ssl_context=context)
