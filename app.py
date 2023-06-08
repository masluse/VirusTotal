from flask import Flask, request, render_template, send_from_directory, json
import requests
import os
import time
import threading
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from werkzeug.serving import run_simple
import subprocess
import os.path
import math

app = Flask(__name__)
API_KEYS = os.environ.get('VT_API_KEY', 'your_default_virustotal_public_api_key').split(',')
key_index = 0
BASE_URL = 'https://www.virustotal.com/api/v3/files'
UPLOAD_DIR = 'uploads'
WAIT_TIME = 15  # 15 seconds total wait time, will be divided by the number of API keys

os.makedirs(UPLOAD_DIR, exist_ok=True)

env = Environment(loader=FileSystemLoader('templates'))

background_task_running = False

if not os.path.isfile('/app/cert.pem') or not os.path.isfile('/app/key.pem'):
    subprocess.call(['openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-nodes', '-out', '/app/cert.pem', '-keyout', '/app/key.pem', '-days', '365', '-subj', '/CN=localhost'])

def check_hash(hash_value, results):
    global key_index
    headers = {'x-apikey': API_KEYS[key_index]}
    url = f"{BASE_URL}/{hash_value}"
    response = requests.get(url, headers=headers)
    key_index = (key_index + 1) % len(API_KEYS)
    time.sleep(WAIT_TIME / len(API_KEYS))
    result = response.json()
    data = result.get('data', {}).get('attributes', {})
    if data:
        size = convert_size(data.get('size', 0))
        threat_label = data.get('popular_threat_classification', {}).get('suggested_threat_label', 'Not found')
        filename = data.get('names', ['Not found'])[0]  # Get the first name from the list
        analysis_results = data.get('last_analysis_results', {})
        malicious_count = sum(1 for engine in analysis_results.values() if engine.get('category') == 'malicious')
        harmless_count = sum(1 for engine in analysis_results.values() if engine.get('category') == 'undetected')
        results.append((hash_value, malicious_count, harmless_count, filename, threat_label, size))
    else:
        results.append((hash_value, 'Not found', 'Not found', 'Not found', 'Not found', '0B'))  # default size to 0 bytes




def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def process_hashes(hashes):
    global background_task_running
    background_task_running = True
    results = []
    for hash_value in hashes:
        check_hash(hash_value, results)
    timestamp = datetime.now().strftime('%d.%m.%Y%H%M%S')
    filename = f'{timestamp}.html'
    with open(os.path.join(UPLOAD_DIR, filename), 'w') as f:
        result_template = env.get_template('result.html')
        html = result_template.render(results=results)
        f.write(html)
    background_task_running = False

@app.route('/', methods=['GET', 'POST'])
def index():
    global background_task_running
    if request.method == 'POST' and not background_task_running:
        hashes = request.form['hashes'].splitlines()
        estimated_time = len(hashes) * WAIT_TIME / 60 / len(API_KEYS)
        threading.Thread(target=process_hashes, args=(hashes,)).start()
        return json.dumps({'success':True, 'estimated_time': estimated_time}), 200, {'ContentType':'application/json'}
    files = sorted(os.listdir(UPLOAD_DIR), reverse=True)
    return render_template('index.html', files=files, task_running=background_task_running)

@app.route('/check_task_status', methods=['GET'])
def check_task_status():
    global background_task_running
    return json.dumps({'task_running':background_task_running}), 200, {'ContentType':'application/json'}

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == '__main__':
    context = ('/app/cert.pem', '/app/key.pem')
    run_simple('0.0.0.0', 5000, app, ssl_context=context)
