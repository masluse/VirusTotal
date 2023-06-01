from flask import Flask, request, render_template, send_from_directory
import requests
import os
import json
from datetime import datetime
import time
import threading
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
API_KEY = os.environ.get('VT_API_KEY', 'your_default_virustotal_public_api_key')
BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
UPLOAD_DIR = 'uploads'
WAIT_TIME = 15  # 15 seconds wait time

os.makedirs(UPLOAD_DIR, exist_ok=True)

env = Environment(loader=FileSystemLoader('templates'))

def check_hash(hash_value, results):
    params = {'apikey': API_KEY, 'resource': hash_value}
    response = requests.get(BASE_URL, params=params)
    time.sleep(WAIT_TIME)
    result = response.json()
    if result.get('response_code'):
        results.append((hash_value, result.get('positives', 'Not found'), result.get('total', 'Not found')))
    else:
        results.append((hash_value, 'Not found', 'Not found'))

def process_hashes(hashes):
    results = []
    for hash_value in hashes:
        check_hash(hash_value, results)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    filename = f'{timestamp}.html'
    with open(os.path.join(UPLOAD_DIR, filename), 'w') as f:
        result_template = env.get_template('result.html')
        html = result_template.render(results=results)
        f.write(html)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        hashes = request.form['hashes'].splitlines()
        threading.Thread(target=process_hashes, args=(hashes,)).start()
        return "Your hashes are being processed. Please check back later."
    files = os.listdir(UPLOAD_DIR)
    return render_template('index.html', files=files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
