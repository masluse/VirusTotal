from flask import Flask, request, render_template, send_from_directory
import requests
import os
import json
from datetime import datetime
import time
from threading import Lock
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
API_KEY = 'your_virustotal_public_api_key'
BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
UPLOAD_DIR = 'uploads'
WAIT_TIME = 15  # 15 seconds wait time
lock = Lock()  # to block simultaneous requests

os.makedirs(UPLOAD_DIR, exist_ok=True)

env = Environment(loader=FileSystemLoader('templates'))

def check_hash(hash_value):
    params = {'apikey': API_KEY, 'resource': hash_value}
    response = requests.get(BASE_URL, params=params)
    return response.json()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        with lock:
            hashes = request.form['hashes'].splitlines()
            wait_time = len(hashes) * WAIT_TIME
            results = []
            for hash_value in hashes:
                result = check_hash(hash_value)
                if result['response_code']:
                    results.append((hash_value, result['positives'], result['total']))
                else:
                    results.append((hash_value, 'Not found', 'Not found'))
                time.sleep(WAIT_TIME)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f'{timestamp}.html'
            with open(os.path.join(UPLOAD_DIR, filename), 'w') as f:
                result_template = env.get_template('result.html')
                html = result_template.render(results=results)
                f.write(html)
            return render_template('result.html', filename=filename, results=results, wait_time=wait_time)
    files = os.listdir(UPLOAD_DIR)
    return render_template('index.html', files=files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
