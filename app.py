from flask import Flask, request, render_template, send_from_directory
import requests
import os
import json
from datetime import datetime

app = Flask(__name__)
API_KEY = 'your_virustotal_public_api_key'
BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
UPLOAD_DIR = 'uploads'

os.makedirs(UPLOAD_DIR, exist_ok=True)

def check_hash(hash_value):
    params = {'apikey': API_KEY, 'resource': hash_value}
    response = requests.get(BASE_URL, params=params)
    return response.json()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # ...
        filename_html = f'{timestamp}.html'
        html_content = render_template_string('''<!DOCTYPE html>
        <html>
        <head>
            <title>Result</title>
        </head>
        <body>
            <h1>Result</h1>
            <table>
                <tr>
                    <th>Hash</th>
                    <th>Malicious</th>
                </tr>
                {% for result in results %}
                <tr>
                    <td>{{ result[0] }}</td>
                    <td>{% if result[1] != 'Not found' %}{{ result[1] }} / {{ result[2] }}{% else %}Not found{% endif %}</td>
                </tr>
                {% endfor %}
            </table>
            <a href="/">Back</a>
        </body>
        </html>''', results=results)
        with open(os.path.join(UPLOAD_DIR, filename_html), 'w') as f:
            f.write(html_content)
        return render_template('result.html', results=results)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
