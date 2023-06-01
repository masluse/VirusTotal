import os
import datetime
import requests
from flask import Flask, request, render_template, render_template_string, send_from_directory

app = Flask(__name__)
API_KEY = 'your-api-key'
UPLOAD_DIR = 'uploads'

@app.route('/')
def index():
    files = os.listdir(UPLOAD_DIR)
    return render_template('index.html', files=files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.route('/', methods=['GET', 'POST'])
def check_hashes():
    if request.method == 'POST':
        hashes = request.form.get('hashes').splitlines()
        results = []
        for h in hashes:
            response = requests.get(f'https://www.virustotal.com/vtapi/v2/file/report?apikey={API_KEY}&resource={h}')
            json_response = response.json()
            if json_response['response_code']:
                results.append([h, json_response['positives'], json_response['total']])
            else:
                results.append([h, 'Not found'])
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
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
    return render_template('index.html')

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
    app.run(debug=True)
