from flask import Flask, request, send_from_directory
import time
import requests
import os
import json

API_KEY = "Your_Virus_Total_API_Key"

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    hashes = request.form['hashes'].splitlines()
    results = []
    for hash_value in hashes:
        results.append(check_virus_total(hash_value))
        time.sleep(15)
    filename = f"results-{time.time()}.json"
    with open(f"results/{filename}", 'w') as f:
        json.dump(results, f)
    return send_from_directory(directory='results', filename=filename)

@app.route('/results')
def list_results():
    files = os.listdir('results')
    return render_template('results.html', files=files)

def check_virus_total(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return f"Error for hash {hash_value}, HTTP {response.status_code}"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)
