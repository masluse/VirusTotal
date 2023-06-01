from flask import Flask, request, render_template, redirect, url_for
import time
import requests
import os

app = Flask(__name__)

API_KEY = "Your_Virus_Total_API_Key"

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

@app.route('/', methods=['GET', 'POST'])
def home():
 if request.method == 'POST':
     hashes = request.form.get('hashes').split('\n')
     for hash_value in hashes:
         hash_value = hash_value.strip()  # remove newlines and any trailing spaces
         result = check_virus_total(hash_value)
         with open(f'results/{hash_value}.txt', 'w') as file:
             file.write(str(result))
         time.sleep(15)  # Wait for 15 seconds to not exceed the rate limit
     return redirect(url_for('home'))
 else:
     files = os.listdir('results/')
     return render_template('index.html', files=files)

@app.route('/results/<filename>')
def results(filename):
 with open(f'results/{filename}') as file:
     content = file.read()
 return render_template('result.html', filename=filename, content=content)

if __name__ == "__main__":
 if not os.path.isdir('results'):
     os.mkdir('results')
 app.run(host='0.0.0.0')
