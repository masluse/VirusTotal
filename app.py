from flask import Flask, render_template, request, redirect
import requests
from datetime import datetime

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        hash_list = request.form['hashes'].split('\n')
        return redirect(f'/check?hashes={",".join(hash_list)}')
    return render_template('home.html')

@app.route('/check')
def hash_check():
    hash_list = request.args.get('hashes').split(',')
    results = {}

    for hash in hash_list:
        response = requests.get(f'https://www.virustotal.com/vtapi/v2/file/report?apikey=<IHR API SCHLÜSSEL>&resource={hash}')
        results[hash] = response.json()

    date_string = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
    filename = f'results_{date_string}.txt'

    with open(filename, 'w') as file:
        for hash, result in results.items():
            file.write(f'Hash: {hash}\n')
            if result['positives'] > 0:
                file.write('Bösartig: Ja\n\n')
            else:
                file.write('Bösartig: Nein\n\n')

    return render_template('result.html', filename=filename, results=results)

if __name__ == '__main__':
    app.run(debug=True)
