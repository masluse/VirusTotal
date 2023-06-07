# Hash Checker

Ein einfacher Service, der die VirusTotal API verwendet, um Hashes zu überprüfen und Berichte zu generieren.

## Anforderungen

- Docker
- VirusTotal API Schlüssel (können mehrere sein)

## Verwendung

Um den Service zu starten, können Sie das offizielle Docker-Image masluse/hash-checker verwenden. Sie müssen Ihren VirusTotal API-Schlüssel (oder Schlüssel) als Umgebungsvariable bereitstellen.

Wenn Sie mehrere API-Schlüssel haben, trennen Sie sie mit einem Komma (,), ohne Leerzeichen. Die Wartezeit zwischen den Anfragen wird automatisch durch die Anzahl der API-Schlüssel geteilt, und die API-Schlüssel werden der Reihe nach verwendet.

Docker Befehl:

``` bash
docker run -p 5000:5000 -e VT_API_KEY='your_virustotal_public_api_key1,your_virustotal_public_api_key2' masluse/hash-checker
```

## Docker Compose:

``` yaml
version: "3.8"
services:
  hash-checker:
    image: masluse/hash-checker:latest
    container_name: hash-checker
    ports:
      - 443:5000
    environment:
	#  At least one API key must be configured.
       - VT_API_KEY=API_KEY1,API_KEY2
    volumes:
	#  The following volume allows you to map the results so that they are not deleted.
       - /host/directory/to/uploads:/app/uploads
	#  If the following Volumes are not configured, the image will generate a certificate.
	#  - /host/directory/to/cert.pem:/app/cert.pem
	#  - /host/directory/to/key.pem:/app/key.pem
    restart: always
```

Ersetzen Sie your_virustotal_public_api_key1,your_virustotal_public_api_key2 durch Ihre eigenen VirusTotal API-Schlüssel.

Danach können Sie auf den Service zugreifen, indem Sie Ihren Webbrowser auf http://localhost:5000 richten.

Geben Sie die Hashes, die Sie überprüfen möchten, in das Textfeld ein (einen Hash pro Zeile) und klicken Sie auf "Submit". Der Service wird dann die Hashes überprüfen und einen Bericht generieren, den Sie nach Abschluss der Verarbeitung herunterladen können.

Die Standard-Wartezeit beträgt 15 Sekunden pro Anfrage, wird jedoch durch die Anzahl der bereitgestellten API-Schlüssel geteilt.
