FROM python:3.9-slim-buster

WORKDIR /app

COPY requirements.txt requirements.txt
RUN apt-get update && apt-get install -y openssl && pip install -r requirements.txt

COPY . .

ENV VT_API_KEY=''
CMD ["python", "app.py"]
