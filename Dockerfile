FROM python:3.9-slim

WORKDIR /app

COPY app.py /app
COPY templates /app/templates

# Install openssl to generate SSL certificates
RUN apt-get update && \
    apt-get install -y openssl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install flask requests

CMD ["python", "app.py"]
