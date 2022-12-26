FROM python:3.11-slim-buster
WORKDIR /var/www
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP app/app.py
ENV FLASK_DEBUG false
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_RUN_PORT 8000
RUN apt-get update  && apt-get install -y --no-install-recommends gcc \
     && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY app app
CMD ["python3", "-m", "flask", "run"]
