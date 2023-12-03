FROM python:3.11-slim-buster
WORKDIR /var/www
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP app/app.py
ENV FLASK_DEBUG false
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_RUN_PORT 8000
ENV PYTHONPATH "${PYTHONPATH}:/var/www/app"
RUN apt-get update  && apt-get install -y --no-install-recommends gcc \
     && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt  --no-cache-dir
COPY app app
COPY manage.py manage.py
COPY tests tests
COPY entrypoint.sh entrypoint.sh
ENTRYPOINT ["/bin/bash", "/var/www/entrypoint.sh"]
