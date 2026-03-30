FROM python:3.12-slim

WORKDIR /app

# Install Proteus (sibling repo) as a package
COPY Proteus/ /proteus/
RUN pip install --no-cache-dir /proteus

# Install client dependencies
COPY Proteus-client/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy client source
COPY Proteus-client/ .

WORKDIR /app/web
CMD ["python", "app.py"]
