FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium

RUN useradd -m agentuser && chown -R agentuser:agentuser /app
USER agentuser

COPY --chown=agentuser:agentuser . .
CMD ["python", "agent.py"]