# Dockerfile for ADK agent system
FROM python:3.13-slim-bookworm


WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your agent code
COPY . .

# Set environment variables
ENV PORT=8080
ENV GOOGLE_CLOUD_PROJECT=cp220-grading-assistant

# Run the application
CMD ["python", "api_server.py"]