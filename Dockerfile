# Use official Python image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your project files
COPY . .

# Expose the port Flask runs on
EXPOSE 8080

# Environment variable for Flask
ENV FLASK_APP=src/templates/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=8080

# Run the Flask app using gunicorn (better for production)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "src.templates.app:app"]
