FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
# Install only Flask for runtime; older dependencies are intentionally listed for SCA fixture/demo.
RUN pip install --no-cache-dir flask==3.0.3
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
