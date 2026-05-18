# 1. Gunakan Python versi ringan
FROM python:3.9-slim

# 2. Set folder kerja
WORKDIR /app

# 3. INSTALL DEPENDENCIES (UPDATE INI)
# Kita tambahkan: build-essential, libssl-dev, libffi-dev, python3-dev
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    nmap \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libx11-6 \
    libxext6 \
    libxrender1 \
    libxtst6 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# 4. Copy file requirements dan install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy sisa file
COPY . .

# 6. Buka port
EXPOSE 5000

# 7. Jalankan
CMD ["python", "run.py"]