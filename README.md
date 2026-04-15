# NetGuard AI 🛡️
AI-powered network anomaly detection chatbot.

## Project Structure
```
netguard/
├── backend/
│   ├── app.py              # Flask API (anomaly detection + AI chat)
│   ├── requirements.txt
│   └── .env.example        # Copy to .env and fill in values
├── frontend/
│   └── index.html          # Terminal-style UI
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── nginx.conf
└── docker-compose.yml
```

---

## Quick Start (Development)

### 1. Set up environment
```bash
cd backend
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY
```

### 2. Install Python dependencies
```bash
pip install -r backend/requirements.txt
```

### 3. Run the backend
```bash
# DEV_MODE=true uses mock anomaly data (no root needed)
cd backend
python app.py
# → Flask running on http://localhost:5000
```

### 4. Open the frontend
Open `frontend/index.html` directly in your browser,
or serve it with:
```bash
cd frontend
python -m http.server 8080
# → http://localhost:8080
```

---

## API Endpoints

| Method | Endpoint     | Description                          |
|--------|-------------|--------------------------------------|
| GET    | `/health`    | Health check + config status         |
| GET    | `/anomalies` | Run scan, return anomaly list        |
| POST   | `/chat`      | AI chat grounded in anomaly context  |

### POST /chat — Request body
```json
{
  "message": "Which anomaly is most critical?",
  "history": [],
  "anomalies": [...],
  "focused_anomaly": null
}
```

---

## Docker Deployment

### Build and run everything
```bash
# 1. Set your API key
cp backend/.env.example backend/.env
echo "ANTHROPIC_API_KEY=sk-ant-..." >> backend/.env

# 2. Start both services
docker compose up --build

# Frontend → http://localhost:8080
# Backend  → http://localhost:5000
```

### Enable real packet capture (Production)
In `docker-compose.yml`, uncomment these lines under `backend:`:
```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
network_mode: host
```
And set `DEV_MODE=false` in your `.env`.

> ⚠️ Real packet capture requires root/sudo privileges.
> On Linux: `sudo docker compose up`

---

## Switching from Mock to Live Traffic

In `backend/.env`:
```
DEV_MODE=false
NETWORK_INTERFACE=eth0   # your actual interface
PACKET_COUNT=200
```

Find your interface name:
- **Linux**: `ip link show`
- **Mac**: `ifconfig` (usually `en0`)
- **Windows**: `ipconfig` (use in WSL2)

---

## Customizing Detection Rules

Edit the constants in `backend/app.py`:

```python
# Add your trusted IPs
INTERNAL_IPS = {"192.168.1.1", "10.0.0.1"}

# Add ports to watch
COMMON_ATTACK_PORTS = {22, 23, 445, 3389, ...}

# Tune thresholds
THRESHOLDS = {
    "ip_very_high":  100,   # packets from single IP
    "tcp_udp_high":  400,   # total TCP/UDP volume
    ...
}
```
