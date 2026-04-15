"""
NetGuard AI - Flask Backend
Provides REST API endpoints for network anomaly detection + AI chatbot.
"""

import os
import json
import logging
from datetime import datetime
from collections import Counter
from flask import Flask, jsonify, request
from flask_cors import CORS
import anthropic

# ── Optional scapy import (falls back to mock in dev mode) ──
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("scapy not available — running in MOCK mode")

app = Flask(__name__)
CORS(app)  # Allow frontend to call this API

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Config ──────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
INTERFACE         = os.environ.get("NETWORK_INTERFACE", "eth0")
PACKET_COUNT      = int(os.environ.get("PACKET_COUNT", "100"))
DEV_MODE          = os.environ.get("DEV_MODE", "true").lower() == "true"

INTERNAL_IPS = set(os.environ.get("INTERNAL_IPS", "192.168.1.1,10.0.0.1").split(","))

COMMON_ATTACK_PORTS = {22, 23, 445, 3389, 1433, 4444, 5900, 6667}

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 58: "ICMPv6"}

THRESHOLDS = {
    "ip_very_high":     100,
    "ip_moderate":      50,
    "tcp_udp_high":     400,
    "icmp_arp_unusual": 50,
    "attack_port_hits": 10,
}

# In-memory anomaly store (replace with SQLite/Postgres for production)
anomaly_store: list[dict] = []


# ── Network capture & analysis ───────────────────────────────

def capture_packets(interface: str, count: int) -> list:
    """Capture packets from network interface."""
    logger.info(f"Capturing {count} packets on {interface}...")
    packets = scapy.sniff(iface=interface, count=count, timeout=15)
    logger.info(f"Captured {len(packets)} packets.")
    return packets


def analyze_packets(packets: list) -> tuple:
    """Extract IP, protocol, and port frequency counters from packets."""
    ip_counts       = Counter()
    protocol_counts = Counter()
    port_counts     = Counter()

    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_counts[packet[scapy.IP].src] += 1
            proto_name = PROTO_MAP.get(packet[scapy.IP].proto, str(packet[scapy.IP].proto))
            protocol_counts[proto_name] += 1

            if packet.haslayer(scapy.TCP):
                port_counts[packet[scapy.TCP].dport] += 1
            elif packet.haslayer(scapy.UDP):
                port_counts[packet[scapy.UDP].dport] += 1

    return ip_counts, protocol_counts, port_counts


def detect_anomalies(ip_counts: Counter, protocol_counts: Counter, port_counts: Counter) -> list[dict]:
    """Run anomaly detection rules and return structured anomaly dicts."""
    anomalies = []
    timestamp = datetime.now().isoformat()

    for ip, count in ip_counts.items():
        if count > THRESHOLDS["ip_very_high"]:
            anomalies.append({
                "timestamp": timestamp,
                "type":      "high_ip_activity",
                "severity":  "high",
                "detail":    f"Very high packet volume from IP {ip} ({count} packets).",
                "count":     count,
                "source_ip": ip,
            })
        elif count > THRESHOLDS["ip_moderate"] and ip not in INTERNAL_IPS:
            anomalies.append({
                "timestamp": timestamp,
                "type":      "moderate_external_ip_activity",
                "severity":  "medium",
                "detail":    f"Moderate activity from external IP {ip} ({count} packets).",
                "count":     count,
                "source_ip": ip,
            })

    for proto, count in protocol_counts.items():
        if proto in ("TCP", "UDP") and count > THRESHOLDS["tcp_udp_high"]:
            anomalies.append({
                "timestamp": timestamp,
                "type":      "high_protocol_volume",
                "severity":  "medium",
                "detail":    f"Unusually high {proto} traffic ({count} packets).",
                "count":     count,
                "protocol":  proto,
            })
        elif proto in ("ICMP", "ARP") and count > THRESHOLDS["icmp_arp_unusual"]:
            anomalies.append({
                "timestamp": timestamp,
                "type":      "unusual_protocol_activity",
                "severity":  "medium",
                "detail":    f"Elevated {proto} activity ({count} packets) — possible scan or flood.",
                "count":     count,
                "protocol":  proto,
            })

    for port, count in port_counts.items():
        if port in COMMON_ATTACK_PORTS and count > THRESHOLDS["attack_port_hits"]:
            anomalies.append({
                "timestamp": timestamp,
                "type":      "attack_port_activity",
                "severity":  "high",
                "detail":    f"Suspicious activity on port {port} ({count} hits) — commonly targeted in attacks.",
                "count":     count,
                "port":      port,
            })

    return anomalies


def mock_anomalies() -> list[dict]:
    """Return mock anomalies for development/testing without root access."""
    now = datetime.now().isoformat()
    return [
        {"timestamp": now, "type": "high_ip_activity",              "severity": "high",   "detail": "Very high packet volume from IP 203.0.113.45 (142 packets).", "count": 142, "source_ip": "203.0.113.45"},
        {"timestamp": now, "type": "attack_port_activity",          "severity": "high",   "detail": "Suspicious activity on port 3389 (18 hits) — commonly targeted in attacks.", "count": 18, "port": 3389},
        {"timestamp": now, "type": "unusual_protocol_activity",     "severity": "medium", "detail": "Elevated ICMP activity (67 packets) — possible scan or flood.", "count": 67, "protocol": "ICMP"},
        {"timestamp": now, "type": "moderate_external_ip_activity", "severity": "medium", "detail": "Moderate activity from external IP 198.51.100.12 (53 packets).", "count": 53, "source_ip": "198.51.100.12"},
    ]


# ── API Routes ───────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status":    "ok",
        "dev_mode":  DEV_MODE,
        "scapy":     SCAPY_AVAILABLE,
        "interface": INTERFACE,
        "time":      datetime.now().isoformat(),
    })


@app.route("/anomalies", methods=["GET"])
def get_anomalies():
    """
    Run anomaly detection and return results.
    Uses mock data in DEV_MODE or if scapy is unavailable.
    """
    global anomaly_store

    try:
        if DEV_MODE or not SCAPY_AVAILABLE:
            anomaly_store = mock_anomalies()
        else:
            packets = capture_packets(INTERFACE, PACKET_COUNT)
            ip_c, proto_c, port_c = analyze_packets(packets)
            anomaly_store = detect_anomalies(ip_c, proto_c, port_c)

        return jsonify({
            "anomalies": anomaly_store,
            "count":     len(anomaly_store),
            "scanned_at": datetime.now().isoformat(),
            "dev_mode":  DEV_MODE or not SCAPY_AVAILABLE,
        })

    except PermissionError:
        return jsonify({
            "error": "Permission denied. Run with sudo or set DEV_MODE=true.",
            "tip":   "sudo python app.py  OR  export DEV_MODE=true"
        }), 403

    except Exception as e:
        logger.exception("Error during anomaly detection")
        return jsonify({"error": str(e)}), 500


@app.route("/chat", methods=["POST"])
def chat():
    """
    AI chatbot endpoint. Accepts user messages and returns AI analysis
    grounded in the current anomaly context.

    Body: { "message": str, "history": [...], "anomalies": [...], "focused_anomaly": dict|null }
    """
    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "ANTHROPIC_API_KEY not set in environment."}), 500

    body = request.get_json(force=True)
    user_message    = body.get("message", "").strip()
    history         = body.get("history", [])
    anomalies       = body.get("anomalies", anomaly_store)
    focused_anomaly = body.get("focused_anomaly", None)

    if not user_message:
        return jsonify({"error": "message is required"}), 400

    # Build system prompt with live anomaly context
    anomaly_context = (
        f"Current detected anomalies:\n{json.dumps(anomalies, indent=2)}"
        if anomalies else "No anomalies currently detected."
    )
    focus_context = (
        f"\n\nThe user is specifically asking about this anomaly:\n{json.dumps(focused_anomaly, indent=2)}"
        if focused_anomaly else ""
    )

    system_prompt = f"""You are NetGuard AI, a cybersecurity analyst assistant integrated with a live network anomaly detection system.

{anomaly_context}{focus_context}

Your role:
- Analyze and explain network anomalies in plain English
- Assess severity and potential attack vectors
- Recommend specific, actionable remediation steps
- Identify patterns that might indicate coordinated attacks
- Be concise but thorough. Use technical terms where appropriate.
- Format key IPs, ports, or values in backticks like `192.168.1.1`

Always ground your answers in the actual anomaly data provided above."""

    # Build messages array (history + new user message)
    messages = [*history, {"role": "user", "content": user_message}]

    try:
        client   = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model      = "claude-sonnet-4-20250514",
            max_tokens = 1024,
            system     = system_prompt,
            messages   = messages,
        )

        ai_text = response.content[0].text
        return jsonify({
            "reply":   ai_text,
            "role":    "assistant",
            "time":    datetime.now().isoformat(),
        })

    except anthropic.AuthenticationError:
        return jsonify({"error": "Invalid Anthropic API key."}), 401
    except Exception as e:
        logger.exception("Claude API error")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting NetGuard backend on port {port} (DEV_MODE={DEV_MODE})")
    app.run(host="0.0.0.0", port=port, debug=DEV_MODE)
