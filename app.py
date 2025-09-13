# app.py
from flask import Flask, request, render_template_string, redirect, url_for, jsonify, Response
import datetime, time, os, csv, io, threading
try:
    import geoip2.database
except Exception:
    geoip2 = None

app = Flask(__name__)

# -----------------------
# Configuration (via ENV vars)
# -----------------------
GEOIP_DB = os.environ.get("GEOIP_DB", "GeoLite2-City.mmdb")
THREAT_FEED_FILE = os.environ.get("THREAT_FEED_FILE", "threat_feeds.txt")

# Email settings (set via env vars)
SEND_EMAIL = os.environ.get("SEND_EMAIL", "0") == "1"     # set SEND_EMAIL=1 to enable
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
ALERT_RECIPIENT = os.environ.get("ALERT_RECIPIENT", "")

# Rate limit: minimum seconds between alert emails for same IP
ALERT_EMAIL_COOLDOWN = int(os.environ.get("ALERT_EMAIL_COOLDOWN", 600))  # default 10 minutes

# -----------------------
# Load GeoIP DB (if available)
# -----------------------
geoip_reader = None
if geoip2 and os.path.isfile(GEOIP_DB):
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_DB)
        print(f"[+] Loaded GeoIP DB: {GEOIP_DB}")
    except Exception as e:
        print("[!] Failed to open GeoIP DB:", e)
else:
    print("[!] GeoIP DB not available. City/country/coords will be Unknown or None.")

# -----------------------
# Load threat feed into memory
# -----------------------
THREAT_FEED = set()
if os.path.isfile(THREAT_FEED_FILE):
    with open(THREAT_FEED_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                THREAT_FEED.add(line)
    print(f"[+] Loaded threat feed ({len(THREAT_FEED)} entries) from {THREAT_FEED_FILE}")
else:
    print(f"[!] Threat feed file '{THREAT_FEED_FILE}' not found. Create it to enable threat checks.")

# -----------------------
# In-memory storage
# -----------------------
events = []  # list of dicts
last_email_sent = {}  # ip -> timestamp of last email sent

# -----------------------
# Email sending helper
# -----------------------
def _send_email(subject: str, body: str):
    """Sends email via SMTP (blocking). Called inside a thread."""
    import smtplib
    from email.mime.text import MIMEText

    if not SEND_EMAIL:
        print("[*] SEND_EMAIL disabled; skipping email send.")
        return False

    if not SMTP_USER or not SMTP_PASS or not ALERT_RECIPIENT:
        print("[!] SMTP credentials or ALERT_RECIPIENT missing; cannot send email.")
        return False

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_RECIPIENT

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15)
        server.ehlo()
        if SMTP_PORT == 587:
            server.starttls()
            server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [ALERT_RECIPIENT], msg.as_string())
        server.quit()
        print("[+] Alert email sent to", ALERT_RECIPIENT)
        return True
    except Exception as e:
        print("[!] Failed to send alert email:", e)
        return False

def send_alert_email_async(ip: str, event: dict):
    """Rate-limited background email send. Non-blocking for Flask request."""
    now = time.time()
    last = last_email_sent.get(ip, 0)
    if now - last < ALERT_EMAIL_COOLDOWN:
        print(f"[*] Skipping email for {ip}: last sent {int(now - last)}s ago.")
        return

    # compose email
    subject = f"SIEM Lite Alert: Suspicious IP {ip}"
    body = (
        f"Suspicious event detected\n\n"
        f"Timestamp: {event['timestamp']}\n"
        f"IP: {ip}\n"
        f"Event: {event['event']}\n"
        f"Country: {event.get('country')}\n"
        f"City: {event.get('city')}\n\n"
        f"This is an automated alert from your SIEM Lite."
    )

    def _worker():
        ok = _send_email(subject, body)
        if ok:
            last_email_sent[ip] = time.time()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

# -----------------------
# HTML template (map + chart + table + export)
# -----------------------
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Lite - Dashboard</title>
    <meta charset="utf-8"/>
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
    <style>
        body { font-family: Arial, sans-serif; margin: 16px; }
        #map { height: 360px; margin-bottom: 18px; border-radius: 6px; }
        .alert-box { background: #ff4d4d; color: white; padding: 10px; border-radius: 6px; margin-bottom: 10px; }
        .controls { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:10px; }
        .controls form { display:inline-block; }
        table { border-collapse: collapse; width: 100%; margin-top:12px; }
        th, td { padding: 8px; border: 1px solid #ddd; text-align: left; }
        .threat { background-color: #ffefef; }
        #chart-container { width: 75%; margin: 10px 0; }
        a.btn { padding:6px 10px; background:#2c7be5; color:white; text-decoration:none; border-radius:4px; }
    </style>
</head>
<body>
    <h1>SIEM Lite - Dashboard</h1>

    {% if suspicious_count > 0 %}
    <div class="alert-box">
        ⚠️ Suspicious Events Detected: {{ suspicious_count }}
        &nbsp;&nbsp;<a class="btn" href="/export_csv">Export CSV</a>
    </div>
    {% endif %}

    <div class="controls">
      <form method="POST" action="/add_event">
        <label><b>Event</b></label><br>
        <input name="description" placeholder="e.g. Failed login attempt" required>
        <br>
        <label><b>Source IP</b></label><br>
        <input name="source_ip" placeholder="e.g. 8.8.8.8" required>
        <br>
        <input type="submit" value="Add Event">
      </form>

      <div>
        <b>Quick test IPs:</b><br>
        <button onclick="fill('8.8.8.8')">8.8.8.8</button>
        <button onclick="fill('1.1.1.1')">1.1.1.1</button>
        <button onclick="fill('185.60.216.35')">185.60.216.35</button>
        <button onclick="fill('103.21.244.0')">103.21.244.0</button>
      </div>
    </div>

    <h3>Event Map</h3>
    <div id="map"></div>

    <h3>Events per Country</h3>
    <div id="chart-container"><canvas id="eventChart"></canvas></div>

    <h3>Event Table</h3>
    <table id="eventTable">
        <thead>
            <tr><th>Timestamp</th><th>Source IP</th><th>Event</th><th>Country</th><th>City</th><th>Status</th></tr>
        </thead>
        <tbody></tbody>
    </table>

    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    function fill(ip){ document.querySelector('input[name="source_ip"]').value = ip; }

    const map = L.map('map').setView([20,0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '© OpenStreetMap contributors' }).addTo(map);
    let markers = [];
    let chart;

    async function fetchEvents(){
        const res = await fetch('/events');
        const events = await res.json();

        // table
        const tbody = document.querySelector('#eventTable tbody');
        tbody.innerHTML = '';
        events.slice().reverse().forEach(e => {
            const tr = document.createElement('tr');
            if (e.is_threat) tr.classList.add('threat');
            tr.innerHTML = `<td>${e.timestamp}</td><td>${e.source_ip}</td><td>${e.event}</td><td>${e.country}</td><td>${e.city}</td><td>${e.is_threat ? '⚠️ Suspicious' : 'Normal'}</td>`;
            tbody.appendChild(tr);
        });

        // map
        markers.forEach(m => m.remove && m.remove());
        markers = [];
        events.forEach(e => {
            if (e.lat && e.lon) {
                const m = L.marker([e.lat, e.lon]).addTo(map);
                let popup = `<b>${e.event}</b><br>IP: ${e.source_ip}<br>Country: ${e.country}<br>City: ${e.city}`;
                if (e.is_threat) popup += "<br><b style='color:red;'>⚠️ Suspicious</b>";
                m.bindPopup(popup);
                markers.push(m);
            }
        });

        // chart
        const counts = {};
        events.forEach(e => {
            if (e.country && e.country !== "Unknown") counts[e.country] = (counts[e.country]||0)+1;
        });
        const labels = Object.keys(counts);
        const data = Object.values(counts);
        if (chart) {
            chart.data.labels = labels; chart.data.datasets[0].data = data; chart.update();
        } else {
            const ctx = document.getElementById('eventChart').getContext('2d');
            chart = new Chart(ctx, {
                type: 'bar',
                data: { labels: labels, datasets: [{ label: 'Events per Country', data: data }]},
                options: { scales: { y: { beginAtZero: true } } }
            });
        }
    }

    // auto-refresh
    setInterval(fetchEvents, 3000);
    fetchEvents();
    </script>
</body>
</html>
"""

# -----------------------
# Routes
# -----------------------
@app.route("/")
def index():
    suspicious_count = sum(1 for e in events if e.get("is_threat"))
    return render_template_string(TEMPLATE, suspicious_count=suspicious_count)

@app.route("/events")
def get_events():
    return jsonify(events)

@app.route("/add_event", methods=["POST"])
def add_event():
    description = request.form.get("description", "")
    source_ip = request.form.get("source_ip", "").strip()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # GeoIP lookup
    country = "Unknown"; city = "Unknown"; lat = None; lon = None
    if geoip_reader:
        try:
            r = geoip_reader.city(source_ip)
            country = r.country.name or "Unknown"
            city = r.city.name or "Unknown"
            lat = r.location.latitude
            lon = r.location.longitude
        except Exception:
            pass

    # Threat check
    is_threat = source_ip in THREAT_FEED

    ev = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event": description,
        "country": country,
        "city": city,
        "lat": lat,
        "lon": lon,
        "is_threat": is_threat
    }
    events.append(ev)

    # If suspicious, trigger alert email (async, rate-limited)
    if is_threat and SEND_EMAIL:
        send_alert_email_async(source_ip, ev)

    return redirect(url_for("index"))

# CSV export of suspicious events
@app.route("/export_csv")
def export_csv():
    suspicious = [e for e in events if e.get("is_threat")]
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["Timestamp", "Source IP", "Event", "Country", "City", "Status"])
    for e in suspicious:
        writer.writerow([e["timestamp"], e["source_ip"], e["event"], e["country"], e["city"], "Suspicious"])
    output = Response(si.getvalue(), mimetype="text/csv")
    output.headers["Content-Disposition"] = "attachment; filename=suspicious_events.csv"
    return output

# -----------------------
# Run server
# -----------------------
if __name__ == "__main__":
    print("[*] Starting SIEM Lite on http://127.0.0.1:5000")
    app.run(debug=True)