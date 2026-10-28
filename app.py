import os
import re
import socket
import requests
import whois
import json
import hashlib
import urllib.parse
import time
import tempfile
import sqlite3
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from werkzeug.utils import secure_filename
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'eml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

# ================= BASE DE DATOS =================
DB_PATH = 'osint_logs.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  herramienta TEXT,
                  consulta TEXT,
                  resultado TEXT,
                  ip TEXT,
                  fecha TEXT)''')
    conn.commit()
    conn.close()

def log_query(herramienta, consulta, resultado_json, req):
    try:
        ip = req.headers.get('X-Forwarded-For', req.remote_addr).split(',')[0].strip()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        res_str = json.dumps(resultado_json) if isinstance(resultado_json, (dict, list)) else str(resultado_json)
        c.execute("INSERT INTO logs (herramienta, consulta, resultado, ip, fecha) VALUES (?, ?, ?, ?, ?)",
                  (herramienta, str(consulta)[:255], res_str[:2000], ip, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error DB: {e}")

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_metadata(filepath, filename):
    metadata = {"filename": filename, "size_bytes": os.path.getsize(filepath)}
    if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.pdf')):
        with open(filepath, 'rb') as f:
            header = f.read(20).hex()
            metadata["magic_bytes"] = header
        metadata["message"] = "Metadatos limitados (sin Pillow)."
    else:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                metadata['md5'] = hashlib.md5(content.encode()).hexdigest()
        except:
            metadata['md5'] = "No se pudo leer (binario)"
    return metadata

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}

# ================= ENDPOINTS =================

@app.route('/api/username', methods=['POST'])
def api_username():
    username = request.get_json().get('value', '')
    if not username: return jsonify({"error": "Username vacío"})
    try:
        r = requests.get(f"https://whatsmyname.app/api/v1/username?username={username}", headers=HEADERS, timeout=15)
        res = r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        res = {"error": str(e)}
    log_query('username', username, res, request)
    return jsonify(res)

@app.route('/api/email', methods=['POST'])
def api_email():
    email = request.get_json().get('value', '')
    if not email: return jsonify({"error": "Correo vacío"})
    result = {}
    try:
        headers = HEADERS.copy()
        EMAILREP_KEY = os.environ.get('EMAILREP_KEY', '')
        if EMAILREP_KEY: headers["X-API-Key"] = EMAILREP_KEY
        r = requests.get(f'https://emailrep.io/{email}', headers=headers, timeout=10)
        result['emailrep'] = r.json() if r.status_code == 200 else f"Error {r.status_code}"
    except Exception as e:
        result['emailrep_error'] = str(e)
    
    try:
        HIBP_KEY = os.environ.get('HIBP_KEY', '')
        if not HIBP_KEY: result['hibp_error'] = "Requiere HIBP_KEY"
        else:
            h_hibp = HEADERS.copy(); h_hibp["hibp-api-key"] = HIBP_KEY
            r = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=h_hibp, timeout=10)
            if r.status_code == 200: result['hibp'] = [b['Name'] for b in r.json()]
            elif r.status_code == 404: result['hibp'] = []
            else: result['hibp_error'] = f"HTTP {r.status_code}"
    except Exception as e:
        result['hibp_error'] = str(e)
    
    log_query('email', email, result, request)
    return jsonify(result)

@app.route('/api/phone', methods=['POST'])
def api_phone():
    NUMVERIFY_KEY = os.environ.get('NUMVERIFY_KEY', '')
    phone = request.get_json().get('value', '')
    if not NUMVERIFY_KEY: return jsonify({"error": "Configura NUMVERIFY_KEY"})
    try:
        r = requests.get(f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={phone}", timeout=10)
        res = r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        res = {"error": str(e)}
    log_query('phone', phone, res, request)
    return jsonify(res)

@app.route('/api/domain', methods=['POST'])
def api_domain():
    domain = request.get_json().get('value', '')
    if not domain: return jsonify({"error": "Dominio vacío"})
    try:
        w = whois.whois(domain)
        res = {
            "domain_name": w.domain_name, "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else "N/A",
            "org": getattr(w, 'org', 'N/A')
        }
    except Exception as e:
        res = {"error": str(e)}
    log_query('domain', domain, res, request)
    return jsonify(res)

@app.route('/api/portscan', methods=['POST'])
def api_portscan():
    data = request.get_json()
    host = data.get('value', '')
    port_range = data.get('range', '21,22,23,80,443,3306,3389,8080')
    if not host: return jsonify({"error": "Host vacío"})
    try:
        ip = socket.gethostbyname(host)
        ports = [int(p.strip()) for p in port_range.split(',')]
    except:
        return jsonify({"error": "Resolución o formato inválido"})
    
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex((ip, port)) == 0: open_ports.append(port)
        sock.close()
    
    res = {"host": host, "ip": ip, "open_ports": open_ports}
    log_query('portscan', host, res, request)
    return jsonify(res)

@app.route('/api/reputation', methods=['POST'])
def api_reputation():
    target = request.get_json().get('value', '')
    if not target: return jsonify({"error": "Target vacío"})
    try:
        ip = socket.gethostbyname(target)
        res = requests.get(f'http://ip-api.com/json/{ip}', timeout=10).json()
    except Exception as e:
        res = {"error": "No se pudo resolver"}
    log_query('reputation', target, res, request)
    return jsonify(res)

@app.route('/api/metadata', methods=['POST'])
def api_metadata():
    if 'file' not in request.files: return jsonify({"error": "No hay archivo"})
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename): return jsonify({"error": "Archivo inválido"})
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    res = extract_metadata(filepath, filename)
    os.remove(filepath)
    log_query('metadata_file', filename, res, request)
    return jsonify(res)

@app.route('/api/metadata_url', methods=['POST'])
def api_metadata_url():
    url = request.get_json().get('value', '')
    if not url: return jsonify({"error": "URL vacía"})
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200: return jsonify({"error": "No descargable"})
        fd, temppath = tempfile.mkstemp(suffix='.jpg')
        os.write(fd, r.content); os.close(fd)
        res = extract_metadata(temppath, url.split('/')[-1])
        os.remove(temppath)
    except Exception as e:
        res = {"error": str(e)}
    log_query('metadata_url', url, res, request)
    return jsonify(res)

@app.route('/api/hash', methods=['POST'])
def api_hash():
    h = request.get_json().get('value', '').strip()
    htype = {32: 'MD5', 40: 'SHA1', 64: 'SHA256'}.get(len(h))
    res = {"hash": h, "type": htype} if htype else {"error": "Longitud no reconocida"}
    log_query('hash', h, res, request)
    return jsonify(res)

@app.route('/api/shodan', methods=['POST'])
def api_shodan():
    SHODAN_KEY = os.environ.get('SHODAN_KEY', '')
    if not SHODAN_KEY: return jsonify({"error": "Requiere SHODAN_KEY"})
    query = request.get_json().get('value', '')
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{query}?key={SHODAN_KEY}", timeout=15)
        res = r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        res = {"error": str(e)}
    log_query('shodan', query, res, request)
    return jsonify(res)

@app.route('/api/dork', methods=['POST'])
def api_dork():
    dork = request.get_json().get('value', '')
    res = {"url": f"https://www.google.com/search?q={urllib.parse.quote(dork)}"}
    log_query('dork', dork, res, request)
    return jsonify(res)

@app.route('/api/bitcoin', methods=['POST'])
def api_bitcoin():
    address = request.get_json().get('value', '')
    try:
        r = requests.get(f'https://blockchain.info/rawaddr/{address}', timeout=15)
        res = {"address": address, "balance": r.json().get('final_balance'), "n_tx": r.json().get('n_tx')} if r.status_code == 200 else {"error": "No encontrado"}
    except Exception as e:
        res = {"error": str(e)}
    log_query('bitcoin', address, res, request)
    return jsonify(res)

@app.route('/api/email_forensics', methods=['POST'])
def api_email_forensics():
    headers_text = request.get_json().get('value', '')
    parsed = {}
    for line in headers_text.split('\n'):
        if ': ' in line:
            key, val = line.split(': ', 1)
            parsed[key.lower()] = val
    log_query('email_forensics', 'headers', parsed, request)
    return jsonify(parsed)

@app.route('/api/breach', methods=['POST'])
def api_breach():
    email = request.get_json().get('value', '')
    try:
        HIBP_KEY = os.environ.get('HIBP_KEY', '')
        if not HIBP_KEY: return jsonify({"error": "Requiere HIBP_KEY"})
        h = HEADERS.copy(); h["hibp-api-key"] = HIBP_KEY
        r = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=h, timeout=10)
        res = [{"name": b['Name'], "date": b['BreachDate']} for b in r.json()] if r.status_code == 200 else []
    except Exception as e:
        res = {"error": str(e)}
    log_query('breach', email, res, request)
    return jsonify({"email": email, "breaches": res})

@app.route('/api/ipgeo', methods=['POST'])
def api_ipgeo():
    return api_reputation()

@app.route('/api/mac', methods=['POST'])
def api_mac():
    mac = request.get_json().get('value', '').replace('-', '').replace(':', '').upper()
    try:
        r = requests.get(f'https://api.macvendors.com/{mac[:6]}', timeout=10)
        res = {"mac": mac, "vendor": r.text} if r.status_code == 200 else {"vendor": "No encontrado"}
    except:
        res = {"error": "Error de conexión"}
    log_query('mac', mac, res, request)
    return jsonify(res)

@app.route('/api/subdomains', methods=['POST'])
def api_subdomains():
    domain = request.get_json().get('value', '')
    try:
        r = requests.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=20)
        subs = list(set([n.strip() for e in r.json() for n in e.get('name_value', '').split('\n') if n.strip().endswith(domain)])) if r.status_code == 200 else []
        res = {"domain": domain, "subdomains": subs[:100]}
    except Exception as e:
        res = {"error": str(e)}
    log_query('subdomains', domain, res, request)
    return jsonify(res)

@app.route('/api/reverse_image', methods=['POST'])
def api_reverse_image():
    url = request.get_json().get('value', '')
    res = {"url": f"https://www.google.com/searchbyimage?image_url={urllib.parse.quote(url)}"}
    log_query('reverse_image', url, res, request)
    return jsonify(res)

@app.route('/api/password_check', methods=['POST'])
def api_password_check():
    pw = request.get_json().get('value', '')
    if not pw: return jsonify({"error": "Contraseña vacía"})
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    try:
        r = requests.get(f'https://api.pwnedpasswords.com/range/{sha1[:5]}', timeout=10)
        res = {"pwned": False}
        for line in r.text.splitlines():
            if line.startswith(sha1[5:]):
                res = {"pwned": True, "count": int(line.split(':')[1])}
                break
    except Exception as e:
        res = {"error": str(e)}
    log_query('password_check', '***', res, request)
    return jsonify(res)

@app.route('/api/ai_threat', methods=['POST'])
def api_ai_threat():
    VIRUSTOTAL_KEY = os.environ.get('VIRUSTOTAL_KEY', '')
    if not VIRUSTOTAL_KEY: return jsonify({"error": "Requiere VIRUSTOTAL_KEY"})
    url = request.get_json().get('value', '')
    try:
        r = requests.post('https://www.virustotal.com/api/v3/urls', headers={"x-apikey": VIRUSTOTAL_KEY}, data={"url": url}, timeout=15)
        res = {"message": "Escaneo enviado", "id": r.json()['data']['id']} if r.status_code == 200 else {"error": "Error"}
    except Exception as e:
        res = {"error": str(e)}
    log_query('ai_threat', url, res, request)
    return jsonify(res)

@app.route('/api/js_secrets', methods=['POST'])
def api_js_secrets():
    url = request.get_json().get('value', '')
    try:
        r = requests.get(url, timeout=10)
        found = []
        if r.status_code == 200:
            pats = {"AWS": r'AKIA[0-9A-Z]{16}', "Google": r'AIza[0-9A-Za-z\-_]{35}', "GitHub": r'ghp_[0-9A-Za-z]{36}'}
            for n, p in pats.items():
                m = re.findall(p, r.text)
                if m: found.append({"type": n, "matches": m[:3]})
        res = {"secrets_found": found}
    except Exception as e:
        res = {"error": str(e)}
    log_query('js_secrets', url, res, request)
    return jsonify(res)

@app.route('/api/wayback', methods=['POST'])
def api_wayback():
    url = request.get_json().get('value', '')
    try:
        r = requests.get(f'https://archive.org/wayback/available?url={url}', timeout=15)
        res = r.json()
    except Exception as e:
        res = {"error": str(e)}
    log_query('wayback', url, res, request)
    return jsonify(res)

@app.route('/api/takeover', methods=['POST'])
def api_takeover():
    domain = request.get_json().get('value', '')
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
        subs = list(set([n.strip() for e in r.json() for n in e.get('name_value', '').split('\n') if n.strip().endswith(domain)])) if r.status_code == 200 else []
        vuln = []
        for sub in subs[:20]:
            try:
                import dns.resolver
                for rdata in dns.resolver.resolve(sub, 'CNAME'):
                    t = str(rdata.target).rstrip('.')
                    if any(x in t for x in ['s3.amazonaws.com', 'github.io', 'herokuapp.com']):
                        vuln.append({"subdomain": sub, "cname": t})
            except: pass
        res = {"subdomains": subs[:50], "potential_takeover": vuln}
    except Exception as e:
        res = {"error": str(e)}
    log_query('takeover', domain, res, request)
    return jsonify(res)

@app.route('/api/exposed_files', methods=['POST'])
def api_exposed_files():
    domain = request.get_json().get('value', '')
    files = ["/robots.txt", "/.env", "/.git/config", "/backup.zip", "/backup.sql", "/config.php", "/wp-config.php", "/.htaccess", "/phpinfo.php"]
    found = []
    for path in files:
        url = f"http://{domain}{path}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200: found.append({"url": url, "size": len(r.content)})
        except: pass
    res = {"exposed": found}
    log_query('exposed_files', domain, res, request)
    return jsonify(res)

@app.route('/api/security_headers', methods=['POST'])
def api_security_headers():
    url = request.get_json().get('value', '')
    if not url.startswith('http'): url = 'https://' + url
    try:
        r = requests.get(url, timeout=10)
        res = {"headers": {h: r.headers.get(h, 'No') for h in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"]}}
    except Exception as e:
        res = {"error": str(e)}
    log_query('security_headers', url, res, request)
    return jsonify(res)

@app.route('/api/cve', methods=['POST'])
def api_cve():
    kw = request.get_json().get('value', '')
    try:
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}&resultsPerPage=20", timeout=20)
        res = r.json()
    except Exception as e:
        res = {"error": str(e)}
    log_query('cve', kw, res, request)
    return jsonify(res)

@app.route('/api/asn', methods=['POST'])
def api_asn():
    ip = request.get_json().get('value', '')
    try:
        r = requests.get(f'https://ipinfo.io/{ip}/json', timeout=10)
        res = {"org": r.json().get('org'), "asn": r.json().get('asn', 'N/A'), "country": r.json().get('country')} if r.status_code == 200 else {"error": "No ASN"}
    except Exception as e:
        res = {"error": str(e)}
    log_query('asn', ip, res, request)
    return jsonify(res)

@app.route('/api/s3finder', methods=['POST'])
def api_s3finder():
    c = request.get_json().get('value', '')
    perms = [c, f"{c}-backup", f"{c}-dev", f"{c}-prod", f"{c}-staging", f"{c}-data", f"{c}-static"]
    found = []
    for b in perms:
        try:
            r = requests.get(f"https://{b}.s3.amazonaws.com", timeout=5)
            if r.status_code in [200, 403]: found.append({"bucket": b, "status": r.status_code})
        except: pass
    res = {"buckets": found}
    log_query('s3finder', c, res, request)
    return jsonify(res)

@app.route('/api/cors', methods=['POST'])
def api_cors():
    url = request.get_json().get('value', '')
    if not url.startswith('http'): url = 'https://' + url
    try:
        r = requests.options(url, timeout=10)
        cors = r.headers.get('Access-Control-Allow-Origin')
        res = {"cors_origin": cors, "cors_enabled": cors is not None}
    except Exception as e:
        res = {"error": str(e)}
    log_query('cors', url, res, request)
    return jsonify(res)

@app.route('/api/github_secrets', methods=['POST'])
def api_github_secrets():
    GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
    if not GITHUB_TOKEN: return jsonify({"error": "Requiere GITHUB_TOKEN"})
    org = request.get_json().get('value', '')
    h = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    try:
        r = requests.get(f"https://api.github.com/search/code?q=org:{org}+extension:env+OR+extension:key", headers=h, timeout=30)
        res = r.json() if r.status_code == 200 else {"error": f"Error {r.status_code}"}
    except Exception as e:
        res = {"error": str(e)}
    log_query('github_secrets', org, res, request)
    return jsonify(res)

@app.route('/api/tech_detect', methods=['POST'])
def api_tech_detect():
    domain = request.get_json().get('value', '')
    if not domain.startswith('http'): domain = 'https://' + domain
    try:
        r = requests.get(domain, timeout=10, verify=False)
        tech = {}
        if 'Server' in r.headers: tech['Servidor'] = r.headers['Server']
        if 'x-powered-by' in r.headers: tech['Powered by'] = r.headers['x-powered-by']
        for c in ['WordPress', 'Drupal', 'Joomla', 'Laravel', 'Django']:
            if c.lower() in r.text.lower(): tech['CMS/Framework'] = c
        res = {"domain": domain, "technologies": tech}
    except Exception as e:
        res = {"error": str(e)}
    log_query('tech_detect', domain, res, request)
    return jsonify(res)

# ================= FRONTEND =================

@app.route('/manifest.json')
def manifest():
    return jsonify({"name": "OSINT Dashboard", "short_name": "OSINT", "start_url": "/", "display": "standalone", "background_color": "#0a0a0a", "theme_color": "#00ff00", "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/1061/1061105.png", "sizes": "512x512", "type": "image/png"}]})

@app.route('/sw.js')
def sw():
    return app.response_class("const CACHE_NAME='osint-v1';self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE_NAME).then(c=>c.addAll(['/']))));self.addEventListener('fetch',e=>e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request))));", content_type='application/javascript')

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>OSINT Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
    <link rel="manifest" href="/manifest.json">
    <style>
        *{box-sizing:border-box}
        body{font-family:'Courier New',monospace;background:#0a0a0a;color:#00ff00;margin:0;padding:20px}
        .container{max-width:1200px;margin:auto;background:#111;border-radius:24px;padding:24px;border:1px solid #0f0;box-shadow:0 0 15px rgba(0,255,0,0.2)}
        h1,h2{color:#0f0;text-shadow:0 0 5px #0f0}
        h1{font-size:1.8rem;text-align:center}
        .sub{text-align:center;margin-bottom:2rem;color:#0f0}
        .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px}
        .card{background:#0a0a0a;border-radius:16px;padding:16px;border-left:4px solid #0f0;border:1px solid #0f0}
        input,button,textarea,select{padding:12px 16px;margin-top:8px;border-radius:12px;font-size:1rem;width:100%;background:#222;color:#0f0;border:1px solid #0f0;font-family:monospace}
        button{background:#0f0;color:#000;font-weight:bold;cursor:pointer;transition:transform 0.1s}
        button:active{transform:scale(0.97)}
        .result-box{background:#0a0a0a;padding:16px;border-radius:12px;margin-top:20px;font-family:monospace;font-size:0.8rem;border:1px solid #0f0;max-height:500px;overflow:auto;white-space:pre-wrap}
        .badge{background:#0f0;color:#000;padding:2px 8px;border-radius:20px;font-size:0.7rem;display:inline-block;margin-bottom:8px}
        .footer{text-align:center;margin-top:24px;font-size:0.7rem;color:#0f0}
        /* Cookies */
        #cookie-banner{display:none;position:fixed;bottom:0;left:0;width:100%;background:#111;border-top:2px solid #0f0;padding:15px;text-align:center;z-index:9999;box-sizing:border-box}
        #cookie-banner p{margin:0 0 10px 0;color:#0f0;font-size:0.85rem}
        #cookie-banner button{padding:10px 20px;width:auto;font-size:1rem;background:#0f0;color:#000;font-weight:bold;border:none;border-radius:8px;cursor:pointer}
    </style>
</head>
<body>
<div class="container">
    <h1>🕵️‍♂️ OSINT Dashboard</h1>
    <div class="sub">Herramientas de inteligencia de fuentes abiertas</div>
    <div class="grid">
        <div class="card"><div class="badge">🔍 Username</div><input type="text" id="username" placeholder="Nombre"><button onclick="analyze('username')">Buscar</button></div>
        <div class="card"><div class="badge">📧 Email</div><input type="text" id="email" placeholder="correo@ejemplo.com"><button onclick="analyze('email')">Analizar</button></div>
        <div class="card"><div class="badge">📞 Teléfono</div><input type="text" id="phone" placeholder="+521234567890"><button onclick="analyze('phone')">Consultar</button></div>
        <div class="card"><div class="badge">🌐 Dominio (WHOIS)</div><input type="text" id="domain" placeholder="ejemplo.com"><button onclick="analyze('domain')">WHOIS</button></div>
        <div class="card"><div class="badge">🔌 Escáner de Puertos</div><input type="text" id="portscan" placeholder="ejemplo.com"><button onclick="analyze('portscan')">Escanear</button></div>
        <div class="card"><div class="badge">⚡ Reputación IP/Dominio</div><input type="text" id="reputation" placeholder="IP o dominio"><button onclick="analyze('reputation')">Verificar</button></div>
        <div class="card"><div class="badge">🖼️ Metadatos (archivo)</div><input type="file" id="metadatafile"><button onclick="uploadMetadata()">Subir</button></div>
        <div class="card"><div class="badge">🖼️ Metadatos (URL)</div><input type="text" id="metadata_url" placeholder="URL imagen"><button onclick="analyze('metadata_url')">Extraer</button></div>
        <div class="card"><div class="badge">🔐 Analizador de Hash</div><input type="text" id="hash" placeholder="MD5,SHA1,SHA256"><button onclick="analyze('hash')">Analizar</button></div>
        <div class="card"><div class="badge">🔎 Shodan</div><input type="text" id="shodan" placeholder="IP"><button onclick="analyze('shodan')">Buscar</button></div>
        <div class="card"><div class="badge">📄 Google Dorking</div><input type="text" id="dork" placeholder="site:example.com"><button onclick="analyze('dork')">Generar</button></div>
        <div class="card"><div class="badge">₿ Bitcoin</div><input type="text" id="bitcoin" placeholder="Dirección BTC"><button onclick="analyze('bitcoin')">Consultar</button></div>
        <div class="card"><div class="badge">✉️ Email Forensics</div><textarea id="email_headers" rows="2" placeholder="Cabeceras"></textarea><button onclick="analyze('email_forensics')">Analizar</button></div>
        <div class="card"><div class="badge">📊 Data Breach</div><input type="text" id="breach" placeholder="correo@ejemplo.com"><button onclick="analyze('breach')">Verificar</button></div>
        <div class="card"><div class="badge">🌍 IP Geolocation</div><input type="text" id="ipgeo" placeholder="IP"><button onclick="analyze('ipgeo')">Localizar</button></div>
        <div class="card"><div class="badge">🖧 MAC Lookup</div><input type="text" id="mac" placeholder="AA:BB:CC:DD:EE:FF"><button onclick="analyze('mac')">Fabricante</button></div>
        <div class="card"><div class="badge">📡 Subdomain Enumeration</div><input type="text" id="subdomains" placeholder="dominio.com"><button onclick="analyze('subdomains')">Enumerar</button></div>
        <div class="card"><div class="badge">🔍 Reverse Image Search</div><input type="text" id="reverse_image" placeholder="URL imagen"><button onclick="analyze('reverse_image')">Generar</button></div>
        <div class="card"><div class="badge">🔑 Password Checker</div><input type="text" id="password" placeholder="Contraseña"><button onclick="analyze('password_check')">Verificar</button></div>
        <div class="card"><div class="badge">🤖 AI Threat Analyzer</div><input type="text" id="ai_threat" placeholder="URL sospechosa"><button onclick="analyze('ai_threat')">Analizar</button></div>
        <div class="card"><div class="badge">💻 JS Secret Scanner</div><input type="text" id="js_secrets" placeholder="URL .js"><button onclick="analyze('js_secrets')">Buscar</button></div>
        <div class="card"><div class="badge">📆 Wayback URLs</div><input type="text" id="wayback" placeholder="URL"><button onclick="analyze('wayback')">Historial</button></div>
        <div class="card"><div class="badge">⚠️ Subdomain Takeover</div><input type="text" id="takeover" placeholder="dominio.com"><button onclick="analyze('takeover')">Detectar</button></div>
        <div class="card"><div class="badge">📁 Exposed Files</div><input type="text" id="exposed" placeholder="dominio.com"><button onclick="analyze('exposed_files')">Buscar</button></div>
        <div class="card"><div class="badge">🛡️ Security Headers</div><input type="text" id="headers" placeholder="https://ejemplo.com"><button onclick="analyze('security_headers')">Auditar</button></div>
        <div class="card"><div class="badge">🐞 CVE Search</div><input type="text" id="cve" placeholder="apache"><button onclick="analyze('cve')">Buscar</button></div>
        <div class="card"><div class="badge">🌐 ASN Lookup</div><input type="text" id="asn" placeholder="IP"><button onclick="analyze('asn')">ASN/Org</button></div>
        <div class="card"><div class="badge">📦 S3 Bucket Finder</div><input type="text" id="s3finder" placeholder="Empresa"><button onclick="analyze('s3finder')">Buscar</button></div>
        <div class="card"><div class="badge">🔗 CORS Check</div><input type="text" id="cors" placeholder="https://ejemplo.com"><button onclick="analyze('cors')">Testear</button></div>
        <div class="card"><div class="badge">🔑 GitHub Secrets</div><input type="text" id="github_secrets" placeholder="Organización"><button onclick="analyze('github_secrets')">Buscar</button></div>
        <div class="card"><div class="badge">🌡️ Tech Detection</div><input type="text" id="tech_detect" placeholder="dominio.com"><button onclick="analyze('tech_detect')">Detectar</button></div>
    </div>
    <div id="result" class="result-box">⚡ Resultados aquí...</div>
    <div class="footer">Desarrollado por @jsemanper · Uso educativo</div>
</div>

<!-- Banner Cookies -->
<div id="cookie-banner">
    <p>Este sitio utiliza cookies y registra las consultas realizadas en una base de datos local para fines de auditoría.</p>
    <button onclick="acceptCookies()">Aceptar</button>
</div>

<script>
    function acceptCookies() {
        document.cookie = "osint_cookie_consent=true; max-age=" + (60 * 60 * 24 * 365) + "; path=/";
        document.getElementById('cookie-banner').style.display = 'none';
    }
    if (!document.cookie.includes('osint_cookie_consent=true')) {
        document.getElementById('cookie-banner').style.display = 'block';
    }

    async function analyze(type) {
        let value = document.getElementById(type).value;
        if (type === 'email_forensics') value = document.getElementById('email_headers').value;
        if (!value) { document.getElementById('result').innerText = '❌ Ingresa un valor.'; return; }
        document.getElementById('result').innerText = '⏳ Consultando...';
        try {
            const res = await fetch(`/api/${type}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ value: value })
            });
            const data = await res.json();
            document.getElementById('result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
        } catch(e) {
            document.getElementById('result').innerText = '❌ Error de conexión.';
        }
    }
    async function uploadMetadata() {
        const file = document.getElementById('metadatafile').files[0];
        if (!file) { document.getElementById('result').innerText = '❌ Selecciona archivo.'; return; }
        const fd = new FormData(); fd.append('file', file);
        document.getElementById('result').innerText = '⏳ Subiendo...';
        try {
            const res = await fetch('/api/metadata', { method: 'POST', body: fd });
            const data = await res.json();
            document.getElementById('result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
        } catch(e) {
            document.getElementById('result').innerText = '❌ Error al subir.';
        }
    }
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').then(r => console.log('SW ok')).catch(e => console.log('SW error', e)));
    }
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)