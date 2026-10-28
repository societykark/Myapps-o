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

# Configuración de Base de Datos (Render usa /tmp para archivos temporales si no hay disco)
DB_PATH = os.environ.get('DB_PATH', '/tmp/osint_logs.db')

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'eml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

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

def log_query(herramienta, consulta, resultado_json, ip):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO logs (herramienta, consulta, resultado, ip, fecha) VALUES (?, ?, ?, ?, ?)",
                  (herramienta, str(consulta)[:255], str(resultado_json)[:2000], ip, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error guardando log: {e}")

# Inicializar DB al arrancar
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
            metadata['md5'] = "No se pudo leer (archivo binario)"
    return metadata

# Headers genéricos para evitar bloqueos
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# ================= API ENDPOINTS =================
@app.route('/api/username', methods=['POST'])
def api_username():
    data = request.get_json()
    username = data.get('value', '')
    if not username: return jsonify({"error": "Username vacío"})
    try:
        r = requests.get(f"https://whatsmyname.app/api/v1/username?username={username}", headers=HEADERS, timeout=15)
        res = {"status": "ok", "total": len(r.json().get('sites', [])), "sites": r.json().get('sites', [])[:50]} if r.status_code == 200 else {"error": f"Error HTTP {r.status_code}"}
        log_query('username', username, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/email', methods=['POST'])
def api_email():
    data = request.get_json()
    email = data.get('value', '')
    if not email: return jsonify({"error": "Correo vacío"})
    result = {}
    EMAILREP_KEY = os.environ.get('EMAILREP_KEY', '')
    HIBP_KEY = os.environ.get('HIBP_KEY', '')
    
    try:
        headers = HEADERS.copy()
        if EMAILREP_KEY: headers["X-API-Key"] = EMAILREP_KEY
        r = requests.get(f'https://emailrep.io/{email}', headers=headers, timeout=10)
        result['emailrep'] = r.json() if r.status_code == 200 else f"Error {r.status_code}"
    except Exception as e:
        result['emailrep_error'] = str(e)

    try:
        if not HIBP_KEY:
            result['hibp_error'] = "Requiere HIBP_KEY en Render"
        else:
            headers_hibp = HEADERS.copy()
            headers_hibp["hibp-api-key"] = HIBP_KEY
            r = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=headers_hibp, timeout=10)
            if r.status_code == 200: result['hibp'] = [b['Name'] for b in r.json()]
            elif r.status_code == 404: result['hibp'] = []
            else: result['hibp_error'] = f"HTTP {r.status_code}"
    except Exception as e:
        result['hibp_error'] = str(e)
    
    log_query('email', email, result, request.remote_addr)
    return jsonify(result)

@app.route('/api/phone', methods=['POST'])
def api_phone():
    NUMVERIFY_KEY = os.environ.get('NUMVERIFY_KEY', '')
    data = request.get_json()
    if not NUMVERIFY_KEY: 
        return jsonify({"error": "Configura NUMVERIFY_KEY en Render"})
    try:
        r = requests.get(f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={data.get('value', '')}", timeout=10)
        res = r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}
        log_query('phone', data.get('value', ''), res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/domain', methods=['POST'])
def api_domain():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain: return jsonify({"error": "Dominio vacío"})
    try:
        w = whois.whois(domain)
        res = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else "N/A",
            "org": getattr(w, 'org', 'N/A')
        }
        log_query('domain', domain, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": f"WHOIS falló: {str(e)}"})

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
        return jsonify({"error": "Resolución o formato de puerto inválido"})
    
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex((ip, port)) == 0: open_ports.append(port)
        sock.close()
    res = {"host": host, "ip": ip, "open_ports": open_ports}
    log_query('portscan', host, res, request.remote_addr)
    return jsonify(res)

@app.route('/api/reputation', methods=['POST'])
def api_reputation():
    target = request.get_json().get('value', '')
    if not target: return jsonify({"error": "Target vacío"})
    try:
        ip = socket.gethostbyname(target)
        res = requests.get(f'http://ip-api.com/json/{ip}', timeout=10).json()
        log_query('reputation', target, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": "No se pudo resolver la IP"})

@app.route('/api/metadata', methods=['POST'])
def api_metadata():
    if 'file' not in request.files: return jsonify({"error": "No se envió archivo"})
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename): return jsonify({"error": "Archivo no válido"})
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    metadata = extract_metadata(filepath, filename)
    os.remove(filepath)
    log_query('metadata', filename, metadata, request.remote_addr)
    return jsonify(metadata)

@app.route('/api/metadata_url', methods=['POST'])
def api_metadata_url():
    url = request.get_json().get('value', '')
    if not url: return jsonify({"error": "URL vacía"})
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200: return jsonify({"error": "No se pudo descargar"})
        fd, temppath = tempfile.mkstemp(suffix='.jpg')
        os.write(fd, r.content)
        os.close(fd)
        metadata = extract_metadata(temppath, url.split('/')[-1])
        os.remove(temppath)
        log_query('metadata_url', url, metadata, request.remote_addr)
        return jsonify(metadata)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/hash', methods=['POST'])
def api_hash():
    h = request.get_json().get('value', '').strip()
    htype = {32: 'MD5', 40: 'SHA1', 64: 'SHA256'}.get(len(h))
    if not htype: return jsonify({"error": "Longitud no reconocida"})
    res = {"hash": h, "type": htype, "message": "Solo identificación"}
    log_query('hash', h, res, request.remote_addr)
    return jsonify(res)

@app.route('/api/shodan', methods=['POST'])
def api_shodan():
    SHODAN_KEY = os.environ.get('SHODAN_KEY', '')
    if not SHODAN_KEY: return jsonify({"error": "Configura SHODAN_KEY"})
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{request.get_json().get('value')}?key={SHODAN_KEY}", timeout=15)
        res = r.json()
        log_query('shodan', request.get_json().get('value'), res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/dork', methods=['POST'])
def api_dork():
    dork = request.get_json().get('value', '')
    res = {"url": f"https://www.google.com/search?q={urllib.parse.quote(dork)}"}
    log_query('dork', dork, res, request.remote_addr)
    return jsonify(res)

@app.route('/api/bitcoin', methods=['POST'])
def api_bitcoin():
    address = request.get_json().get('value', '')
    try:
        r = requests.get(f'https://blockchain.info/rawaddr/{address}', timeout=15)
        res = {"address": address, "total_received": r.json().get('total_received'), "total_sent": r.json().get('total_sent'), "balance": r.json().get('balance'), "n_tx": r.json().get('n_tx')} if r.status_code == 200 else {"error": "No encontrado"}
        log_query('bitcoin', address, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/email_forensics', methods=['POST'])
def api_email_forensics():
    headers_text = request.get_json().get('value', '')
    parsed = {}
    for line in headers_text.split('\n'):
        if ': ' in line:
            key, val = line.split(': ', 1)
            parsed[key.lower()] = val
    log_query('email_forensics', 'headers', parsed, request.remote_addr)
    return jsonify(parsed)

@app.route('/api/breach', methods=['POST'])
def api_breach():
    email = request.get_json().get('value', '')
    HIBP_KEY = os.environ.get('HIBP_KEY', '')
    if not HIBP_KEY: return jsonify({"error": "Requiere HIBP_KEY"})
    try:
        headers_hibp = HEADERS.copy()
        headers_hibp["hibp-api-key"] = HIBP_KEY
        r = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=headers_hibp, timeout=10)
        res = {"email": email, "breaches": [{"name": b['Name'], "date": b['BreachDate']} for b in r.json()]} if r.status_code == 200 else {"email": email, "breaches": []}
        log_query('breach', email, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/ipgeo', methods=['POST'])
def api_ipgeo():
    ip = request.get_json().get('value', '')
    try:
        res = requests.get(f'http://ip-api.com/json/{ip}', timeout=10).json()
        log_query('ipgeo', ip, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/mac', methods=['POST'])
def api_mac():
    mac = request.get_json().get('value', '').replace('-', '').replace(':', '').upper()
    try:
        r = requests.get(f'https://api.macvendors.com/{mac[:6]}', timeout=10)
        res = {"mac": mac, "vendor": r.text} if r.status_code == 200 else {"vendor": "No encontrado"}
        log_query('mac', mac, res, request.remote_addr)
        return jsonify(res)
    except:
        return jsonify({"error": "Error de conexión"})

@app.route('/api/subdomains', methods=['POST'])
def api_subdomains():
    domain = request.get_json().get('value', '')
    try:
        r = requests.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=20)
        if r.status_code == 200:
            subdomains = set()
            for entry in r.json():
                name = entry.get('name_value')
                if name:
                    for n in name.split('\n'):
                        if n.endswith(domain): subdomains.add(n.strip())
            res = {"domain": domain, "subdomains": list(subdomains)[:100]}
            log_query('subdomains', domain, res, request.remote_addr)
            return jsonify(res)
        return jsonify({"error": "Error consultando crt.sh"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/reverse_image', methods=['POST'])
def api_reverse_image():
    img_url = request.get_json().get('value', '')
    res = {"url": f"https://www.google.com/searchbyimage?image_url={urllib.parse.quote(img_url)}"}
    log_query('reverse_image', img_url, res, request.remote_addr)
    return jsonify(res)

@app.route('/api/password_check', methods=['POST'])
def api_password_check():
    pw = request.get_json().get('value', '')
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    try:
        r = requests.get(f'https://api.pwnedpasswords.com/range/{sha1[:5]}', timeout=10)
        for line in r.text.splitlines():
            if line.startswith(sha1[5:]):
                res = {"pwned": True, "count": int(line.split(':')[1])}
                log_query('password_check', '***', res, request.remote_addr)
                return jsonify(res)
        res = {"pwned": False}
        log_query('password_check', '***', res, request.remote_addr)
        return jsonify(res)
    except:
        return jsonify({"error": "Error en API"})

@app.route('/api/ai_threat', methods=['POST'])
def api_ai_threat():
    VT_KEY = os.environ.get('VIRUSTOTAL_KEY', '')
    if not VT_KEY: return jsonify({"error": "Configura VIRUSTOTAL_KEY"})
    url = request.get_json().get('value', '')
    try:
        headers = {"x-apikey": VT_KEY}
        r = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={"url": url})
        res = {"message": "Escaneo enviado", "id": r.json()['data']['id']} if r.status_code == 200 else {"error": "Error en VirusTotal"}
        log_query('ai_threat', url, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/js_secrets', methods=['POST'])
def api_js_secrets():
    url = request.get_json().get('value', '')
    try:
        r = requests.get(url, timeout=10)
        patterns = {"AWS Key": r'AKIA[0-9A-Z]{16}', "Google API": r'AIza[0-9A-Za-z\-_]{35}', "GitHub Token": r'ghp_[0-9A-Za-z]{36}', "JWT": r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'}
        found = [{"type": name, "matches": re.findall(pat, r.text)[:3]} for name, pat in patterns.items() if re.findall(pat, r.text)]
        res = {"secrets_found": found}
        log_query('js_secrets', url, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/wayback', methods=['POST'])
def api_wayback():
    url = request.get_json().get('value', '')
    try:
        r = requests.get(f'https://archive.org/wayback/available?url={url}', timeout=15)
        res = r.json()
        log_query('wayback', url, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/takeover', methods=['POST'])
def api_takeover():
    domain = request.get_json().get('value', '')
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
        if r.status_code == 200:
            subdomains = {n.strip() for entry in r.json() if entry.get('name_value') for n in entry.get('name_value').split('\n') if n.endswith(domain)}
            vulnerable = []
            # Se omite resolución DNS interna para evitar timeouts en Render Free
            res = {"subdomains": list(subdomains)[:50], "potential_takeover": vulnerable}
            log_query('takeover', domain, res, request.remote_addr)
            return jsonify(res)
        return jsonify({"error": "Error en crt.sh"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/exposed_files', methods=['POST'])
def api_exposed_files():
    domain = request.get_json().get('value', '')
    common = ["/robots.txt", "/.env", "/.git/config", "/backup.zip", "/backup.sql", "/config.php", "/wp-config.php", "/.htaccess", "/phpinfo.php"]
    found = [{"url": f"http://{domain}{path}", "size": len(requests.get(f"http://{domain}{path}", timeout=3).content)} for path in common if requests.get(f"http://{domain}{path}", timeout=3).status_code == 200]
    res = {"exposed": found}
    log_query('exposed_files', domain, res, request.remote_addr)
    return jsonify(res)

@app.route('/api/security_headers', methods=['POST'])
def api_security_headers():
    url = request.get_json().get('value', '')
    if not url.startswith('http'): url = 'https://' + url
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        res = {"headers": {
            "Content-Security-Policy": r.headers.get('Content-Security-Policy', 'No'),
            "X-Frame-Options": r.headers.get('X-Frame-Options', 'No'),
            "X-Content-Type-Options": r.headers.get('X-Content-Type-Options', 'No'),
            "Strict-Transport-Security": r.headers.get('Strict-Transport-Security', 'No'),
            "Referrer-Policy": r.headers.get('Referrer-Policy', 'No')
        }}
        log_query('security_headers', url, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/cve', methods=['POST'])
def api_cve():
    keyword = request.get_json().get('value', '')
    try:
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20", timeout=20)
        res = r.json()
        log_query('cve', keyword, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/asn', methods=['POST'])
def api_asn():
    ip = request.get_json().get('value', '')
    try:
        r = requests.get(f'https://ipinfo.io/{ip}/json', timeout=10)
        info = r.json()
        res = {"org": info.get('org'), "asn": info.get('asn', 'N/A'), "country": info.get('country')}
        log_query('asn', ip, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/s3finder', methods=['POST'])
def api_s3finder():
    company = request.get_json().get('value', '')
    perms = [company, f"{company}-backup", f"{company}-dev", f"{company}-prod", f"{company}-staging", f"{company}-data", f"{company}-static", f"{company}-assets", f"{company}-media", f"{company}-cdn"]
    found = [{"bucket": b, "status": requests.get(f"https://{b}.s3.amazonaws.com", timeout=3).status_code} for b in perms if requests.get(f"https://{b}.s3.amazonaws.com", timeout=3).status_code in [200,403]]
    res = {"buckets": found}
    log_query('s3finder', company, res, request.remote_addr)
    return jsonify(res)

@app.route('/api/cors', methods=['POST'])
def api_cors():
    url = request.get_json().get('value', '')
    if not url.startswith('http'): url = 'https://' + url
    try:
        r = requests.options(url, timeout=10)
        cors = r.headers.get('Access-Control-Allow-Origin')
        res = {"cors_origin": cors, "cors_enabled": cors is not None}
        log_query('cors', url, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/github_secrets', methods=['POST'])
def api_github_secrets():
    GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
    if not GITHUB_TOKEN: return jsonify({"error": "Configura GITHUB_TOKEN"})
    org = request.get_json().get('value', '')
    try:
        headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
        r = requests.get(f"https://api.github.com/search/code?q=org:{org}+extension:conf+OR+extension:env", headers=headers, timeout=30)
        res = r.json()
        log_query('github_secrets', org, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/tech_detect', methods=['POST'])
def api_tech_detect():
    domain = request.get_json().get('value', '')
    if not domain.startswith('http'): domain = 'https://' + domain
    try:
        r = requests.get(domain, timeout=10, verify=False)
        tech = {}
        if 'Server' in r.headers: tech['Servidor'] = r.headers['Server']
        if 'x-powered-by' in r.headers: tech['Powered by'] = r.headers['x-powered-by']
        if '/wp-content/' in r.text: tech['CMS'] = 'WordPress'
        if 'Drupal' in r.text: tech['CMS'] = 'Drupal'
        if 'Joomla' in r.text: tech['CMS'] = 'Joomla'
        if 'laravel' in r.text.lower(): tech['Framework'] = 'Laravel'
        if 'django' in r.text.lower(): tech['Framework'] = 'Django'
        res = {"domain": domain, "technologies": tech}
        log_query('tech_detect', domain, res, request.remote_addr)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

# ================= PWA y FRONTEND =================
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
        
        /* Estilos del Banner de Cookies */
        #cookie-banner{display:none;position:fixed;bottom:0;left:0;width:100%;background:#111;border-top:2px solid #0f0;padding:15px;text-align:center;z-index:9999;box-sizing:border-box}
        #cookie-banner p{margin:0 0 10px 0;color:#0f0;font-size:0.85rem}
        #cookie-banner button{padding:10px 20px;width:auto;font-size:1rem;background:#0f0;color:#000;font-weight:bold;border:none;border-radius:8px;cursor:pointer}
    </style>
</head>
<body>

<!-- Banner de Cookies -->
<div id="cookie-banner">
    <p>Este sitio utiliza cookies y registra las consultas realizadas en una base de datos local para fines de auditoría.</p>
    <button onclick="acceptCookies()">Aceptar y Continuar</button>
</div>

<div class="container">
    <h1>🕵️‍♂️ OSINT Dashboard</h1>
    <div class="sub">Herramientas de inteligencia de fuentes abiertas</div>
    <div class="grid">
        <div class="card"><div class="badge">🔍 Username</div><input type="text" id="username" placeholder="Nombre"><button onclick="analyze('username')">Buscar</button></div>
        <div class="card"><div class="badge">📧 Email</div><input type="text" id="email" placeholder="correo@ejemplo.com"><button onclick="analyze('email')">Analizar</button></div>
        <div class="card"><div class="badge">📞 Teléfono</div><input type="text" id="phone" placeholder="+521234567890"><button onclick="analyze('phone')">Consultar</button></div>
        <div class="card"><div class="badge">🌐 Dominio (WHOIS)</div><input type="text" id="domain" placeholder="ejemplo.com"><button onclick="analyze('domain')">WHOIS</button></div>
        <div class="card"><div class="badge">🔌 Escáner de Puertos</div><input type="text" id="portscan" placeholder="ejemplo.com"><button onclick="analyze('portscan')">Escanea puertos comunes</button></div>
        <div class="card"><div class="badge">⚡ Reputación IP/Dominio</div><input type="text" id="reputation" placeholder="IP o dominio"><button onclick="analyze('reputation')">Verificar</button></div>
        <div class="card"><div class="badge">🖼️ Metadatos (archivo)</div><input type="file" id="metadatafile"><button onclick="uploadMetadata()">Subir</button></div>
        <div class="card"><div class="badge">🖼️ Metadatos (URL)</div><input type="text" id="metadata_url" placeholder="URL imagen"><button onclick="analyze('metadata_url')">Extraer</button></div>
        <div class="card"><div class="badge">🔐 Analizador de Hash</div><input type="text" id="hash" placeholder="MD5,SHA1,SHA256"><button onclick="analyze('hash')">Analizar</button></div>
        <div class="card"><div class="badge">🔎 Shodan</div><input type="text" id="shodan" placeholder="IP"><button onclick="analyze('shodan')">Buscar</button><small>Requiere API key</small></div>
        <div class="card"><div class="badge">📄 Google Dorking</div><input type="text" id="dork" placeholder="site:example.com"><button onclick="analyze('dork')">Generar URL</button></div>
        <div class="card"><div class="badge">₿ Bitcoin</div><input type="text" id="bitcoin" placeholder="Dirección BTC"><button onclick="analyze('bitcoin')">Consultar</button></div>
        <div class="card"><div class="badge">✉️ Email Forensics</div><textarea id="email_headers" rows="2" placeholder="Cabeceras de email"></textarea><button onclick="analyze('email_forensics')">Analizar</button></div>
        <div class="card"><div class="badge">📊 Data Breach</div><input type="text" id="breach" placeholder="correo@ejemplo.com"><button onclick="analyze('breach')">Verificar filtraciones</button></div>
        <div class="card"><div class="badge">🌍 IP Geolocation</div><input type="text" id="ipgeo" placeholder="IP"><button onclick="analyze('ipgeo')">Localizar</button></div>
        <div class="card"><div class="badge">🖧 MAC Lookup</div><input type="text" id="mac" placeholder="AA:BB:CC:DD:EE:FF"><button onclick="analyze('mac')">Fabricante</button></div>
        <div class="card"><div class="badge">📡 Subdomain Enumeration</div><input type="text" id="subdomains" placeholder="dominio.com"><button onclick="analyze('subdomains')">Enumerar</button></div>
        <div class="card"><div class="badge">🔍 Reverse Image Search</div><input type="text" id="reverse_image" placeholder="URL imagen"><button onclick="analyze('reverse_image')">Generar búsqueda</button></div>
        <div class="card"><div class="badge">🔑 Password Checker</div><input type="text" id="password_check" placeholder="Contraseña"><button onclick="analyze('password_check')">Verificar filtrada</button></div>
        <div class="card"><div class="badge">🤖 AI Threat Analyzer</div><input type="text" id="ai_threat" placeholder="URL sospechosa"><button onclick="analyze('ai_threat')">Analizar</button><small>Requiere VT key</small></div>
        <div class="card"><div class="badge">💻 JS Secret Scanner</div><input type="text" id="js_secrets" placeholder="URL .js"><button onclick="analyze('js_secrets')">Buscar secretos</button></div>
        <div class="card"><div class="badge">📆 Wayback URLs</div><input type="text" id="wayback" placeholder="URL"><button onclick="analyze('wayback')">Historial</button></div>
        <div class="card"><div class="badge">⚠️ Subdomain Takeover</div><input type="text" id="takeover" placeholder="dominio.com"><button onclick="analyze('takeover')">Detectar</button></div>
        <div class="card"><div class="badge">📁 Exposed Files</div><input type="text" id="exposed" placeholder="dominio.com"><button onclick="analyze('exposed_files')">Buscar archivos sensibles</button></div>
        <div class="card"><div class="badge">🛡️ Security Headers</div><input type="text" id="headers" placeholder="https://ejemplo.com"><button onclick="analyze('security_headers')">Auditar</button></div>
        <div class="card"><div class="badge">🐞 CVE Search</div><input type="text" id="cve" placeholder="apache"><button onclick="analyze('cve')">Buscar vulnerabilidades</button></div>
        <div class="card"><div class="badge">🌐 ASN Lookup</div><input type="text" id="asn" placeholder="IP"><button onclick="analyze('asn')">ASN/Org</button></div>
        <div class="card"><div class="badge">📦 S3 Bucket Finder</div><input type="text" id="s3finder" placeholder="Empresa"><button onclick="analyze('s3finder')">Buscar buckets</button></div>
        <div class="card"><div class="badge">🔗 CORS Check</div><input type="text" id="cors" placeholder="https://ejemplo.com"><button onclick="analyze('cors')">Testear CORS</button></div>
        <div class="card"><div class="badge">🔑 GitHub Secrets</div><input type="text" id="github_secrets" placeholder="Organización"><button onclick="analyze('github_secrets')">Buscar secretos</button><small>Requiere token</small></div>
        <div class="card"><div class="badge">🌡️ Tech Detection</div><input type="text" id="tech_detect" placeholder="dominio.com"><button onclick="analyze('tech_detect')">Detectar tecnologías</button></div>
    </div>
    <div id="result" class="result-box">⚡ Resultados aquí...</div>
    <div class="footer">Desarrollado por @jsemanper · Uso educativo</div>
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