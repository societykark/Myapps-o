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
from flask import Flask, render_template_string, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = '/tmp'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'eml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

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

# ================= API ENDPOINTS =================
# Username
@app.route('/api/username', methods=['POST'])
def api_username():
    data = request.get_json()
    username = data.get('value', '')
    if not username:
        return jsonify({"error": "Username vacío"})
    time.sleep(1)
    try:
        r = requests.get(f"https://whatsmyname.app/api/v1/username?username={username}", timeout=20)
        if r.status_code == 200:
            results = r.json()
            sites = results.get('sites', [])
            if sites:
                return jsonify({"status": "ok", "total": len(sites), "sites": sites[:50]})
            else:
                return jsonify({"status": "empty", "message": "No se encontraron resultados."})
        else:
            return jsonify({"error": f"Error HTTP {r.status_code}"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Email (EmailRep + HIBP)
EMAILREP_KEY = os.environ.get('EMAILREP_KEY', '')
@app.route('/api/email', methods=['POST'])
def api_email():
    data = request.get_json()
    email = data.get('value', '')
    if not email:
        return jsonify({"error": "Correo vacío"})
    result = {}
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        if EMAILREP_KEY:
            headers["X-API-Key"] = EMAILREP_KEY
        r = requests.get(f'https://emailrep.io/{email}', headers=headers, timeout=15)
        if r.status_code == 200:
            result['emailrep'] = r.json()
        else:
            result['emailrep_error'] = f"Código {r.status_code}"
    except Exception as e:
        result['emailrep_error'] = str(e)
    try:
        r = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        if r.status_code == 200:
            result['hibp'] = [b['Name'] for b in r.json()]
        elif r.status_code == 404:
            result['hibp'] = []
        else:
            result['hibp_error'] = f"Código {r.status_code}"
    except Exception as e:
        result['hibp_error'] = str(e)
    return jsonify(result)

# Teléfono
NUMVERIFY_KEY = os.environ.get('NUMVERIFY_KEY', '')
@app.route('/api/phone', methods=['POST'])
def api_phone():
    if not NUMVERIFY_KEY:
        return jsonify({"error": "API key de Numverify no configurada"})
    data = request.get_json()
    phone = data.get('value', '')
    if not phone:
        return jsonify({"error": "Número vacío"})
    try:
        url = f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={phone}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": f"Error HTTP {r.status_code}"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Dominio WHOIS
@app.route('/api/domain', methods=['POST'])
def api_domain():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain:
        return jsonify({"error": "Dominio vacío"})
    try:
        w = whois.whois(domain)
        result = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else "N/A",
            "org": getattr(w, 'org', 'N/A')
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

# Escáner de puertos (con rango opcional)
@app.route('/api/portscan', methods=['POST'])
def api_portscan():
    data = request.get_json()
    host = data.get('value', '')
    port_range = data.get('range', '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017')
    if not host:
        return jsonify({"error": "Host vacío"})
    try:
        ip = socket.gethostbyname(host)
    except:
        return jsonify({"error": "No se pudo resolver el host"})
    ports = []
    if '-' in port_range:
        try:
            start, end = map(int, port_range.split('-'))
            if end - start > 1000:
                return jsonify({"error": "Rango demasiado amplio (máx 1000)"})
            ports = range(start, end+1)
        except:
            return jsonify({"error": "Formato inválido"})
    else:
        try:
            ports = [int(p.strip()) for p in port_range.split(',')]
        except:
            return jsonify({"error": "Formato inválido"})
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return jsonify({"host": host, "ip": ip, "open_ports": open_ports})

# Reputación IP
@app.route('/api/reputation', methods=['POST'])
def api_reputation():
    data = request.get_json()
    target = data.get('value', '')
    if not target:
        return jsonify({"error": "Target vacío"})
    try:
        socket.inet_aton(target)
        ip = target
    except:
        try:
            ip = socket.gethostbyname(target)
        except:
            return jsonify({"error": "No se pudo resolver"})
    r = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
    return jsonify(r.json())

# Metadatos desde archivo
@app.route('/api/metadata', methods=['POST'])
def api_metadata():
    if 'file' not in request.files:
        return jsonify({"error": "No se envió ningún archivo"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Nombre de archivo vacío"})
    if not allowed_file(file.filename):
        return jsonify({"error": "Tipo de archivo no permitido"})
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    metadata = extract_metadata(filepath, filename)
    os.remove(filepath)
    return jsonify(metadata)

# Metadatos desde URL
@app.route('/api/metadata_url', methods=['POST'])
def api_metadata_url():
    data = request.get_json()
    url = data.get('value', '')
    if not url:
        return jsonify({"error": "URL vacía"})
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return jsonify({"error": "No se pudo descargar"})
        fd, temppath = tempfile.mkstemp(suffix='.jpg')
        os.write(fd, r.content)
        os.close(fd)
        metadata = extract_metadata(temppath, url.split('/')[-1])
        os.remove(temppath)
        return jsonify(metadata)
    except Exception as e:
        return jsonify({"error": str(e)})

# Hash
@app.route('/api/hash', methods=['POST'])
def api_hash():
    data = request.get_json()
    hash_str = data.get('value', '').strip()
    if not hash_str:
        return jsonify({"error": "Hash vacío"})
    length = len(hash_str)
    if length == 32: htype = 'MD5'
    elif length == 40: htype = 'SHA1'
    elif length == 64: htype = 'SHA256'
    else: return jsonify({"error": "Longitud no reconocida"})
    return jsonify({"hash": hash_str, "type": htype, "message": "Solo identificación"})

# Shodan (requiere clave)
SHODAN_KEY = os.environ.get('SHODAN_KEY', '')
@app.route('/api/shodan', methods=['POST'])
def api_shodan():
    if not SHODAN_KEY:
        return jsonify({"error": "Se requiere API key de Shodan"})
    data = request.get_json()
    query = data.get('value', '')
    if not query:
        return jsonify({"error": "Consulta vacía"})
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{query}?key={SHODAN_KEY}", timeout=15)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": f"Error {r.status_code}"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Google Dorking
@app.route('/api/dork', methods=['POST'])
def api_dork():
    data = request.get_json()
    dork = data.get('value', '')
    if not dork:
        return jsonify({"error": "Consulta vacía"})
    encoded = urllib.parse.quote(dork)
    return jsonify({"url": f"https://www.google.com/search?q={encoded}"})

# Bitcoin Analyzer
@app.route('/api/bitcoin', methods=['POST'])
def api_bitcoin():
    data = request.get_json()
    address = data.get('value', '')
    if not address:
        return jsonify({"error": "Dirección vacía"})
    try:
        r = requests.get(f'https://blockchain.info/rawaddr/{address}', timeout=15)
        if r.status_code == 200:
            info = r.json()
            return jsonify({"address": address, "total_received": info.get('total_received'), "total_sent": info.get('total_sent'), "balance": info.get('balance'), "n_tx": info.get('n_tx')})
        else:
            return jsonify({"error": "No se encontró información"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Email Forensics (manual)
@app.route('/api/email_forensics', methods=['POST'])
def api_email_forensics():
    data = request.get_json()
    headers_text = data.get('value', '')
    if not headers_text:
        return jsonify({"error": "Cabeceras vacías"})
    lines = headers_text.split('\n')
    parsed = {}
    for line in lines:
        if ': ' in line:
            key, val = line.split(': ', 1)
            parsed[key.lower()] = val
    return jsonify(parsed)

# Data Breach Checker
@app.route('/api/breach', methods=['POST'])
def api_breach():
    data = request.get_json()
    email = data.get('value', '')
    if not email:
        return jsonify({"error": "Correo vacío"})
    try:
        r = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        if r.status_code == 200:
            breaches = [{"name": b['Name'], "date": b['BreachDate']} for b in r.json()]
            return jsonify({"email": email, "breaches": breaches})
        elif r.status_code == 404:
            return jsonify({"email": email, "breaches": []})
        else:
            return jsonify({"error": f"Error {r.status_code}"})
    except Exception as e:
        return jsonify({"error": str(e)})

# IP Geolocation
@app.route('/api/ipgeo', methods=['POST'])
def api_ipgeo():
    data = request.get_json()
    ip = data.get('value', '')
    if not ip:
        return jsonify({"error": "IP vacía"})
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)})

# MAC Address Lookup
@app.route('/api/mac', methods=['POST'])
def api_mac():
    data = request.get_json()
    mac = data.get('value', '').upper()
    if not mac:
        return jsonify({"error": "MAC vacía"})
    mac = mac.replace('-', '').replace(':', '')
    if len(mac) < 6:
        return jsonify({"error": "MAC demasiado corta"})
    prefix = mac[:6]
    try:
        r = requests.get(f'https://api.macvendors.com/{prefix}', timeout=10)
        if r.status_code == 200:
            return jsonify({"mac": mac, "vendor": r.text})
        else:
            return jsonify({"mac": mac, "vendor": "No encontrado"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Subdomain Enumeration
@app.route('/api/subdomains', methods=['POST'])
def api_subdomains():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain:
        return jsonify({"error": "Dominio vacío"})
    try:
        r = requests.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=20)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value')
                if name:
                    for n in name.split('\n'):
                        if n.endswith(domain):
                            subdomains.add(n.strip())
            return jsonify({"domain": domain, "subdomains": list(subdomains)[:100]})
        else:
            return jsonify({"error": "Error consultando crt.sh"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Reverse Image Search (genera URL)
@app.route('/api/reverse_image', methods=['POST'])
def api_reverse_image():
    data = request.get_json()
    image_url = data.get('value', '')
    if not image_url:
        return jsonify({"error": "URL vacía"})
    encoded = urllib.parse.quote(image_url)
    return jsonify({"url": f"https://www.google.com/searchbyimage?image_url={encoded}"})

# Password Checker
@app.route('/api/password_check', methods=['POST'])
def api_password_check():
    data = request.get_json()
    password = data.get('value', '')
    if not password:
        return jsonify({"error": "Contraseña vacía"})
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=10)
        if r.status_code == 200:
            lines = r.text.splitlines()
            for line in lines:
                if line.startswith(suffix):
                    count = int(line.split(':')[1])
                    return jsonify({"pwned": True, "count": count})
            return jsonify({"pwned": False})
        else:
            return jsonify({"error": "Error en API"})
    except Exception as e:
        return jsonify({"error": str(e)})

# AI Threat Analyzer (VirusTotal)
VIRUSTOTAL_KEY = os.environ.get('VIRUSTOTAL_KEY', '')
@app.route('/api/ai_threat', methods=['POST'])
def api_ai_threat():
    if not VIRUSTOTAL_KEY:
        return jsonify({"error": "Se requiere API key de VirusTotal"})
    data = request.get_json()
    url = data.get('value', '')
    if not url:
        return jsonify({"error": "URL vacía"})
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        r = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={"url": url})
        if r.status_code == 200:
            return jsonify({"message": "Escaneo enviado", "id": r.json()['data']['id']})
        else:
            return jsonify({"error": "Error en VirusTotal"})
    except Exception as e:
        return jsonify({"error": str(e)})

# JS Secret Scanner
@app.route('/api/js_secrets', methods=['POST'])
def api_js_secrets():
    data = request.get_json()
    url = data.get('value', '')
    if not url:
        return jsonify({"error": "URL vacía"})
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            content = r.text
            patterns = {
                "AWS Key": r'AKIA[0-9A-Z]{16}',
                "Google API": r'AIza[0-9A-Za-z\-_]{35}',
                "GitHub Token": r'ghp_[0-9A-Za-z]{36}',
                "JWT": r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
            }
            found = []
            for name, pat in patterns.items():
                matches = re.findall(pat, content)
                if matches:
                    found.append({"type": name, "matches": matches[:3]})
            return jsonify({"secrets_found": found})
        else:
            return jsonify({"error": "No se pudo obtener el archivo"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Wayback URLs
@app.route('/api/wayback', methods=['POST'])
def api_wayback():
    data = request.get_json()
    url = data.get('value', '')
    if not url:
        return jsonify({"error": "URL vacía"})
    try:
        r = requests.get(f'https://archive.org/wayback/available?url={url}', timeout=15)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": "Error consultando Wayback"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Subdomain Takeover
@app.route('/api/takeover', methods=['POST'])
def api_takeover():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain:
        return jsonify({"error": "Dominio vacío"})
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value')
                if name:
                    for n in name.split('\n'):
                        if n.endswith(domain):
                            subdomains.add(n.strip())
            vulnerable = []
            for sub in list(subdomains)[:20]:
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(sub, 'CNAME')
                    for rdata in answers:
                        target = str(rdata.target).rstrip('.')
                        if 's3.amazonaws.com' in target or 'github.io' in target or 'herokuapp.com' in target:
                            vulnerable.append({"subdomain": sub, "cname": target})
                except:
                    pass
            return jsonify({"subdomains": list(subdomains)[:50], "potential_takeover": vulnerable})
        else:
            return jsonify({"error": "Error en crt.sh"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Exposed Files
@app.route('/api/exposed_files', methods=['POST'])
def api_exposed_files():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain:
        return jsonify({"error": "Dominio vacío"})
    common_files = ["/robots.txt", "/.env", "/.git/config", "/backup.zip", "/backup.sql", "/config.php", "/wp-config.php", "/.htaccess", "/phpinfo.php", "/admin/config.php"]
    found = []
    for path in common_files:
        url = f"http://{domain}{path}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                found.append({"url": url, "size": len(r.content)})
        except:
            pass
    return jsonify({"exposed": found})

# Security Headers
@app.route('/api/security_headers', methods=['POST'])
def api_security_headers():
    data = request.get_json()
    url = data.get('value', '')
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        headers = r.headers
        important = {
            "Content-Security-Policy": headers.get('Content-Security-Policy', 'No'),
            "X-Frame-Options": headers.get('X-Frame-Options', 'No'),
            "X-Content-Type-Options": headers.get('X-Content-Type-Options', 'No'),
            "Strict-Transport-Security": headers.get('Strict-Transport-Security', 'No'),
            "Referrer-Policy": headers.get('Referrer-Policy', 'No'),
            "Permissions-Policy": headers.get('Permissions-Policy', 'No')
        }
        return jsonify({"headers": important})
    except Exception as e:
        return jsonify({"error": str(e)})

# CVE Search
@app.route('/api/cve', methods=['POST'])
def api_cve():
    data = request.get_json()
    keyword = data.get('value', '')
    if not keyword:
        return jsonify({"error": "Palabra clave vacía"})
    try:
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20", timeout=20)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": "Error consultando NVD"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ASN Lookup
@app.route('/api/asn', methods=['POST'])
def api_asn():
    data = request.get_json()
    ip = data.get('value', '')
    if not ip:
        return jsonify({"error": "IP vacía"})
    try:
        r = requests.get(f'https://ipinfo.io/{ip}/json', timeout=10)
        if r.status_code == 200:
            info = r.json()
            return jsonify({"org": info.get('org'), "asn": info.get('asn', 'N/A'), "country": info.get('country')})
        else:
            return jsonify({"error": "No se pudo obtener ASN"})
    except Exception as e:
        return jsonify({"error": str(e)})

# S3 Bucket Finder
@app.route('/api/s3finder', methods=['POST'])
def api_s3finder():
    data = request.get_json()
    company = data.get('value', '')
    if not company:
        return jsonify({"error": "Nombre vacío"})
    perms = [company, f"{company}-backup", f"{company}-dev", f"{company}-prod", f"{company}-staging", f"{company}-data", f"{company}-static", f"{company}-assets", f"{company}-media", f"{company}-cdn"]
    found = []
    for bucket in perms:
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200,403]:
                found.append({"bucket": bucket, "status": r.status_code})
        except:
            pass
    return jsonify({"buckets": found})

# CORS Check
@app.route('/api/cors', methods=['POST'])
def api_cors():
    data = request.get_json()
    url = data.get('value', '')
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        r = requests.options(url, timeout=10)
        cors = r.headers.get('Access-Control-Allow-Origin')
        return jsonify({"cors_origin": cors, "cors_enabled": cors is not None})
    except Exception as e:
        return jsonify({"error": str(e)})

# GitHub Secrets
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
@app.route('/api/github_secrets', methods=['POST'])
def api_github_secrets():
    if not GITHUB_TOKEN:
        return jsonify({"error": "Se requiere GitHub token"})
    data = request.get_json()
    org = data.get('value', '')
    if not org:
        return jsonify({"error": "Organización vacía"})
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    query = f"org:{org} extension:conf OR extension:env OR extension:key OR filename:.env"
    try:
        r = requests.get(f"https://api.github.com/search/code?q={query}", headers=headers, timeout=30)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": f"Error {r.status_code}"})
    except Exception as e:
        return jsonify({"error": str(e)})

# Tech Detection
@app.route('/api/tech_detect', methods=['POST'])
def api_tech_detect():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain:
        return jsonify({"error": "Dominio vacío"})
    if not domain.startswith('http'):
        domain = 'https://' + domain
    try:
        r = requests.get(domain, timeout=10, verify=False)
        headers = r.headers
        content = r.text[:5000]
        tech = {}
        if 'Server' in headers:
            tech['Servidor'] = headers['Server']
        if 'x-powered-by' in headers:
            tech['Powered by'] = headers['x-powered-by']
        if '/wp-content/' in content:
            tech['CMS'] = 'WordPress'
        if 'Drupal' in content:
            tech['CMS'] = 'Drupal'
        if 'Joomla' in content:
            tech['CMS'] = 'Joomla'
        if 'laravel' in content.lower():
            tech['Framework'] = 'Laravel'
        if 'django' in content.lower():
            tech['Framework'] = 'Django'
        return jsonify({"domain": domain, "technologies": tech})
    except Exception as e:
        return jsonify({"error": str(e)})

# ================= PWA y FRONTEND =================
@app.route('/manifest.json')
def manifest():
    return jsonify({
        "name": "OSINT Dashboard",
        "short_name": "OSINT",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0a0a0a",
        "theme_color": "#00ff00",
        "icons": [{
            "src": "https://cdn-icons-png.flaticon.com/512/1061/1061105.png",
            "sizes": "512x512",
            "type": "image/png"
        }]
    })

@app.route('/sw.js')
def sw():
    return app.response_class("""
const CACHE_NAME = 'osint-v1';
const urlsToCache = ['/'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(urlsToCache))));
self.addEventListener('fetch', e => e.respondWith(caches.match(e.request).then(r => r || fetch(e.request))));
""", content_type='application/javascript')

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
        <div class="card"><div class="badge">🔑 Password Checker</div><input type="text" id="password" placeholder="Contraseña"><button onclick="analyze('password_check')">Verificar filtrada</button></div>
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
    app.run(host='0.0.0.0', port=5000, debug=False)