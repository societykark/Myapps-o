import os
import re
import socket
import subprocess
import requests
import whois
import json
import hashlib
from flask import Flask, render_template_string, request, jsonify, session
from werkzeug.utils import secure_filename
import urllib.parse
import time
from datetime import datetime

# ================= CONFIGURACIÓN INICIAL =================
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuración de archivos subidos (para metadatos)
UPLOAD_FOLDER = '/tmp'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'eml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB

# ================= FUNCIONES AUXILIARES =================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_public_ip():
    try:
        r = requests.get('https://api.ipify.org?format=json', timeout=5)
        return r.json().get('ip')
    except:
        return "No detectada"

# ================= RUTAS DE LA API =================

# ----- 1. ANALIZADOR DE USUARIOS (WhatsMyName) -----
@app.route('/api/username', methods=['POST'])
def api_username():
    data = request.get_json()
    username = data.get('value', '')
    if not username:
        return jsonify({"error": "Username vacío"})
    try:
        url = f"https://whatsmyname.app/api/v1/username?username={username}"
        r = requests.get(url, timeout=20)
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

# ----- 2. ANALIZADOR DE EMAIL (EmailRep + HIBP) -----
EMAILREP_API_KEY = os.environ.get('EMAILREP_KEY', '')  # opcional, consíguela gratis en emailrep.io
@app.route('/api/email', methods=['POST'])
def api_email():
    data = request.get_json()
    email = data.get('value', '')
    if not email:
        return jsonify({"error": "Correo vacío"})
    result = {}
    # EmailRep
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        if EMAILREP_API_KEY:
            headers["X-API-Key"] = EMAILREP_API_KEY
        r = requests.get(f'https://emailrep.io/{email}', headers=headers, timeout=15)
        if r.status_code == 200:
            result['emailrep'] = r.json()
        else:
            result['emailrep_error'] = f"Código {r.status_code}"
    except Exception as e:
        result['emailrep_error'] = str(e)
    # HIBP (haveibeenpwned)
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

# ----- 3. ANALIZADOR DE TELÉFONO (Numverify) -----
NUMVERIFY_KEY = os.environ.get('NUMVERIFY_KEY', '')
@app.route('/api/phone', methods=['POST'])
def api_phone():
    if not NUMVERIFY_KEY:
        return jsonify({"error": "API key de Numverify no configurada. Obtén una gratis en numverify.com"})
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

# ----- 4. DOMINIO (WHOIS) -----
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
            "org": w.org if hasattr(w, 'org') else "N/A"
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 5. ESCÁNER DE PUERTOS (básico) -----
@app.route('/api/portscan', methods=['POST'])
def api_portscan():
    data = request.get_json()
    host = data.get('value', '')
    if not host:
        return jsonify({"error": "Host vacío"})
    # Resolver nombre a IP
    try:
        ip = socket.gethostbyname(host)
    except:
        return jsonify({"error": "No se pudo resolver el host"})
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return jsonify({"host": host, "ip": ip, "open_ports": open_ports})

# ----- 6. VERIFICADOR DE REPUTACIÓN (IP con ip-api) -----
@app.route('/api/reputation', methods=['POST'])
def api_reputation():
    data = request.get_json()
    target = data.get('value', '')
    if not target:
        return jsonify({"error": "Target vacío"})
    # Intentar como IP
    try:
        socket.inet_aton(target)
        ip = target
    except:
        # Resolver dominio
        try:
            ip = socket.gethostbyname(target)
        except:
            return jsonify({"error": "No se pudo resolver"})
    r = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
    return jsonify(r.json())

# ----- 7. EXTRACTOR DE METADATOS (subir archivo) -----
def extract_metadata(filepath, filename):
    metadata = {}
    # Imagen (PIL)
    if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
        from PIL import Image
        try:
            img = Image.open(filepath)
            metadata['format'] = img.format
            metadata['size'] = img.size
            metadata['mode'] = img.mode
            # EXIF
            exif = img._getexif()
            if exif:
                metadata['exif'] = {str(k): str(v) for k, v in exif.items()}
        except Exception as e:
            metadata['error'] = str(e)
    elif filename.lower().endswith('.pdf'):
        import PyPDF2
        try:
            with open(filepath, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                info = reader.metadata
                metadata['metadata'] = {k: str(v) for k, v in info.items()} if info else {}
                metadata['num_pages'] = len(reader.pages)
        except Exception as e:
            metadata['error'] = str(e)
    else:
        # Archivo de texto, solo hash
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                metadata['md5'] = hashlib.md5(content.encode()).hexdigest()
        except:
            pass
    return metadata

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

# ----- 8. ANALIZADOR DE HASH (MD5, SHA1, SHA256) -----
@app.route('/api/hash', methods=['POST'])
def api_hash():
    data = request.get_json()
    hash_str = data.get('value', '').strip()
    if not hash_str:
        return jsonify({"error": "Hash vacío"})
    # Intentar determinar tipo por longitud
    length = len(hash_str)
    if length == 32:
        hash_type = 'MD5'
    elif length == 40:
        hash_type = 'SHA1'
    elif length == 64:
        hash_type = 'SHA256'
    else:
        return jsonify({"error": "Longitud de hash no reconocida"})
    # Consultar a md5online.org (simple)
    result = {"hash": hash_str, "type": hash_type, "cracked": "No disponible en esta demo"}
    # Opcional: usar API de crackstation? Mejor dejar solo cálculo.
    return jsonify(result)

# ----- 9. SHODAN SEARCH (requiere API key) -----
SHODAN_KEY = os.environ.get('SHODAN_KEY', '')
@app.route('/api/shodan', methods=['POST'])
def api_shodan():
    if not SHODAN_KEY:
        return jsonify({"error": "Se requiere API key de Shodan. Obtén una gratis en shodan.io"})
    data = request.get_json()
    query = data.get('value', '')
    if not query:
        return jsonify({"error": "Consulta vacía"})
    try:
        url = f'https://api.shodan.io/shodan/host/{query}?key={SHODAN_KEY}'
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": f"Error {r.status_code}: {r.text[:200]}"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 10. GOOGLE DORKING (genera URL) -----
@app.route('/api/dork', methods=['POST'])
def api_dork():
    data = request.get_json()
    dork = data.get('value', '')
    if not dork:
        return jsonify({"error": "Consulta vacía"})
    encoded = urllib.parse.quote(dork)
    url = f"https://www.google.com/search?q={encoded}"
    return jsonify({"url": url})

# ----- 11. ANALIZADOR DE BITCOIN (blockchain.info) -----
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

# ----- 12. EMAIL FORENSICS (análisis de cabeceras desde texto) -----
@app.route('/api/email_forensics', methods=['POST'])
def api_email_forensics():
    data = request.get_json()
    headers_text = data.get('value', '')
    if not headers_text:
        return jsonify({"error": "Cabeceras vacías"})
    # Parseo básico de líneas
    lines = headers_text.split('\n')
    parsed = {}
    for line in lines:
        if ': ' in line:
            key, val = line.split(': ', 1)
            parsed[key.lower()] = val
    # Información relevante
    result = {
        "from": parsed.get('from'),
        "to": parsed.get('to'),
        "subject": parsed.get('subject'),
        "date": parsed.get('date'),
        "reply-to": parsed.get('reply-to'),
        "return-path": parsed.get('return-path'),
        "spf": parsed.get('received-spf'),
        "dkim": parsed.get('dkim-signature') is not None
    }
    return jsonify(result)

# ----- 13. DATA BREACH CHECKER (HIBP mismo) -----
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

# ----- 14. IP GEOLOCATION PRO (más detalles) -----
@app.route('/api/ipgeo', methods=['POST'])
def api_ipgeo():
    data = request.get_json()
    ip = data.get('value', '')
    if not ip:
        return jsonify({"error": "IP vacía"})
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query', timeout=10)
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 15. MAC ADDRESS LOOKUP (macvendors.com) -----
@app.route('/api/mac', methods=['POST'])
def api_mac():
    data = request.get_json()
    mac = data.get('value', '').upper()
    if not mac:
        return jsonify({"error": "MAC vacía"})
    # Limpiar formato
    mac = mac.replace('-', '').replace(':', '').upper()
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

# ----- 16. SUBDOMAIN ENUMERATION (crt.sh) -----
@app.route('/api/subdomains', methods=['POST'])
def api_subdomains():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain:
        return jsonify({"error": "Dominio vacío"})
    try:
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        r = requests.get(url, timeout=20)
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

# ----- 17. REVERSE IMAGE SEARCH (genera URL a Google Images) -----
@app.route('/api/reverse_image', methods=['POST'])
def api_reverse_image():
    data = request.get_json()
    image_url = data.get('value', '')
    if not image_url:
        return jsonify({"error": "URL de imagen vacía"})
    encoded = urllib.parse.quote(image_url)
    google_url = f"https://www.google.com/searchbyimage?image_url={encoded}"
    return jsonify({"url": google_url})

# ----- 18. PASSWORD CHECKER (HIBP Passwords) -----
@app.route('/api/password_check', methods=['POST'])
def api_password_check():
    data = request.get_json()
    password = data.get('value', '')
    if not password:
        return jsonify({"error": "Contraseña vacía"})
    # Calcular SHA1 y consultar HIBP API range
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=10)
        if r.status_code == 200:
            lines = r.text.splitlines()
            found = False
            for line in lines:
                if line.startswith(suffix):
                    count = int(line.split(':')[1])
                    found = True
                    return jsonify({"password": password, "pwned": True, "count": count})
            if not found:
                return jsonify({"password": password, "pwned": False})
        else:
            return jsonify({"error": "Error en la API"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 19. AI THREAT ANALYZER (simulado con VirusTotal si tienes clave) -----
VIRUSTOTAL_KEY = os.environ.get('VIRUSTOTAL_KEY', '')
@app.route('/api/ai_threat', methods=['POST'])
def api_ai_threat():
    data = request.get_json()
    url = data.get('value', '')
    if not url:
        return jsonify({"error": "URL vacía"})
    if not VIRUSTOTAL_KEY:
        # Análisis simple: verificar si la URL está en listas de phishing conocidas (puede usar API de Google Safe Browsing, pero requiere clave)
        return jsonify({"warning": "Clave de VirusTotal no configurada. Análisis limitado."})
    try:
        # Escaneo con VirusTotal
        scan_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        # Primero enviar URL para escanear
        data = {"url": url}
        r = requests.post(scan_url, headers=headers, data=data)
        if r.status_code == 200:
            # Obtener análisis
            scan_id = r.json()['data']['id']
            # Esperar y consultar resultados (simplificado)
            return jsonify({"message": "Escaneo enviado, revisa los resultados en unos segundos"})
        else:
            return jsonify({"error": "Error en VirusTotal"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 20. JS SECRET SCANNER (desde URL) -----
@app.route('/api/js_secrets', methods=['POST'])
def api_js_secrets():
    data = request.get_json()
    url = data.get('value', '')
    if not url:
        return jsonify({"error": "URL vacía"})
    # Descargar el contenido JS (si es .js o extraer de página)
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            content = r.text
            # Patrones comunes de secretos
            patterns = {
                "AWS Key": r'AKIA[0-9A-Z]{16}',
                "Google API": r'AIza[0-9A-Za-z\-_]{35}',
                "GitHub Token": r'ghp_[0-9A-Za-z]{36}',
                "JWT": r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
                "API Key genérica": r'[a-zA-Z0-9]{32,}'
            }
            found = []
            for name, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    found.append({"type": name, "matches": matches[:3]})
            return jsonify({"url": url, "secrets_found": found})
        else:
            return jsonify({"error": "No se pudo obtener el archivo"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 21. WAYBACK URLS (archive.org) -----
@app.route('/api/wayback', methods=['POST'])
def api_wayback():
    data = request.get_json()
    url = data.get('value', '')
    if not url:
        return jsonify({"error": "URL vacía"})
    try:
        api = f"https://archive.org/wayback/available?url={url}"
        r = requests.get(api, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return jsonify(data)
        else:
            return jsonify({"error": "Error consultando Wayback"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 22. SUBDOMAIN TAKEOVER (básico) -----
@app.route('/api/takeover', methods=['POST'])
def api_takeover():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain:
        return jsonify({"error": "Dominio vacío"})
    # Buscar subdominios con crt.sh
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value')
                if name:
                    for n in name.split('\n'):
                        if n.endswith(domain):
                            subdomains.add(n.strip())
            # Verificar CNAME para vulnerabilidad (simplificado)
            vulnerable = []
            for sub in subdomains:
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(sub, 'CNAME')
                    for rdata in answers:
                        target = str(rdata.target).rstrip('.')
                        # Servicios comunes vulnerables
                        if 's3.amazonaws.com' in target or 'github.io' in target or 'herokuapp.com' in target:
                            vulnerable.append({"subdomain": sub, "cname": target})
                except:
                    pass
            return jsonify({"subdomains": list(subdomains)[:50], "potential_takeover": vulnerable})
        else:
            return jsonify({"error": "Error en crt.sh"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 23. EXPOSED FILES (búsqueda de archivos comunes) -----
@app.route('/api/exposed_files', methods=['POST'])
def api_exposed_files():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain:
        return jsonify({"error": "Dominio vacío"})
    common_files = [
        "/robots.txt", "/.env", "/.git/config", "/backup.zip", "/backup.sql",
        "/config.php", "/wp-config.php", "/.htaccess", "/phpinfo.php", "/admin/config.php"
    ]
    found = []
    for path in common_files:
        url = f"http://{domain}{path}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                found.append({"url": url, "size": len(r.content)})
        except:
            pass
    return jsonify({"domain": domain, "exposed": found})

# ----- 24. SECURITY HEADERS -----
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
        return jsonify({"url": url, "headers": important})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 25. CVE SEARCH (NVD) -----
@app.route('/api/cve', methods=['POST'])
def api_cve():
    data = request.get_json()
    keyword = data.get('value', '')
    if not keyword:
        return jsonify({"error": "Palabra clave vacía"})
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20"
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": "Error consultando NVD"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 26. ASN LOOKUP (ipinfo.io) -----
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
            return jsonify({"ip": ip, "org": info.get('org'), "asn": info.get('asn', 'No disponible'), "country": info.get('country')})
        else:
            return jsonify({"error": "No se pudo obtener ASN"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 27. S3 BUCKET FINDER (permutaciones) -----
@app.route('/api/s3finder', methods=['POST'])
def api_s3finder():
    data = request.get_json()
    company = data.get('value', '')
    if not company:
        return jsonify({"error": "Nombre de empresa vacío"})
    permutations = [
        company, f"{company}-backup", f"{company}-dev", f"{company}-prod", f"{company}-staging",
        f"{company}-data", f"{company}-static", f"{company}-assets", f"{company}-media", f"{company}-cdn"
    ]
    found = []
    for bucket in permutations:
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 403]:  # 403 también indica existencia
                found.append({"bucket": bucket, "url": url, "status": r.status_code})
        except:
            pass
    return jsonify({"company": company, "buckets": found})

# ----- 28. CORS CHECK -----
@app.route('/api/cors', methods=['POST'])
def api_cors():
    data = request.get_json()
    url = data.get('value', '')
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        r = requests.options(url, timeout=10)
        cors = r.headers.get('Access-Control-Allow-Origin')
        return jsonify({"url": url, "cors_origin": cors, "cors_enabled": cors is not None})
    except Exception as e:
        return jsonify({"error": str(e)})

# ----- 29. GITHUB SECRETS (búsqueda en GitHub) -----
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
@app.route('/api/github_secrets', methods=['POST'])
def api_github_secrets():
    if not GITHUB_TOKEN:
        return jsonify({"error": "Se requiere GitHub token. Crea uno en github.com/settings/tokens"})
    data = request.get_json()
    org = data.get('value', '')
    if not org:
        return jsonify({"error": "Nombre de organización vacío"})
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    query = f"org:{org} extension:conf OR extension:env OR extension:key OR filename:.env"
    try:
        r = requests.get(f"https://api.github.com/search/code?q={query}", headers=headers, timeout=30)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": f"Error {r.status_code}: {r.text[:200]}"})
    except Exception as e:
        return jsonify({"error": str(e)})

# ================= INTERFAZ PRINCIPAL (HTML) =================
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>OSINT Dashboard Ultimate</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: auto;
            background: #1e293b;
            border-radius: 24px;
            padding: 24px;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5);
        }
        h1, h2 {
            color: #facc15;
        }
        h1 {
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
            text-align: center;
        }
        .sub {
            text-align: center;
            margin-bottom: 2rem;
            color: #94a3b8;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }
        .card {
            background: #0f172a;
            border-radius: 16px;
            padding: 16px;
            border-left: 4px solid #facc15;
        }
        input, button, textarea, select {
            padding: 12px 16px;
            margin-top: 8px;
            border-radius: 12px;
            border: none;
            font-size: 1rem;
            width: 100%;
        }
        input, textarea, select {
            background: #1e293b;
            color: #e2e8f0;
            border: 1px solid #334155;
        }
        button {
            background: #facc15;
            color: #0f172a;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.1s;
        }
        button:active {
            transform: scale(0.97);
        }
        .result-box {
            background: #0f172a;
            padding: 16px;
            border-radius: 12px;
            margin-top: 20px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: monospace;
            font-size: 0.8rem;
            border: 1px solid #334155;
            max-height: 500px;
            overflow: auto;
        }
        hr {
            border-color: #334155;
            margin: 30px 0;
        }
        .footer {
            text-align: center;
            margin-top: 24px;
            font-size: 0.7rem;
            color: #475569;
        }
        .badge {
            background: #facc15;
            color: #0f172a;
            padding: 2px 8px;
            border-radius: 20px;
            font-size: 0.7rem;
            display: inline-block;
            margin-bottom: 8px;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🕵️‍♂️ OSINT Dashboard Ultimate</h1>
    <div class="sub">Herramientas de inteligencia de fuentes abiertas</div>
    <div class="grid">
        <!-- Cada tarjeta es una herramienta -->
        <div class="card"><div class="badge">🔍 Username</div><input type="text" id="username" placeholder="Nombre de usuario"><button onclick="analyze('username')">Buscar</button></div>
        <div class="card"><div class="badge">📧 Email</div><input type="text" id="email" placeholder="correo@ejemplo.com"><button onclick="analyze('email')">Analizar</button></div>
        <div class="card"><div class="badge">📞 Teléfono</div><input type="text" id="phone" placeholder="+521234567890"><button onclick="analyze('phone')">Consultar</button></div>
        <div class="card"><div class="badge">🌐 Dominio (WHOIS)</div><input type="text" id="domain" placeholder="ejemplo.com"><button onclick="analyze('domain')">WHOIS</button></div>
        <div class="card"><div class="badge">🔌 Escáner de Puertos</div><input type="text" id="portscan" placeholder="ejemplo.com o IP"><button onclick="analyze('portscan')">Escanea puertos comunes</button></div>
        <div class="card"><div class="badge">⚡ Reputación IP/Dominio</div><input type="text" id="reputation" placeholder="IP o dominio"><button onclick="analyze('reputation')">Verificar</button></div>
        <div class="card"><div class="badge">🖼️ Metadatos de Archivo</div><input type="file" id="metadatafile" accept="image/*,application/pdf,.txt"><button onclick="uploadMetadata()">Subir y extraer</button></div>
        <div class="card"><div class="badge">🔐 Analizador de Hash</div><input type="text" id="hash" placeholder="MD5, SHA1, SHA256"><button onclick="analyze('hash')">Analizar</button></div>
        <div class="card"><div class="badge">🔎 Shodan Search</div><input type="text" id="shodan" placeholder="IP o dominio"><button onclick="analyze('shodan')">Buscar</button><small style="display:block">Requiere API key</small></div>
        <div class="card"><div class="badge">📄 Google Dorking</div><input type="text" id="dork" placeholder="site:example.com filetype:pdf"><button onclick="analyze('dork')">Generar URL</button></div>
        <div class="card"><div class="badge">₿ Bitcoin Analyzer</div><input type="text" id="bitcoin" placeholder="Dirección BTC"><button onclick="analyze('bitcoin')">Consultar</button></div>
        <div class="card"><div class="badge">✉️ Email Forensics</div><textarea id="email_headers" rows="3" placeholder="Pega cabeceras de email aquí..."></textarea><button onclick="analyze('email_forensics')">Analizar</button></div>
        <div class="card"><div class="badge">📊 Data Breach Checker</div><input type="text" id="breach" placeholder="correo@ejemplo.com"><button onclick="analyze('breach')">Verificar filtraciones</button></div>
        <div class="card"><div class="badge">🌍 IP Geolocation Pro</div><input type="text" id="ipgeo" placeholder="IP"><button onclick="analyze('ipgeo')">Localizar</button></div>
        <div class="card"><div class="badge">🖧 MAC Address Lookup</div><input type="text" id="mac" placeholder="AA:BB:CC:DD:EE:FF"><button onclick="analyze('mac')">Buscar fabricante</button></div>
        <div class="card"><div class="badge">📡 Subdomain Enumeration</div><input type="text" id="subdomains" placeholder="dominio.com"><button onclick="analyze('subdomains')">Enumerar</button></div>
        <div class="card"><div class="badge">🔍 Reverse Image Search</div><input type="text" id="reverse_image" placeholder="URL de imagen"><button onclick="analyze('reverse_image')">Generar búsqueda en Google</button></div>
        <div class="card"><div class="badge">🔑 Password Checker</div><input type="text" id="password" placeholder="Contraseña"><button onclick="analyze('password_check')">Verificar filtrada</button></div>
        <div class="card"><div class="badge">🤖 AI Threat Analyzer</div><input type="text" id="ai_threat" placeholder="URL sospechosa"><button onclick="analyze('ai_threat')">Analizar</button><small>Requiere VirusTotal key</small></div>
        <div class="card"><div class="badge">💻 JS Secret Scanner</div><input type="text" id="js_secrets" placeholder="URL de archivo .js"><button onclick="analyze('js_secrets')">Buscar secretos</button></div>
        <div class="card"><div class="badge">📆 Wayback URLs</div><input type="text" id="wayback" placeholder="URL"><button onclick="analyze('wayback')">Historial</button></div>
        <div class="card"><div class="badge">⚠️ Subdomain Takeover</div><input type="text" id="takeover" placeholder="dominio.com"><button onclick="analyze('takeover')">Detectar</button></div>
        <div class="card"><div class="badge">📁 Exposed Files</div><input type="text" id="exposed" placeholder="dominio.com"><button onclick="analyze('exposed_files')">Buscar archivos sensibles</button></div>
        <div class="card"><div class="badge">🛡️ Security Headers</div><input type="text" id="headers" placeholder="https://ejemplo.com"><button onclick="analyze('security_headers')">Auditar</button></div>
        <div class="card"><div class="badge">🐞 CVE Search</div><input type="text" id="cve" placeholder="apache, wordpress, etc."><button onclick="analyze('cve')">Buscar vulnerabilidades</button></div>
        <div class="card"><div class="badge">🌐 ASN Lookup</div><input type="text" id="asn" placeholder="IP"><button onclick="analyze('asn')">ASN/Org</button></div>
        <div class="card"><div class="badge">📦 S3 Bucket Finder</div><input type="text" id="s3finder" placeholder="Nombre de empresa"><button onclick="analyze('s3finder')">Buscar buckets</button></div>
        <div class="card"><div class="badge">🔗 CORS Check</div><input type="text" id="cors" placeholder="https://ejemplo.com"><button onclick="analyze('cors')">Testear CORS</button></div>
        <div class="card"><div class="badge">🔑 GitHub Secrets (org)</div><input type="text" id="github_secrets" placeholder="Organización"><button onclick="analyze('github_secrets')">Buscar secretos en repos</button><small>Requiere GitHub token</small></div>
    </div>
    <div id="result" class="result-box">⚡ Los resultados aparecerán aquí...</div>
    <div class="footer">Desarrollado por @jsemanper · Uso educativo · Algunas funciones requieren claves API configurables en Render</div>
</div>

<script>
    async function analyze(type) {
        let inputId = type;
        let value = document.getElementById(inputId).value;
        if (type === 'email_forensics') {
            value = document.getElementById('email_headers').value;
        }
        if (!value) {
            document.getElementById('result').innerText = '❌ Por favor, ingresa un valor.';
            return;
        }
        document.getElementById('result').innerText = '⏳ Consultando...';
        let endpoint = '';
        let body = {value: value};
        if (type === 'email_forensics') {
            endpoint = 'email_forensics';
        } else if (type === 'password_check') {
            endpoint = 'password_check';
        } else if (type === 'ai_threat') {
            endpoint = 'ai_threat';
        } else if (type === 'js_secrets') {
            endpoint = 'js_secrets';
        } else if (type === 'wayback') {
            endpoint = 'wayback';
        } else if (type === 'takeover') {
            endpoint = 'takeover';
        } else if (type === 'exposed_files') {
            endpoint = 'exposed_files';
        } else if (type === 'security_headers') {
            endpoint = 'security_headers';
        } else if (type === 'cve') {
            endpoint = 'cve';
        } else if (type === 'asn') {
            endpoint = 'asn';
        } else if (type === 's3finder') {
            endpoint = 's3finder';
        } else if (type === 'cors') {
            endpoint = 'cors';
        } else if (type === 'github_secrets') {
            endpoint = 'github_secrets';
        } else {
            endpoint = type;
        }
        try {
            const response = await fetch(`/api/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ value: value })
            });
            const data = await response.json();
            document.getElementById('result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
        } catch (error) {
            document.getElementById('result').innerText = '❌ Error al conectar con el servidor.';
        }
    }

    async function uploadMetadata() {
        const fileInput = document.getElementById('metadatafile');
        const file = fileInput.files[0];
        if (!file) {
            document.getElementById('result').innerText = '❌ Selecciona un archivo.';
            return;
        }
        const formData = new FormData();
        formData.append('file', file);
        document.getElementById('result').innerText = '⏳ Procesando archivo...';
        try {
            const response = await fetch('/api/metadata', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            document.getElementById('result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
        } catch (error) {
            document.getElementById('result').innerText = '❌ Error al subir archivo.';
        }
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