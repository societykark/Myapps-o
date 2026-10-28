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
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Habilita CORS para evitar bloqueos desde el frontend
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = tempfile.gettempdir() # Usa el directorio temporal del sistema (Render usa /tmp)
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

# Headers genéricos para evitar bloqueos de APIs
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
        # Se agrega header para evitar bloqueo
        r = requests.get(f"https://whatsmyname.app/api/v1/username?username={username}", headers=HEADERS, timeout=15)
        if r.status_code == 200:
            results = r.json()
            sites = results.get('sites', [])
            return jsonify({"status": "ok", "total": len(sites), "sites": sites[:50]}) if sites else jsonify({"status": "empty", "message": "No se encontraron resultados."})
        return jsonify({"error": f"WhatsMyName API caída o bloqueada (HTTP {r.status_code})"})
    except Exception as e:
        return jsonify({"error": f"Error de conexión: {str(e)}"})

@app.route('/api/email', methods=['POST'])
def api_email():
    data = request.get_json()
    email = data.get('value', '')
    if not email: return jsonify({"error": "Correo vacío"})
    
    result = {}
    EMAILREP_KEY = os.environ.get('EMAILREP_KEY', '')
    HIBP_KEY = os.environ.get('HIBP_KEY', '') # HIBP es obligatorio ahora

    # EmailRep
    try:
        headers = HEADERS.copy()
        if EMAILREP_KEY: headers["X-API-Key"] = EMAILREP_KEY
        r = requests.get(f'https://emailrep.io/{email}', headers=headers, timeout=10)
        result['emailrep'] = r.json() if r.status_code == 200 else f"Error {r.status_code}"
    except Exception as e:
        result['emailrep_error'] = str(e)

    # HIBP
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

    return jsonify(result)

@app.route('/api/phone', methods=['POST'])
def api_phone():
    NUMVERIFY_KEY = os.environ.get('NUMVERIFY_KEY', '')
    if not NUMVERIFY_KEY: return jsonify({"error": "Configura NUMVERIFY_KEY en Render"})
    data = request.get_json()
    try:
        r = requests.get(f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={data.get('value', '')}", timeout=10)
        return jsonify(r.json()) if r.status_code == 200 else jsonify({"error": f"HTTP {r.status_code}"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/domain', methods=['POST'])
def api_domain():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain: return jsonify({"error": "Dominio vacío"})
    try:
        w = whois.whois(domain)
        return jsonify({
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else "N/A",
            "org": getattr(w, 'org', 'N/A')
        })
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
    return jsonify({"host": host, "ip": ip, "open_ports": open_ports})

@app.route('/api/reputation', methods=['POST'])
def api_reputation():
    target = request.get_json().get('value', '')
    if not target: return jsonify({"error": "Target vacío"})
    try:
        ip = socket.gethostbyname(target)
        return jsonify(requests.get(f'http://ip-api.com/json/{ip}', timeout=10).json())
    except Exception as e:
        return jsonify({"error": "No se pudo resolver la IP"})

@app.route('/api/hash', methods=['POST'])
def api_hash():
    h = request.get_json().get('value', '').strip()
    htype = {32: 'MD5', 40: 'SHA1', 64: 'SHA256'}.get(len(h))
    return jsonify({"hash": h, "type": htype}) if htype else jsonify({"error": "Longitud no reconocida"})

@app.route('/api/shodan', methods=['POST'])
def api_shodan():
    SHODAN_KEY = os.environ.get('SHODAN_KEY', '')
    if not SHODAN_KEY: return jsonify({"error": "Configura SHODAN_KEY en Render"})
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{request.get_json().get('value')}?key={SHODAN_KEY}", timeout=15)
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)})

# ... (El resto de tus endpoints están bien, pero asegúrate de agregar timeout=10 a todos los requests.get)

@app.route('/api/ipgeo', methods=['POST'])
def api_ipgeo():
    return api_reputation() # Reutiliza la misma lógica de ip-api

@app.route('/api/mac', methods=['POST'])
def api_mac():
    mac = request.get_json().get('value', '').replace('-', '').replace(':', '').upper()
    try:
        r = requests.get(f'https://api.macvendors.com/{mac[:6]}', timeout=10)
        return jsonify({"mac": mac, "vendor": r.text}) if r.status_code == 200 else jsonify({"vendor": "No encontrado"})
    except:
        return jsonify({"error": "Error de conexión"})

@app.route('/api/password_check', methods=['POST'])
def api_password_check():
    pw = request.get_json().get('value', '')
    if not pw: return jsonify({"error": "Contraseña vacía"})
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    try:
        r = requests.get(f'https://api.pwnedpasswords.com/range/{sha1[:5]}', timeout=10)
        for line in r.text.splitlines():
            if line.startswith(sha1[5:]):
                return jsonify({"pwned": True, "count": int(line.split(':')[1])})
        return jsonify({"pwned": False})
    except:
        return jsonify({"error": "Error en API"})

# ================= PWA y FRONTEND =================
# (Tu bloque de HTML, manifest.json y sw.js se quedan EXACTAMENTE IGUAL hasta la línea del HTML)

HTML = """ [PEGA AQUÍ TODO TU BLOQUE HTML QUE YA TENÍAS, NO LO CAMBIES] """

@app.route('/manifest.json')
def manifest():
    return jsonify({"name": "OSINT Dashboard", "short_name": "OSINT", "start_url": "/", "display": "standalone", "background_color": "#0a0a0a", "theme_color": "#00ff00", "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/1061/1061105.png", "sizes": "512x512", "type": "image/png"}]})

@app.route('/sw.js')
def sw():
    return app.response_class("const CACHE_NAME='osint-v1';self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE_NAME).then(c=>c.addAll(['/']))));self.addEventListener('fetch',e=>e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request))));", content_type='application/javascript')

@app.route('/')
def index():
    return render_template_string(HTML)

if __name__ == '__main__':
    # ARREGLO CLAVE PARA RENDER: Usar la variable de entorno PORT
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)