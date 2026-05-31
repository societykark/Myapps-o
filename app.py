import subprocess
import re
import sys
import requests
import whois
import json
import os
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# El HTML de tu dashboard (interfaz de usuario)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>OSINT Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
    <style>
        /* Estilos para que se vea chido y funcione en el celular */
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 800px;
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
        .card {
            background: #0f172a;
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 24px;
            border-left: 4px solid #facc15;
        }
        input, button {
            padding: 12px 16px;
            margin-top: 8px;
            border-radius: 12px;
            border: none;
            font-size: 1rem;
        }
        input {
            background: #1e293b;
            color: #e2e8f0;
            border: 1px solid #334155;
            width: 100%;
        }
        button {
            background: #facc15;
            color: #0f172a;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.1s;
            width: 100%;
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
            max-height: 400px;
            overflow: auto;
        }
        hr {
            border-color: #334155;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            margin-top: 24px;
            font-size: 0.7rem;
            color: #475569;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🕵️ OSINT Dashboard</h1>
    <div class="sub">Herramientas de inteligencia de fuentes abiertas</div>

    <!-- Username -->
    <div class="card">
        <h2>🔍 Analizar Username</h2>
        <input type="text" id="username" placeholder="Ejemplo: john_doe">
        <button onclick="analyze('username')">Buscar en Redes</button>
    </div>

    <!-- IP -->
    <div class="card">
        <h2>🌍 Geolocalizar IP</h2>
        <input type="text" id="ip" placeholder="Ejemplo: 8.8.8.8">
        <button onclick="analyze('ip')">Localizar</button>
    </div>

    <!-- Email -->
    <div class="card">
        <h2>📧 Analizar Correo (EmailRep)</h2>
        <input type="text" id="email" placeholder="Ejemplo: test@example.com">
        <button onclick="analyze('email')">Verificar</button>
        <small style="display:block; margin-top:8px;">* Usa la API pública de EmailRep (gratis, sin clave)</small>
    </div>

    <!-- Dominio -->
    <div class="card">
        <h2>🌐 Info de Dominio (WHOIS)</h2>
        <input type="text" id="domain" placeholder="Ejemplo: google.com">
        <button onclick="analyze('domain')">Consultar</button>
    </div>

    <!-- Teléfono -->
    <div class="card">
        <h2>📞 Número de Teléfono (Numverify)</h2>
        <input type="text" id="phone" placeholder="Ejemplo: +521234567890">
        <button onclick="analyze('phone')">Consultar</button>
        <small style="display:block; margin-top:8px;">* Requiere API Key (gratis, 100/mes). Configúrala en Render.</small>
    </div>

    <div id="result" class="result-box">⚡ Los resultados aparecerán aquí...</div>
    <div class="footer">Desarrollado para uso educativo</div>
</div>

<script>
    // Función para enviar los datos al backend y mostrar resultados
    async function analyze(type) {
        let inputId = type;
        let value = document.getElementById(inputId).value;
        if (!value) {
            document.getElementById('result').innerText = '❌ Por favor, ingresa un valor.';
            return;
        }
        document.getElementById('result').innerText = '⏳ Consultando...';
        try {
            const response = await fetch(`/api/${type}`, {
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
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

# -------------------------------------------------------
# API PARA USERNAME (Usa Sherlock)
# -------------------------------------------------------
@app.route('/api/username', methods=['POST'])
def api_username():
    data = request.get_json()
    username = data.get('value', '')
    if not username:
        return jsonify({"error": "Username vacío"})
    try:
        # Ejecutamos Sherlock como un proceso externo
        # timeout 30 segundos, capturamos salida
        result = subprocess.run(['sherlock', username], capture_output=True, text=True, timeout=60)
        output = result.stdout
        if "Nothing found" in output or "No results" in output:
            return jsonify({"resultado": f"No se encontró el usuario '{username}' en las plataformas."})
        return jsonify({"resultado": output})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "La búsqueda tardó demasiado"})
    except Exception as e:
        return jsonify({"error": str(e)})

# -------------------------------------------------------
# API PARA IP (Usa ip-api.com, gratuita)
# -------------------------------------------------------
@app.route('/api/ip', methods=['POST'])
def api_ip():
    data = request.get_json()
    ip = data.get('value', '')
    if not ip:
        return jsonify({"error": "IP vacía"})
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
        info = r.json()
        if info.get('status') == 'success':
            return jsonify(info)
        else:
            return jsonify({"error": "No se pudo geolocalizar la IP"})
    except Exception as e:
        return jsonify({"error": str(e)})

# -------------------------------------------------------
# API PARA EMAIL (Usa emailrep.io, requiere User-Agent)
# -------------------------------------------------------
@app.route('/api/email', methods=['POST'])
def api_email():
    data = request.get_json()
    email = data.get('value', '')
    if not email:
        return jsonify({"error": "Correo vacío"})
    try:
        headers = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"}
        r = requests.get(f'https://emailrep.io/{email}', headers=headers, timeout=15)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": f"Error {r.status_code} de la API de EmailRep"})
    except Exception as e:
        return jsonify({"error": str(e)})

# -------------------------------------------------------
# API PARA DOMINIO (WHOIS)
# -------------------------------------------------------
@app.route('/api/domain', methods=['POST'])
def api_domain():
    data = request.get_json()
    domain = data.get('value', '')
    if not domain:
        return jsonify({"error": "Dominio vacío"})
    try:
        w = whois.whois(domain)
        # Convertimos a string para evitar errores con fechas None
        result = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else "N/A",
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

# -------------------------------------------------------
# API PARA TELEFONO (Numverify - requiere API Key)
# -------------------------------------------------------
@app.route('/api/phone', methods=['POST'])
def api_phone():
    data = request.get_json()
    phone = data.get('value', '')
    if not phone:
        return jsonify({"error": "Número vacío"})
    api_key = os.environ.get('NUMVERIFY_KEY')
    if not api_key:
        return jsonify({"error": "NUMVERIFY_KEY no configurada en Render"})
    url = f"http://apilayer.net/api/validate?access_key={api_key}&number={phone}"
    try:
        r = requests.get(url, timeout=10)
        data = r.json()
        if data.get('valid'):
            return jsonify(data)
        else:
            return jsonify({"error": "Número inválido o no encontrado"})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)