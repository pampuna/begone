#!/bin/bash
set -e

DOMAIN_REGEX='^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'

echo "I have read and accept the disclaimer at https://github.com/pampuna/begone/blob/main/README.md (y/n)"
read -r response
[[ "$response" == "y" ]] || { echo "Exiting. Disclaimer not accepted."; exit 1; }

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root."
  exit 1
fi

if [ -z "$1" ]; then
  echo "Usage: $0 example.com"
  exit 1
fi

DOMAIN="$1"

if ! [[ "$DOMAIN" =~ $DOMAIN_REGEX ]]; then
  echo "Invalid domain format: $DOMAIN"
  exit 1
fi

APP_DIR="/opt/begone"

echo "Installing packages..."
apt install -y python3 python3-pip nginx certbot python3-venv

echo "Setting up app directory at $APP_DIR..."
mkdir -p "$APP_DIR"
chmod o+x /opt
chmod o+x "$APP_DIR"
chown -R www-data:www-data "$APP_DIR"
cd "$APP_DIR"

echo "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install flask gunicorn requests

echo "Creating Flask begone app..."
cat > "$APP_DIR/gateway.py" <<EOF
import json
import os
import re
import logging
import requests
from flask import Flask, request, Response, redirect, abort

app = Flask(__name__)
APP_DIR = os.path.dirname(__file__)
SUBDOMAIN_REGEX = re.compile(r'^[a-z0-9-]+$')
DOMAIN = "${DOMAIN}".lower()
try:
    with open(os.path.join(APP_DIR, "bindings.json")) as f:
        bindings_map = json.load(f)
except Exception as e:
    bindings_map = {}
    print(f"Failed to load bindings.json: {e}")
app.config['SERVER_NAME'] = DOMAIN
logging.basicConfig(level=logging.INFO)

@app.before_request
def log_request_info():
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    remote_addr = request.remote_addr
    client_ip = forwarded_for.split(',')[0].strip() if forwarded_for else remote_addr
    logging.info("[Client IP]: %s", client_ip)
    logging.info("[Request Method]: %s", request.method)
    logging.info("[Request Path]: %s", request.path)
    logging.info("[Query String]: %s", request.query_string.decode())
    logging.info("[Headers]: %s", dict(request.headers))
    logging.info("[Body]: %s", request.get_data(as_text=True))

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    host = request.host.lower()

    if not host.endswith(DOMAIN):
        return abort(404, "reason=0")

    sub = host[:-len(DOMAIN)].rstrip('.')
    if not sub or not SUBDOMAIN_REGEX.match(sub):
        return abort(404, "reason=1")

    mapping = bindings_map.get(sub)
    if mapping:
        (target, redirect_status_code, proxy) = mapping.values()
        if redirect_status_code and not proxy:
            return redirect(target, code=redirect_status_code)
        elif proxy:
            headers = {key: value for key, value in request.headers if key.lower() != 'host'}
            try:
                resp = requests.request(
                    method=request.method, url=target, headers=headers, data=request.get_data(), 
                    cookies=request.cookies, allow_redirects=False, params=request.args
                )
                excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
                response_headers = [(name, value) for name, value in resp.raw.headers.items() if name.lower() not in excluded_headers]
                return Response(resp.content, resp.status_code, response_headers)
            except requests.RequestException:
                return abort(502)
    return abort(404, "reason=2")

if __name__ == '__main__':
    app.run()

EOF

echo "Creating default bindings.json (if not exists)..."
if [ ! -f "$APP_DIR/bindings.json" ]; then
cat > "$APP_DIR/bindings.json" <<EOF
{
    "localhost": { "target": "http://127.0.0.1", "redirect": 302, "proxy": false }
}
EOF
  chown www-data:www-data "$APP_DIR/bindings.json"
  chmod 600 "$APP_DIR/bindings.json"
else
  echo "bindings.json already exists — skipping creation."
  chown www-data:www-data "$APP_DIR/bindings.json"
  chmod 600 "$APP_DIR/bindings.json"
fi

echo "Creating Gunicorn systemd service..."
cat > /etc/systemd/system/begone.service <<EOF
[Unit]
Description=Flask begone App
After=network.target

[Service]
User=www-data
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 1 --bind 127.0.0.1:5000 gateway:app --timeout 30
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now begone

echo "Creating initial Nginx config (HTTP only)..."
cat > /etc/nginx/sites-available/$DOMAIN <<EOF
server {
    listen 80;
    server_name .$DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx

CERT_PATH="/etc/letsencrypt/live/$DOMAIN"

echo "Checking if certificate already exists and is valid for $DOMAIN..."
if [ -d "$CERT_PATH" ] && openssl x509 -checkend $((30*24*60*60)) -noout -in "$CERT_PATH/config/live/$DOMAIN/fullchain.pem"; then
  echo "Valid certificate found for $DOMAIN (not expiring within 30 days) — skipping certbot."
else
  rm -rf $CERT_PATH
  read -p "Enter your email for Let's Encrypt: " EMAIL
  echo "No valid certificate found or it is expiring soon — running certbot..."
  certbot certonly --manual --preferred-challenges dns \
      --email "$EMAIL" --agree-tos --no-eff-email \
      --config-dir "$CERT_PATH/config" \
      --work-dir "$CERT_PATH/work" \
      --logs-dir "$CERT_PATH/logs" \
      -d "$DOMAIN" -d "*.$DOMAIN"
fi

echo "Updating Nginx config for HTTPS..."
if ! grep -q 'limit_req_zone \$binary_remote_addr zone=mylimit' /etc/nginx/nginx.conf; then
  echo "Adding rate limiting zone to /etc/nginx/nginx.conf"
  sed -i '/http {/a \
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;' /etc/nginx/nginx.conf
fi

cat > /etc/nginx/sites-available/$DOMAIN <<EOF
server {
    listen 443 ssl;
    server_name .$DOMAIN;

    ssl_certificate $CERT_PATH/config/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key $CERT_PATH/config/live/$DOMAIN/privkey.pem;
    
    large_client_header_buffers 16 128k;
    
    limit_req zone=mylimit burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}

server {
    listen 80;
    server_name .$DOMAIN;
    return 301 https://\$host\$request_uri;
}
EOF

nginx -t && systemctl reload nginx

echo ""
echo " Setup complete!"
echo "--------------------------------------------"
echo " Gateway config: $APP_DIR/bindings.json"
echo " HTTPS enabled for: *.$DOMAIN"
echo "--------------------------------------------"
echo " Registered domains: "
cat "$APP_DIR/bindings.json"
echo "--------------------------------------------"
echo ""
