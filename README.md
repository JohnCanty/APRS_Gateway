# APRS_Gateway
Local Web Driven APRS Message originator

# APRS-IS Message Gateway

A secure-ish, lightweight web-based gateway to send APRS messages via the APRS-IS network. Designed for deployment on Debian 13 (Trixie) within an LXC container.

## Features
- **SSL/TLS Encryption**: Native HTTPS support using ACME (acme.sh).
- **Security**: CSRF protection, secure HTTP headers, and input sanitization.
- **Robust Connectivity**: Automatic failover across multiple APRS-IS servers and common ports (14580, 10152, 14581).
- **Logging**: Console logging and remote Syslog support with user IP tracking.
- **Public IP Ready**: Runs via Gunicorn as a systemd service.

---

## 1. System Preparation (Debian 13 LXC)

Update the system and install required dependencies:

```
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-venv python3-pip git socat curl
```
## 2. If you are using a local rootCA Trust it's certificate
```
sudo cp rootca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```
## 3. Application Setup
Create the directory and enter it
```
sudo mkdir -p /opt/aprs-gateway
sudo chown $USER:$USER /opt/aprs-gateway
cd /opt/aprs-gateway
```
Create the Virtual Environment and install the dependencies
```
python3 -m venv venv
source venv/bin/activate
pip install flask gunicorn flask-wtf flask-limiter python-dotenv
```
## 4. Get your certificate (local rootCA via ACME example)
You may have to do some sudo su action here.... 
```
curl https://get.acme.sh | sh
sudo su -
```
# Replace with your CA directory and domain
```
~/.acme.sh/acme.sh --set-default-ca --server https://ca.example.com/acme/acme/directory
~/.acme.sh/acme.sh --issue -d aprs-gateway.example.com --standalone
```
# Install certs to a standard location
```
mkdir -p /etc/ssl/private /etc/ssl/certs
~/.acme.sh/acme.sh --install-cert -d aprs-gateway.fupcinternational.com \
--key-file /etc/ssl/private/aprs-gateway.key \
--fullchain-file /etc/ssl/certs/aprs-gateway.crt
exit
```
## 5. Configuration
Launch your favorite editor (vi I hope)
```
sudo vi /opt/aprs-gateway/.env
```
Add the environment bits to your liking
```
SECRET_KEY=<This is simply a place holder>
APRS_SERVER=rotate.aprs2.net
APRS_PORT=14580
LOG_SERVER=192.168.1.50:514
FALLBACK_SERVERS=noam.aprs.net,euro.aprs.net,asia.aprs.net
```
## 6. SystemD Bits
Open an editor 
```
sudo vi /etc/systemd/system/aprs-gateway.service
```
Add the Systemd Service Information the "aprs_gateway:app" is really important I had lots of issues with gunicorn using the '-' instead of the '_'.
```
[Unit]
Description=APRS-IS Message Gateway
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/opt/aprs-gateway
EnvironmentFile=/opt/aprs-gateway/.env
ExecStart=/opt/aprs-gateway/venv/bin/gunicorn \
    --workers 2 \
    --bind 0.0.0.0:443 \
    --keyfile /etc/ssl/private/aprs-gateway.key \
    --certfile /etc/ssl/certs/aprs-gateway.crt \
    aprs_gateway:app
Restart=always

[Install]
WantedBy=multi-user.target
```
## 7. Enable and start the service
```
sudo systemctl daemon-reload
sudo systemctl enable aprs-gateway
sudo systemctl start aprs-gateway
```
## If you need to see the errors more cleanly as you are starting up
```
sudo journalctl -u aprs-gateway -f
```


