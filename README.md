# Begone

This is a proof of concept tool created for demonstrative purposes and pentesting. The tool is not "production" worthy and should be treated as such. If you want to try it, review the disclaimer below.

This setup script (`begone.sh`) creates a service which acts as a gateway to redirect or proxy a specified endpoints based on a subdomain. It has the following features:

- If a subdomain is specified, fetch its mapping.
- Using the mapping either redirect using the set status code or proxy the target. If set, pass along the source path to the target.
- Support both HTTP and HTTPS.
- If the main domain or an unknown subdomain is approached, return a 404.
- Ignores source paths, but is able to write to target paths.
- Basic rate limiting.

It uses the following components:

- Nginx: The web server.
- Python venv, flask, requests and gunicorn: Handling the redirects and proxying.
- Certbot: Used for letsencrypt wildcard certificate creation.

## Setup

```sh
/opt/begone.sh <domain>
```

On first time setup, or if your certificate has expired, the script will prompt for an e-mailaddress for letsencrypt. It will also instruct you to add two txt records needed for a wildcard certificate creation.

## Updating Bindings

Subdomain bindings can be added or removed by updating `bindings.json`. A binding has the following properties:

- target: The target domain including the protocol.
- redirect: Set to redirect by subdomain function. Its value is used as the redirect status code.
- keep_path: Toggle to combine the source path and target domain.
- proxy: Set to let the service proxy the target and return fetched contents. If both redirect and proxy are set, a redirect will happen.

For example, an `bindings.json` configured for with multiple localhost-like bindings could look like this:  

```json
{
    "l1": { "target": "http://127.0.0.1", "redirect": 302, "keep_path": true, "proxy": false },
    "l2": { "target": "http://127.0.0.1", "redirect": 307, "keep_path": true, "proxy": false },
    "l3": { "target": "http://127.1", "redirect": 302, "keep_path": true, "proxy": false },
    "l4": { "target": "http://localhost", "redirect": 302, "keep_path": true, "proxy": false },
    "l5": { "target": "http://[::1]", "redirect": 302, "keep_path": true, "proxy": false },
    "l6": { "target": "http://0.0.0.0", "redirect": 302, "keep_path": true, "proxy": false },
    "l7": { "target": "http://localhost.localdomain", "redirect": 302, "keep_path": true, "proxy": false },
    "l8": { "target": "http://loopback", "redirect": 302, "keep_path": true, "proxy": false },
    "l9": { "target": "http://127.0.0.1:3000", "redirect": 302, "keep_path": false, "proxy": false },
    "l10": { "target": "http://127.0.0.1:8000", "redirect": 302, "keep_path": false, "proxy": false },
    "l11": { "target": "http://127.0.0.1:8080", "redirect": 302, "keep_path": false, "proxy": false }
}
```

After updating the file, restart the `begone` service:

```sh
nano /opt/begone/bindings.json

sudo systemctl restart begone 
```

## General Debugging

```sh
# Restarting
sudo systemctl restart nginx   
sudo systemctl restart begone 

# Verifying status
sudo systemctl status nginx
sudo systemctl status begone

# Checking logs
journalctl -u begone.service -e
```

## Disclaimer

The tools and code hosted in [this repository](https://github.com/pampuna/begone) are intended **ONLY** for educational purposes and lawful penetration testing. **Begone is not a production-ready tool** and is **not stable, secure, or safe for real-world deployment**. It is experimental and should be used with extreme caution.

## Important Notes:

1. **Not for Production Use**  
   Begone is an experimental tool and should **not** be used in any production environment. It is unstable, may contain serious bugs, and has not undergone thorough security reviews. Use at your own risk.

2. **Ethical Use Only**  
   This tool must be used **only** on systems you own or have explicit, written permission to test. Any unauthorized use is illegal, unethical, and strictly prohibited.

3. **Legal Compliance**  
   You are solely responsible for ensuring your use of this tool complies with all applicable laws and regulations in your jurisdiction. The author assumes **no responsibility** for any legal consequences resulting from misuse.

4. **No Warranty or Guarantees**  
   Begone is provided **"as is"**, without any warranties or guarantees of functionality, reliability, or security. The author does not guarantee that the tool will function correctly or safely.

5. **User Responsibility**  
   By using this tool, you accept full responsibility for any outcomes, including data loss, system damage, or legal issues. The author is **not liable** for any harm resulting from its use.

6. **Indemnification**  
   By using Begone, you agree to indemnify and hold harmless the author from any claims, damages, or liabilities that may arise from its use or misuse.

7. **Educational Purpose Only**  
   This tool is intended solely for learning, research, and educational purposes in the context of ethical hacking and cybersecurity. Use it responsibly and **only in authorized environments**.
