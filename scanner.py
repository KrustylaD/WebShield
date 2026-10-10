"""WebShield: récupération HTTP et analyse des en-têtes/cookies."""
from urllib.parse import urlparse
import requests

TIMEOUT = 10
USER_AGENT = {"User-Agent": "WebShield/4.0 (educational security header checker)"}

SECURITY_HEADERS = [
    {"name": "HSTS", "header": "Strict-Transport-Security", "weight": 20,
     "description": "Demande au navigateur de privilégier HTTPS pour le domaine.",
     "recommendation": "Sur HTTPS, définir un max-age adapté après vérification des sous-domaines."},
    {"name": "Content Security Policy (CSP)", "header": "Content-Security-Policy", "weight": 25,
     "description": "Définit les sources autorisées pour différents types de contenu.",
     "recommendation": "Construire et tester une CSP adaptée aux ressources réellement utilisées."},
    {"name": "Protection MIME", "header": "X-Content-Type-Options", "weight": 15,
     "description": "Empêche certains types de détection MIME automatiques.",
     "recommendation": "Définir X-Content-Type-Options: nosniff."},
    {"name": "Protection clickjacking", "header": "X-Frame-Options", "weight": 15,
     "description": "Peut limiter l'intégration du site dans une iframe.",
     "recommendation": "Configurer X-Frame-Options ou frame-ancestors dans une CSP appliquée."},
    {"name": "Referrer-Policy", "header": "Referrer-Policy", "weight": 10,
     "description": "Contrôle les informations de référent transmises par le navigateur.",
     "recommendation": "Choisir une politique adaptée, par exemple strict-origin-when-cross-origin."},
    {"name": "Permissions Policy", "header": "Permissions-Policy", "weight": 15,
     "description": "Contrôle certaines fonctionnalités du navigateur.",
     "recommendation": "Limiter les fonctionnalités selon les besoins du site."},
]

def validate_http_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("L'URL doit être une URL HTTP(S) valide.")
    if parsed.username or parsed.password:
        raise ValueError("N'inclus pas d'identifiants dans l'URL.")
    return parsed

def fetch_responses(url):
    """Effectue une requête GET et conserve les réponses de redirection."""
    validate_http_url(url)
    response = requests.get(url, timeout=TIMEOUT, allow_redirects=True,
                            headers=USER_AGENT, stream=False)
    return response, list(response.history) + [response]

def parse_directives(policy):
    directives = {}
    for part in policy.split(";"):
        words = part.strip().split()
        if words:
            directives[words[0].lower()] = words[1:]
    return directives

def _parse_max_age(value):
    for directive in value.split(";"):
        if "=" in directive:
            key, raw_value = directive.split("=", 1)
            if key.strip().lower() == "max-age":
                try:
                    parsed = int(raw_value.strip())
                except ValueError:
                    return None
                return parsed if parsed >= 0 else None
    return None

def check_header(item, headers, is_https):
    value = headers.get(item["header"])
    status = "NON_DETECTE"
    details = "En-tête non détecté dans la réponse finale."

    if value is not None:
        status = "CONFORME"
        details = "En-tête détecté."
        if item["header"] == "Strict-Transport-Security":
            max_age = _parse_max_age(value)
            if not is_https:
                status, details = "A_VERIFIER", "HSTS observé sur une URL finale non HTTPS."
            elif max_age is None:
                status, details = "A_VERIFIER", "Directive max-age absente ou invalide."
            elif max_age == 0:
                status, details = "A_VERIFIER", "max-age=0 désactive la mémorisation HSTS."
            else:
                details = f"HSTS détecté avec max-age={max_age}."
        elif item["header"] == "X-Content-Type-Options" and value.strip().lower() != "nosniff":
            status, details = "A_VERIFIER", "Valeur détectée différente de nosniff."
        elif item["header"] == "Referrer-Policy":
            valid_values = {"no-referrer", "no-referrer-when-downgrade", "origin",
                            "origin-when-cross-origin", "same-origin", "strict-origin",
                            "strict-origin-when-cross-origin", "unsafe-url"}
            values = [v.strip().lower() for v in value.split(",") if v.strip()]
            if not values or values[-1] not in valid_values:
                status, details = "A_VERIFIER", "Valeur de Referrer-Policy à vérifier."

    return {
        "name": item["name"], "header": item["header"], "weight": item["weight"],
        "value": value or "", "description": item["description"],
        "recommendation": item["recommendation"], "status": status, "details": details,
    }

def scan_headers(responses):
    """Analyse les en-têtes de sécurité de la réponse finale."""
    final_response = responses[-1]
    headers = final_response.headers
    is_https = urlparse(final_response.url).scheme.lower() == "https"
    results = [check_header(item, headers, is_https) for item in SECURITY_HEADERS]

    csp_result = next(r for r in results if r["header"] == "Content-Security-Policy")
    csp = headers.get("Content-Security-Policy", "")
    report_only_csp = headers.get("Content-Security-Policy-Report-Only", "")
    if not csp and report_only_csp:
        csp_result["status"] = "A_VERIFIER"
        csp_result["details"] = ("CSP Report-Only détectée : elle signale les violations "
                                 "mais n'applique pas les blocages de la politique.")

    frame_result = next(r for r in results if r["header"] == "X-Frame-Options")
    enforced = parse_directives(csp)
    report_only = parse_directives(report_only_csp)
    if "frame-ancestors" in enforced:
        frame_result["status"] = "COUVERT_PAR_CSP"
        frame_result["details"] = "La CSP appliquée contient frame-ancestors."
    elif "frame-ancestors" in report_only:
        frame_result["status"] = "A_VERIFIER"
        frame_result["details"] = ("frame-ancestors est uniquement présent dans une CSP "
                                   "Report-Only ; la protection n'est pas imposée.")
    return results

def get_set_cookie_headers(response):
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values = raw_headers.getlist("Set-Cookie")
        if values:
            return values
    value = response.headers.get("Set-Cookie")
    return [value] if value else []

def scan_cookies(responses):
    """Vérifie les attributs basiques des cookies sans exposer leurs valeurs."""
    results = []
    for response_number, response in enumerate(responses, start=1):
        for raw_cookie in get_set_cookie_headers(response):
            parts = [part.strip() for part in raw_cookie.split(";")]
            cookie_name = parts[0].split("=", 1)[0].strip() if parts else ""
            attributes = {}
            for part in parts[1:]:
                if "=" in part:
                    key, value = part.split("=", 1)
                    attributes[key.strip().lower()] = value.strip()
                else:
                    attributes[part.strip().lower()] = True
            secure = "secure" in attributes
            httponly = "httponly" in attributes
            samesite = attributes.get("samesite", "")
            missing = []
            if not secure:
                missing.append("Secure")
            if not httponly:
                missing.append("HttpOnly")
            if not samesite:
                missing.append("SameSite")
            results.append({
                "name": cookie_name or "(nom inconnu)", "response_number": response_number,
                "url": response.url, "secure": secure, "httponly": httponly,
                "samesite": str(samesite) if samesite else "Absent",
                "status": "A_VERIFIER" if missing else "CONFORME",
                "details": ("Attributs à examiner : " + ", ".join(missing) if missing
                            else "Attributs Secure, HttpOnly et SameSite détectés."),
                "recommendation": ("Vérifier les besoins de ce cookie. Les attributs requis "
                                   "dépendent de son usage ; HttpOnly n'est pas nécessaire "
                                   "pour tous les cookies."),
            })
    if not results:
        results.append({
            "name": "(aucun cookie détecté)", "response_number": 0, "url": "",
            "secure": False, "httponly": False, "samesite": "N/A", "status": "INFO",
            "details": "Aucun en-tête Set-Cookie détecté dans les réponses examinées.",
            "recommendation": "Cela ne prouve pas qu'aucun cookie n'est utilisé plus tard.",
        })
    return results

def scan_redirects(responses):
    """Résumé des en-têtes clés de chaque réponse de la chaîne HTTP."""
    results = []
    for index, response in enumerate(responses, start=1):
        h = response.headers
        results.append({
            "step": index, "url": response.url, "status_code": response.status_code,
            "https": urlparse(response.url).scheme.lower() == "https",
            "hsts": bool(h.get("Strict-Transport-Security")),
            "csp": bool(h.get("Content-Security-Policy")),
            "csp_report_only": bool(h.get("Content-Security-Policy-Report-Only")),
            "x_content_type_options": bool(h.get("X-Content-Type-Options")),
            "x_frame_options": bool(h.get("X-Frame-Options")),
        })
    return results
