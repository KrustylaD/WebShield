
import requests
from urllib.parse import urlparse

TIMEOUT = 10

USER_AGENT = {
    "User-Agent": "WebShield/3.0"
}

SECURITY_HEADERS = [
    {
        "name": "HSTS",
        "header": "Strict-Transport-Security",
        "weight": 20,
        "severity": "HAUTE",
        "description": "Force les navigateurs à utiliser HTTPS.",
        "recommendation": "Configurer un max-age adapté sur le site HTTPS."
    },
    {
        "name": "CSP",
        "header": "Content-Security-Policy",
        "weight": 25,
        "severity": "MOYENNE",
        "description": "Limite les sources de contenu autorisées.",
        "recommendation": "Définir une Content Security Policy adaptée au site."
    },
    {
        "name": "Protection MIME",
        "header": "X-Content-Type-Options",
        "weight": 15,
        "severity": "FAIBLE",
        "description": "Empêche certains types de détection MIME automatiques.",
        "recommendation": "Définir X-Content-Type-Options: nosniff."
    },
    {
        "name": "Protection clickjacking",
        "header": "X-Frame-Options",
        "weight": 15,
        "severity": "MOYENNE",
        "description": "Contrôle l'affichage du site dans une iframe.",
        "recommendation": "Configurer X-Frame-Options ou la directive CSP frame-ancestors."
    },
    {
        "name": "Politique de référent",
        "header": "Referrer-Policy",
        "weight": 10,
        "severity": "FAIBLE",
        "description": "Contrôle les informations envoyées dans l'en-tête Referer.",
        "recommendation": "Choisir une politique adaptée, par exemple strict-origin-when-cross-origin."
    },
    {
        "name": "Permissions Policy",
        "header": "Permissions-Policy",
        "weight": 15,
        "severity": "FAIBLE",
        "description": "Contrôle l'accès à certaines fonctionnalités du navigateur.",
        "recommendation": "Définir les permissions nécessaires au site."
    },
]


def fetch_responses(url):
    """Effectue une requête GET et conserve toutes les réponses de redirection."""
    response = requests.get(
        url,
        timeout=TIMEOUT,
        allow_redirects=True,
        headers=USER_AGENT
    )

    responses = list(response.history) + [response]
    return response, responses


def get_csp_directives(csp):
    """Extrait les directives d'une CSP simple."""
    directives = {}

    for part in csp.split(";"):
        words = part.strip().split()

        if words:
            directives[words[0].lower()] = words[1:]

    return directives


def check_header(item, headers, is_https):
    """Vérifie la présence et certaines valeurs d'un en-tête."""
    value = headers.get(item["header"])
    status = "ABSENT"
    details = "En-tête absent."

    if value is not None:
        status = "PRESENT"
        details = "En-tête présent."

        if item["header"] == "Strict-Transport-Security":
            max_age = None

            for directive in value.split(";"):
                directive = directive.strip()

                if "=" in directive:
                    key, val = directive.split("=", 1)

                    if key.strip().lower() == "max-age":
                        try:
                            max_age = int(val.strip())
                        except ValueError:
                            max_age = None

            if not is_https:
                status = "A_VERIFIER"
                details = "HSTS reçu sur une URL qui n'est pas HTTPS."
            elif max_age is None:
                status = "A_VERIFIER"
                details = "Directive max-age absente ou invalide."
            elif max_age <= 0:
                status = "A_VERIFIER"
                details = "max-age est nul ou négatif."
            else:
                details = f"HSTS actif avec max-age={max_age}."

        elif item["header"] == "X-Content-Type-Options":
            if value.strip().lower() != "nosniff":
                status = "A_VERIFIER"
                details = "Valeur différente de nosniff."

    return {
        "name": item["name"],
        "header": item["header"],
        "weight": item["weight"],
        "severity": item["severity"],
        "value": value or "",
        "description": item["description"],
        "recommendation": item["recommendation"],
        "status": status,
        "details": details,
    }


def scan_headers(url, responses):
    """Analyse les en-têtes de la réponse finale."""
    final_response = responses[-1]
    headers = final_response.headers
    is_https = urlparse(final_response.url).scheme.lower() == "https"

    results = [
        check_header(item, headers, is_https)
        for item in SECURITY_HEADERS
    ]

    csp = headers.get("Content-Security-Policy", "")
    directives = get_csp_directives(csp)

    # frame-ancestors dans la CSP peut remplacer X-Frame-Options.
    frame_result = next(
        result for result in results
        if result["header"] == "X-Frame-Options"
    )

    if "frame-ancestors" in directives:
        frame_result["status"] = "COUVERT_PAR_CSP"
        frame_result["details"] = (
            "La CSP contient la directive frame-ancestors."
        )

    # Une CSP en mode report-only ne bloque pas réellement le contenu.
    report_only = headers.get("Content-Security-Policy-Report-Only")

    if not csp and report_only:
        csp_result = next(
            result for result in results
            if result["header"] == "Content-Security-Policy"
        )
        csp_result["status"] = "A_VERIFIER"
        csp_result["details"] = (
            "Seule une CSP Report-Only est présente : "
            "elle signale les violations sans les bloquer."
        )

    return results


def get_set_cookie_headers(response):
    """Récupère les en-têtes Set-Cookie sans afficher les valeurs des cookies."""
    raw_headers = getattr(response.raw, "headers", None)

    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values = raw_headers.getlist("Set-Cookie")

        if values:
            return values

    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def scan_cookies(responses):
    """Vérifie les attributs de sécurité des cookies de chaque réponse."""
    results = []

    for response_number, response in enumerate(responses, start=1):
        cookies = get_set_cookie_headers(response)

        for raw_cookie in cookies:
            parts = [part.strip() for part in raw_cookie.split(";")]
            cookie_name = parts[0].split("=", 1)[0].strip()

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
                "name": cookie_name or "(nom inconnu)",
                "response_number": response_number,
                "url": response.url,
                "secure": secure,
                "httponly": httponly,
                "samesite": str(samesite) if samesite else "Absent",
                "status": "A_VERIFIER" if missing else "PRESENT",
                "details": (
                    "Attributs manquants : " + ", ".join(missing)
                    if missing else "Attributs de sécurité présents."
                ),
                "recommendation": (
                    "Vérifier si Secure, HttpOnly et SameSite sont nécessaires "
                    "pour ce cookie."
                ),
            })

    if not results:
        results.append({
            "name": "(aucun cookie détecté)",
            "response_number": 0,
            "url": "",
            "secure": False,
            "httponly": False,
            "samesite": "N/A",
            "status": "INFO",
            "details": "Aucun en-tête Set-Cookie détecté.",
            "recommendation": (
                "Aucune action automatique : certains sites n'ont pas besoin "
                "d'envoyer des cookies."
            ),
        })

    return results


def scan_redirects(responses):
    """Compare les en-têtes de sécurité entre chaque réponse HTTP."""
    results = []

    for index, response in enumerate(responses, start=1):
        results.append({
            "step": index,
            "url": response.url,
            "status_code": response.status_code,
            "https": urlparse(response.url).scheme.lower() == "https",
            "hsts": response.headers.get("Strict-Transport-Security", ""),
            "csp": response.headers.get("Content-Security-Policy", ""),
            "x_content_type_options": response.headers.get(
                "X-Content-Type-Options", ""
            ),
            "x_frame_options": response.headers.get("X-Frame-Options", ""),
        })

    return results
