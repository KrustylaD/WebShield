
"""WebShield V5 : récupération HTTP contrôlée et analyse défensive."""

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests


TIMEOUT = 10
MAX_REDIRECTS = 10
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

USER_AGENT = {
    "User-Agent": "WebShield/5.0 (educational security header checker)"
}

REDIRECT_CODES = {301, 302, 303, 307, 308}

CSP_DIRECTIVES = {
    "default-src", "script-src", "script-src-elem", "script-src-attr",
    "style-src", "style-src-elem", "style-src-attr", "img-src",
    "connect-src", "font-src", "media-src", "object-src", "frame-src",
    "child-src", "worker-src", "manifest-src", "base-uri", "form-action",
    "frame-ancestors", "sandbox", "upgrade-insecure-requests",
    "block-all-mixed-content", "plugin-types", "require-sri-for",
    "require-trusted-types-for", "trusted-types", "report-uri", "report-to",
    "navigate-to", "prefetch-src",
}

CSP_SOURCE_DIRECTIVES = {
    "default-src", "script-src", "script-src-elem", "script-src-attr",
    "style-src", "style-src-elem", "style-src-attr", "img-src",
    "connect-src", "font-src", "media-src", "object-src", "frame-src",
    "child-src", "worker-src", "manifest-src", "base-uri", "form-action",
    "frame-ancestors", "prefetch-src", "navigate-to",
}

SECURITY_HEADERS = [
    {
        "name": "HSTS",
        "header": "Strict-Transport-Security",
        "weight": 20,
        "description": "Demande au navigateur de privilégier HTTPS.",
        "recommendation": (
            "Sur HTTPS, définir un max-age adapté après vérification "
            "des sous-domaines."
        ),
    },
    {
        "name": "Content Security Policy (CSP)",
        "header": "Content-Security-Policy",
        "weight": 25,
        "description": "Définit les sources autorisées pour le contenu.",
        "recommendation": (
            "Construire et tester une CSP adaptée aux ressources du site."
        ),
    },
    {
        "name": "Protection MIME",
        "header": "X-Content-Type-Options",
        "weight": 15,
        "description": "Limite certaines interprétations MIME automatiques.",
        "recommendation": "Définir X-Content-Type-Options: nosniff.",
    },
    {
        "name": "Protection clickjacking",
        "header": "X-Frame-Options",
        "weight": 15,
        "description": "Peut limiter l'intégration du site dans une iframe.",
        "recommendation": (
            "Configurer X-Frame-Options ou frame-ancestors dans une CSP "
            "appliquée."
        ),
    },
    {
        "name": "Referrer-Policy",
        "header": "Referrer-Policy",
        "weight": 10,
        "description": "Contrôle les informations de référent transmises.",
        "recommendation": (
            "Choisir une politique adaptée, par exemple "
            "strict-origin-when-cross-origin."
        ),
    },
    {
        "name": "Permissions Policy",
        "header": "Permissions-Policy",
        "weight": 15,
        "description": "Contrôle certaines fonctionnalités du navigateur.",
        "recommendation": (
            "Limiter les fonctionnalités selon les besoins du site."
        ),
    },
]


def _parse_url(url):
    """Analyse une URL et renvoie ses composants après validation syntaxique."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL vide ou invalide.")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL mal formée.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Seuls HTTP et HTTPS sont autorisés.")

    if not hostname:
        raise ValueError("L'URL doit contenir un nom d'hôte.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Les identifiants dans l'URL sont interdits.")

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port invalide.")

    hostname = hostname.rstrip(".").lower()

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Les destinations locales sont interdites.")

    return parsed, hostname, port


def _resolve_public_ips(hostname, port):
    """Résout un hôte et refuse toute adresse non publique."""
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not literal_ip.is_global:
            raise ValueError(
                f"Destination refusée : adresse IP non publique ({literal_ip})."
            )
        return {literal_ip}

    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            "Impossible de résoudre le nom d'hôte."
        ) from exc

    if not results:
        raise ValueError("Le nom d'hôte ne possède aucune adresse IP.")

    resolved_ips = set()

    for result in results:
        address = result[4][0].split("%")[0]

        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("Adresse IP DNS invalide.") from exc

        if not ip.is_global:
            raise ValueError(
                f"Destination refusée : adresse IP non publique ({ip})."
            )

        resolved_ips.add(ip)

    return resolved_ips


def validate_http_url(url: str) -> str:
    """Valide une URL HTTP(S) et vérifie que toutes ses IP sont publiques."""
    parsed, hostname, port = _parse_url(url)

    destination_port = port or (
        443 if parsed.scheme.lower() == "https" else 80
    )

    _resolve_public_ips(hostname, destination_port)
    return url


def validate_public_destination(url: str) -> str:
    """Valide une destination avant chaque requête ou redirection."""
    return validate_http_url(url)


def fetch_responses(url):
    """
    Récupère les réponses HTTP en contrôlant chaque redirection.

    Renvoie (réponse_finale, liste_des_réponses).
    Les réponses sont fermées en cas d'erreur. En cas de succès,
    l'appelant doit les fermer après l'analyse.
    """
    current_url = url
    responses = []

    try:
        with requests.Session() as session:
            session.headers.update(USER_AGENT)
            session.trust_env = False

            for redirect_count in range(MAX_REDIRECTS + 1):
                validate_public_destination(current_url)

                response = session.get(
                    current_url,
                    timeout=TIMEOUT,
                    allow_redirects=False,
                    stream=True,
                )
                responses.append(response)

                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except ValueError as exc:
                        raise ValueError(
                            "Réponse HTTP avec Content-Length invalide."
                        ) from exc

                    if declared_size < 0:
                        raise ValueError(
                            "Réponse HTTP avec Content-Length négatif."
                        )

                    if declared_size > MAX_RESPONSE_BYTES:
                        raise ValueError(
                            "Réponse HTTP trop volumineuse "
                            f"(limite : {MAX_RESPONSE_BYTES} octets)."
                        )

                bytes_read = 0
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    if not isinstance(chunk, bytes):
                        raise ValueError(
                            "Réponse HTTP avec un contenu non binaire."
                        )
                    bytes_read += len(chunk)
                    if bytes_read > MAX_RESPONSE_BYTES:
                        raise ValueError(
                            "Réponse HTTP trop volumineuse après lecture "
                            f"(limite : {MAX_RESPONSE_BYTES} octets)."
                        )

                if response.status_code not in REDIRECT_CODES:
                    return response, responses

                location = response.headers.get("Location")

                if not location:
                    return response, responses

                if redirect_count >= MAX_REDIRECTS:
                    raise requests.TooManyRedirects(
                        f"Plus de {MAX_REDIRECTS} redirections."
                    )

                next_url = urljoin(current_url, location)
                validate_public_destination(next_url)

                old = urlsplit(current_url)
                new = urlsplit(next_url)

                # Ne pas conserver l'authentification entre origines différentes.
                if (
                    old.hostname != new.hostname
                    or old.port != new.port
                    or old.scheme.lower() != new.scheme.lower()
                ):
                    session.auth = None
                    session.headers.pop("Authorization", None)

                current_url = next_url

    except Exception:
        for response in responses:
            try:
                response.close()
            except Exception:
                pass
        raise

    raise requests.RequestException("La récupération HTTP a échoué.")


def parse_directives(policy):
    """Analyse les directives CSP et signale les noms répétés."""
    directives = {}

    if not isinstance(policy, str):
        return directives

    for part in policy.split(";"):
        words = part.strip().split()

        if not words:
            continue

        name = words[0].lower()

        if name in directives:
            directives[name]["duplicate"] = True
            continue

        directives[name] = {
            "values": words[1:],
            "duplicate": False,
        }

    return directives


def _parse_max_age(value):
    """Extrait max-age si la directive est valide et non ambiguë."""
    if not isinstance(value, str) or not value.strip():
        return None

    values = []

    for directive in value.split(";"):
        directive = directive.strip()

        if "=" not in directive:
            continue

        key, raw_value = directive.split("=", 1)

        if key.strip().lower() == "max-age":
            raw_value = raw_value.strip()

            if not raw_value.isascii() or not raw_value.isdigit():
                return None

            values.append(int(raw_value))

    if len(values) != 1:
        return None

    return values[0]


def analyze_csp(value: str) -> dict:
    """
    Évalue des signaux de faiblesse CSP.

    Le score est heuristique : ce n'est pas une certification de sécurité.
    """
    directives = parse_directives(value)
    issues = []
    warnings = []

    if not directives:
        return {
            "status": "ABSENTE",
            "score": 0,
            "issues": ["Politique CSP vide ou sans directive exploitable."],
            "warnings": [],
        }

    for name, directive in directives.items():
        values = [item.lower() for item in directive["values"]]

        if name not in CSP_DIRECTIVES:
            warnings.append(f"Directive inconnue ou non standard : {name}.")

        if directive["duplicate"]:
            warnings.append(f"Directive {name} déclarée plusieurs fois.")

        if not values and name in CSP_SOURCE_DIRECTIVES:
            warnings.append(f"Directive {name} sans valeur.")

        if "'unsafe-inline'" in values:
            issues.append(f"{name} autorise unsafe-inline.")

        if "'unsafe-eval'" in values:
            issues.append(f"{name} autorise unsafe-eval.")

        if "*" in values:
            issues.append(f"{name} autorise toutes les sources (*).")

        if "http:" in values:
            warnings.append(f"{name} autorise des sources HTTP.")

    if "default-src" not in directives:
        warnings.append("Directive default-src absente.")

    for name in ("object-src", "base-uri", "frame-ancestors"):
        if name not in directives:
            warnings.append(f"Directive {name} absente.")

    script_policy = directives.get(
        "script-src",
        directives.get("default-src", {"values": []}),
    )["values"]

    normalized_script_policy = [item.lower() for item in script_policy]

    if not normalized_script_policy:
        warnings.append("Aucune restriction de scripts clairement définie.")

    score = max(0, 100 - 25 * len(issues) - 10 * len(warnings))

    if issues:
        status = "FAIBLE"
    elif warnings:
        status = "À_AMÉLIORER"
    else:
        status = "CONFIGURATION_APPAREMMENT_SOLIDE"

    return {
        "status": status,
        "score": score,
        "issues": issues,
        "warnings": warnings,
    }


def check_header(item, headers, is_https):
    """Évalue un en-tête de sécurité avec des contrôles préliminaires."""
    header_name = item["header"]
    value = headers.get(header_name)

    status = "NON_DETECTE"
    details = "En-tête non détecté dans la réponse finale."

    if value is not None:
        normalized = value.strip()
        status = "A_VERIFIER"
        details = "Valeur présente, mais sa conformité reste à vérifier."

        if not normalized:
            details = "En-tête présent, mais sa valeur est vide."

        elif header_name == "Strict-Transport-Security":
            max_age = _parse_max_age(normalized)

            if not is_https:
                details = "HSTS ne doit être évalué que sur HTTPS."
            elif max_age is None:
                details = "Directive max-age absente ou invalide."
            elif max_age == 0:
                details = "max-age=0 désactive la mémorisation HSTS."
            else:
                status = "CONFORME"
                details = f"HSTS détecté avec max-age={max_age}."

        elif header_name == "Content-Security-Policy":
            csp = analyze_csp(normalized)
            status = csp["status"]
            details = (
                f"Score heuristique CSP : {csp['score']}/100. "
                + " ".join(csp["issues"] + csp["warnings"])
            )

        elif header_name == "X-Content-Type-Options":
            if normalized.lower() == "nosniff":
                status = "CONFORME"
                details = "Valeur nosniff détectée."
            else:
                details = "Valeur invalide : nosniff est attendu."

        elif header_name == "X-Frame-Options":
            if normalized.upper() in {"DENY", "SAMEORIGIN"}:
                status = "CONFORME"
                details = "Valeur X-Frame-Options reconnue."
            else:
                details = (
                    "Valeur invalide ou non prise en charge "
                    "pour X-Frame-Options."
                )

        elif header_name == "Referrer-Policy":
            valid_values = {
                "no-referrer",
                "no-referrer-when-downgrade",
                "origin",
                "origin-when-cross-origin",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "unsafe-url",
            }

            values = [
                part.strip().lower()
                for part in normalized.split(",")
                if part.strip()
            ]

            if values and values[-1] in valid_values:
                status = "CONFORME"
                details = "Valeur Referrer-Policy reconnue."
            else:
                details = "Valeur Referrer-Policy invalide."

        elif header_name == "Permissions-Policy":
            if "\r" in normalized or "\n" in normalized:
                details = "Valeur Permissions-Policy invalide."
            else:
                status = "A_VERIFIER"
                details = (
                    "En-tête présent ; syntaxe et directives "
                    "à vérifier plus précisément."
                )

    return {
        "name": item["name"],
        "header": header_name,
        "weight": item["weight"],
        "value": value or "",
        "description": item["description"],
        "recommendation": item["recommendation"],
        "status": status,
        "details": details,
    }


def scan_headers(responses):
    """Analyse les en-têtes de sécurité de la réponse finale."""
    if not responses:
        raise ValueError("Aucune réponse HTTP à analyser.")

    final_response = responses[-1]
    headers = final_response.headers
    is_https = urlsplit(final_response.url).scheme.lower() == "https"

    results = [
        check_header(item, headers, is_https)
        for item in SECURITY_HEADERS
    ]

    csp_result = next(
        result for result in results
        if result["header"] == "Content-Security-Policy"
    )

    csp = headers.get("Content-Security-Policy", "")
    report_only_csp = headers.get(
        "Content-Security-Policy-Report-Only", ""
    )

    if not csp and report_only_csp:
        csp_result["status"] = "A_VERIFIER"
        csp_result["details"] = (
            "CSP Report-Only détectée : elle signale les violations, "
            "mais n'applique pas les blocages."
        )

    frame_result = next(
        result for result in results
        if result["header"] == "X-Frame-Options"
    )

    enforced = parse_directives(csp)
    report_only = parse_directives(report_only_csp)

    if "frame-ancestors" in enforced:
        frame_result["status"] = "COUVERT_PAR_CSP"
        frame_result["details"] = (
            "La CSP appliquée contient frame-ancestors."
        )
    elif "frame-ancestors" in report_only:
        frame_result["status"] = "A_VERIFIER"
        frame_result["details"] = (
            "frame-ancestors est uniquement présent dans une CSP "
            "Report-Only ; la protection n'est pas imposée."
        )

    return results


def get_set_cookie_headers(response):
    """Récupère les en-têtes Set-Cookie sans les fusionner si possible."""
    raw_response = getattr(response, "raw", None)
    raw_headers = getattr(raw_response, "headers", None)

    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values = raw_headers.getlist("Set-Cookie")
        if values:
            return values

    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def scan_cookies(responses):
    """Vérifie des attributs de cookies sans exposer leurs valeurs."""
    results = []

    for response_number, response in enumerate(responses, start=1):
        for raw_cookie in get_set_cookie_headers(response):
            parts = [
                part.strip()
                for part in raw_cookie.split(";")
            ]

            cookie_name = (
                parts[0].split("=", 1)[0].strip()
                if parts else ""
            )

            attributes = {}
            duplicate_attributes = set()

            for part in parts[1:]:
                if "=" in part:
                    key, value = part.split("=", 1)
                    normalized_key = key.strip().lower()
                    if normalized_key in attributes:
                        duplicate_attributes.add(normalized_key)
                    attributes[normalized_key] = value.strip()
                else:
                    normalized_key = part.strip().lower()
                    if normalized_key in attributes:
                        duplicate_attributes.add(normalized_key)
                    attributes[normalized_key] = True

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
            elif str(samesite).lower() not in {"strict", "lax", "none"}:
                missing.append("SameSite (valeur invalide)")
            elif "samesite" in duplicate_attributes:
                missing.append("SameSite (dupliqué)")

            results.append({
                "name": cookie_name or "(nom inconnu)",
                "response_number": response_number,
                "url": _redacted_response_url(response.url),
                "secure": secure,
                "httponly": httponly,
                "samesite": str(samesite) if samesite else "Absent",
                "status": "A_VERIFIER" if missing else "CONFORME",
                "details": (
                    "Attributs à examiner : " + ", ".join(missing)
                    if missing
                    else "Attributs Secure, HttpOnly et SameSite détectés."
                ),
                "recommendation": (
                    "Vérifier les besoins de ce cookie. Les attributs requis "
                    "dépendent de son usage ; HttpOnly n'est pas nécessaire "
                    "pour tous les cookies."
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
            "details": (
                "Aucun en-tête Set-Cookie détecté dans les réponses examinées."
            ),
            "recommendation": (
                "Cela ne prouve pas qu'aucun cookie n'est utilisé plus tard."
            ),
        })

    return results


def _redacted_response_url(url):
    """Retourne une URL de rapport sans query string ni fragment."""
    parsed = urlsplit(str(url))
    return parsed._replace(query="", fragment="").geturl()


def scan_redirects(responses):
    """Résume les en-têtes clés de chaque réponse de la chaîne HTTP."""
    results = []

    for index, response in enumerate(responses, start=1):
        headers = response.headers

        results.append({
            "step": index,
            "url": response.url,
            "status_code": response.status_code,
            "https": urlsplit(response.url).scheme.lower() == "https",
            "hsts": bool(headers.get("Strict-Transport-Security")),
            "csp": bool(headers.get("Content-Security-Policy")),
            "csp_report_only": bool(
                headers.get("Content-Security-Policy-Report-Only")
            ),
            "x_content_type_options": bool(
                headers.get("X-Content-Type-Options")
            ),
            "x_frame_options": bool(headers.get("X-Frame-Options")),
        })

    return results
