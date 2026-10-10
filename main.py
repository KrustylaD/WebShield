
from html import escape
from urllib.parse import urlparse
from pathlib import Path

from scanner import (
    fetch_responses,
    scan_headers,
    scan_cookies,
    scan_redirects,
)


REPORT_FILE = "webshield_report.html"


def calculate_score(results):
    """Calcule un score pédagogique sur 100."""
    total_weight = sum(result["weight"] for result in results)

    if total_weight == 0:
        return 0

    points = 0

    for result in results:
        if result["status"] in ("PRESENT", "COUVERT_PAR_CSP"):
            points += result["weight"]
        elif result["status"] == "A_VERIFIER":
            points += result["weight"] * 0.5

    return round(points / total_weight * 100)


def risk_level(score):
    if score >= 85:
        return "FAIBLE"
    if score >= 65:
        return "MODÉRÉ"
    if score >= 40:
        return "ÉLEVÉ"
    return "IMPORTANT"


def status_label(status):
    labels = {
        "PRESENT": "Présent",
        "ABSENT": "Absent",
        "A_VERIFIER": "À vérifier",
        "COUVERT_PAR_CSP": "Couvert par la CSP",
        "INFO": "Information",
        "ERREUR": "Erreur",
    }
    return labels.get(status, status)


def generate_html_report(
    url,
    final_response,
    header_results,
    cookie_results,
    redirect_results,
    score,
):
    """Génère un rapport HTML autonome."""
    risk = risk_level(score)

    header_rows = ""

    for item in header_results:
        header_rows += f"""
        <tr>
            <td>{escape(item['name'])}</td>
            <td>{escape(status_label(item['status']))}</td>
            <td>{escape(item['details'])}</td>
            <td>{escape(item['recommendation'])}</td>
        </tr>
        """

    cookie_rows = ""

    for item in cookie_results:
        cookie_rows += f"""
        <tr>
            <td>{escape(item['name'])}</td>
            <td>{escape(status_label(item['status']))}</td>
            <td>{escape(str(item['secure']))}</td>
            <td>{escape(str(item['httponly']))}</td>
            <td>{escape(item['samesite'])}</td>
            <td>{escape(item['details'])}</td>
        </tr>
        """

    redirect_rows = ""

    for item in redirect_results:
        redirect_rows += f"""
        <tr>
            <td>{item['step']}</td>
            <td>{escape(item['url'])}</td>
            <td>{item['status_code']}</td>
            <td>{"Oui" if item['https'] else "Non"}</td>
            <td>{"Oui" if item['hsts'] else "Non"}</td>
            <td>{"Oui" if item['csp'] else "Non"}</td>
            <td>{"Oui" if item['x_content_type_options'] else "Non"}</td>
            <td>{"Oui" if item['x_frame_options'] else "Non"}</td>
        </tr>
        """

    html_document = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport WebShield</title>
<style>
    body {{
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 30px;
        background: #101322;
        color: #f3f4f6;
    }}
    main {{ max-width: 1200px; margin: auto; }}
    h1, h2 {{ color: #a5b4fc; }}
    .card {{
        background: #1b2034;
        border: 1px solid #343b58;
        border-radius: 12px;
        padding: 20px;
        margin: 20px 0;
    }}
    .score {{ font-size: 42px; font-weight: bold; }}
    .risk {{ font-weight: bold; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; min-width: 650px; }}
    th, td {{
        border-bottom: 1px solid #343b58;
        text-align: left;
        padding: 12px;
        vertical-align: top;
        overflow-wrap: anywhere;
    }}
    th {{ color: #c7d2fe; }}
    .notice {{ color: #d1d5db; line-height: 1.6; }}
</style>
</head>
<body>
<main>
    <h1>WebShield — Rapport de sécurité</h1>

    <div class="card">
        <p><strong>URL analysée :</strong> {escape(url)}</p>
        <p><strong>URL finale :</strong> {escape(final_response.url)}</p>
        <p><strong>Code HTTP final :</strong> {final_response.status_code}</p>
        <p class="score">{score}/100</p>
        <p class="risk">Niveau de risque indicatif : {escape(risk)}</p>
        <p class="notice">
            Ce score évalue uniquement les contrôles implémentés par WebShield.
            Il ne représente pas une note globale de sécurité du site.
        </p>
    </div>

    <div class="card">
        <h2>1. En-têtes de sécurité</h2>
        <div class="table-wrap">
        <table>
            <thead><tr>
                <th>Contrôle</th><th>Résultat</th>
                <th>Détail</th><th>Recommandation</th>
            </tr></thead>
            <tbody>{header_rows}</tbody>
        </table>
        </div>
    </div>

    <div class="card">
        <h2>2. Cookies</h2>
        <div class="table-wrap">
        <table>
            <thead><tr>
                <th>Nom</th><th>Résultat</th><th>Secure</th>
                <th>HttpOnly</th><th>SameSite</th><th>Détail</th>
            </tr></thead>
            <tbody>{cookie_rows}</tbody>
        </table>
        </div>
        <p class="notice">
            Les valeurs des cookies ne sont pas incluses dans ce rapport.
        </p>
    </div>

    <div class="card">
        <h2>3. Chaîne de redirections</h2>
        <div class="table-wrap">
        <table>
            <thead><tr>
                <th>Étape</th><th>URL</th><th>HTTP</th><th>HTTPS</th>
                <th>HSTS</th><th>CSP</th><th>Protection MIME</th>
                <th>Anti-clicjacking</th>
            </tr></thead>
            <tbody>{redirect_rows}</tbody>
        </table>
        </div>
        <p class="notice">
            La comparaison montre quels en-têtes sont présents à chaque étape.
            Leur absence sur une redirection intermédiaire n'est pas toujours
            une vulnérabilité : la réponse finale et le comportement du site
            doivent aussi être examinés.
        </p>
    </div>

    <p class="notice">
        Rapport généré localement par WebShield. Une analyse automatique
        peut produire des faux positifs et ne remplace pas un audit complet.
    </p>
</main>
</body>
</html>
"""

    Path(REPORT_FILE).write_text(html_document, encoding="utf-8")
    return REPORT_FILE


def main():
    print("=" * 48)
    print("          WEBSHIELD V3")
    print("  Analyse des en-têtes, cookies et redirections")
    print("=" * 48)

    url = input("\nURL du site à analyser : ").strip()

    if not url.startswith(("https://", "http://")):
        print("Erreur : l'URL doit commencer par https:// ou http://.")
        return

    parsed_url = urlparse(url)

    if not parsed_url.hostname:
        print("Erreur : nom de domaine invalide.")
        return

    try:
        final_response, responses = fetch_responses(url)
    except Exception as error:
        # Le message aide au diagnostic, sans afficher de trace complète.
        print(f"\nImpossible d'analyser ce site : {error}")
        return

    header_results = scan_headers(url, responses)
    cookie_results = scan_cookies(responses)
    redirect_results = scan_redirects(responses)
    score = calculate_score(header_results)

    print(f"\nURL finale : {final_response.url}")
    print(f"Code HTTP : {final_response.status_code}")

    print("\n--- EN-TÊTES DE SÉCURITÉ ---")

    for item in header_results:
        print(f"\n[{status_label(item['status'])}] {item['name']}")
        print(f"  Détail : {item['details']}")

        if item["status"] in ("ABSENT", "A_VERIFIER"):
            print(f"  Conseil : {item['recommendation']}")

    print("\n--- COOKIES ---")

    for item in cookie_results:
        print(f"\n{item['name']} : {status_label(item['status'])}")
        print(f"  Détail : {item['details']}")

        if item["status"] == "A_VERIFIER":
            print(f"  Conseil : {item['recommendation']}")

    print("\n--- REDIRECTIONS ---")

    for item in redirect_results:
        print(
            f"Étape {item['step']} : HTTP {item['status_code']} "
            f"| HTTPS : {'oui' if item['https'] else 'non'}"
        )
        print(f"  {item['url']}")

    print("\n--- SCORE INDICATIF ---")
    print(f"Score : {score}/100")
    print(f"Niveau de risque indicatif : {risk_level(score)}")

    try:
        report_path = generate_html_report(
            url,
            final_response,
            header_results,
            cookie_results,
            redirect_results,
            score,
        )
        print(f"\nRapport HTML créé : {report_path}")
        print("Ouvre ce fichier dans ton navigateur pour consulter le rapport.")
    except OSError as error:
        print(f"\nImpossible d'enregistrer le rapport : {error}")


if __name__ == "__main__":
    main()
