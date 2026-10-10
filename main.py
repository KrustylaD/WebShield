"""Point d'entrée de WebShield V4."""
from urllib.parse import urlparse
import requests

from scanner import fetch_responses, scan_headers, scan_cookies, scan_redirects
from report import generate_html_report, calculate_coverage

def main():
    print("=" * 54)
    print("                 WEBSHIELD V4")
    print("   Vérification défensive des en-têtes HTTP")
    print("=" * 54)
    print("Utilise uniquement des sites que tu possèdes ou pour lesquels")
    print("tu as l'autorisation d'effectuer des vérifications.\n")

    url = input("URL du site à analyser : ").strip()
    if not url.startswith(("https://", "http://")):
        print("Erreur : l'URL doit commencer par https:// ou http://.")
        return
    parsed = urlparse(url)
    if not parsed.hostname or parsed.username or parsed.password:
        print("Erreur : URL invalide ou contenant des identifiants.")
        return

    try:
        final_response, responses = fetch_responses(url)
    except (requests.RequestException, ValueError) as error:
        print(f"\nImpossible d'analyser cette URL : {error}")
        return

    header_results = scan_headers(responses)
    cookie_results = scan_cookies(responses)
    redirect_results = scan_redirects(responses)
    score = calculate_coverage(header_results)

    print(f"\nURL finale : {final_response.url}")
    print(f"Code HTTP final : {final_response.status_code}")
    print(f"Nombre de réponses examinées : {len(responses)}")

    labels = {"CONFORME": "Conforme", "COUVERT_PAR_CSP": "Couvert par CSP",
              "NON_DETECTE": "Non détecté", "A_VERIFIER": "À vérifier"}
    print("\n--- EN-TÊTES DE SÉCURITÉ ---")
    for item in header_results:
        print(f"\n[{labels.get(item['status'], item['status'])}] {item['name']}")
        print(f"  Détail : {item['details']}")
        if item["status"] in ("NON_DETECTE", "A_VERIFIER"):
            print(f"  Recommandation : {item['recommendation']}")

    print("\n--- COOKIES ---")
    for item in cookie_results:
        print(f"\n{item['name']} : {labels.get(item['status'], item['status'])}")
        print(f"  Détail : {item['details']}")
        if item["status"] == "A_VERIFIER":
            print(f"  Recommandation : {item['recommendation']}")

    print("\n--- CHAÎNE DE REDIRECTIONS ---")
    for item in redirect_results:
        print(f"Étape {item['step']} | HTTP {item['status_code']} | HTTPS : {'oui' if item['https'] else 'non'}")
        print(f"  {item['url']}")
        print("  HSTS: {h} | CSP: {c} | CSP Report-Only: {ro} | MIME: {m} | X-Frame-Options: {f}".format(
            h="oui" if item["hsts"] else "non", c="oui" if item["csp"] else "non",
            ro="oui" if item["csp_report_only"] else "non",
            m="oui" if item["x_content_type_options"] else "non",
            f="oui" if item["x_frame_options"] else "non"))

    counts = {}
    for item in header_results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    print("\n--- RÉSUMÉ ---")
    print(f"Couverture indicative des en-têtes : {score}/100")
    print("Ce chiffre mesure la couverture des contrôles pondérés, pas le risque global.")
    print(f"Conformes / couverts : {counts.get('CONFORME', 0) + counts.get('COUVERT_PAR_CSP', 0)}")
    print(f"Non détectés : {counts.get('NON_DETECTE', 0)}")
    print(f"À vérifier : {counts.get('A_VERIFIER', 0)}")

    try:
        path = generate_html_report(url, final_response, header_results,
                                    cookie_results, redirect_results, score)
        print(f"\nRapport HTML créé : {path}")
        print("Ouvre ce fichier dans ton navigateur.")
    except OSError as error:
        print(f"\nErreur lors de la création du rapport : {error}")

if __name__ == "__main__":
    main()
