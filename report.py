"""Calcul du score de couverture et génération du rapport HTML."""
from html import escape
from pathlib import Path

REPORT_FILE = "webshield_report.html"

def calculate_coverage(header_results):
    """Score pondéré de couverture des contrôles, pas score de risque global."""
    total_weight = sum(item["weight"] for item in header_results)
    if total_weight <= 0:
        return 0
    points = 0.0
    for item in header_results:
        if item["status"] in ("CONFORME", "COUVERT_PAR_CSP"):
            points += item["weight"]
        elif item["status"] == "A_VERIFIER":
            points += item["weight"] * 0.5
    return round(points / total_weight * 100)

def _rows(items, keys):
    rows = []
    for item in items:
        cells = []
        for key in keys:
            value = item.get(key, "")
            if isinstance(value, bool):
                value = "Oui" if value else "Non"
            cells.append("<td>" + escape(str(value)) + "</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return "\n".join(rows)

def generate_html_report(url, final_response, header_results, cookie_results,
                         redirect_results, coverage_score):
    labels = {"CONFORME": "Conforme", "COUVERT_PAR_CSP": "Couvert par CSP",
              "NON_DETECTE": "Non détecté", "A_VERIFIER": "À vérifier",
              "INFO": "Information", "ERREUR": "Erreur"}
    headers = []
    for item in header_results:
        copy = dict(item)
        copy["status"] = labels.get(copy["status"], copy["status"])
        headers.append(copy)
    cookies = []
    for item in cookie_results:
        copy = dict(item)
        copy["status"] = labels.get(copy["status"], copy["status"])
        cookies.append(copy)

    header_rows = _rows(headers, ["name", "status", "details", "recommendation"])
    cookie_rows = _rows(cookies, ["name", "status", "secure", "httponly", "samesite", "details"])
    redirect_rows = _rows(redirect_results, [
        "step", "url", "status_code", "https", "hsts", "csp", "csp_report_only",
        "x_content_type_options", "x_frame_options"
    ])

    counts = {}
    for item in header_results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    passed = counts.get("CONFORME", 0) + counts.get("COUVERT_PAR_CSP", 0)
    missing = counts.get("NON_DETECTE", 0)
    review = counts.get("A_VERIFIER", 0)

    html_doc = f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebShield V4 — Rapport</title>
<style>
:root{{--bg:#0d1020;--panel:#171c30;--line:#303956;--text:#eef2ff;--muted:#b7c0d9;--accent:#a5b4fc}}
*{{box-sizing:border-box}} body{{margin:0;padding:28px;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}}
main{{max-width:1200px;margin:auto}} h1,h2{{color:var(--accent)}}
.panel{{margin:20px 0;padding:22px;border:1px solid var(--line);border-radius:14px;background:var(--panel)}}
.muted{{color:var(--muted)}} .score{{font-size:44px;font-weight:750;margin:4px 0}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
.stat{{padding:14px;border:1px solid var(--line);border-radius:10px}}
.table-wrap{{overflow-x:auto}} table{{width:100%;min-width:760px;border-collapse:collapse}}
th,td{{padding:12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;overflow-wrap:anywhere}}
th{{color:var(--accent)}} footer{{color:var(--muted);margin:24px 0}}
@media(max-width:600px){{body{{padding:14px}}.panel{{padding:15px}}}}
</style></head><body><main>
<h1>WebShield V4</h1><p class="muted">Rapport local de vérification défensive des en-têtes HTTP.</p>
<section class="panel"><h2>Résumé</h2>
<p><strong>URL demandée :</strong> {escape(url)}</p>
<p><strong>URL finale :</strong> {escape(final_response.url)}</p>
<p><strong>Code HTTP final :</strong> {final_response.status_code}</p>
<div class="score">{coverage_score}/100</div><strong>Couverture indicative des contrôles configurés</strong>
<div class="stats">
<div class="stat"><strong>{passed}</strong><br>Conformes / couverts</div>
<div class="stat"><strong>{missing}</strong><br>Non détectés</div>
<div class="stat"><strong>{review}</strong><br>À vérifier</div></div>
<p class="muted">Ce score pondéré décrit uniquement la couverture des contrôles listés.
Il ne mesure pas le risque global, ne prouve pas l'absence de vulnérabilités et ne
remplace pas un audit. Une absence d'en-tête n'est pas toujours une vulnérabilité.</p>
</section>
<section class="panel"><h2>1. En-têtes de sécurité</h2><div class="table-wrap"><table>
<thead><tr><th>Contrôle</th><th>Résultat</th><th>Détail</th><th>Recommandation</th></tr></thead>
<tbody>{header_rows}</tbody></table></div></section>
<section class="panel"><h2>2. Cookies</h2><div class="table-wrap"><table>
<thead><tr><th>Cookie</th><th>Résultat</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Détail</th></tr></thead>
<tbody>{cookie_rows}</tbody></table></div>
<p class="muted">Les valeurs des cookies ne sont pas incluses. Les besoins dépendent du rôle de chaque cookie.</p></section>
<section class="panel"><h2>3. Chaîne de redirections</h2><div class="table-wrap"><table>
<thead><tr><th>Étape</th><th>URL</th><th>HTTP</th><th>HTTPS</th><th>HSTS</th><th>CSP appliquée</th><th>CSP Report-Only</th><th>MIME</th><th>X-Frame-Options</th></tr></thead>
<tbody>{redirect_rows}</tbody></table></div>
<p class="muted">Les en-têtes des réponses intermédiaires sont informatifs. Leur absence ne prouve pas un défaut exploitable.</p></section>
<footer>Généré localement par WebShield V4. À utiliser uniquement sur des sites que tu possèdes ou pour lesquels tu as une autorisation.</footer>
</main></body></html>"""
    Path(REPORT_FILE).write_text(html_doc, encoding="utf-8")
    return REPORT_FILE
