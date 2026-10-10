
"""Calcul du score de couverture et génération du rapport HTML WebShield V5."""
from html import escape
from pathlib import Path

REPORT_FILE = "webshield_report.html"


def calculate_coverage(header_results):
    """Calcule la couverture pondérée, pas le risque global."""
    if not header_results:
        return 0

    accepted_statuses = {
        "CONFORME",
        "COUVERT_PAR_CSP",
        "A_VERIFIER",
        "NON_DETECTE",
    }

    total_weight = 0.0
    points = 0.0

    for item in header_results:
        status = item.get("status")
        weight = item.get("weight")

        if status not in accepted_statuses:
            raise ValueError(f"Statut inconnu : {status!r}")

        if (
            isinstance(weight, bool)
            or not isinstance(weight, (int, float))
            or weight < 0
        ):
            raise ValueError(f"Poids invalide : {weight!r}")

        total_weight += weight

        if status in ("CONFORME", "COUVERT_PAR_CSP"):
            points += weight
        elif status == "A_VERIFIER":
            points += weight * 0.5

    if total_weight <= 0:
        return 0

    return round(points / total_weight * 100)


def _safe(value):
    """Convertit une valeur en texte échappé pour HTML."""
    if value is None:
        value = "—"
    elif isinstance(value, bool):
        value = "Oui" if value else "Non"
    return escape(str(value))


def _status_label(status):
    labels = {
        "CONFORME": "Conforme",
        "COUVERT_PAR_CSP": "Couvert par CSP",
        "NON_DETECTE": "Non détecté",
        "A_VERIFIER": "À vérifier",
        "INFO": "Information",
        "ERREUR": "Erreur",
        "ABSENTE": "Absente",
        "FAIBLE": "Faible",
        "À_AMÉLIORER": "À améliorer",
        "CONFIGURATION_APPAREMMENT_SOLIDE": "Configuration apparemment solide",
    }
    return labels.get(status, str(status or "Inconnu"))


def _status_class(status):
    """Classe CSS fondée sur le statut, sans prétendre mesurer le risque global."""
    if status in ("CONFORME", "COUVERT_PAR_CSP",
                  "CONFIGURATION_APPAREMMENT_SOLIDE"):
        return "good"
    if status in ("NON_DETECTE", "ABSENTE", "FAIBLE"):
        return "issue"
    if status in ("A_VERIFIER", "À_AMÉLIORER", "ERREUR"):
        return "warning"
    return "neutral"


def _table_rows(items, columns, status_key=None):
    """Construit des lignes HTML en échappant chaque valeur affichée."""
    if not items:
        return (
            '<tr><td class="empty" colspan="'
            + str(len(columns))
            + '">Aucun résultat à afficher.</td></tr>'
        )

    rows = []

    for item in items:
        cells = []

        for key, label in columns:
            value = item.get(key, "")

            if key == status_key:
                css_class = _status_class(value)
                displayed = _safe(_status_label(value))
                cell = (
                    f'<td><span class="badge {css_class}">'
                    f'{displayed}</span></td>'
                )
            else:
                cell = f"<td>{_safe(value)}</td>"

            cells.append(cell)

        rows.append("<tr>" + "".join(cells) + "</tr>")

    return "\n".join(rows)


def _stat_card(number, label, css_class, description=""):
    return f"""
    <article class="stat-card {css_class}">
      <div class="stat-number">{_safe(number)}</div>
      <div class="stat-label">{_safe(label)}</div>
      <div class="stat-description">{_safe(description)}</div>
    </article>
    """


def generate_html_report(
    url,
    final_response,
    header_results,
    cookie_results,
    redirect_results,
    coverage_score,
):
    """Génère un rapport HTML autonome et lisible."""

    header_results = list(header_results or [])
    cookie_results = list(cookie_results or [])
    redirect_results = list(redirect_results or [])

    # Compter les statuts d'origine avant de les traduire.
    counts = {}
    for item in header_results:
        status = item.get("status", "INCONNU")
        counts[status] = counts.get(status, 0) + 1

    passed = (
        counts.get("CONFORME", 0)
        + counts.get("COUVERT_PAR_CSP", 0)
    )
    missing = counts.get("NON_DETECTE", 0)
    review = (
        counts.get("A_VERIFIER", 0)
        + counts.get("À_AMÉLIORER", 0)
    )
    other = len(header_results) - passed - missing - review

    # Préparer les lignes : toutes les données dynamiques sont échappées.
    header_rows = _table_rows(
        header_results,
        [
            ("name", "Contrôle"),
            ("status", "Résultat"),
            ("details", "Détails"),
            ("recommendation", "Recommandation"),
        ],
        status_key="status",
    )

    cookie_rows = _table_rows(
        cookie_results,
        [
            ("name", "Cookie"),
            ("status", "Résultat"),
            ("secure", "Secure"),
            ("httponly", "HttpOnly"),
            ("samesite", "SameSite"),
            ("details", "Détails"),
        ],
        status_key="status",
    )

    redirect_rows = _table_rows(
        redirect_results,
        [
            ("step", "Étape"),
            ("url", "URL"),
            ("status_code", "Code HTTP"),
            ("https", "HTTPS"),
            ("hsts", "HSTS"),
            ("csp", "CSP"),
            ("csp_report_only", "CSP Report-Only"),
            ("x_content_type_options", "Protection MIME"),
            ("x_frame_options", "Protection iframe"),
        ],
    )

    # Mettre en avant les contrôles à examiner, sans inventer de gravité.
    attention_items = [
        item for item in header_results
        if item.get("status") in (
            "NON_DETECTE", "A_VERIFIER", "À_AMÉLIORER", "ABSENTE", "FAIBLE"
        )
    ]

    if attention_items:
        attention_html = "".join(
            f"""
            <article class="finding">
              <div class="finding-top">
                <strong>{_safe(item.get("name", "Contrôle"))}</strong>
                <span class="badge {_status_class(item.get("status"))}">
                  {_safe(_status_label(item.get("status")))}
                </span>
              </div>
              <p>{_safe(item.get("details", "Aucun détail fourni."))}</p>
              <p class="recommendation">
                <strong>À envisager :</strong>
                {_safe(item.get("recommendation", "Examiner la configuration selon le besoin du site."))}
              </p>
            </article>
            """
            for item in attention_items
        )
    else:
        attention_html = """
        <div class="notice">
          Aucun contrôle avec un statut nécessitant une attention particulière
          n'a été signalé par le scanner. Cela ne garantit pas l'absence
de vulnérabilités et ne prouve pas l'absence de vulnérabilités.
        </div>
        """

    score = max(0, min(100, int(coverage_score)))
    if score >= 80:
        score_class = "score-good"
        score_label = "Couverture élevée"
    elif score >= 50:
        score_class = "score-medium"
        score_label = "Couverture intermédiaire"
    else:
        score_class = "score-low"
        score_label = "Couverture limitée"

    final_url = getattr(final_response, "url", "Non disponible")
    status_code = getattr(final_response, "status_code", "Inconnu")

    html_doc = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>WebShield V5 — Rapport de sécurité</title>
<style>
:root {{
  --bg: #0b1020;
  --panel: #131c30;
  --panel-soft: #18243a;
  --line: #293750;
  --text: #edf3ff;
  --muted: #9eafc9;
  --accent: #76a9ff;
  --good: #45d6a0;
  --warning: #f4c66a;
  --issue: #ff8585;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background:
    radial-gradient(ellipse at 10% 0%, #19284a 0, transparent 40%),
    var(--bg);
  color: var(--text);
  font: 15px/1.6 system-ui, -apple-system, Segoe UI, sans-serif;
}}
main {{ max-width: 1250px; margin: auto; padding: 34px 24px 50px; }}
h1, h2, h3, p {{ margin-top: 0; }}
h1 {{ font-size: clamp(27px, 4vw, 42px); margin-bottom: 4px; letter-spacing: -1px; }}
h2 {{ font-size: 21px; margin-bottom: 18px; }}
h3 {{ font-size: 16px; }}
p {{ overflow-wrap: anywhere; }}
a {{ color: var(--accent); }}
.muted, .subtitle {{ color: var(--muted); }}
.subtitle {{ margin-bottom: 26px; }}
.topline {{
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; flex-wrap: wrap; margin-bottom: 20px;
}}
.brand {{ display: flex; align-items: center; gap: 13px; }}
.brand-icon {{
  width: 46px; height: 46px; display: grid; place-items: center;
  border-radius: 14px; background: #20375c; color: #a9caff;
  font-weight: 900; font-size: 21px; border: 1px solid #36527e;
}}
.pill {{
  border: 1px solid var(--line); color: var(--muted);
  padding: 6px 11px; border-radius: 999px; font-size: 12px;
}}
.panel {{
  background: linear-gradient(145deg, #151f34, #11192b);
  border: 1px solid var(--line); border-radius: 18px;
  padding: 24px; margin: 20px 0;
  box-shadow: 0 10px 30px #00000012;
}}
.summary-grid {{
  display: grid; grid-template-columns: minmax(250px, 0.9fr) minmax(0, 1.5fr);
  gap: 24px; align-items: center;
}}
.score-area {{ display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }}
.gauge {{
  --score: {score};
  width: 142px; height: 142px; border-radius: 50%;
  display: grid; place-items: center; flex-shrink: 0;
  background: conic-gradient(var(--accent) calc(var(--score) * 1%), #29364d 0);
  position: relative;
}}
.gauge::before {{
  content: ""; position: absolute; inset: 10px;
  border-radius: 50%; background: var(--panel);
}}
.gauge-inner {{ position: relative; text-align: center; }}
.score-number {{ font-size: 32px; font-weight: 800; line-height: 1.2; }}
.score-denom {{ font-size: 12px; color: var(--muted); }}
.score-good {{ color: var(--good); }}
.score-medium {{ color: var(--warning); }}
.score-low {{ color: var(--issue); }}
.score-caption {{ font-weight: 700; margin-top: 7px; }}
.meta-list {{ display: grid; gap: 11px; }}
.meta-item {{
  padding: 12px 14px; background: #0d1526;
  border: 1px solid var(--line); border-radius: 10px;
}}
.meta-label {{ display: block; color: var(--muted); font-size: 12px; margin-bottom: 3px; }}
.meta-value {{ font-weight: 600; overflow-wrap: anywhere; }}
.stats {{
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px; margin-top: 24px;
}}
.stat-card {{
  border: 1px solid var(--line); background: #10192b;
  padding: 16px; border-radius: 13px; min-width: 0;
}}
.stat-number {{ font-size: 28px; font-weight: 800; }}
.stat-label {{ font-weight: 650; }}
.stat-description {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
.stat-card.good .stat-number {{ color: var(--good); }}
.stat-card.issue .stat-number {{ color: var(--issue); }}
.stat-card.warning .stat-number {{ color: var(--warning); }}
.stat-card.neutral .stat-number {{ color: var(--accent); }}
.notice {{
  background: #14283a; border: 1px solid #2e536d;
  border-radius: 12px; padding: 15px;
}}
.finding {{
  background: #10192b; border: 1px solid var(--line);
  border-radius: 12px; padding: 16px; margin: 12px 0;
}}
.finding-top {{
  display: flex; justify-content: space-between; gap: 12px;
  align-items: center; flex-wrap: wrap; margin-bottom: 10px;
}}
.finding p {{ margin-bottom: 8px; }}
.finding p:last-child {{ margin-bottom: 0; }}
.recommendation {{ color: #cbd7eb; }}
.badge {{
  display: inline-flex; padding: 4px 9px; border-radius: 999px;
  font-size: 12px; line-height: 1.5; font-weight: 700;
  border: 1px solid transparent; white-space: normal;
}}
.badge.good {{ background: #153a32; color: #7be5bb; border-color: #28614e; }}
.badge.warning {{ background: #40341e; color: #ffdc8b; border-color: #68532b; }}
.badge.issue {{ background: #40252d; color: #ffaaaa; border-color: #6d3943; }}
.badge.neutral {{ background: #202d45; color: #c1d3f3; border-color: #34496b; }}
.table-wrap {{ overflow-x: auto; border: 1px solid var(--line); border-radius: 12px; }}
table {{ width: 100%; min-width: 760px; border-collapse: collapse; }}
th, td {{
  text-align: left; vertical-align: top; padding: 13px 14px;
  border-bottom: 1px solid var(--line); overflow-wrap: anywhere;
}}
th {{ background: #1a2740; color: #c7d9f7; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
td {{ color: #dbe5f5; }}
tbody tr:hover {{ background: #ffffff06; }}
tbody tr:last-child td {{ border-bottom: 0; }}
.empty {{ text-align: center; color: var(--muted); padding: 25px; }}
.section-heading {{
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; flex-wrap: wrap;
}}
.section-count {{ color: var(--muted); font-size: 13px; }}
.disclaimer {{
  color: var(--muted); background: #0d1526;
  padding: 14px; border-radius: 10px; font-size: 13px; margin-bottom: 0;
}}
footer {{ color: var(--muted); font-size: 12px; text-align: center; padding: 22px 0; }}
@media (max-width: 800px) {{
  main {{ padding: 22px 14px 35px; }}
  .summary-grid {{ grid-template-columns: 1fr; }}
  .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  .panel {{ padding: 17px; }}
}}
@media (max-width: 420px) {{
  .gauge {{ width: 118px; height: 118px; }}
  .score-number {{ font-size: 27px; }}
  .stat-number {{ font-size: 24px; }}
}}
@media print {{
  :root {{ --bg: white; --panel: white; --panel-soft: white; --line: #ddd; --text: #111; --muted: #555; }}
  body {{ background: white; color: #111; }}
  main {{ max-width: none; padding: 0; }}
  .panel, .stat-card, .meta-item, .finding {{ box-shadow: none; break-inside: avoid; background: white; }}
  th {{ background: #eee; color: #111; }}
  td {{ color: #111; }}
}}
</style>
</head>
<body>
<main>
  <header class="topline">
    <div class="brand">
      <div class="brand-icon">W</div>
      <div>
        <h1>WebShield <span style="color:var(--accent)">V5</span></h1>
        <div class="muted">Tableau de bord de vérification HTTP</div>
      </div>
    </div>
    <span class="pill">Rapport généré localement</span>
  </header>

  <p class="subtitle">
    Analyse défensive des en-têtes HTTP, des cookies et de la chaîne de redirections.
  </p>

  <section class="panel">
    <h2>Vue d'ensemble</h2>
    <div class="summary-grid">
      <div class="score-area">
        <div class="gauge" role="img"
             aria-label="Couverture indicative : {score} sur 100">
          <div class="gauge-inner">
            <div class="score-number">{score}/100</div>
          </div>
        </div>
        <div>
          <div class="score-caption {score_class}">{_safe(score_label)}</div>
          <div class="muted">Couverture indicative des contrôles</div>
        </div>
      </div>

      <div class="meta-list">
        <div class="meta-item">
          <span class="meta-label">URL demandée</span>
          <div class="meta-value">{_safe(url)}</div>
        </div>
        <div class="meta-item">
          <span class="meta-label">URL finale</span>
          <div class="meta-value">{_safe(final_url)}</div>
        </div>
        <div class="meta-item">
          <span class="meta-label">Code HTTP final</span>
          <div class="meta-value">{_safe(status_code)}</div>
        </div>
      </div>
    </div>

    <div class="stats">
      {_stat_card(passed, "Conformes / couverts", "good", "Contrôles validés par le scanner")}
      {_stat_card(missing, "Non détectés", "issue", "Éléments absents ou non détectés")}
      {_stat_card(review, "À examiner", "warning", "Contrôles nécessitant une vérification")}
      {_stat_card(len(header_results), "Contrôles analysés", "neutral", f"{other} autre(s) résultat(s)")}
    </div>

    <p class="disclaimer" style="margin-top:20px">
      <strong>Important :</strong> ce score pondéré décrit uniquement la couverture
      des contrôles configurés. Il ne représente ni le risque global du site ni
      une certification de sécurité. Une absence d'en-tête n'est pas toujours
      une vulnérabilité ; les recommandations doivent être adaptées au site.
    </p>
  </section>

  <section class="panel">
    <div class="section-heading">
      <h2>Points à examiner</h2>
      <span class="section-count">{len(attention_items)} contrôle(s)</span>
    </div>
    {attention_html}
  </section>

  <section class="panel">
    <div class="section-heading">
      <h2>En-têtes de sécurité</h2>
      <span class="section-count">{len(header_results)} résultat(s)</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Contrôle</th><th>Résultat</th><th>Détails</th><th>Recommandation</th>
        </tr></thead>
        <tbody>{header_rows}</tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <div class="section-heading">
      <h2>Analyse des cookies</h2>
      <span class="section-count">{len(cookie_results)} cookie(s)</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Cookie</th><th>Résultat</th><th>Secure</th>
          <th>HttpOnly</th><th>SameSite</th><th>Détails</th>
        </tr></thead>
        <tbody>{cookie_rows}</tbody>
      </table>
    </div>
    <p class="disclaimer" style="margin-top:14px">
      Les valeurs des cookies ne sont pas affichées. Les attributs attendus
      dépendent notamment du rôle du cookie et de la façon dont le site l'utilise.
    </p>
  </section>

  <section class="panel">
    <div class="section-heading">
      <h2>Chaîne de redirections</h2>
      <span class="section-count">{len(redirect_results)} étape(s)</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Étape</th><th>URL</th><th>Code HTTP</th><th>HTTPS</th>
          <th>HSTS</th><th>CSP</th><th>CSP Report-Only</th>
          <th>Protection MIME</th><th>Protection iframe</th>
        </tr></thead>
        <tbody>{redirect_rows}</tbody>
      </table>
    </div>
    <p class="disclaimer" style="margin-top:14px">
      Les réponses intermédiaires apportent du contexte. L'absence d'un en-tête
      sur une étape ne suffit pas, à elle seule, à démontrer un défaut exploitable.
    </p>
  </section>

  <footer>
    WebShield V5 · Rapport HTML autonome · À utiliser uniquement sur des sites
    que tu possèdes ou pour lesquels tu as une autorisation.
  </footer>
</main>
</body>
</html>
"""

    Path(REPORT_FILE).write_text(html_doc, encoding="utf-8")
    return REPORT_FILE
