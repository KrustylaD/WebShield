# WebShield V5

WebShield est un outil pédagogique Python qui effectue une requête HTTP
contrôlée vers une URL autorisée, puis analyse les en-têtes de sécurité, les
attributs des cookies et la chaîne de redirections.

> **Utilisation autorisée uniquement :** teste tes propres sites ou des sites
> pour lesquels tu disposes d'une autorisation. WebShield n'est ni un scanner
> exhaustif ni un audit de sécurité professionnel.

## Fonctionnalités

- Contrôle indicatif de six protections HTTP :
  - HSTS (`Strict-Transport-Security`) ;
  - Content Security Policy (`Content-Security-Policy`) ;
  - protection MIME (`X-Content-Type-Options`) ;
  - protection contre le clickjacking (`X-Frame-Options`) ;
  - `Referrer-Policy` ;
  - `Permissions-Policy`.
- Analyse heuristique de la CSP : directives, valeurs, sources trop
  permissives, directives manquantes et CSP Report-Only.
- Prise en compte de `frame-ancestors` lorsqu'il couvre
  `X-Frame-Options`.
- Vérification des attributs `Secure`, `HttpOnly` et `SameSite` des cookies.
- Résumé des en-têtes clés à chaque étape de redirection.
- Score pondéré de couverture des contrôles.
- Génération d'un rapport HTML et d'un rapport JSON pour chaque scan.
- Conservation des rapports précédents grâce à un nom de fichier horodaté.

## Prérequis

- Python 3.10 ou version ultérieure ;
- `pip` ;
- une connexion réseau vers le site autorisé à analyser.

La dépendance principale est `requests`.

## Installation sous Windows

Dans le terminal de VS Code, depuis le dossier du projet :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Si l'environnement virtuel existe déjà, active-le simplement :

```powershell
.\.venv\Scripts\Activate.ps1
```

## Lancement

```powershell
python main.py
```

Saisis ensuite une URL complète, par exemple :

```text
https://example.com
```

Après l'analyse, les deux rapports sont enregistrés dans `reports/` avec le
même identifiant :

```text
reports/
├── webshield_20261010_151500_123456.html
└── webshield_20261010_151500_123456.json
```

Le nom contient la date, l'heure et les microsecondes afin de réduire le
risque de collision entre deux scans rapides.

## Rapports

### Rapport HTML

Le rapport HTML est autonome et peut être ouvert directement dans un
navigateur. Il présente :

- l'URL demandée et l'URL finale ;
- le statut HTTP final ;
- le score de couverture ;
- les résultats détaillés des en-têtes ;
- les cookies et leurs attributs, sans afficher leurs valeurs ;
- la chaîne de redirections.

### Rapport JSON

Le rapport JSON contient les mêmes résultats sous une forme exploitable par
un autre programme :

- `tool` ;
- `url_requested` et `url_final` ;
- `http_status` ;
- `responses_examined` ;
- `coverage_score` ;
- le résumé des statuts ;
- `headers`, `cookies` et `redirects`.

Les valeurs sensibles des cookies (`value`, `cookie_value`, `raw_value` et
`set_cookie`) sont exclues de l'export JSON.

## Comprendre le score

Le score est une mesure indicative de la couverture des six contrôles
configurés. Il ne représente pas le risque global du site.

| Statut | Contribution |
| --- | ---: |
| `CONFORME` | 100 % du poids |
| `COUVERT_PAR_CSP` | 100 % du poids |
| `CONFIGURATION_APPAREMMENT_SOLIDE` | 100 % du poids |
| `A_VERIFIER` | 50 % du poids |
| `À_AMÉLIORER` | 50 % du poids |
| `NON_DETECTE` | 0 % du poids |
| `ABSENTE` | 0 % du poids |
| `FAIBLE` | 0 % du poids |

Une absence d'en-tête n'est pas toujours une vulnérabilité. Les résultats
doivent être interprétés selon le contexte du site.

## Tests

Pour exécuter toute la suite de tests :

```powershell
python -m unittest discover -v
```

Les tests couvrent notamment le calcul du score, l'analyse des en-têtes,
l'échappement HTML, les rapports JSON et la fermeture des réponses HTTP.

## Fichiers principaux

- `main.py` : interface console et orchestration d'un scan.
- `scanner.py` : requêtes HTTP, validation des redirections, analyse des
  en-têtes, cookies et redirections.
- `report.py` : calcul du score et génération du rapport HTML.
- `test_headers.py` : tests des contrôles d'en-têtes.
- `test_integration.py` : tests d'intégration sur un serveur local.
- `test_report.py` : tests du score et des rapports HTML/JSON.
- `test_webshield.py` : tests des redirections et du nettoyage des réponses.
- `requirements.txt` : dépendances Python.
- `reports/` : rapports générés localement après un scan.

## Limites et sécurité

- L'analyse HTTP est passive et ne teste pas le comportement réel d'un
  navigateur.
- WebShield ne recherche pas les failles applicatives, les erreurs
  d'autorisation, les problèmes métier ou les vulnérabilités de dépendances.
- L'analyse des cookies reste simple ; les attributs nécessaires dépendent du
  rôle de chaque cookie.
- L'analyse CSP est heuristique et ne valide pas complètement la qualité ou la
  compatibilité d'une politique.
- Les redirections sont contrôlées et résumées, mais leur sûreté n'est pas
  garantie par le seul rapport.
- La validation d'URL ne constitue pas une protection SSRF complète. Ne
  déploie pas cet outil comme service public permettant à des tiers de
  soumettre des URL.
- Des faux positifs et faux négatifs sont possibles.

## Structure

```text
WebShield/
├── main.py
├── scanner.py
├── report.py
├── test_headers.py
├── test_integration.py
├── test_report.py
├── test_webshield.py
├── requirements.txt
├── README.md
└── reports/
```

## Licence

Projet pédagogique.
