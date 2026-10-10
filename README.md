# WebShield V4

WebShield est un outil pédagogique Python qui envoie une requête HTTP GET vers une URL et examine certains en-têtes de sécurité, les attributs de cookies présents dans les réponses et la chaîne de redirections.

> **Utilisation autorisée uniquement :** teste tes propres sites ou des sites pour lesquels tu as une autorisation. WebShield n'est pas un scanner exhaustif ni un audit professionnel.

## Fonctionnalités

- Contrôle indicatif de HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy et Permissions-Policy.
- Vérification de base de quelques valeurs, notamment HSTS `max-age` et `nosniff`.
- Distinction de CSP appliquée et CSP Report-Only pour le contrôle `frame-ancestors`.
- Inspection des attributs `Secure`, `HttpOnly` et `SameSite` des en-têtes `Set-Cookie`.
- Résumé des en-têtes clés à chaque étape de redirection.
- Rapport HTML local.
- Score pondéré de couverture des contrôles, qui ne constitue pas un score de risque global.

## Prérequis

Python 3.10+ conseillé, `pip` et une connexion réseau vers le site autorisé.

## Installation sous Windows

Dans le terminal de VS Code, dans le dossier du projet :

```powershell
python -m pip install -r requirements.txt
```

## Lancement

```powershell
python main.py
```

Saisis ensuite une URL, par exemple `https://example.com`. Le programme affiche les résultats et génère `webshield_report.html` dans le dossier courant. Chaque exécution remplace ce rapport.

## Fichiers

- `main.py` : lancement et affichage console.
- `scanner.py` : requêtes HTTP, en-têtes, cookies et redirections.
- `report.py` : calcul du score de couverture et création du rapport.
- `requirements.txt` : dépendance Python.
- `webshield_report.html` : rapport généré ; le fichier fourni est un modèle en attente de la première exécution.

## Comprendre le score

Le score de couverture porte uniquement sur les six contrôles configurés, avec une pondération pédagogique. Les statuts `CONFORME` et `COUVERT_PAR_CSP` obtiennent tous les points, `A_VERIFIER` la moitié et `NON_DETECTE` zéro. Ce chiffre ne représente pas la probabilité d'une attaque ni la sécurité totale du site. Une absence d'en-tête n'est pas toujours une vulnérabilité.

## Limites

- Analyse HTTP passive limitée ; aucun test du comportement réel du navigateur.
- Ne recherche pas les failles applicatives, les erreurs d'autorisation, les problèmes métier ou les vulnérabilités de dépendances.
- L'analyse des cookies est simple et les attributs nécessaires dépendent de leur rôle.
- Les redirections sont résumées, mais leur sûreté n'est pas garantie.
- La validation d'URL n'est pas une protection SSRF complète : ne déploie pas cet outil comme service public permettant à des tiers de soumettre des URL.
- Des faux positifs et faux négatifs sont possibles.

## Structure

```text
WebShield/
├── main.py
├── scanner.py
├── report.py
├── requirements.txt
├── README.md
└── webshield_report.html
```

## Licence

Projet pédagogique. Ajoute une licence explicite si tu souhaites définir les conditions de réutilisation.
