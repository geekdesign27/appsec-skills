#!/usr/bin/env python3
"""Crée l'arborescence standard security/ d'une mission AppSec (profil, section 6.11).

Usage :
  init_security.py <racine-du-depot-de-l-app> --app "<nom>" [--niveau-asvs 2]
  init_security.py <racine> --verifier        # liste ce qui manque, ne crée rien

Le script n'écrase jamais un fichier existant : il complète. Il ajoute une entrée au journal.
"""
import argparse
import datetime as dt
import os
import sys

MARQUEUR = "<!-- gabarit appsec : non rempli -->"
DOSSIERS = ["05-statique", "06-dynamique", "07-findings", "08-rapports", "09-mitigation",
            "10-retest", "10-retest/resultats"]

def gabarits(app, niveau, date):
    g = _gabarits(app, niveau, date)
    # Les .md portent un marqueur à retirer quand le livrable est rempli ; --verifier le détecte.
    return {k: (MARQUEUR + "\n" + v if k.endswith(".md") and k != "journal.md" else v) for k, v in g.items()}


def _gabarits(app, niveau, date):
    return {
        "00-cadrage.md": f"""# Cadrage et autorisation : {app}

- Date : {date}
- Niveau ASVS cible : L{niveau}
- Porte G1 : en attente

## 1. App, environnements, propriétaires, fournisseurs
| Élément | Valeur |
|---|---|
| App | {app} |
| Propriétaire (autorise les tests) | <à compléter> |
| Environnements | labo : <url locale> ; staging : <url ou aucun> ; prod : <url> |
| Fournisseurs | <Supabase, Vercel (plan : Hobby/Pro/Enterprise), ...> |

## 2. Classification des données (nLPD)
| Donnée | Classe (publique, interne, personnelle, sensible nLPD) | Où |
|---|---|---|

## 3. Règles d'engagement
- Périmètre inclus :
- Périmètre exclu :
- Environnements et niveau de risque autorisé par environnement :
- Fenêtres de test :
- Tests interdits :
- Contacts et arrêt d'urgence (qui, canal, critères) :
- Autorisation écrite : <référence du document ou message de PA, date>

## 4. Décision G1
<décision de PA, date>
""",
        "01-inventaire.md": f"# Reconnaissance et inventaire : {app}\n\n## Surface d'attaque\n\n## Bundle JS public\n\n## Rôles et tenants\n\n## Dépendances et outillage\n",
        "02-menaces.md": f"# Modélisation des menaces : {app}\n\n## DFD\n\n```mermaid\nflowchart LR\n```\n\n## STRIDE par flux\n\n## Cas d'abus\n\n## Cotation\n",
        "03-plan.md": f"# Plan de test : {app}\n\n- Porte G2 : en attente\n\n## Exigences ASVS L{niveau} retenues\n\n## Lots et ordre d'exécution\n\n## Charge estimée\n\n## Couverture attendue\n",
        "03-plan.yaml": "# Liste de cas de test au format partagé (references/partage/formats.md, section 1)\n[]\n",
        "04-labo.md": f"# Laboratoire : {app}\n\n## Lancer\n\n## Vérifier\n\n## Remettre à zéro\n\n## Arrêter\n\n## Limites par rapport à la production\n",
        "09-mitigation/mitigation-pack.yaml": "# Format : references/partage/formats.md, section 3\n",
        "09-mitigation/PROMPT-IA.md": "# Prompt pour l'IA de développement\n\n<généré par appsec-mitigation-retest>\n",
        "10-retest/retest-plan.yaml": "# Format : references/partage/formats.md, section 5\n[]\n",
        "journal.md": f"# Journal de mission : {app}\n\n| Date | Phase | Événement ou décision | Par |\n|---|---|---|---|\n",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("racine")
    p.add_argument("--app", default=None)
    p.add_argument("--niveau-asvs", type=int, choices=[1, 2, 3], default=2)
    p.add_argument("--verifier", action="store_true")
    a = p.parse_args()

    base = os.path.join(os.path.abspath(a.racine), "security")
    app = a.app or os.path.basename(os.path.abspath(a.racine))
    date = dt.date.today().isoformat()
    fichiers = gabarits(app, a.niveau_asvs, date)

    manquants = [d + "/" for d in DOSSIERS if not os.path.isdir(os.path.join(base, d))]
    manquants += [f for f in fichiers if not os.path.exists(os.path.join(base, f))]
    if a.verifier:
        non_remplis = [f for f in fichiers if f.endswith(".md") and os.path.exists(os.path.join(base, f))
                       and MARQUEUR in open(os.path.join(base, f), encoding="utf-8").read()]
        vides = [d + "/" for d in ("05-statique", "06-dynamique", "07-findings", "08-rapports")
                 if os.path.isdir(os.path.join(base, d)) and not [x for x in os.listdir(os.path.join(base, d)) if not x.startswith(".")]]
        print("Manquant : " + (", ".join(manquants) if manquants else "rien"))
        print("Gabarits non remplis : " + (", ".join(non_remplis) if non_remplis else "aucun"))
        print("Dossiers de résultats vides : " + (", ".join(vides) if vides else "aucun"))
        print("Rappel : comparer avec journal.md. Une phase notée faite au journal doit avoir son livrable rempli.")
        sys.exit(0 if not (manquants or non_remplis) else 1)

    for d in DOSSIERS:
        os.makedirs(os.path.join(base, d), exist_ok=True)
    crees = []
    for nom, contenu in fichiers.items():
        chemin = os.path.join(base, nom)
        if not os.path.exists(chemin):
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as f:
                f.write(contenu)
            crees.append(nom)
    with open(os.path.join(base, "journal.md"), "a", encoding="utf-8") as f:
        f.write(f"| {date} | 0 | Arborescence security/ initialisée ({len(crees)} fichiers créés), ASVS L{a.niveau_asvs} | appsec-chef-de-mission |\n")
    print(f"security/ prêt dans {base}")
    print("Créés : " + (", ".join(crees) if crees else "aucun (tout existait)"))


if __name__ == "__main__":
    main()
