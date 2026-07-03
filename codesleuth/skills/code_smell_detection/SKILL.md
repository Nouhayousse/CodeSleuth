# Skill: Code Smell Detection

## Quand utiliser cette skill
Quand un agent doit évaluer la qualité et la maintenabilité d'un fichier de code source Python, dans le cadre d'un audit de dette technique.

## Heuristiques appliquées

| Heuristique | Seuil | Outil |
|---|---|---|
| Fonction trop longue | > 50 lignes | `detect_long_functions` |
| Complexité cyclomatique | > 10 | `analyze_complexity` (radon) |
| TODO/FIXME accumulés | > 5 par fichier | `count_todos_and_fixmes` |
| Ratio de documentation | < 30% de fonctions documentées | `check_documentation_ratio` |
| Duplication entre fichiers | > 80% de lignes communes | `detect_code_duplication_simple` |

## Grille de sévérité

- **CRITIQUE** : absence totale de tests sur le repo (signalé par le Scanner Agent en amont)
- **MAJEUR** : complexité cyclomatique > 15, OU duplication > 80%, OU fonction > 100 lignes
- **MINEUR** : tout le reste (TODO accumulés, documentation faible, fonctions modérément longues)

## Limites connues (à assumer honnêtement dans le rapport)
- La détection de duplication est simple (comparaison de lignes normalisées), pas une analyse AST structurelle — elle peut avoir des faux positifs sur du code court avec des patterns communs (imports, boilerplate)
- L'analyse de complexité et de documentation est spécifique à Python ; pour d'autres langages, seules les heuristiques génériques (longueur de fichier, TODO) s'appliquent

## Sortie attendue
Une liste structurée d'objets `{fichier, type_smell, sévérité, ligne, valeur_mesurée}`, que le Reporter Agent utilisera ensuite pour prioriser le rapport final.