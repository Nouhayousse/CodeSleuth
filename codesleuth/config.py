"""
CodeSleuth - Configuration globale et seuils de détection.
Centralise toutes les constantes de configuration du pipeline d'analyse.
"""

# Seuils pour l'Analyst Agent (Code Smells)
FUNCTION_LENGTH_THRESHOLD = 50       # en lignes de code
FILE_LENGTH_THRESHOLD = 500          # en lignes de code
CYCLOMATIC_COMPLEXITY_THRESHOLD = 10  # seuil radon
TODO_THRESHOLD = 5                   # nombre max acceptable de TODO/FIXME
MIN_DOCUMENTATION_RATIO = 30.0       # pourcentage min de fonctions documentées

# Grille de Sévérité
SEVERITY_CRITICAL = "CRITIQUE"
SEVERITY_MAJOR = "MAJEUR"
SEVERITY_MINOR = "MINEUR"
