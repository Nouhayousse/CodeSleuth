"""
Script de test manuel : vérifie que les fonctions GitHub marchent
AVANT de les brancher sur ADK. Lancez ceci en premier.

Usage: python test_scanner_manual.py
"""

import os
from dotenv import load_dotenv
from github import Github, Auth

load_dotenv()

def main():
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("[ERROR] GITHUB_TOKEN manquant dans .env")
        return

    # PyGithub >= 2.1 : la méthode login_or_token=... est dépréciée,
    # il faut passer par un objet Auth explicite.
    gh = Github(auth=Auth.Token(token))

    # Test 1: connexion + rate limit
    # PyGithub >= 2.9 : get_rate_limit() retourne un RateLimitOverview,
    # le détail "core" est maintenant sous .resources.core (et non .core directement)
    rate = gh.get_rate_limit()
    print(f"[OK] Connexion OK. Rate limit restant : {rate.resources.core.remaining}/{rate.resources.core.limit}")

    # Test 2: scan d'un repo public connu (petit repo pour test rapide)
    test_owner = "Nouhayousse"
    test_repo = "learn_RAG"

    r = gh.get_repo(f"{test_owner}/{test_repo}")
    print(f"[OK] Repo trouve : {r.full_name}, langage principal : {r.language}, stars : {r.stargazers_count}")

    contents = r.get_contents("")
    print(f"[OK] Fichiers a la racine : {[c.path for c in contents]}")

    print("\n--- Test termine avec succes ---")
    print("Vous pouvez maintenant remplacer 'Nouhayousse/learn_RAG' par VOTRE repo TamTrack.")

if __name__ == "__main__":
    main()