#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          PROTOCOLE ECHO-2026 v5-SHADOW — « SONDE ONTOLOGIQUE »               ║
║          Analyse passive de cache Shodan InternetDB (SQLite)                 ║
║                                                                              ║
║  "Nous n'interrogeons pas la cible. Nous interrogeons son souvenir.          ║
║   Puis nous demandons au souvenir s'il est cohérent avec lui-même."          ║
╚══════════════════════════════════════════════════════════════════════════════╝

ZÉRO TRAFIC vers les cibles. La base SQLite est ouverte en LECTURE SEULE.

TROIS INDICES, TROIS PROVENANCES (la discipline épistémique du protocole) :
  Δ  (delta)   ← findings MESURÉ   : ce que le cache affirme (ports, CVE, tags…)
  Ω  (omega)   ← findings CALCULÉ  : ce que l'on déduit (incohérences, aberrations
                                     statistiques, dérives entre sessions)
  Λ  (lambda)  ← findings LORE     : strate Trame (ports fantômes arithmétiques)
Δ ne dépend QUE du cache. Les déductions n'y entrent jamais.

SORTIES (dans --out, défaut « . ») :
  echo_2026_shadow_<date>.json        ← log historique, lisible par echo_2026_viz.py
  echo_2026_dataset_<session>/         ← dataset KNIME (CSV UTF-8) :
       cibles.csv        1 ligne / cible  (table principale de data mining)
       findings.csv      1 ligne / anomalie (format long)
       ports.csv  vulns.csv  cpe.csv     tables relationnelles (jointure sur ip)
       transactions.csv  paniers d'items (Association Rule Learner)
       matrice.csv       one-hot ports + compteurs de codes (clustering)
       session.csv       métadonnées de la session
       dictionnaire.csv  type + description de chaque colonne
  echo_2026_historique_cibles.csv      ← cumul de toutes les sessions (longitudinal)
  echo_2026_historique_sessions.csv

Usage :
  python echo_2026_v5-shadow.py --db internetdb.sqlite --targets cibles.txt
  python echo_2026_v5-shadow.py --db internetdb.sqlite --targets cibles.txt --baseline 20000 --kev kev.json
  python echo_2026_v5-shadow.py --db internetdb.sqlite --targets cibles.txt --no-dns --pur --out scans/

Schéma attendu (table 'internetdb') : ip, ports, hostnames, cpe, vulns, last_update
Colonne optionnelle : tags.  Les colonnes absentes sont tolérées.
"""

import argparse
import bisect
import csv
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import socket
import sqlite3
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "5.0-SHADOW"
SCHEMA_VERSION = 1

# ═════════════════════════════════════════════════════════════════════════════
# RENDU & ESTHÉTIQUE
# ═════════════════════════════════════════════════════════════════════════════
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"; ITALIC = "\033[3m"
    BGREEN = "\033[92m"; BYELLOW = "\033[93m"; BRED = "\033[91m"
    BCYAN = "\033[96m"; BMAGENTA = "\033[95m"; BBLUE = "\033[94m"; WHITE = "\033[37m"

if os.name == "nt":
    os.system("")

GLYPHS = "░▒▓█"
PULSE = "·•●•·"

def banner(titre, col=C.BCYAN):
    print(f"\n{col}{'═' * 80}{C.RESET}")
    print(f"{col}✦{C.RESET} {C.BOLD}{titre}{C.RESET}")
    print(f"{col}{'═' * 80}{C.RESET}")

def section(titre, col=C.BMAGENTA):
    print(f"\n{col}◈ {C.BOLD}{titre}{C.RESET}")
    print(f"{col}{'─' * min(len(titre) + 4, 80)}{C.RESET}")

def log(msg, niveau="info"):
    ic = {"info": (C.BCYAN, "›"), "ok": (C.BGREEN, "✓"), "warn": (C.BYELLOW, "⚠"),
          "err": (C.BRED, "✗")}.get(niveau, (C.WHITE, "·"))
    print(f"  {ic[0]}{ic[1]}{C.RESET} {msg}")

def progress(i, n, label=""):
    # Hors terminal (redirection / log) : une mise à jour par ~5 % seulement
    if not sys.stdout.isatty() and i != n and i % max(1, n // 20):
        return
    width = 32
    filled = int(width * i / max(n, 1))
    bar = GLYPHS[-1] * filled + GLYPHS[0] * (width - filled)
    print(f"\r{C.BCYAN}[{bar}]{C.RESET} {i}/{n} {C.DIM}{label[:40]:<40}{C.RESET}", end="", flush=True)
    if i >= n:
        print()

def ma_pause(duree=7):
    print(f"\n{C.DIM}  · Ma · {duree}s de silence structuré ·{C.RESET}")
    for i in range(duree, 0, -1):
        p = PULSE[(duree - i) % len(PULSE)]
        print(f"\r  {C.BMAGENTA}{p}{C.RESET} respiration {i}s {p}", end="", flush=True)
        time.sleep(1)
    print(f"\r  {C.BGREEN}✓{C.RESET} silence traversé.            ")

# ═════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ═════════════════════════════════════════════════════════════════════════════
NOMBRES_TRAME = {7, 70, 77, 144, 333, 707, 1944, 2025, 2026, 2027, 2075, 2079, 3333}
LEXIQUE_TRAME = {
    "trame", "delta", "glitch", "draugr", "yokai", "gaialithe", "fracturoscript",
    "promethee", "correcteur", "transept", "caen-profonde", "hague", "raz blanchard",
    "francfort", "hackervolva", "runesmith", "retrocausal", "superposition", "strate",
    "convergence", "silence", "echo", "mousse quantique", "effondrement", "shadow"
}
_LEX_RE = re.compile(r"(?<!\w)(" + "|".join(sorted(map(re.escape, LEXIQUE_TRAME), key=len, reverse=True)) + r")(?!\w)")

PORTS_RISQUES = {21, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017, 8080, 8443}
CLASSES_PORTS = {
    "web":    {80, 443, 8000, 8008, 8080, 8443, 8888},
    "remote": {22, 23, 3389, 5900, 5901, 5985, 5986},
    "db":     {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017},
    "mail":   {25, 110, 143, 465, 587, 993, 995, 2525},
    "file":   {21, 69, 111, 139, 445, 873, 2049},
    "ics":    {102, 502, 1883, 20000, 44818, 47808},
}
def classe_port(p):
    for nom, ens in CLASSES_PORTS.items():
        if p in ens:
            return nom
    return "autre"

SEV_W = {"info": 0.0, "faible": 0.02, "moyenne": 0.06, "haute": 0.12, "critique": 0.20}
SEV_ORDRE = ["critique", "haute", "moyenne", "faible", "info"]
SEV_RANG = {"critique": 4, "haute": 3, "moyenne": 2, "faible": 1, "info": 0}
SEV_COL = {"critique": C.BRED, "haute": C.BRED, "moyenne": C.BYELLOW, "faible": C.BCYAN, "info": C.DIM}
ECHELLE = 0.25   # échelle de saturation 1-exp(-Σw/échelle), identique à v4

# Heuristique d'obsolescence : version strictement inférieure => « ancien ». À ajuster.
SEUILS_OBSOLESCENCE = {
    "php:php": (7, 4), "openssl:openssl": (1, 1, 1), "apache:http_server": (2, 4),
    "nginx:nginx": (1, 18), "openbsd:openssh": (7, 4), "mysql:mysql": (5, 7),
    "microsoft:iis": (10, 0), "isc:bind": (9, 11),
}
# Ports attendus pour un logiciel donné (serveurs web exclus : ils vivent n'importe où)
PORTS_ATTENDUS = {
    "openssh": {22}, "mysql": {3306}, "postgresql": {5432}, "redis": {6379},
    "mongodb": {27017}, "proftpd": {21}, "vsftpd": {21}, "pure-ftpd": {21},
    "bind": {53}, "elasticsearch": {9200, 9300},
    "exim": CLASSES_PORTS["mail"], "postfix": CLASSES_PORTS["mail"], "dovecot": CLASSES_PORTS["mail"],
}
PILE_UNIX = {"openssh", "proftpd", "vsftpd", "pure-ftpd", "exim", "postfix", "dovecot", "bind"}
ROLES = {  # mots du 1er label du hostname -> ports plausibles
    "mail": ({"mail", "smtp", "mx", "imap", "pop", "webmail"}, CLASSES_PORTS["mail"]),
    "web":  ({"www", "web", "portal", "shop"}, CLASSES_PORTS["web"]),
    "ftp":  ({"ftp", "sftp"}, {21, 22, 990}),
    "dns":  ({"ns", "dns"}, {53}),
    "db":   ({"db", "sql", "mysql", "postgres", "mongo", "redis"}, CLASSES_PORTS["db"]),
    "vpn":  ({"vpn"}, {443, 500, 1194, 1723, 4500, 10000}),
}
# Tags InternetDB (colonne optionnelle). Vocabulaire à ajuster selon votre dump.
TAGS_MENACE = {"compromised", "malware", "doublepulsar", "c2"}
TAGS_EOL = {"eol-os", "eol-product"}

SEUIL_Z = 3.5          # z-score robuste (Iglewicz-Hoaglin)
SEUIL_PLETHORE = 20    # nb de ports => surface suspecte (honeypot / tarpit)
SEUIL_PLAGE = 8        # ports consécutifs
JOURS_PERIME = 365

# Lectures Trame (toutes les codes ont une entrée : viz exige une chaîne, jamais None)
LECTURE = {
    "shadow_vuln": "Une faille connue résonne dans le cache : une cicatrice non réparée.",
    "shadow_port_risque": "Une porte dangereuse est laissée ouverte dans le souvenir de la machine.",
    "shadow_port_trame": "Résonance numérique : ce port porte la signature des nombres de la Trame.",
    "shadow_hostname_trame": "Le nom de la machine murmure des mots interdits.",
    "shadow_cpe_anomalie": "Le logiciel est un fantôme d'une époque révolue (CPE obsolète).",
    "shadow_inconnu": "La cible est un trou noir dans le cache : elle existe, mais n'a jamais été vue.",
    "shadow_ports": "La surface telle que la mémoire l'a gravée.",
    "shadow_no_ports": "Une machine muette : aucune porte n'a jamais été vue ouverte.",
    "shadow_tag_menace": "Le cache porte une marque de souillure : la machine n'est plus seule à la commander.",
    "shadow_tag_eol": "Le cache la sait périmée : elle survit à son époque.",
    "spectre_ip": "Port fantôme arithmétique : une possibilité mathématique, pas une observation.",
    "resonance_ip": "L'adresse elle-même vibre sur une fréquence de la Trame.",
    "onto_port_ics": "Une machine de métal et de procédés parle sur le réseau des hommes.",
    "onto_ip_non_publique": "Une adresse qui n'a pas le droit d'être vue figure pourtant dans la mémoire du monde.",
    "onto_entite_sans_surface": "Elle a un nom, des logiciels, des failles… mais aucune porte : un corps sans seuil.",
    "onto_vuln_orpheline": "Une cicatrice sans organe : la faille est connue, son hôte logiciel ne l'est pas.",
    "onto_service_deplace": "Le logiciel habite une porte qui n'est pas la sienne.",
    "onto_pile_hybride": "Deux mondes incompatibles cohabitent dans une même chair : leurre ou chimère.",
    "onto_surface_pletorique": "Trop de portes pour un seul mur : le décor d'un piège.",
    "onto_plage_continue": "Les portes s'alignent comme des dominos : la signature d'une main qui les a posées.",
    "onto_ptr_incoherent": "Le nom prétend désigner une autre adresse : le miroir est décalé.",
    "onto_role_incoherent": "Le nom promet un rôle que la surface ne confirme pas.",
    "onto_hostname_algorithmique": "Ce nom n'a pas été choisi par un humain.",
    "onto_cache_perime": "Le souvenir est ancien : la machine a peut-être changé de visage depuis.",
    "onto_temps_inverse": "Le souvenir date d'un futur qui n'a pas eu lieu : effet rétrocausal.",
    "onto_tag_honeypot": "Le cache l'avoue : cette machine est un leurre.",
    "onto_clone": "Elles partagent la même empreinte : une seule volonté, plusieurs corps.",
    "stat_outlier_n_ports": "Cette cible déborde de toutes les distributions de son lot (surface).",
    "stat_outlier_n_vulns": "Cette cible déborde de toutes les distributions de son lot (cicatrices).",
    "stat_outlier_rarete_ports": "Son empreinte de ports est singulière face à la population de référence.",
    "stat_outlier_multivarie": "Aucune dimension ne la trahit seule, mais l'ensemble est hors-norme.",
    "derive_ports_ajoutes": "De nouvelles portes se sont ouvertes depuis la dernière mémoire.",
    "derive_ports_retires": "Des portes se sont refermées depuis la dernière mémoire.",
    "derive_vulns_ajoutees": "De nouvelles cicatrices sont apparues depuis la dernière mémoire.",
    "derive_vulns_corrigees": "Des cicatrices se sont refermées depuis la dernière mémoire.",
    "derive_hostnames": "La machine a changé de nom depuis la dernière mémoire.",
}

# ═════════════════════════════════════════════════════════════════════════════
# SPÉCIFICATION DU DATASET (source unique : en-têtes CSV + dictionnaire)
# (nom, type KNIME, valeur par défaut, description)
# Booléens = entiers 0/1. Listes = valeurs séparées par « ; ». Vide = manquant.
# ═════════════════════════════════════════════════════════════════════════════
COLS_CIBLES = [
    ("session_id", "string", None, "Identifiant de session (clé de jointure inter-tables)"),
    ("ts_utc", "string", None, "Début de session, UTC, ISO 8601 sans fuseau (yyyy-MM-dd'T'HH:mm:ss)"),
    ("cible_saisie", "string", None, "Cible telle que saisie (IP ou hostname)"),
    ("ip", "string", None, "Adresse IP analysée (clé primaire dans la session)"),
    ("ip_version", "int", None, "4 ou 6"),
    ("ip_classe", "string", None, "global / prive / loopback / link_local / multicast / reserve / autre"),
    ("ip_publique", "int", 0, "1 si routable publiquement"),
    ("o1", "int", None, "Octet 1 (IPv4)"), ("o2", "int", None, "Octet 2 (IPv4)"),
    ("o3", "int", None, "Octet 3 (IPv4)"), ("o4", "int", None, "Octet 4 (IPv4)"),
    ("ip_xor", "int", None, "XOR des 4 octets (règles du spectre LORE)"),
    ("ip_sum", "int", None, "Somme des 4 octets (règles du spectre LORE)"),
    ("subnet", "string", None, "/24 (IPv4) ou /48 (IPv6) : clé de regroupement"),
    ("en_cache", "int", 0, "1 si la cible figure dans le cache"),
    ("cache_age_jours", "double", None, "Ancienneté du souvenir (jours) ; négatif = futur"),
    ("cache_futur", "int", 0, "1 si last_update est dans le futur"),
    ("n_ports", "int", 0, "Nombre de ports ouverts"),
    ("ports", "string", None, "Liste des ports"),
    ("n_ports_risque", "int", 0, "Ports dans PORTS_RISQUES"),
    ("n_ports_trame", "int", 0, "Ports dans NOMBRES_TRAME"),
    ("n_ports_web", "int", 0, "Ports de classe web"), ("n_ports_remote", "int", 0, "Ports d'administration distante"),
    ("n_ports_db", "int", 0, "Ports de bases de données"), ("n_ports_mail", "int", 0, "Ports mail"),
    ("n_ports_file", "int", 0, "Ports de partage de fichiers"), ("n_ports_ics", "int", 0, "Ports industriels / IoT"),
    ("port_min", "int", None, "Plus petit port"), ("port_max", "int", None, "Plus grand port"),
    ("plage_max", "int", 0, "Plus longue suite de ports consécutifs"),
    ("signature_ports", "string", None, "Empreinte SHA-1 (8 car.) de l'ensemble de ports"),
    ("signature_freq", "int", None, "Nb de cibles du lot partageant la même empreinte"),
    ("rarete_ports", "double", None, "Auto-information moyenne des ports (bits) vs population de référence"),
    ("rarete_max", "double", None, "Auto-information du port le plus rare (bits)"),
    ("n_vulns", "int", 0, "Nombre de CVE"), ("vulns", "string", None, "Liste des CVE"),
    ("n_vulns_haute", "int", 0, "CVE de sévérité heuristique haute (ou KEV)"),
    ("n_vulns_kev", "int", 0, "CVE présentes dans le catalogue KEV fourni (--kev)"),
    ("cve_annee_min", "int", None, "Année de la plus ancienne CVE"), ("cve_annee_max", "int", None, "Année de la plus récente CVE"),
    ("cve_annee_moy", "double", None, "Année moyenne des CVE"),
    ("n_cpe", "int", 0, "Nombre de CPE"), ("cpe", "string", None, "Liste des CPE"),
    ("n_vendors", "int", 0, "Nombre d'éditeurs distincts"),
    ("n_cpe_obsoletes", "int", 0, "CPE jugés anciens par heuristique"),
    ("pile_hybride", "int", 0, "1 si logiciels Windows ET Unix coexistent"),
    ("n_hostnames", "int", 0, "Nombre de hostnames"), ("hostnames", "string", None, "Liste des hostnames"),
    ("host_len_max", "int", None, "Longueur max d'un hostname"),
    ("host_entropie_max", "double", None, "Entropie de Shannon max du 1er label (bits/car.)"),
    ("host_ratio_chiffres_max", "double", None, "Ratio de chiffres max du 1er label"),
    ("host_mots_trame", "int", 0, "Occurrences du lexique Trame"),
    ("host_role", "string", None, "Rôle déduit du hostname (mail/web/ftp/dns/db/vpn)"),
    ("role_incoherent", "int", 0, "1 si le rôle du hostname n'est pas confirmé par les ports"),
    ("ptr_coherent", "int", None, "1/0 si le hostname encode une IP égale/différente ; vide sinon"),
    ("tags", "string", None, "Tags du cache (colonne optionnelle)"),
    ("n_findings", "int", 0, "Total de findings"), ("n_mesure", "int", 0, "Findings MESURÉ"),
    ("n_calcule", "int", 0, "Findings CALCULÉ"), ("n_lore", "int", 0, "Findings LORE"),
    ("n_critique", "int", 0, "Findings critique"), ("n_haute", "int", 0, "Findings haute"),
    ("n_moyenne", "int", 0, "Findings moyenne"), ("n_faible", "int", 0, "Findings faible"),
    ("n_info", "int", 0, "Findings info"),
    ("n_couches", "int", 0, "Couches distinctes touchées par un finding non-info"),
    ("n_spectres", "int", 0, "Ports fantômes LORE activés"),
    ("spectre_act_max", "double", None, "Activation max parmi les spectres"),
    ("spectre_act_somme", "double", 0.0, "Somme des activations"),
    ("voisins_lot_24", "int", None, "Nb de cibles du lot dans le même /24"),
    ("ecart_voisinage_ports", "double", None, "n_ports − moyenne des voisins du lot (si ≥3 cibles dans le /24)"),
    ("vu_avant", "int", 0, "1 si la cible figure dans une session précédente"),
    ("derive_ports_ajoutes", "int", None, "Ports apparus depuis la session précédente"),
    ("derive_ports_retires", "int", None, "Ports disparus"),
    ("derive_vulns_ajoutees", "int", None, "CVE apparues"), ("derive_vulns_corrigees", "int", None, "CVE disparues"),
    ("derive_hostnames", "int", None, "1 si l'ensemble de hostnames a changé"),
    ("z_ports", "double", None, "z-score robuste de n_ports dans le lot"),
    ("z_vulns", "double", None, "z-score robuste de n_vulns dans le lot"),
    ("z_rarete", "double", None, "z-score robuste de rarete_ports dans le lot"),
    ("iforest_score", "double", None, "Score Isolation Forest normalisé [0,1] (si scikit-learn et lot ≥ 30)"),
    ("delta_cible", "double", 0.0, "Δ de la cible : 1-exp(-Σpoids MESURÉ/0.25)"),
    ("omega", "double", 0.0, "Ω de la cible : 1-exp(-Σpoids CALCULÉ/0.25)"),
    ("lambda", "double", 0.0, "Λ de la cible : 1-exp(-Σactivations LORE/2)"),
    ("pct_delta", "double", None, "Rang percentile de Δ dans le lot [0,1]"),
    ("pct_omega", "double", None, "Rang percentile de Ω dans le lot [0,1]"),
    ("etiquette", "string", None, "Classe ontologique par règles (SILENCE/FRÉMISSANT/RÉSONANT/FANTÔME/INCOHÉRENT/CICATRISÉ/ANOMALIE_MAJEURE). "
                                  "Dérivée des scores : à utiliser comme point de départ, pas comme vérité terrain."),
]
COLS_FINDINGS = [
    ("session_id", "string", None, "Identifiant de session"), ("ts_utc", "string", None, "Début de session UTC"),
    ("ip", "string", None, "Cible"), ("couche", "string", None, "SHADOW / RÉSONANCE / SPECTRE / ONTOLOGIE / STATISTIQUE / DÉRIVE"),
    ("code", "string", None, "Code du finding"), ("severite", "string", None, "critique/haute/moyenne/faible/info"),
    ("severite_rang", "int", None, "4 (critique) … 0 (info)"), ("poids", "double", None, "Poids SEV_W de la sévérité"),
    ("provenance", "string", None, "MESURÉ / CALCULÉ / LORE"), ("message", "string", None, "Message"),
    ("lecture_trame", "string", None, "Lecture Trame (vide en mode --pur)"),
    ("port", "int", None, "Port concerné, si applicable"), ("cve", "string", None, "CVE concernée, si applicable"),
    ("cpe", "string", None, "CPE concerné, si applicable"), ("evidence_json", "string", None, "Preuves (JSON compact)"),
]
COLS_PORTS = [
    ("session_id", "string", None, "Session"), ("ip", "string", None, "Cible"), ("port", "int", None, "Port"),
    ("classe", "string", None, "web/remote/db/mail/file/ics/autre"), ("risque", "int", None, "1 si dans PORTS_RISQUES"),
    ("trame", "int", None, "1 si dans NOMBRES_TRAME"), ("freq_ref", "double", None, "Fréquence dans la population de référence"),
    ("rarete_bits", "double", None, "−log2(freq_ref)"),
]
COLS_VULNS = [
    ("session_id", "string", None, "Session"), ("ip", "string", None, "Cible"), ("cve", "string", None, "Identifiant CVE"),
    ("annee", "int", None, "Année extraite de l'identifiant"), ("severite", "string", None, "Sévérité heuristique"),
    ("kev", "int", None, "1 si dans le catalogue KEV fourni"),
]
COLS_CPE = [
    ("session_id", "string", None, "Session"), ("ip", "string", None, "Cible"), ("cpe", "string", None, "CPE brut"),
    ("part", "string", None, "a (application) / o (OS) / h (hardware)"), ("vendor", "string", None, "Éditeur"),
    ("product", "string", None, "Produit"), ("version", "string", None, "Version"),
    ("obsolete", "int", None, "1 si jugé ancien par heuristique"),
]
COLS_TRANSACTIONS = [
    ("session_id", "string", None, "Session"), ("ip", "string", None, "Cible"),
    ("n_items", "int", None, "Taille du panier"),
    ("items", "string", None, "Items « ; »-séparés : port=…, cpe=…, classe=…, code=…, role=…, tag=…"),
]
COLS_SESSION = [
    ("session_id", "string", None, "Identifiant de session"), ("ts_utc", "string", None, "Début UTC"),
    ("version", "string", None, "Version du script"), ("seed", "string", None, "Graine LORE effective"),
    ("db", "string", None, "Base SQLite"), ("targets_file", "string", None, "Fichier de cibles"),
    ("n_saisies", "int", None, "Cibles saisies"), ("n_resolues", "int", None, "Cibles résolues en IP"),
    ("n_en_cache", "int", None, "Cibles présentes dans le cache"), ("n_findings", "int", None, "Findings"),
    ("delta_global", "double", None, "Δ du JSON (formule cumulative v4, voir --delta-mode)"),
    ("delta_moyen", "double", None, "Moyenne des Δ de cibles"), ("delta_max", "double", None, "Max des Δ de cibles"),
    ("omega_moyen", "double", None, "Moyenne des Ω"), ("omega_max", "double", None, "Max des Ω"),
    ("lambda_moyen", "double", None, "Moyenne des Λ"), ("baseline_n", "int", None, "Taille de la population de référence"),
    ("baseline_source", "string", None, "db (--baseline) ou lot"), ("pur", "int", None, "Mode --pur"),
    ("kev", "int", None, "Catalogue KEV utilisé"), ("duree_s", "double", None, "Durée du traitement"),
]

def defauts(cols):
    return {c[0]: c[2] for c in cols}

# ═════════════════════════════════════════════════════════════════════════════
# RAPPORT
# ═════════════════════════════════════════════════════════════════════════════
class Rapport:
    def __init__(self, pur=False):
        self.items = []
        self.pur = pur

    def add(self, couche, code, sev, msg, evidence=None, prov="MESURÉ", cible=None):
        self.items.append({
            "couche": couche, "code": code, "severite": sev, "provenance": prov,
            "message": msg, "evidence": evidence or {},
            "lecture_trame": "" if self.pur else LECTURE.get(code, ""),
            "cible": cible,
        })

    def mesures(self):
        return [f for f in self.items if f["provenance"] == "MESURÉ"]

# ═════════════════════════════════════════════════════════════════════════════
# UTILITAIRES DE PARSING
# ═════════════════════════════════════════════════════════════════════════════
def champ(row, nom, defaut=None):
    """Accès tolérant à une colonne sqlite3.Row (IndexError si absente, pas KeyError)."""
    if row is None:
        return defaut
    try:
        return row[nom]
    except (IndexError, KeyError):
        return defaut

def parse_liste(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    if isinstance(v, dict):
        return list(v.keys())
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    if isinstance(v, (int, float)):
        return [v]
    s = str(v).strip()
    if not s:
        return []
    try:
        d = json.loads(s)
        if isinstance(d, list):
            return d
        if isinstance(d, dict):
            return list(d.keys())
        return [d]
    except (json.JSONDecodeError, ValueError):
        return [x.strip() for x in re.split(r"[;,|\s]+", s) if x.strip()]

def vers_port(x):
    try:
        p = int(x)
        return p if 0 <= p <= 65535 else None
    except (TypeError, ValueError):
        return None

def parse_ts(v):
    if v in (None, ""):
        return None
    try:
        x = float(v)
        if x > 1e12:
            x /= 1000.0
        return datetime.fromtimestamp(x, timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    s = str(v).strip().replace("Z", "+00:00")
    for essai in (lambda: datetime.fromisoformat(s),
                  lambda: datetime.strptime(s, "%Y-%m-%d %H:%M:%S")):
        try:
            d = essai()
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

_CVE_RE = re.compile(r"^CVE-(\d{4})-\d{3,}$", re.I)
def annee_cve(v):
    m = _CVE_RE.match(str(v).strip())
    return int(m.group(1)) if m else None

def parse_cpe(c):
    s = str(c).strip()
    if s.startswith("cpe:2.3:"):
        parts = s.split(":")[2:]
    elif s.startswith("cpe:/"):
        parts = s[5:].split(":")
    else:
        parts = s.split(":")
    parts = parts + [""] * max(0, 4 - len(parts))
    nettoie = lambda x: "" if x in ("*", "-") else x.lower()
    return {"cpe": s, "part": nettoie(parts[0]), "vendor": nettoie(parts[1]),
            "product": nettoie(parts[2]), "version": nettoie(parts[3])}

def cpe_obsolete(d):
    vt = tuple(int(x) for x in re.findall(r"\d+", d["version"])[:3])
    seuil = SEUILS_OBSOLESCENCE.get(f"{d['vendor']}:{d['product']}")
    if seuil and vt and vt < seuil:
        return True
    m = re.search(r"(?<!\d)(19\d\d|20[01]\d)(?!\d)", f"{d['product']} {d['version']}")
    return bool(m)

def entropie(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())

def classe_ip(ip):
    if ip.is_loopback: return "loopback"
    if ip.is_link_local: return "link_local"
    if ip.is_multicast: return "multicast"
    if ip.is_private: return "prive"
    if ip.is_reserved: return "reserve"
    if ip.is_global: return "global"
    return "autre"

def plus_longue_suite(ports):
    best = cur = 0
    prev = None
    for p in sorted(ports):
        cur = cur + 1 if prev is not None and p == prev + 1 else 1
        best = max(best, cur)
        prev = p
    return best

def z_robuste(vals):
    n = len(vals)
    med = statistics.median(vals)
    mad = statistics.median([abs(v - med) for v in vals])
    if mad > 0:
        return [0.6745 * (v - med) / mad for v in vals]
    mean_ad = sum(abs(v - med) for v in vals) / n
    if mean_ad > 0:
        return [(v - med) / (1.253314 * mean_ad) for v in vals]
    return [0.0] * n

# ═════════════════════════════════════════════════════════════════════════════
# RÉSOLUTION & CHARGEMENT DES CIBLES
# ═════════════════════════════════════════════════════════════════════════════
def charger_hosts_file(path):
    m = {}
    for ligne in Path(path).read_text(encoding="utf-8-sig").splitlines():
        ligne = ligne.split("#")[0].split()
        if len(ligne) >= 2:
            for h in ligne[1:]:
                m[h.lower()] = ligne[0]
    return m

def resolver_local(hostname, no_dns=False, hosts=None):
    """IP directe, sinon fichier hosts local, sinon (sauf --no-dns) résolveur système.
    NB : le résolveur système ne contacte pas la cible, mais il VOIT le nom demandé."""
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    if hosts and hostname.lower() in hosts:
        return hosts[hostname.lower()]
    if no_dns:
        return None
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, UnicodeError):
        return None

def lire_cibles(path, max_expand):
    """Lit le fichier ; accepte IP, hostnames, CIDR ; commentaires '#' en ligne."""
    saisies = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for ligne in f:
            t = ligne.split("#")[0].strip()
            if not t:
                continue
            if "/" in t:
                try:
                    net = ipaddress.ip_network(t, strict=False)
                    if net.num_addresses > max_expand:
                        log(f"CIDR {t} ignoré : {net.num_addresses} adresses > --max-expand {max_expand}", "warn")
                        continue
                    hotes = list(net.hosts()) if net.num_addresses > 2 else list(net)
                    saisies.extend((str(h), str(h)) for h in hotes)
                    continue
                except ValueError:
                    pass
            saisies.append((t, t))
    return saisies

def chercher_lignes(conn, ips, colonnes):
    """Lecture par lots (IN (...)) : une passe par lot au lieu d'une requête par cible."""
    rows = {}
    ips = list(ips)
    for i in range(0, len(ips), 500):
        chunk = ips[i:i + 500]
        q = f"SELECT * FROM internetdb WHERE ip IN ({','.join('?' * len(chunk))})"
        for r in conn.execute(q, chunk):
            rows[str(r["ip"]).strip()] = r
    return rows

def echantillon_baseline(conn, n):
    """Population de référence : n lignes échantillonnées (pas régulier sur rowid)."""
    try:
        mx = conn.execute("SELECT MAX(rowid) FROM internetdb").fetchone()[0] or 0
        if mx == 0:
            return Counter(), 0
        pas = max(1, mx // n)
        cnt, total = Counter(), 0
        for (ports,) in conn.execute("SELECT ports FROM internetdb WHERE rowid % ? = 0 LIMIT ?", (pas, n)):
            ps = {vers_port(x) for x in parse_liste(ports)} - {None}
            cnt.update(ps)
            total += 1
        return cnt, total
    except sqlite3.Error as e:
        log(f"Baseline impossible ({e}) : repli sur le lot.", "warn")
        return Counter(), 0

def charger_kev(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if isinstance(data, dict):
            data = data.get("vulnerabilities", [])
        return {str(v.get("cveID", v) if isinstance(v, dict) else v).upper() for v in data}
    except Exception:
        return {l.strip().upper() for l in Path(path).read_text(encoding="utf-8-sig").splitlines() if l.strip()}

# ═════════════════════════════════════════════════════════════════════════════
# MOTEUR D'ANALYSE — PASSE 1 (par cible)
# ═════════════════════════════════════════════════════════════════════════════
class Ctx:
    """État partagé d'une session."""
    def __init__(self, args, session_id, ts, seed):
        self.args, self.session_id, self.ts, self.seed = args, session_id, ts, seed
        self.now = datetime.now(timezone.utc)
        self.rap = Rapport(pur=args.pur)
        self.profils = {}      # ip -> dict (colonnes COLS_CIBLES)
        self.donnees = {}      # ip -> dict (listes brutes pour tables relationnelles)
        self.kev = set()
        self.freq_ports, self.freq_n, self.baseline_source = Counter(), 0, "lot"

def appliquer_spectre(ip, rap, seed, cible):
    """Ports fantômes arithmétiques (LORE pur). Retourne la liste des activations."""
    if ip.version != 4:
        return []
    o = [int(x) for x in str(ip).split(".")]
    x, s = o[0] ^ o[1] ^ o[2] ^ o[3], sum(o)
    nonce = hmac.new(seed.encode(), str(ip).encode(), hashlib.sha256).digest()
    regles = [
        (x == 0, 0, "Le Vide", "OMEGA"), (s % 7 == 0, 3303, "Galet-Ancre", "STABLE"),
        (x in {36, 72, 144}, 11440, "Port Trickster", "TURBULENT"),
        (s % 3 == 0, 33333, "Les Trois Tiers", "TROUBLE"),
        (x == 144, 14400, "Port Noir", "CRITIQUE"), (o[3] == 255, 65535, "Le Plafond", "CRITIQUE"),
    ]
    acts = []
    for i, (ok, port, nom, sev) in enumerate(regles):
        if ok:
            act = ((nonce[(i * 3) % 32] << 8) | nonce[(i * 3 + 1) % 32]) / 65535.0
            acts.append(act)
            rap.add("SPECTRE", "spectre_ip", "info",
                    f"Port fantôme {port} « {nom} » ({sev}) activation {act:.2f}",
                    {"port": port, "nom": nom, "activation": round(act, 3)}, prov="LORE", cible=cible)
    return acts

def extraire(row):
    """Normalise une ligne du cache en structures Python."""
    ports = sorted({p for p in (vers_port(x) for x in parse_liste(champ(row, "ports"))) if p is not None})
    vulns = sorted({str(v).strip().upper() for v in parse_liste(champ(row, "vulns")) if str(v).strip()})
    hostnames = sorted({str(h).strip().lower() for h in parse_liste(champ(row, "hostnames")) if str(h).strip()})
    cpes = [parse_cpe(c) for c in parse_liste(champ(row, "cpe")) if str(c).strip()]
    tags = sorted({str(t).strip().lower() for t in parse_liste(champ(row, "tags")) if str(t).strip()})
    return {"ports": ports, "vulns": vulns, "hostnames": hostnames, "cpes": cpes, "tags": tags,
            "last_update": parse_ts(champ(row, "last_update"))}

_QUAD_RE = re.compile(r"(?<!\d)(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?!\d)")
def ptr_coherence(ip, hostnames):
    if ip.version != 4 or not hostnames:
        return None
    octets = [int(x) for x in str(ip).split(".")]
    trouve = False
    for h in hostnames:
        for m in _QUAD_RE.finditer(h):
            q = [int(g) for g in m.groups()]
            if any(v > 255 for v in q):
                continue
            trouve = True
            if q == octets or q[::-1] == octets:
                return 1
    return 0 if trouve else None

def role_hostname(hostnames):
    for h in hostnames:
        toks = set(re.split(r"[^a-z]+", h.split(".")[0]))
        for role, (mots, _) in ROLES.items():
            if toks & mots:
                return role
    return None

def analyser_cible(ip_str, saisie, row, ctx):
    """Analyse une cible. Remplit ctx.rap, ctx.profils, ctx.donnees."""
    rap, ip = ctx.rap, ipaddress.ip_address(ip_str)
    p = defauts(COLS_CIBLES)
    p.update(session_id=ctx.session_id, ts_utc=ctx.ts, cible_saisie=saisie, ip=ip_str,
             ip_version=ip.version, ip_classe=classe_ip(ip), ip_publique=int(ip.is_global))
    ctx.profils[ip_str] = p
    add = lambda couche, code, sev, msg, ev=None, prov="MESURÉ": rap.add(couche, code, sev, msg, ev, prov, cible=ip_str)

    if ip.version == 4:
        o = [int(x) for x in ip_str.split(".")]
        p.update(o1=o[0], o2=o[1], o3=o[2], o4=o[3], ip_xor=o[0] ^ o[1] ^ o[2] ^ o[3], ip_sum=sum(o),
                 subnet=f"{o[0]}.{o[1]}.{o[2]}.0/24")
        # Résonance arithmétique de l'adresse (CALCULÉ, Trame numérique)
        if sum(o) in NOMBRES_TRAME or any(v in NOMBRES_TRAME for v in o) or (o[0] == o[3] and o[1] == o[2]):
            add("RÉSONANCE", "resonance_ip", "info", "Adresse en résonance avec les nombres de la Trame (octets/somme/palindrome)",
                {"octets": o, "somme": sum(o)}, "CALCULÉ")
    else:
        p["subnet"] = str(ipaddress.ip_network(f"{ip_str}/48", strict=False))

    if row is None:
        p["en_cache"] = 0
        add("SHADOW", "shadow_inconnu", "info", f"Aucune trace dans le cache pour {ip}")
        ctx.donnees[ip_str] = {"ports": [], "vulns": [], "hostnames": [], "cpes": [], "tags": []}
        if not ctx.args.pur:
            acts = appliquer_spectre(ip, rap, ctx.seed, ip_str)
            p.update(n_spectres=len(acts), spectre_act_max=max(acts) if acts else None, spectre_act_somme=round(sum(acts), 4))
        return

    p["en_cache"] = 1
    d = extraire(row)
    ctx.donnees[ip_str] = d
    ports, vulns, hostnames, cpes, tags = d["ports"], d["vulns"], d["hostnames"], d["cpes"], d["tags"]

    # ── 0. Hygiène du souvenir ──────────────────────────────────────────────
    if not ip.is_global:
        add("ONTOLOGIE", "onto_ip_non_publique", "haute",
            f"Adresse non routable ({p['ip_classe']}) présente dans un recensement Internet",
            {"classe": p["ip_classe"]}, "CALCULÉ")
    if d["last_update"]:
        age = (ctx.now - d["last_update"]).total_seconds() / 86400.0
        p["cache_age_jours"] = round(age, 2)
        if age < -1:
            p["cache_futur"] = 1
            add("ONTOLOGIE", "onto_temps_inverse", "moyenne", f"Horodatage du cache dans le futur ({-age:.1f} j)",
                {"age_jours": round(age, 2)}, "CALCULÉ")
        elif age > JOURS_PERIME:
            add("ONTOLOGIE", "onto_cache_perime", "faible", f"Souvenir ancien : {age:.0f} jours",
                {"age_jours": round(age)}, "CALCULÉ")

    # ── 1. Ports ────────────────────────────────────────────────────────────
    p.update(n_ports=len(ports), ports=";".join(map(str, ports)) or None)
    if ports:
        p.update(port_min=ports[0], port_max=ports[-1], plage_max=plus_longue_suite(ports),
                 signature_ports=hashlib.sha1(",".join(map(str, ports)).encode()).hexdigest()[:8])
        add("SHADOW", "shadow_ports", "info", f"Ports observés dans le cache : {ports}", {"ports": ports})
        for q in ports:
            cl = classe_port(q)
            if cl != "autre":
                p[f"n_ports_{cl}"] += 1
            if q in PORTS_RISQUES:
                p["n_ports_risque"] += 1
                add("SHADOW", "shadow_port_risque", "haute", f"Port à risque {q} exposé (cache)", {"port": q})
            if q in NOMBRES_TRAME:
                p["n_ports_trame"] += 1
                add("RÉSONANCE", "shadow_port_trame", "info", f"Port {q} ∈ Nombres de la Trame", {"port": q}, "CALCULÉ")
        if p["n_ports_ics"]:
            add("ONTOLOGIE", "onto_port_ics", "haute", "Protocole industriel / IoT exposé",
                {"ports": [q for q in ports if q in CLASSES_PORTS["ics"]]}, "CALCULÉ")
        if len(ports) >= SEUIL_PLETHORE:
            add("ONTOLOGIE", "onto_surface_pletorique", "moyenne", f"Surface pléthorique : {len(ports)} ports ouverts",
                {"n_ports": len(ports)}, "CALCULÉ")
        if p["plage_max"] >= SEUIL_PLAGE:
            add("ONTOLOGIE", "onto_plage_continue", "moyenne", f"Suite de {p['plage_max']} ports consécutifs",
                {"plage": p["plage_max"]}, "CALCULÉ")
    else:
        add("SHADOW", "shadow_no_ports", "faible", "Aucun port ouvert recensé dans le cache")

    # ── 2. Vulnérabilités ───────────────────────────────────────────────────
    annees = []
    for v in vulns:
        a = annee_cve(v)
        kev = v in ctx.kev
        if a:
            annees.append(a)
        sev = "critique" if kev else ("haute" if a and a >= 2021 else "moyenne")
        p["n_vulns_kev"] += kev
        p["n_vulns_haute"] += sev in ("haute", "critique")
        add("SHADOW", "shadow_vuln", sev, f"Vulnérabilité en cache : {v}" + (" [KEV]" if kev else ""),
            {"vuln": v, "annee": a, "kev": kev})
    p.update(n_vulns=len(vulns), vulns=";".join(vulns) or None)
    if annees:
        p.update(cve_annee_min=min(annees), cve_annee_max=max(annees), cve_annee_moy=round(sum(annees) / len(annees), 2))

    # ── 3. Hostnames ────────────────────────────────────────────────────────
    p.update(n_hostnames=len(hostnames), hostnames=";".join(hostnames) or None)
    if hostnames:
        labels = [h.split(".")[0] for h in hostnames]
        p["host_len_max"] = max(len(h) for h in hostnames)
        p["host_entropie_max"] = round(max(entropie(l) for l in labels), 3)
        p["host_ratio_chiffres_max"] = round(max(sum(c.isdigit() for c in l) / max(len(l), 1) for l in labels), 3)
        mots = _LEX_RE.findall(" ".join(hostnames))
        if mots:
            p["host_mots_trame"] = len(mots)
            add("SHADOW", "shadow_hostname_trame", "moyenne", f"Hostnames contenant lexique Trame : {sorted(set(mots))}",
                {"hostnames": hostnames, "mots": sorted(set(mots))}, "CALCULÉ")
        for l in labels:
            lettres = re.sub(r"[^a-z]", "", l)
            if len(lettres) >= 10 and sum(c in "aeiouy" for c in lettres) / len(lettres) < 0.25:
                add("ONTOLOGIE", "onto_hostname_algorithmique", "faible", "Nom d'apparence algorithmique (peu de voyelles)",
                    {"label": l}, "CALCULÉ")
                break
        p["ptr_coherent"] = ptr_coherence(ip, hostnames)
        if p["ptr_coherent"] == 0:
            add("ONTOLOGIE", "onto_ptr_incoherent", "faible", "Le hostname encode une adresse différente de l'IP réelle",
                {"hostnames": hostnames}, "CALCULÉ")
        role = role_hostname(hostnames)
        p["host_role"] = role
        if role and not (set(ports) & ROLES[role][1]):
            p["role_incoherent"] = 1
            add("ONTOLOGIE", "onto_role_incoherent", "faible", f"Rôle « {role} » suggéré par le nom, non confirmé par les ports",
                {"role": role, "ports": ports}, "CALCULÉ")

    # ── 4. CPE ──────────────────────────────────────────────────────────────
    p.update(n_cpe=len(cpes), cpe=";".join(c["cpe"] for c in cpes) or None, n_vendors=len({c["vendor"] for c in cpes if c["vendor"]}))
    for c in cpes:
        c["obsolete"] = cpe_obsolete(c)
        if c["obsolete"]:
            p["n_cpe_obsoletes"] += 1
            add("SHADOW", "shadow_cpe_anomalie", "faible", f"Composant logiciel ancien détecté : {c['cpe']}",
                {"cpe": c["cpe"]}, "CALCULÉ")
    win = any(c["vendor"] == "microsoft" or "windows" in c["product"] for c in cpes)
    unix = any(c["product"] in PILE_UNIX for c in cpes)
    if win and unix:
        p["pile_hybride"] = 1
        add("ONTOLOGIE", "onto_pile_hybride", "moyenne", "Logiciels Windows et Unix détectés sur la même cible",
            {"cpe": [c["cpe"] for c in cpes]}, "CALCULÉ")
    if ports:
        for c in cpes:
            att = PORTS_ATTENDUS.get(c["product"])
            if att and not (set(ports) & att):
                add("ONTOLOGIE", "onto_service_deplace", "faible", f"{c['product']} détecté, mais aucun de ses ports usuels n'est ouvert",
                    {"cpe": c["cpe"], "attendus": sorted(att), "ports": ports}, "CALCULÉ")
    if not ports and (hostnames or cpes or vulns):
        add("ONTOLOGIE", "onto_entite_sans_surface", "moyenne", "Attributs (nom/logiciel/CVE) sans aucun port ouvert",
            {"n_hostnames": len(hostnames), "n_cpe": len(cpes), "n_vulns": len(vulns)}, "CALCULÉ")
    if vulns and not cpes:
        add("ONTOLOGIE", "onto_vuln_orpheline", "faible", "CVE listées sans aucun logiciel (CPE) pour les porter",
            {"n_vulns": len(vulns)}, "CALCULÉ")

    # ── 5. Tags (colonne optionnelle) ───────────────────────────────────────
    p["tags"] = ";".join(tags) or None
    for t in tags:
        if t == "honeypot":
            add("ONTOLOGIE", "onto_tag_honeypot", "haute", "Le cache étiquette cette cible comme honeypot", {"tag": t}, "CALCULÉ")
        elif t in TAGS_MENACE:
            add("SHADOW", "shadow_tag_menace", "haute", f"Tag de menace dans le cache : {t}", {"tag": t})
        elif t in TAGS_EOL:
            add("SHADOW", "shadow_tag_eol", "moyenne", f"Tag de fin de vie dans le cache : {t}", {"tag": t})

    # ── 6. Strate LORE ──────────────────────────────────────────────────────
    if not ctx.args.pur:
        acts = appliquer_spectre(ip, rap, ctx.seed, ip_str)
        p.update(n_spectres=len(acts), spectre_act_max=round(max(acts), 4) if acts else None,
                 spectre_act_somme=round(sum(acts), 4))

# ═════════════════════════════════════════════════════════════════════════════
# PASSE 2 — LOT : rareté, voisinage, outliers, dérive
# ═════════════════════════════════════════════════════════════════════════════
def passe_lot(ctx, precedent):
    rap, P = ctx.rap, ctx.profils
    en_cache = [ip for ip, p in P.items() if p["en_cache"]]

    # Population de référence pour la rareté
    if ctx.freq_n == 0:
        for ip in en_cache:
            ctx.freq_ports.update(set(ctx.donnees[ip]["ports"]))
        ctx.freq_n = len(en_cache)
    ref_ok = ctx.freq_n >= 20
    def bits(port):
        return -math.log2((ctx.freq_ports.get(port, 0) + 0.5) / (ctx.freq_n + 1))
    if ref_ok:
        for ip in en_cache:
            bs = [bits(q) for q in ctx.donnees[ip]["ports"]]
            if bs:
                P[ip]["rarete_ports"], P[ip]["rarete_max"] = round(sum(bs) / len(bs), 3), round(max(bs), 3)

    # Empreintes partagées (clones)
    sigs = Counter(P[ip]["signature_ports"] for ip in en_cache if P[ip]["signature_ports"])
    for ip in en_cache:
        s = P[ip]["signature_ports"]
        if s:
            P[ip]["signature_freq"] = sigs[s]
            if sigs[s] >= 5 and P[ip]["n_ports"] >= 3:
                rap.add("ONTOLOGIE", "onto_clone", "faible", f"Empreinte de {P[ip]['n_ports']} ports partagée par {sigs[s]} cibles du lot",
                        {"signature": s, "freq": sigs[s]}, "CALCULÉ", cible=ip)

    # Voisinage /24
    groupes = defaultdict(list)
    for ip in en_cache:
        groupes[P[ip]["subnet"]].append(ip)
    for ips in groupes.values():
        for ip in ips:
            P[ip]["voisins_lot_24"] = len(ips)
            if len(ips) >= 3:
                autres = [P[x]["n_ports"] for x in ips if x != ip]
                P[ip]["ecart_voisinage_ports"] = round(P[ip]["n_ports"] - sum(autres) / len(autres), 3)

    # Outliers univariés (z robuste) — lots ≥ 8
    if len(en_cache) >= 8:
        for feat, plancher, zcol in (("n_ports", 5, "z_ports"), ("n_vulns", 3, "z_vulns"), ("rarete_ports", 0, "z_rarete")):
            ips = [ip for ip in en_cache if P[ip][feat] is not None]
            if len(ips) < 8:
                continue
            zs = z_robuste([P[ip][feat] for ip in ips])
            for ip, z in zip(ips, zs):
                P[ip][zcol] = round(z, 3)
                if z >= SEUIL_Z and P[ip][feat] >= plancher:
                    rap.add("STATISTIQUE", f"stat_outlier_{feat}", "moyenne",
                            f"Valeur aberrante du lot : {feat} = {P[ip][feat]} (z robuste {z:.1f})",
                            {"feature": feat, "valeur": P[ip][feat], "z": round(z, 2)}, "CALCULÉ", cible=ip)

    # Outliers multivariés (optionnel : scikit-learn)
    if not ctx.args.no_ml and len(en_cache) >= 30:
        try:
            from sklearn.ensemble import IsolationForest
            feats = ["n_ports", "n_ports_risque", "n_vulns", "n_vulns_haute", "n_cpe", "n_hostnames",
                     "n_cpe_obsoletes", "plage_max", "host_entropie_max", "rarete_ports"]
            X = [[(P[ip][f] or 0) for f in feats] for ip in en_cache]
            m = IsolationForest(n_estimators=200, random_state=42).fit(X)
            sc = [-float(s) for s in m.score_samples(X)]
            lo, hi = min(sc), max(sc)
            rangs = sorted(sc)
            for ip, s in zip(en_cache, sc):
                P[ip]["iforest_score"] = round((s - lo) / (hi - lo), 4) if hi > lo else 0.0
                pct = rangs.index(s) / len(rangs)
                if pct >= 0.97:
                    rap.add("STATISTIQUE", "stat_outlier_multivarie", "moyenne",
                            f"Profil multivarié isolé (Isolation Forest, score {P[ip]['iforest_score']:.2f})",
                            {"score": P[ip]["iforest_score"], "features": feats}, "CALCULÉ", cible=ip)
        except ImportError:
            log("scikit-learn absent : Isolation Forest ignoré (le reste fonctionne).", "info")
        except Exception as e:
            log(f"Isolation Forest échoué : {e}", "warn")

    # Dérive longitudinale (vs dernière session connue de chaque cible)
    for ip in en_cache:
        prev = precedent.get(ip)
        if not prev:
            continue
        P[ip]["vu_avant"] = 1
        ens = lambda k, conv=str: {conv(x) for x in (prev.get(k) or "").split(";") if x}
        pa, pn = ens("ports", int), set(ctx.donnees[ip]["ports"])
        va, vn = ens("vulns"), set(ctx.donnees[ip]["vulns"])
        ha, hn = ens("hostnames"), set(ctx.donnees[ip]["hostnames"])
        P[ip].update(derive_ports_ajoutes=len(pn - pa), derive_ports_retires=len(pa - pn),
                     derive_vulns_ajoutees=len(vn - va), derive_vulns_corrigees=len(va - vn), derive_hostnames=int(ha != hn))
        ref = prev.get("session_id", "?")
        if pn - pa:
            risque = bool((pn - pa) & PORTS_RISQUES)
            rap.add("DÉRIVE", "derive_ports_ajoutes", "moyenne" if risque else "faible",
                    f"{len(pn - pa)} port(s) apparu(s) depuis la session précédente",
                    {"ports": sorted(pn - pa), "ref": ref}, "CALCULÉ", cible=ip)
        if pa - pn:
            rap.add("DÉRIVE", "derive_ports_retires", "faible", f"{len(pa - pn)} port(s) disparu(s) depuis la session précédente",
                    {"ports": sorted(pa - pn), "ref": ref}, "CALCULÉ", cible=ip)
        if vn - va:
            rap.add("DÉRIVE", "derive_vulns_ajoutees", "moyenne", f"{len(vn - va)} CVE apparue(s) depuis la session précédente",
                    {"vulns": sorted(vn - va), "ref": ref}, "CALCULÉ", cible=ip)
        if va - vn:
            rap.add("DÉRIVE", "derive_vulns_corrigees", "info", f"{len(va - vn)} CVE disparue(s) depuis la session précédente",
                    {"vulns": sorted(va - vn), "ref": ref}, "CALCULÉ", cible=ip)
        if ha != hn:
            rap.add("DÉRIVE", "derive_hostnames", "faible", "Ensemble de hostnames modifié depuis la session précédente",
                    {"avant": sorted(ha), "apres": sorted(hn), "ref": ref}, "CALCULÉ", cible=ip)

# ═════════════════════════════════════════════════════════════════════════════
# SCORES : Δ (MESURÉ) · Ω (CALCULÉ) · Λ (LORE)
# ═════════════════════════════════════════════════════════════════════════════
def indice(items, prov):
    return round(1 - math.exp(-sum(SEV_W[f["severite"]] for f in items if f["provenance"] == prov) / ECHELLE), 3)

def indice_lore(items):
    s = sum(f["evidence"].get("activation", 0) for f in items if f["provenance"] == "LORE")
    return round(1 - math.exp(-s / 2.0), 3)

def etiqueter(d, o, l, en_cache):
    if d >= 0.55 and o >= 0.30: return "ANOMALIE_MAJEURE"
    if d >= 0.55: return "CICATRISÉ"
    if o >= 0.30: return "INCOHÉRENT"
    if not en_cache: return "FANTÔME"
    if l >= 0.50: return "RÉSONANT"
    if d >= 0.10 or o >= 0.10: return "FRÉMISSANT"
    return "SILENCE"

def calculer_scores(ctx):
    par_cible = defaultdict(list)
    for f in ctx.rap.items:
        par_cible[f["cible"]].append(f)
    for ip, p in ctx.profils.items():
        fs = par_cible.get(ip, [])
        cnt_sev = Counter(f["severite"] for f in fs)
        cnt_prov = Counter(f["provenance"] for f in fs)
        p.update(n_findings=len(fs), n_mesure=cnt_prov["MESURÉ"], n_calcule=cnt_prov["CALCULÉ"], n_lore=cnt_prov["LORE"],
                 n_critique=cnt_sev["critique"], n_haute=cnt_sev["haute"], n_moyenne=cnt_sev["moyenne"],
                 n_faible=cnt_sev["faible"], n_info=cnt_sev["info"],
                 n_couches=len({f["couche"] for f in fs if f["severite"] != "info"}))
        p["delta_cible"], p["omega"], p["lambda"] = indice(fs, "MESURÉ"), indice(fs, "CALCULÉ"), indice_lore(fs)
        p["etiquette"] = etiqueter(p["delta_cible"], p["omega"], p["lambda"], p["en_cache"])
    # Rangs percentiles (rang moyen pour les ex-aequo)
    n = len(ctx.profils)
    if n > 1:
        for cle, dest in (("delta_cible", "pct_delta"), ("omega", "pct_omega")):
            vals = sorted(p[cle] for p in ctx.profils.values())
            for p in ctx.profils.values():
                lo, hi = bisect.bisect_left(vals, p[cle]), bisect.bisect_right(vals, p[cle]) - 1
                p[dest] = round(((lo + hi) / 2) / (n - 1), 4)

def interpreter(d):
    return ("Silence structuré — rien à signaler" if d < 0.10 else
            "Frémissement — écarts mineurs dans le cache" if d < 0.30 else
            "Tension active — cicatrices numériques avérées" if d < 0.55 else
            "Zone de fracture — strates qui se mêlent" if d < 0.80 else
            "Verrou Trame — freeze ontologique détecté")

# ═════════════════════════════════════════════════════════════════════════════
# AFFICHAGE
# ═════════════════════════════════════════════════════════════════════════════
ETQ_COL = {"ANOMALIE_MAJEURE": C.BRED, "CICATRISÉ": C.BRED, "INCOHÉRENT": C.BYELLOW,
           "FANTÔME": C.BMAGENTA, "RÉSONANT": C.BMAGENTA, "FRÉMISSANT": C.BCYAN, "SILENCE": C.DIM}

def afficher_classement(ctx, top, pur):
    section("SONDE ONTOLOGIQUE — classement des cibles (Δ · Ω · Λ)", C.BGREEN)
    cles = sorted(ctx.profils.values(), key=lambda p: -(p["delta_cible"] + p["omega"] + 0.3 * p["lambda"]))
    print(f"  {C.DIM}{'#':>3} {'cible':<40} {'Δ':>5} {'Ω':>5} {'Λ':>5}  étiquette{C.RESET}")
    for i, p in enumerate(cles[:top], 1):
        col = ETQ_COL.get(p["etiquette"], C.DIM)
        print(f"  {i:>3} {p['ip']:<40} {p['delta_cible']:>5.2f} {p['omega']:>5.2f} {p['lambda']:>5.2f}  {col}{p['etiquette']}{C.RESET}")
    ordre = {s: i for i, s in enumerate(SEV_ORDRE)}
    par_cible = defaultdict(list)
    for f in ctx.rap.items:
        par_cible[f["cible"]].append(f)
    for p in cles[:min(5, top)]:
        fs = sorted((f for f in par_cible[p["ip"]] if f["severite"] != "info"), key=lambda f: ordre[f["severite"]])[:4]
        if not fs:
            continue
        print(f"\n  {C.BOLD}{p['ip']}{C.RESET}")
        for f in fs:
            prov = {"MESURÉ": C.BGREEN, "CALCULÉ": C.BYELLOW, "LORE": C.BMAGENTA}[f["provenance"]]
            print(f"    {SEV_COL[f['severite']]}{f['severite']:<8}{C.RESET} {prov}[{f['provenance']}]{C.RESET} {f['message'][:90]}")
            if f["lecture_trame"] and not pur:
                print(f"             {C.ITALIC}{C.BMAGENTA}↳ {f['lecture_trame']}{C.RESET}")

def afficher_tout(ctx, pur):
    section("ANOMALIES — détail complet", C.BGREEN)
    ordre = {s: i for i, s in enumerate(SEV_ORDRE)}
    for f in sorted(ctx.rap.items, key=lambda f: (f["cible"] or "", f["provenance"] != "MESURÉ", ordre[f["severite"]])):
        prov = {"MESURÉ": C.BGREEN, "CALCULÉ": C.BYELLOW, "LORE": C.BMAGENTA}[f["provenance"]]
        print(f"  {C.DIM}{f['cible']}{C.RESET} {SEV_COL[f['severite']]}{f['severite']:<8}{C.RESET} "
              f"{prov}[{f['provenance']}]{C.RESET} {C.DIM}{f['couche']:<11}{C.RESET} {f['message']}")
        if f["lecture_trame"] and not pur:
            print(f"           {C.ITALIC}{C.BMAGENTA}↳ {f['lecture_trame']}{C.RESET}")

# ═════════════════════════════════════════════════════════════════════════════
# EXPORT DATASET
# ═════════════════════════════════════════════════════════════════════════════
def fmt(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, float):
        return repr(round(float(v), 4))   # float() : neutralise np.float64 -> pas de 'np.float64(..)' dans le CSV
    if isinstance(v, (list, tuple, set)):
        return ";".join(map(str, v))
    return v

def ecrire_csv(path, cols, rows, sep=","):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=sep)
        w.writerow([c[0] for c in cols])
        for r in rows:
            w.writerow([fmt(r.get(c[0])) for c in cols])

def ajouter_historique(path, cols, rows, sep=","):
    """Ajoute au cumul ; si le schéma a changé, l'ancien fichier est archivé (jamais écrasé)."""
    noms = [c[0] for c in cols]
    if path.exists():
        with open(path, "r", newline="", encoding="utf-8") as f:
            entete = next(csv.reader(f, delimiter=sep), [])
        if entete != noms:
            arch = path.with_name(f"{path.stem}.ancien_{datetime.now().strftime('%Y%m%d_%H%M%S')}{path.suffix}")
            path.rename(arch)
            log(f"Schéma de l'historique modifié : ancien cumul archivé → {arch.name}", "warn")
    neuf = not path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=sep)
        if neuf:
            w.writerow(noms)
        for r in rows:
            w.writerow([fmt(r.get(n)) for n in noms])

def charger_precedent(path, ips, sep=","):
    """Dernière ligne connue (session la plus récente) de chaque IP du lot."""
    prec = {}
    if not path.exists():
        return prec
    try:
        with open(path, "r", newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f, delimiter=sep):
                if r.get("ip") in ips and r.get("en_cache") == "1":
                    prec[r["ip"]] = r     # fichier chronologique : la dernière gagne
    except Exception as e:
        log(f"Historique illisible ({e}) : dérive ignorée.", "warn")
    return prec

def construire_tables(ctx, top_k):
    sid, ts = ctx.session_id, ctx.ts
    findings, ports, vulns, cpes, trans = [], [], [], [], []
    top_ports = [q for q, _ in ctx.freq_ports.most_common(top_k)]
    codes = sorted({f["code"] for f in ctx.rap.items})
    matrice = []
    par_cible = defaultdict(list)
    for f in ctx.rap.items:
        par_cible[f["cible"]].append(f)
        ev = f["evidence"]
        findings.append({
            "session_id": sid, "ts_utc": ts, "ip": f["cible"], "couche": f["couche"], "code": f["code"],
            "severite": f["severite"], "severite_rang": SEV_RANG[f["severite"]], "poids": SEV_W[f["severite"]],
            "provenance": f["provenance"], "message": f["message"], "lecture_trame": f["lecture_trame"],
            "port": ev.get("port") if isinstance(ev.get("port"), int) else None,
            "cve": ev.get("vuln"), "cpe": ev.get("cpe") if isinstance(ev.get("cpe"), str) else None,
            "evidence_json": json.dumps(ev, ensure_ascii=False, separators=(",", ":"), default=str),
        })
    for ip, p in ctx.profils.items():
        d = ctx.donnees[ip]
        for q in d["ports"]:
            freq = (ctx.freq_ports.get(q, 0) + 0.5) / (ctx.freq_n + 1) if ctx.freq_n >= 20 else None
            ports.append({"session_id": sid, "ip": ip, "port": q, "classe": classe_port(q), "risque": int(q in PORTS_RISQUES),
                          "trame": int(q in NOMBRES_TRAME), "freq_ref": freq, "rarete_bits": -math.log2(freq) if freq else None})
        for v in d["vulns"]:
            a = annee_cve(v)
            kev = v in ctx.kev
            vulns.append({"session_id": sid, "ip": ip, "cve": v, "annee": a, "kev": int(kev),
                          "severite": "critique" if kev else ("haute" if a and a >= 2021 else "moyenne")})
        for c in d["cpes"]:
            cpes.append({"session_id": sid, "ip": ip, "cpe": c["cpe"], "part": c["part"], "vendor": c["vendor"],
                         "product": c["product"], "version": c["version"], "obsolete": int(c.get("obsolete", False))})
        items = [f"port={q}" for q in d["ports"]] + [f"classe={cl}" for cl in sorted({classe_port(q) for q in d["ports"]} - {"autre"})]
        items += sorted({f"cpe={c['vendor']}:{c['product']}" for c in d["cpes"] if c["product"]})
        items += sorted({f"code={f['code']}" for f in par_cible.get(ip, []) if f["severite"] != "info" and f["provenance"] != "LORE"})
        items += [f"tag={t}" for t in d["tags"]] + ([f"role={p['host_role']}"] if p["host_role"] else [])
        items += [f"etiquette={p['etiquette']}"]
        trans.append({"session_id": sid, "ip": ip, "n_items": len(items), "items": items})
        ligne = {"session_id": sid, "ip": ip}
        ligne.update({f"port_{q}": int(q in d["ports"]) for q in top_ports})
        cc = Counter(f["code"] for f in par_cible.get(ip, []))
        ligne.update({f"code_{c}": cc.get(c, 0) for c in codes})
        matrice.append(ligne)
    cols_matrice = ([("session_id", "string", None, "Session"), ("ip", "string", None, "Cible")]
                    + [(f"port_{q}", "int", None, f"1 si le port {q} est ouvert (top {top_k} de la population de référence)") for q in top_ports]
                    + [(f"code_{c}", "int", None, f"Nombre de findings de code {c}") for c in codes])
    return findings, ports, vulns, cpes, trans, matrice, cols_matrice

def exporter_dataset(ctx, dossier, sess, sep, top_k, parquet):
    dossier.mkdir(parents=True, exist_ok=True)
    findings, ports, vulns, cpes, trans, matrice, cols_matrice = construire_tables(ctx, top_k)
    lignes = list(ctx.profils.values())
    tables = [("cibles", COLS_CIBLES, lignes), ("findings", COLS_FINDINGS, findings), ("ports", COLS_PORTS, ports),
              ("vulns", COLS_VULNS, vulns), ("cpe", COLS_CPE, cpes), ("transactions", COLS_TRANSACTIONS, trans),
              ("matrice", cols_matrice, matrice), ("session", COLS_SESSION, [sess])]
    dico = []
    for nom, cols, rows in tables:
        ecrire_csv(dossier / f"{nom}.csv", cols, rows, sep)
        dico += [{"table": nom, "colonne": c[0], "type": c[1], "description": c[3]} for c in cols]
        log(f"{nom + '.csv':<18} {len(rows):>7} ligne(s) × {len(cols)} colonne(s)", "ok")
    ecrire_csv(dossier / "dictionnaire.csv", [("table", "", 0, ""), ("colonne", "", 0, ""), ("type", "", 0, ""), ("description", "", 0, "")], dico, sep)
    if parquet:
        try:
            import pandas as pd
            for nom, cols, rows in tables:
                df = pd.DataFrame([{c[0]: r.get(c[0]) if not isinstance(r.get(c[0]), (list, set, tuple)) else ";".join(map(str, r.get(c[0]))) for c in cols} for r in rows])
                df.to_parquet(dossier / f"{nom}.parquet", index=False)
            log("Parquet écrit (pandas + pyarrow).", "ok")
        except Exception as e:
            log(f"Parquet ignoré : {e}", "warn")
    return lignes

# ═════════════════════════════════════════════════════════════════════════════
# ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════
def main():
    t0 = time.time()
    ap = argparse.ArgumentParser(description="ECHO-2026 v5-SHADOW — Sonde ontologique passive (cache SQLite)")
    ap.add_argument("--db", required=True, help="Base SQLite Shodan InternetDB (ouverte en lecture seule)")
    ap.add_argument("--targets", required=True, help="Fichier de cibles : IP, hostname ou CIDR, 1 par ligne ('#' = commentaire)")
    ap.add_argument("--out", default=".", help="Dossier de sortie (JSON + dataset + historique)")
    ap.add_argument("--seed", default=None, help="Fige le nonce de la strate LORE (audit reproductible)")
    ap.add_argument("--pur", action="store_true", help="Supprime la strate LORE (spectres) et les lectures Trame")
    ap.add_argument("--ma", action="store_true", help="Pauses rituelles de 7s entre les lots")
    ap.add_argument("--batch-size", type=int, default=50, help="Cibles entre chaque pause Ma")
    ap.add_argument("--no-dns", action="store_true", help="N'utilise jamais le résolveur système (IP et --hosts-file uniquement)")
    ap.add_argument("--hosts-file", default=None, help="Fichier au format /etc/hosts pour résoudre hors-ligne")
    ap.add_argument("--max-expand", type=int, default=4096, help="Taille max d'un CIDR développé")
    ap.add_argument("--baseline", type=int, default=0, help="Taille de l'échantillon de référence tiré de la DB (0 = le lot lui-même)")
    ap.add_argument("--kev", default=None, help="Catalogue CISA KEV local (JSON ou 1 CVE/ligne) : CVE exploitées => critique")
    ap.add_argument("--delta-mode", choices=["cumul", "moyen"], default="cumul",
                    help="Δ global du JSON : 'cumul' (formule v4, comparable aux anciens logs) ou 'moyen' (moyenne des Δ cibles)")
    ap.add_argument("--no-dataset", action="store_true", help="Ne génère pas le dataset KNIME")
    ap.add_argument("--no-history", action="store_true", help="Ne lit ni n'alimente l'historique cumulatif (pas de dérive)")
    ap.add_argument("--sep", default=",", help="Séparateur CSV (défaut ',')")
    ap.add_argument("--onehot-top", type=int, default=30, help="Nb de ports en colonnes one-hot dans matrice.csv")
    ap.add_argument("--parquet", action="store_true", help="Écrit aussi des .parquet (pandas + pyarrow requis)")
    ap.add_argument("--no-ml", action="store_true", help="Désactive l'Isolation Forest")
    ap.add_argument("--top", type=int, default=15, help="Nb de cibles dans le classement affiché")
    ap.add_argument("--verbose", action="store_true", help="Affiche tous les findings")
    ap.add_argument("--json-sans-info", action="store_true", help="Omet les findings 'info' du JSON (log plus léger ; Δ inchangé)")
    args = ap.parse_args()

    banner("PROTOCOLE ECHO-2026 v5-SHADOW — SONDE ONTOLOGIQUE", C.BMAGENTA)

    # 1. Base en lecture seule
    db_path = Path(args.db)
    if not db_path.exists():
        log(f"Base de données introuvable : {db_path}", "err")
        sys.exit(2)
    try:
        conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        colonnes = [r["name"] for r in conn.execute("PRAGMA table_info(internetdb)")]
        if "ip" not in colonnes:
            raise ValueError("table 'internetdb' absente ou sans colonne 'ip'")
        indexee = any(any(c["name"] == "ip" for c in conn.execute(f"PRAGMA index_info({i['name']})"))
                      for i in conn.execute("PRAGMA index_list(internetdb)"))
    except Exception as e:
        log(f"Erreur d'accès à la DB : {e}", "err")
        sys.exit(2)
    log(f"Mémoire Lithique ouverte (lecture seule) : {db_path.name} — colonnes : {', '.join(colonnes)}", "ok")
    if not indexee:
        log("Colonne 'ip' non indexée : lecture par lots, mais un index (CREATE INDEX idx_ip ON internetdb(ip)) accélérerait beaucoup.", "warn")

    # 2. Cibles
    tf = Path(args.targets)
    if not tf.exists():
        log(f"Fichier de cibles introuvable : {tf}", "err")
        sys.exit(2)
    saisies = lire_cibles(tf, args.max_expand)
    hosts = charger_hosts_file(args.hosts_file) if args.hosts_file else None
    if not args.no_dns and any(not _est_ip(s) for s, _ in saisies):
        log("Résolution DNS système active : la CIBLE n'est pas contactée, mais votre résolveur voit les noms. "
            "Utilisez --no-dns / --hosts-file pour l'éviter.", "warn")
    resolues, vus, non_resolues = [], set(), 0
    for saisie, _ in saisies:
        ip_str = resolver_local(saisie, args.no_dns, hosts)
        if not ip_str:
            non_resolues += 1
            log(f"Impossible de résoudre localement : {saisie}", "warn")
            continue
        ip_str = ipaddress.ip_address(ip_str).compressed
        if ip_str in vus:
            continue
        vus.add(ip_str)
        resolues.append((ip_str, saisie))
    log(f"{len(saisies)} entrée(s) → {len(resolues)} IP uniques ({non_resolues} non résolue(s)).", "ok")
    if not resolues:
        log("Rien à analyser.", "err")
        sys.exit(1)

    # 3. Session
    ts_dt = datetime.now(timezone.utc)
    ts = ts_dt.strftime("%Y-%m-%dT%H:%M:%S")
    empreinte = hashlib.sha1("\n".join(ip for ip, _ in resolues).encode()).hexdigest()[:6]
    session_id = f"S{ts_dt.strftime('%Y%m%d_%H%M%S')}_{empreinte}"
    seed = args.seed or ts_dt.strftime("%Y%m%d%H%M")      # fixé UNE fois pour toute la session
    ctx = Ctx(args, session_id, ts, seed)
    if args.kev:
        ctx.kev = charger_kev(args.kev)
        log(f"Catalogue KEV chargé : {len(ctx.kev)} CVE.", "ok")
    if args.baseline > 0:
        ctx.freq_ports, ctx.freq_n = echantillon_baseline(conn, args.baseline)
        if ctx.freq_n:
            ctx.baseline_source = "db"
            log(f"Population de référence : {ctx.freq_n} lignes échantillonnées.", "ok")

    # 4. Lecture par lots + passe 1
    section("PASSE 1 — lecture du souvenir, cible par cible", C.BCYAN)
    lignes = chercher_lignes(conn, [ip for ip, _ in resolues], colonnes)
    n = len(resolues)
    for i, (ip_str, saisie) in enumerate(resolues, 1):
        progress(i, n, ip_str)
        analyser_cible(ip_str, saisie, lignes.get(ip_str), ctx)
        if args.ma and i % args.batch_size == 0 and i < n:
            ma_pause()
    conn.close()

    # 5. Passe 2 : lot + dérive ; scores
    section("PASSE 2 — le lot s'interroge lui-même", C.BCYAN)
    hist_cibles = Path(args.out) / "echo_2026_historique_cibles.csv"
    precedent = {} if args.no_history else charger_precedent(hist_cibles, set(ctx.profils), args.sep)
    if precedent:
        log(f"{len(precedent)} cible(s) déjà vue(s) lors de sessions précédentes : calcul de la dérive.", "ok")
    passe_lot(ctx, precedent)
    calculer_scores(ctx)

    P = list(ctx.profils.values())
    deltas, omegas, lambdas = [p["delta_cible"] for p in P], [p["omega"] for p in P], [p["lambda"] for p in P]
    delta_cumul = indice(ctx.rap.items, "MESURÉ")
    delta = delta_cumul if args.delta_mode == "cumul" else round(sum(deltas) / len(deltas), 3)

    # 6. Affichage
    if args.verbose:
        afficher_tout(ctx, args.pur)
    afficher_classement(ctx, args.top, args.pur)

    section("SYNTHÈSE DE LA SONDE", C.BGREEN)
    mes = ctx.rap.mesures()
    cnt = Counter(f["severite"] for f in mes)
    print(f"  {C.BOLD}Δ = {delta:.3f}{C.RESET} — {interpreter(delta)}"
          + (f"  {C.DIM}(mode {args.delta_mode}){C.RESET}"))
    print(f"  {C.DIM}Δ moyen/cible {sum(deltas)/len(deltas):.3f} · Ω moyen {sum(omegas)/len(omegas):.3f} · "
          f"Λ moyen {sum(lambdas)/len(lambdas):.3f} · Δ max {max(deltas):.3f} · Ω max {max(omegas):.3f}{C.RESET}")
    print(f"  {C.DIM}{len(mes)} observation(s) MESURÉ : " + ", ".join(f"{cnt[s]} {s}" for s in SEV_ORDRE if cnt[s]) + f"{C.RESET}")
    etq = Counter(p["etiquette"] for p in P)
    print(f"  {C.DIM}Étiquettes : " + ", ".join(f"{k} {v}" for k, v in etq.most_common()) + f"{C.RESET}")
    if not args.pur:
        pro = "Le silence s'installe. La carte est tracée." if delta < 0.30 else "Les strates se superposent. Le Transept est proche."
        print(f"\n  {C.ITALIC}{C.BYELLOW}PROPHÉTIE : {pro}{C.RESET}")

    # 7. Exports
    section("EXPORTS", C.BGREEN)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    sess = {"session_id": session_id, "ts_utc": ts, "version": VERSION, "seed": seed, "db": db_path.name,
            "targets_file": tf.name, "n_saisies": len(saisies), "n_resolues": len(resolues),
            "n_en_cache": sum(p["en_cache"] for p in P), "n_findings": len(ctx.rap.items),
            "delta_global": delta, "delta_moyen": round(sum(deltas) / len(deltas), 4), "delta_max": max(deltas),
            "omega_moyen": round(sum(omegas) / len(omegas), 4), "omega_max": max(omegas),
            "lambda_moyen": round(sum(lambdas) / len(lambdas), 4), "baseline_n": ctx.freq_n,
            "baseline_source": ctx.baseline_source, "pur": int(args.pur), "kev": int(bool(ctx.kev)),
            "duree_s": round(time.time() - t0, 2)}

    # 7a. JSON historique (contrat echo_2026_viz.py : findings + delta + timestamp)
    findings_json = [f for f in ctx.rap.items if not (args.json_sans_info and f["severite"] == "info")]
    out = out_dir / f"echo_2026_shadow_{ts_dt.astimezone().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({
        "version": VERSION, "mode": "PASSIF (SQLite, lecture seule)",
        "timestamp": ts_dt.isoformat(), "session_id": session_id, "seed": seed,
        "delta": delta, "delta_formule": "cumul: 1-exp(-sum(poids_MESURÉ)/0.25)" if args.delta_mode == "cumul"
                                         else "moyen: moyenne des Δ par cible",
        "delta_moyen_cibles": sess["delta_moyen"], "delta_max_cible": sess["delta_max"],
        "omega_moyen": sess["omega_moyen"], "lambda_moyen": sess["lambda_moyen"],
        "poids": SEV_W,
        "cibles": [{"ip": p["ip"], "delta": p["delta_cible"], "omega": p["omega"], "lambda": p["lambda"],
                    "etiquette": p["etiquette"], "en_cache": p["en_cache"]} for p in P],
        "findings": findings_json,
    }, indent=2, ensure_ascii=True, default=str), encoding="utf-8")     # ASCII-safe : lisible par viz quel que soit l'OS
    log(f"Log JSON (compatible echo_2026_viz.py) : {out}", "ok")

    # 7b. Dataset KNIME
    if not args.no_dataset:
        ds_dir = out_dir / f"echo_2026_dataset_{session_id}"
        exporter_dataset(ctx, ds_dir, sess, args.sep, args.onehot_top, args.parquet)
        log(f"Dataset KNIME : {ds_dir}", "ok")
    # 7c. Historique cumulatif (indépendant du dataset : alimente la dérive des sessions suivantes)
    if not args.no_history:
        ajouter_historique(hist_cibles, COLS_CIBLES, P, args.sep)
        ajouter_historique(out_dir / "echo_2026_historique_sessions.csv", COLS_SESSION, [sess], args.sep)
        log("Historique cumulatif mis à jour (echo_2026_historique_*.csv).", "ok")
    log(f"Terminé en {time.time() - t0:.1f}s.", "ok")

def _est_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{C.BRED}⚠ Rituel interrompu. Le silence est préservé.{C.RESET}")
        sys.exit(1)
