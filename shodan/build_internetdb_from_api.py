#!/usr/bin/env python3
"""
build_internetdb_from_api.py — plan B sans accès Enterprise.

Construit un petit internetdb.sqlite à partir de l'API gratuite https://internetdb.shodan.io/<ip>
(sans clé, rafraîchie chaque semaine par Shodan, gratuite pour un usage non commercial)
UNIQUEMENT pour les IP de votre fichier de cibles.

  • Les cibles ne sont jamais contactées : seul internetdb.shodan.io l'est (mais Shodan voit
    la liste des IP que vous interrogez — c'est la contrepartie du plan B).
  • Schéma produit, compatible echo_2026_v5-shadow.py :
      internetdb(ip PRIMARY KEY, ports, hostnames, cpe, vulns, tags, last_update)
    Listes en JSON. L'API nomme le champ « cpes » : il est stocké dans la colonne « cpe ».
  • last_update reste NULL : l'API ne donne pas la date d'observation (mettre la date du
    téléchargement fausserait les anomalies « souvenir périmé »).
  • IP absente de l'API (HTTP 404) : aucune ligne => « shadow_inconnu » dans la sonde.
  • Reprise : les IP déjà présentes sont ignorées (--refresh pour les réinterroger).

Usage :
  python build_internetdb_from_api.py --targets cibles.txt --db internetdb.sqlite
  python build_internetdb_from_api.py --targets cibles.txt --db internetdb.sqlite --delay 1.5
"""
import argparse
import ipaddress
import json
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

def lire_ips(path, max_expand):
    ips, vus = [], set()
    for ligne in Path(path).read_text(encoding="utf-8-sig").splitlines():
        t = ligne.split("#")[0].strip()
        if not t:
            continue
        try:
            if "/" in t:
                net = ipaddress.ip_network(t, strict=False)
                if net.num_addresses > max_expand:
                    print(f"CIDR {t} ignoré ({net.num_addresses} adresses > --max-expand)", file=sys.stderr)
                    continue
                cand = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
            else:
                cand = [str(ipaddress.ip_address(t))]
        except ValueError:
            print(f"Ignoré (pas une IP/CIDR ; l'API n'accepte que des IP) : {t}", file=sys.stderr)
            continue
        for ip in cand:
            if ip not in vus:
                vus.add(ip)
                ips.append(ip)
    return ips

def interroger(base, ip, timeout, essais=4):
    """Retourne le dict JSON, None si 404 (inconnue), lève RuntimeError si échec persistant."""
    attente = 5
    for _ in range(essais):
        req = urllib.request.Request(f"{base.rstrip('/')}/{ip}", headers={"User-Agent": "echo-2026-builder"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429 or e.code >= 500:
                time.sleep(attente)
                attente *= 2
                continue
            raise RuntimeError(f"HTTP {e.code}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            time.sleep(attente)
            attente *= 2
    raise RuntimeError("échecs répétés")

def main():
    ap = argparse.ArgumentParser(description="Construit internetdb.sqlite depuis l'API gratuite InternetDB")
    ap.add_argument("--targets", required=True)
    ap.add_argument("--db", default="internetdb.sqlite")
    ap.add_argument("--delay", type=float, default=1.0, help="Pause entre requêtes (s). Soyez courtois.")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--max-expand", type=int, default=1024)
    ap.add_argument("--refresh", action="store_true", help="Réinterroge aussi les IP déjà en base")
    ap.add_argument("--base-url", default="https://internetdb.shodan.io")
    a = ap.parse_args()

    ips = lire_ips(a.targets, a.max_expand)
    if not ips:
        sys.exit("Aucune IP exploitable.")
    conn = sqlite3.connect(a.db)
    conn.execute("""CREATE TABLE IF NOT EXISTS internetdb(
        ip TEXT PRIMARY KEY, ports TEXT, hostnames TEXT, cpe TEXT, vulns TEXT, tags TEXT, last_update TEXT)""")
    deja = {r[0] for r in conn.execute("SELECT ip FROM internetdb")}
    a_faire = ips if a.refresh else [ip for ip in ips if ip not in deja]
    print(f"{len(ips)} IP, {len(a_faire)} à interroger ({len(ips) - len(a_faire)} déjà en base).")

    ok = inconnues = erreurs = 0
    try:
        for i, ip in enumerate(a_faire, 1):
            try:
                d = interroger(a.base_url, ip, a.timeout)
            except RuntimeError as e:
                erreurs += 1
                print(f"  {ip}: {e}", file=sys.stderr)
                d = False
            if d:
                conn.execute("INSERT OR REPLACE INTO internetdb VALUES(?,?,?,?,?,?,NULL)", (
                    ip, json.dumps(d.get("ports", [])), json.dumps(d.get("hostnames", [])),
                    json.dumps(d.get("cpes", [])), json.dumps(d.get("vulns", [])), json.dumps(d.get("tags", []))))
                ok += 1
            elif d is None:
                inconnues += 1
            if i % 50 == 0:
                conn.commit()
                print(f"  {i}/{len(a_faire)}…")
            time.sleep(a.delay)
    except KeyboardInterrupt:
        print("\nInterrompu : les données déjà récupérées sont conservées (relancez pour reprendre).")
    conn.commit()
    conn.close()
    print(f"Terminé : {ok} enregistrées, {inconnues} inconnues de Shodan (404), {erreurs} erreur(s). Base : {a.db}")

if __name__ == "__main__":
    main()
