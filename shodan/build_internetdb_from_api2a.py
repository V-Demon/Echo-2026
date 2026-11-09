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
  • last_update reste NULL : l'API ne donne pas la date d'observation.
  • IP absente de l'API (HTTP 404) : aucune ligne => « shadow_inconnu » dans la sonde.
  • Reprise : les IP déjà présentes sont ignorées (--refresh pour les réinterroger).

Usage :
  python build_internetdb_from_api.py --targets cibles.txt --db internetdb.sqlite
  python build_internetdb_from_api.py --targets cibles.txt --db internetdb.sqlite --delay 1.5
"""
import argparse
import ipaddress
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
#  Palette & helpers d'affichage
# ─────────────────────────────────────────────────────────────────────────────
_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class C:
    RESET = "\033[0m" if _TTY else ""
    BOLD = "\033[1m" if _TTY else ""
    DIM = "\033[2m" if _TTY else ""
    CYAN = "\033[36m" if _TTY else ""
    BLUE = "\033[94m" if _TTY else ""
    GREEN = "\033[32m" if _TTY else ""
    YELLOW = "\033[33m" if _TTY else ""
    RED = "\033[31m" if _TTY else ""
    MAGENTA = "\033[35m" if _TTY else ""
    GREY = "\033[90m" if _TTY else ""


def _w(s):
    """Écrit sur stdout en gérant l'absence de terminal."""
    sys.stdout.write(s)
    sys.stdout.flush()


def _fmt_dur(sec):
    if sec < 1:
        return f"{sec * 1000:.0f} ms"
    if sec < 60:
        return f"{sec:.1f} s"
    m, s = divmod(int(sec), 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m{s:02d}s"


def _fmt_int(n):
    return f"{n:,}".replace(",", " ")


def banner(base_url, targets, db):
    line = C.GREY + "─" * 66 + C.RESET
    _w(f"\n{C.CYAN}{C.BOLD}╭{'─' * 66}╮{C.RESET}\n")
    _w(f"{C.CYAN}│{C.RESET} {C.BOLD}{C.MAGENTA}◈  InternetDB Builder{C.RESET} "
       f"{C.GREY}— récolte passive depuis l'API Shodan{C.RESET}"
       f"{' ' * 8}{C.CYAN}│{C.RESET}\n")
    _w(f"{C.CYAN}╰{'─' * 66}╯{C.RESET}\n")
    _w(f"  {C.GREY}API     {C.RESET}{C.BLUE}{base_url}{C.RESET}\n")
    _w(f"  {C.GREY}Cibles  {C.RESET}{C.BOLD}{targets}{C.RESET}\n")
    _w(f"  {C.GREY}Base    {C.RESET}{C.BOLD}{db}{C.RESET}\n")
    _w(f"  {line}\n\n")


def progress_line(done, total, ok, unknown, errors, start, width=34):
    """Barre de progression + compteurs + ETA, réécrite sur place."""
    frac = done / total if total else 1.0
    filled = int(width * frac)
    # barre avec caractères pleins/dégradé
    bar = (C.GREEN + "█" * filled + C.RESET
           + C.GREY + "░" * (width - filled) + C.RESET)
    pct = f"{frac * 100:5.1f}%"
    elapsed = time.monotonic() - start
    rate = done / elapsed if elapsed > 0 else 0.0
    eta = (total - done) / rate if rate > 0 else 0.0

    stats = (
        f"{C.GREEN}●{C.RESET} {ok:<5} "
        f"{C.YELLOW}○{C.RESET} {unknown:<5} "
        f"{C.RED}✕{C.RESET} {errors:<4}"
    )
    line = (
        f"\r  {C.CYAN}[{C.RESET}{bar}{C.CYAN}]{C.RESET} "
        f"{C.BOLD}{pct}{C.RESET}  "
        f"{C.GREY}{done:>5}/{total:<5}{C.RESET}  "
        f"{stats}  "
        f"{C.GREY}{rate:5.2f} req/s  ETA {_fmt_dur(eta):>7}{C.RESET}   "
    )
    _w(line)


def event_line(ip, kind, detail="", pad=72):
    """Une ligne d'événement discrète sous la barre (nouvelle ligne)."""
    marks = {
        "ok":     (C.GREEN,  "●"),
        "unknown":(C.YELLOW, "○"),
        "error":  (C.RED,    "✕"),
        "info":   (C.BLUE,   "·"),
    }
    col, glyph = marks.get(kind, (C.GREY, "·"))
    _w(f"\r{' ' * pad}\r")  # efface la ligne de progression
    _w(f"    {col}{glyph}{C.RESET} {C.GREY}{ip:<15}{C.RESET} {detail}\n")


def summary(ok, unknown, errors, elapsed, db):
    line = C.GREY + "─" * 66 + C.RESET
    _w(f"\n  {line}\n")
    _w(f"  {C.BOLD}{C.MAGENTA}✦  Terminé{C.RESET}  {C.GREY}en {_fmt_dur(elapsed)}{C.RESET}\n\n")
    _w(f"    {C.GREEN}●{C.RESET} enregistrées {C.BOLD}{_fmt_int(ok):>7}{C.RESET}\n")
    _w(f"    {C.YELLOW}○{C.RESET} inconnues 404 {C.BOLD}{_fmt_int(unknown):>7}{C.RESET}\n")
    _w(f"    {C.RED}✕{C.RESET} erreurs       {C.BOLD}{_fmt_int(errors):>7}{C.RESET}\n")
    _w(f"    {C.GREY}base{C.RESET}          {C.BOLD}{db}{C.RESET}\n")
    _w(f"  {line}\n\n")


# ─────────────────────────────────────────────────────────────────────────────
#  Cœur fonctionnel (inchangé)
# ─────────────────────────────────────────────────────────────────────────────
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
                    event_line(t, "error", f"CIDR ignoré ({net.num_addresses} > --max-expand)")
                    continue
                cand = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
            else:
                cand = [str(ipaddress.ip_address(t))]
        except ValueError:
            event_line(t, "error", "pas une IP/CIDR (l'API n'accepte que des IP)")
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
        req = urllib.request.Request(
            f"{base.rstrip('/')}/{ip}",
            headers={"User-Agent": "echo-2026-builder"},
        )
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

    banner(a.base_url, a.targets, a.db)

    ips = lire_ips(a.targets, a.max_expand)
    if not ips:
        sys.exit(f"{C.RED}Aucune IP exploitable.{C.RESET}")

    conn = sqlite3.connect(a.db)
    conn.execute("""CREATE TABLE IF NOT EXISTS internetdb(
        ip TEXT PRIMARY KEY, ports TEXT, hostnames TEXT, cpe TEXT, vulns TEXT, tags TEXT, last_update TEXT)""")
    deja = {r[0] for r in conn.execute("SELECT ip FROM internetdb")}
    a_faire = ips if a.refresh else [ip for ip in ips if ip not in deja]

    skipped = len(ips) - len(a_faire)
    _w(f"  {C.GREY}▸{C.RESET} {C.BOLD}{_fmt_int(len(ips))}{C.RESET} IP lues  ·  "
       f"{C.BOLD}{_fmt_int(len(a_faire))}{C.RESET} à interroger  ·  "
       f"{C.GREY}{_fmt_int(skipped)} déjà en base{C.RESET}\n")

    if not a_faire:
        _w(f"\n  {C.GREEN}✓{C.RESET} Rien à faire — tout est déjà en cache. "
           f"{C.GREY}(--refresh pour réinterroger){C.RESET}\n")
        conn.close()
        summary(0, 0, 0, 0.0, a.db)
        return

    _w("\n")
    total = len(a_faire)
    ok = unknown = errors = 0
    start = time.monotonic()
    last_render = 0.0

    try:
        for i, ip in enumerate(a_faire, 1):
            try:
                d = interroger(a.base_url, ip, a.timeout)
            except RuntimeError as e:
                errors += 1
                event_line(ip, "error", str(e))
                d = False

            if d:
                conn.execute(
                    "INSERT OR REPLACE INTO internetdb VALUES(?,?,?,?,?,?,NULL)",
                    (ip, json.dumps(d.get("ports", [])),
                         json.dumps(d.get("hostnames", [])),
                         json.dumps(d.get("cpes", [])),
                         json.dumps(d.get("vulns", [])),
                         json.dumps(d.get("tags", []))),
                )
                ok += 1
                ports = d.get("ports", [])
                vulns = d.get("vulns", [])
                if isinstance(vulns, dict):
                    vulns = list(vulns)
                tagbits = []
                if ports:
                    tagbits.append(f"{C.CYAN}{len(ports)} ports{C.RESET}")
                if vulns:
                    tagbits.append(f"{C.RED}{len(vulns)} vulns{C.RESET}")
                detail = "  ".join(tagbits) if tagbits else f"{C.GREY}aucun port exposé{C.RESET}"
                event_line(ip, "ok", detail)
            elif d is None:
                unknown += 1
                event_line(ip, "unknown", f"{C.GREY}absent de l'API (404){C.RESET}")

            # rendu barre (throttlé à ~15 Hz pour ne pas saturer le terminal)
            now = time.monotonic()
            if now - last_render >= 0.066:
                progress_line(i, total, ok, unknown, errors, start)
                last_render = now

            if i % 50 == 0:
                conn.commit()

            time.sleep(a.delay)

    except KeyboardInterrupt:
        _w(f"\n\n  {C.YELLOW}⚠{C.RESET} Interrompu — les données déjà récupérées sont conservées.\n"
           f"    {C.GREY}Relancez pour reprendre là où vous en étiez.{C.RESET}\n")
    finally:
        conn.commit()
        conn.close()
        progress_line(total if not isinstance(sys.exc_info()[1], KeyboardInterrupt) else i,
                      total, ok, unknown, errors, start)
        elapsed = time.monotonic() - start
        _w("\n")
        summary(ok, unknown, errors, elapsed, a.db)


if __name__ == "__main__":
    main()