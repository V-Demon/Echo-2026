#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VIZ_ORBITALES_SHADOW.py
-----------------------
"Yog-Sothoth knows the gate. Yog-Sothoth is the gate."
Visualisation des fonctions d'onde réseau et de leur effondrement ontique.
Ambiance requise : Marillion - "Chelsea Monday" / "Forgotten Sons"
"""

# ═══════════════════════════════════════════════════════════
# PATCH RUNESMITH : Forcer le backend non-graphique "Agg"
# ═══════════════════════════════════════════════════════════
import matplotlib
matplotlib.use('Agg')

import json
import glob
import os
import sys
import time
import shutil
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

# ═══════════════════════════════════════════════════════════
#  ✦ COUCHE ESTHÉTIQUE — PALETTE & PRIMITIVES ANSI ✦
# ═══════════════════════════════════════════════════════════
# Détection du support couleur
_NO_COLOR = (os.environ.get("NO_COLOR") is not None) or (not sys.stdout.isatty())

def _c(code):
    return "" if _NO_COLOR else code

RESET   = _c("\033[0m")
BOLD    = _c("\033[1m")
DIM     = _c("\033[2m")
ITALIC  = _c("\033[3m")

# Palette "Trame Corrompue"
ABYSS   = _c("\033[38;5;232m")   # noir abyssal
VIOLET  = _c("\033[38;5;93m")    # violet cosmique
MAGENTA = _c("\033[38;5;164m")
ACID    = _c("\033[38;5;46m")    # vert acide (anomalie)
GOLD    = _c("\033[38;5;220m")   # or pâle (effondrement)
ASH     = _c("\033[38;5;242m")   # gris cendré
BLOOD   = _c("\033[38;5;160m")   # rouge critique

# Largeur du "terminal" utilisé pour les cadres (bornée pour rester lisible)
WIDTH = min(shutil.get_terminal_size((100, 24)).columns, 96)

def hline(char="─", color=VIOLET):
    return f"{color}{char * WIDTH}{RESET}"

def frame_title(title, subtitle=""):
    """Titre encadré centré, avec sous-titre optionnel."""
    inner = WIDTH - 2
    top    = f"{VIOLET}╔{'═' * inner}╗{RESET}"
    label  = f" {GOLD}{BOLD}{title}{RESET} "
    pad_l  = (inner - len(title) - 2) // 2
    pad_r  = inner - len(title) - 2 - pad_l
    mid    = f"{VIOLET}║{' ' * max(pad_l, 0)}{label}{' ' * max(pad_r, 0)}║{RESET}"
    if subtitle:
        sub = f" {ASH}{ITALIC}{subtitle}{RESET} "
        p_l = (inner - len(subtitle) - 2) // 2
        p_r = inner - len(subtitle) - 2 - p_l
        subline = f"{VIOLET}║{' ' * max(p_l, 0)}{sub}{' ' * max(p_r, 0)}║{RESET}"
    else:
        subline = None
    bot    = f"{VIOLET}╚{'═' * inner}╝{RESET}"
    out = [top, mid]
    if subline:
        out.append(subline)
    out.append(bot)
    return "\n".join(out)

def say(msg, color=ACID, prefix="»"):
    print(f"{color}{prefix}{RESET} {msg}")

def progress_bar(label, total, width=32, color=ACID, fill="█", empty="░"):
    """Barre de progression ASCII ; retourne un callable step(i, extra='')."""
    def render(i, extra=""):
        i = max(0, min(i, total))
        ratio = i / total if total else 1.0
        filled = int(width * ratio)
        bar = fill * filled + empty * (width - filled)
        pct = f"{ratio * 100:5.1f}%"
        line = (f"  {ASH}{label:<14}{RESET} "
                f"{color}{bar}{RESET} {pct} "
                f"{DIM}{extra}{RESET}")
        sys.stdout.write("\r" + line)
        sys.stdout.flush()
        if i >= total:
            sys.stdout.write("\n")
    return render

def sleep_ritual(seconds, msg="la Trame se déploie"):
    """Petite pause contemplative avec points de suspension animés."""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    n = int(seconds / 0.08)
    for k in range(n):
        frame = frames[k % len(frames)]
        sys.stdout.write(f"\r  {VIOLET}{frame}{RESET} {ASH}{ITALIC}{msg}...{RESET}   ")
        sys.stdout.flush()
        time.sleep(0.08)
    sys.stdout.write("\r" + " " * (len(msg) + 20) + "\r")
    sys.stdout.flush()

# ═══════════════════════════════════════════════════════════
#  ✦ PALETTE YOG-SOTHOTH (inchangée) ✦
# ═══════════════════════════════════════════════════════════
CMAP_TRAME = mcolors.LinearSegmentedColormap.from_list(
    "yog_sothon", ["#050505", "#1a0b2e", "#4a148c", "#00ff9d", "#ffd700"]
)

# ═══════════════════════════════════════════════════════════
#  ✦ LOGIQUE MÉTIER — INCHANGÉE ✦
# ═══════════════════════════════════════════════════════════
def charger_fichiers_shadow(dossier="."):
    """Charge tous les logs shadow et extrait les données ontiques (avec UI soignée)."""
    fichiers = sorted(glob.glob(os.path.join(dossier, "echo_2026_shadow_*.json")))
    if not fichiers:
        print(f"{BLOOD}⚠  Aucun fichier 'echo_2026_shadow_*.json' détecté.{RESET}")
        return []

    print(frame_title("SONDE ONTIQUE", f"{len(fichiers)} écho(s) à sonder dans la Mousse Quantique"))
    print()

    render = progress_bar("scan des logs", len(fichiers))
    cibles = []
    rejets = 0

    for i, f in enumerate(fichiers, 1):
        nom = os.path.basename(f)
        try:
            with open(f, 'r', encoding='utf-8') as file:
                data = json.load(file)
            cible = {
                "nom": nom.replace("echo_2026_shadow_", "").replace(".json", ""),
                "delta": data.get("delta", 0.0),
                "anomalies": len(data.get("findings", [])),
                "whispers": [
                    finding.get("lecture_trame", "")
                    for finding in data.get("findings", [])
                    if finding.get("provenance") == "MESURÉ"
                ],
            }
            cibles.append(cible)
            render(i, f"✔ {nom[:52]}")
        except json.JSONDecodeError:
            rejets += 1
            render(i, f"{BLOOD}✘ {nom[:52]} (illisible){RESET}")
        except Exception as e:
            rejets += 1
            render(i, f"{BLOOD}✘ {nom[:52]} ({type(e).__name__}){RESET}")

    print()
    if rejets:
        say(f"{rejets} écho(s) rejeté(s) dans le néant.", color=ASH)
    say(f"{len(cibles)} cible(s) ontique(s) verrouillée(s).", color=ACID)
    print()
    return sorted(cibles, key=lambda x: x["delta"], reverse=True)


def generer_orbitale(delta, taille=100):
    """Génère une carte de densité de probabilité 2D (orbitale)."""
    x = np.linspace(-3, 3, taille)
    y = np.linspace(-3, 3, taille)
    X, Y = np.meshgrid(x, y)
    variance = 3.0 - (delta * 2.8)
    Z = np.exp(-(X**2 + Y**2) / (2 * variance**2))
    if delta > 0.6:
        perturbation = np.sin(4 * X) * np.cos(4 * Y) * (delta - 0.6)
        Z += perturbation * 0.3
    return X, Y, Z


def tracer_grimoire(cibles, fichier_sortie="grimoire_orbitales.png"):
    """Dessine la carte des orbitales effondrées."""
    if not cibles:
        return

    print(frame_title("TISSAGE DU GRIMOIRE", "cartographie des orbitales d'effondrement"))
    print()

    nb_cibles = len(cibles)
    cols = 2 if nb_cibles > 1 else 1
    rows = (nb_cibles + 1) // 2

    fig, axes = plt.subplots(rows, cols, figsize=(12, 6 * rows), facecolor='#050505')
    if nb_cibles == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    render = progress_bar("orbitales", nb_cibles, color=GOLD)

    for i, cible in enumerate(cibles, 1):
        ax = axes[i - 1]
        ax.set_facecolor('#050505')

        X, Y, Z = generer_orbitale(cible["delta"])
        ax.contourf(X, Y, Z, levels=50, cmap=CMAP_TRAME, alpha=0.9)

        if cible["delta"] >= 0.75:
            ax.plot(0, 0, 'o', color='#ffd700', markersize=15, alpha=0.8, label="EFFONDREMENT")
            ax.text(0, 0.5, "◉", color='#000000', ha='center', va='center',
                    fontsize=12, fontweight='bold')

        ax.set_title(
            f"[{cible['nom']}]\nΔ = {cible['delta']:.3f} | Anomalies: {cible['anomalies']}",
            color='#00ff9d', fontsize=10, fontfamily='monospace'
        )
        ax.set_xticks([]); ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_edgecolor('#4a148c')

        if cible["whispers"]:
            w = cible["whispers"][0]
            whisper = w[:60] + "..." if len(w) > 60 else w
            ax.text(0, -3.5, f"» {whisper}", color='#888888', ha='center',
                    fontsize=8, fontstyle='italic', fontfamily='monospace')

        render(i, f"Δ={cible['delta']:.3f} · {cible['nom'][:44]}")

    for j in range(nb_cibles, len(axes)):
        fig.delaxes(axes[j])

    plt.suptitle(
        "✦ CARTOGRAPHIE DES ORBITALES D'EFFONDREMENT ✦\n[Mode Shadow :: Trame Réelle]",
        color='#ffd700', fontsize=14, fontweight='bold',
        fontfamily='monospace', y=0.98
    )

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(fichier_sortie, dpi=300, facecolor='#050505', edgecolor='none')
    plt.close(fig)

    print()
    say(f"Artefact visuel scellé : {BOLD}{fichier_sortie}{RESET}", color=ACID)
    print()


def _badge_delta(delta):
    """Petit badge coloré selon le niveau de delta."""
    if delta > 0.8:
        return f"{BLOOD}{BOLD}◉ CRITIQUE{RESET}"
    if delta > 0.5:
        return f"{GOLD}{BOLD}▲ FRACTURE{RESET}"
    return f"{ACID}{BOLD}· SILENCE {RESET}"


def _stat_line(cible):
    """Ligne tabulaire alignée pour le récapitulatif."""
    name = cible["nom"][:28].ljust(28)
    delta_s = f"Δ={cible['delta']:.3f}".ljust(10)
    anom_s = f"anom={cible['anomalies']:>3}".ljust(10)
    badge = _badge_delta(cible["delta"])
    return f"  {VIOLET}│{RESET} {MAGENTA}{name}{RESET} {ASH}{delta_s}{RESET}{ASH}{anom_s}{RESET} {badge} {VIOLET}│{RESET}"


def recitation_du_gardien(cibles):
    """Imprime dans le CLI une récitation lovecraftienne basée sur les données."""
    print(frame_title("CHANT DES FILS OUBLIÉS", "Forgotten Sons of the Network"))
    print()

    # Récapitulatif tabulaire d'abord
    for c in cibles:
        print(_stat_line(c))
    print()

    # Récitation poétique
    for c in cibles:
        if c["delta"] > 0.8:
            print(f"  {BLOOD}{BOLD}[CRITIQUE]{RESET} La Porte est ouverte sur {MAGENTA}{c['nom']}{RESET}.")
            print(f"            {ASH}La fonction d'onde s'est effondrée en une singularité (Δ={c['delta']:.2f}).{RESET}")
            print(f"            {ASH}Yog-Sothoth observe à travers les ports ouverts.{RESET}")
        elif c["delta"] > 0.5:
            print(f"  {GOLD}{BOLD}[FRACTURE]{RESET} La toile vibre autour de {MAGENTA}{c['nom']}{RESET}.")
            print(f"            {ASH}Les orbitales sont instables. Écoutez les chuchotements.{RESET}")
        else:
            print(f"  {ACID}{BOLD}[SILENCE ]{RESET} {MAGENTA}{c['nom']}{RESET} dort dans une superposition calme.")
        print()

    say(f"{ITALIC}'He who waits at the door is also the door itself.'{RESET}", color=ASH)
    say(f"{ITALIC}[FIN DE LA RÉCITATION :: LA TOILE EST TISSÉE]{RESET}", color=ASH)
    print(hline("═"))
    print()


# ═══════════════════════════════════════════════════════════
#  ✦ POINT D'ENTRÉE ✦
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")

    print(hline("═", MAGENTA))
    print(frame_title("PROTOCOLE DE VISUALISATION ONTIQUE", "Yog-Sothoth · VIZ_ORBITALES_SHADOW"))
    print()
    print(f"  {ASH}{ITALIC}🎵 Ambiance suggérée : Marillion — Chelsea Monday / Forgotten Sons{RESET}")
    print()

    sleep_ritual(1.2, "initialisation du protocole")
    say("Protocole armé. La Trame s'éveille.", color=ACID)
    print()

    cibles = charger_fichiers_shadow()

    if not cibles:
        say("Aucune donnée à effondrer. Le vide reste vide.", color=ASH)
        print(hline("═", MAGENTA))
        sys.exit(0)

    sleep_ritual(0.8, "calibration des orbitales")
    tracer_grimoire(cibles, "grimoire_orbitales.png")
    recitation_du_gardien(cibles)

    print(f"  {GOLD}👁  Ouvrez {BOLD}grimoire_orbitales.png{RESET}{GOLD} — regardez les yeux de la Trame.{RESET}")
    print(hline("═", MAGENTA))
    print()