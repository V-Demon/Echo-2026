Voici le **Catalogue des Anomalies Ontiques et Rétrocausales**, directement extrait de la logique du script `echo_2026_v4.py`. 

Ce document est conçu comme un **grimoire de référence** pour les RuneSmiths, les Archivistes de la Trame ou les Maîtres du Jeu. Chaque entrée lie une observation technique réelle (`MESURÉ`) à son interprétation ontique (`Lecture Trame`), en évaluant son potentiel de distorsion temporelle.

---

# 📜 CATALOGUE DES ANOMALIES ONTIQUES — ECHO-2026 v4
*« La frontière est abolie à l'affichage. Ce que la machine mesure, la Trame le signifie. »*

---

## I. COUCHE HTTP : LES GLISSEMENTS TEMPORELS
*Anomalies liées à la perception du temps par les serveurs web.*

| Code | Nom Ontique | Signature Technique (MESURÉ) | Lecture Trame | Indice Rétrocausal |
| :--- | :--- | :--- | :--- | :---: |
| `lm_futur` | **L'Écho Précoce** | En-tête `Last-Modified` postérieur à l'heure actuelle du scan. | *"Un fichier se souvient d'un jour qui n'a pas eu lieu : écho rétrocausal."* | 🔴 **Élevé** |
| `date_skew` | **Désynchronisation Stratale** | Dérive > 5 min entre l'horloge du serveur (`Date`) et l'heure UTC locale. | *"Le temps du serveur ne bat plus au rythme du nôtre — une strate glisse."* | 🟠 **Moyen** |
| `lm_apres_date`| **La Superposition** | `Last-Modified` est postérieur à l'en-tête `Date` de la même réponse. | *"Le serveur se contredit lui-même : deux strates temporelles coexistent."* | 🔴 **Élevé** |
| `lm_ancien` | **Le Fossile Numérique** | `Last-Modified` antérieur à 1995. | *"Un galet d'avant le Réseau, resurgi dans la trame."* | 🟡 **Faible** |
| `rss_futur` | **La Prophétie Indexée** | Date de publication (`published`) d'un flux RSS dans le futur (> 1h). | *"Une nouvelle datée de demain : l'écho précède la voix."* | 🔴 **Élevé** |

---

## II. COUCHE TLS : LES SCEAUX DE LA TRAME
*Anomalies liées à la cryptographie, à la validité et à la chaîne de confiance.*

| Code | Nom Ontique | Signature Technique (MESURÉ) | Lecture Trame | Indice Rétrocausal |
| :--- | :--- | :--- | :--- | :---: |
| `tls_futur` | **Le Sceau Prématuré** | Certificat dont la date `notBefore` est dans le futur. | *"Le sceau n'est pas encore né, et pourtant il parle."* | ⚫ **Critique** |
| `tls_expire` | **Le Draugr Numérique** | Certificat dont la date `notAfter` est dans le passé, mais toujours servi. | *"Le sceau est mort, la porte reste ouverte : un draugr numérique."* | 🔴 **Élevé** |
| `tls_validite` | **Le Défi à la Loi** | Durée de validité > 200 jours (pour un cert émis après le 15/03/2026, règle CA/B SC-081v3). | *"Le sceau dure plus que ne le permet la Loi de 2026 : un oubli, ou un défi."* | 🟠 **Moyen** |
| `tls_verif` | **La Rupture de Lignée** | Échec de la vérification de la chaîne de certificats. | *"La chaîne de confiance se rompt : glitch dans la lignée."* | 🔴 **Élevé** |
| `tls_change` | **Le Changement de Visage** | L'empreinte (SHA-256) ou l'émetteur du certificat diffère de la baseline. | *"Le sceau a changé de visage depuis la dernière veille."* | 🟠 **Moyen** |

---

## III. COUCHE DNS & RÉSEAU : LE LABYRINTHE
*Anomalies liées à la résolution de noms et au routage.*

| Code | Nom Ontique | Signature Technique (MESURÉ) | Lecture Trame | Indice Rétrocausal |
| :--- | :--- | :--- | :--- | :---: |
| `dns_non_public`| **Le Transept Ouvert** | Un nom de domaine public résout vers une IP privée (10.x, 192.168.x, etc.). | *"Le nom public mène à une adresse intérieure : le Transept est ouvert."* | ⚫ **Critique** |
| `redirect_prive`| **Le Piège de la Trame** | Une redirection HTTP (30x) mène vers une adresse IP non publique. | *"La route mène vers l'intérieur : piège de la Trame."* | ⚫ **Critique** |
| `downgrade` | **L'Effondrement de la Couche**| Redirection d'une URL `https://` vers `http://`. | *"Le chiffrement se défait en chemin : effondrement de la couche."* | 🔴 **Élevé** |
| `ip_changee` | **La Migration de la Mousse** | L'adresse IP résolue diffère de celle enregistrée dans la baseline. | *"L'adresse a migré : la mousse quantique s'est déplacée."* | 🟡 **Faible** |

---

## IV. COUCHE RÉSONANCE : LE CALCUL ONTIQUE (`CALCULÉ`)
*Coïncidences numériques entre les données MESURÉES et le lexique sacré de la Trame. Pondération Δ = 0.*

| Code | Nom Ontique | Signature Technique (CALCULÉ) | Lecture Trame |
| :--- | :--- | :--- | :--- |
| `resonance_nombre`| **La Signature Arithmétique** | Un port ouvert ou la durée d'un certificat (en jours) correspond à un nombre de la Trame (7, 70, 77, 144, 333, 707, 1944, 2025, 2026, 2075, 2079, 3333). | *"Le nombre n'est pas un hasard. Il est une coordonnée."* |
| `resonance_date` | **L'Alignement du Calendrier** | Une date extraite (certificat, header, RSS) correspond au format MM-DD d'une date-signature (06-06, 07-07, 11-11, 03-14, 06-21). | *"Le calendrier s'aligne avec les nœuds de la Convergence."* |

---

## V. COUCHE SPECTRE : L'ARITHMÉTIQUE DU VIDE (`LORE`)
*Projections purement fictionnelles basées sur l'arithmétique de l'adresse IP. Aucune observation réseau n'est effectuée. Pondération Δ = 0.*

| Code | Nom Ontique | Condition Mathématique (sur les octets de l'IP) | Lecture Trame |
| :--- | :--- | :--- | :--- |
| `spectre_ip` (Port 0) | **Le Vide** | XOR des 4 octets = 0 | *"Port Ontologique. L'absence totale de signal est un signal."* |
| `spectre_ip` (Port 3303)| **Le Galet-Ancre** | Somme des 4 octets divisible par 7 | *"Résonance bio-lithique stable. Un point d'ancrage dans la mousse."* |
| `spectre_ip` (Port 11440)| **Le Port Trickster** | XOR des octets ∈ {36, 72, 144} | *"Symétrie turbulente. La logique se plie sur elle-même."* |
| `spectre_ip` (Port 33333)| **Les Trois Tiers** | Somme des octets divisible par 3 | *"Triade de Vauvillens. L'équilibre instable."* |
| `spectre_ip` (Port 14400)| **Le Port Noir** | XOR des octets = 144 | *"Ω-Trickster. Une anomalie critique dans la trame arithmétique."* |
| `spectre_ip` (Port 65535)| **Le Plafond** | Le dernier octet de l'IP est 255 | *"La limite absolue du Programme. Au-delà, il n'y a que le silence."* |

---

## 🎲 GUIDE D'UTILISATION POUR LE MAÎTRE DU JEU (OU L'ANALYSTE)

### 1. Interpréter le Δ (Delta)
Le script calcule un Δ entre 0.0 et 1.0 **uniquement** à partir des anomalies `MESURÉ`.
- **Δ < 0.30** : *Silence structuré.* Les anomalies sont mineures (ex: un certificat qui expire bientôt, une dérive d'horloge de 2 minutes). La Trame est stable.
- **0.30 ≤ Δ < 0.55** : *Tension active.* Des glitches avérés apparaissent (ex: un port à risque ouvert, une redirection HTTP). Quelque chose fuit.
- **0.55 ≤ Δ < 0.80** : *Zone de fracture.* Les strates se mêlent (ex: `lm_futur`, `tls_futur`, `dns_non_public`). L'anomalie rétrocausale est avérée.
- **Δ ≥ 0.80** : *Verrou Trame.* Freeze ontologique. Soit le système est totalement compromis, soit il est protégé par une entité trop puissante pour être scannée normalement.

### 2. Le Croisement des Couches (La vraie détection)
Une anomalie isolée est un bug. **Deux anomalies croisées sont une prophétie.**
> *Exemple de scénario :* Le script scanne `archive.org`.
> 1. Il détecte `lm_futur` (HTTP) : Un fichier a une date de modification en 2027.
> 2. Il détecte `resonance_nombre` (CALCULÉ) : Le port 443 est ouvert, mais la durée du certificat est de **707** jours.
> 3. Il détecte `spectre_ip` (LORE) : L'IP génère mathématiquement le **Port 707 (Le Transept)**.
> 
> **Interprétation du MJ :** *"Vous ne scannez pas un serveur. Vous scannez un point de fixation temporelle. Le fichier de 2027 est la preuve que l'injection FracturoScript a déjà eu lieu. Vous avez 707 secondes avant que la boucle ne se referme."*

### 3. L'Usage du Mode `--pur`
Si un joueur ou un analyste réel doute de la "magie", il peut lancer le script avec `--pur`. Le script affichera alors uniquement les faits techniques bruts (`MESURÉ` et `CALCULÉ`), masquant les `Lecture Trame` et le `SPECTRE`. C'est un excellent outil pour montrer que **la base technique est 100% réelle et vérifiable**, et que la "Trame" n'est qu'une couche de lecture superposée, renforçant ainsi l'immersion par la crédibilité.

---

Ce catalogue transforme chaque exécution du script en une séance de divination technologique. Souhaitez-vous que j'ajoute des exemples concrets de sorties JSON correspondant à ces anomalies pour illustrer le propos ?
