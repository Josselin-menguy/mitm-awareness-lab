# MITM Awareness Lab

Ce dépôt propose un environnement de démonstration complet pour sensibiliser aux attaques de type "Man-in-the-Middle" (MITM) sur un réseau local. Il permet de simuler une attaque combinée d'ARP poisoning, DNS spoofing et d'interception de requêtes HTTP/HTTPS via un proxy transparent.

## Objectif

Ce projet a pour but **pédagogique** de montrer comment un attaquant peut intercepter des données sensibles dans un réseau local mal protégé. Il permet notamment de démontrer comment les requêtes POST peuvent être capturées même lorsqu’un site utilise HTTPS.

## Composants

- **ARP Spoofing** : usurpation de la passerelle et du serveur cible
- **DNS Spoofing** : redirection de certains noms de domaine vers un faux serveur
- **Proxy HTTPS transparent** : mitmdump (mitmproxy) utilisé pour intercepter et décrypter le trafic chiffré
- **Sniffer POST** : script personnalisé pour capturer et enregistrer les requêtes POST

## Structure du dépôt

- `arp_tls.py` : script principal lançant l’attaque
- `post_sniffer.py` : script mitmproxy pour enregistrer les requêtes POST interceptées
- `dnsSpoofed.txt` : mapping des domaines à rediriger vers un faux serveur
- `posts.txt` : fichier généré contenant les requêtes POST capturées
- `README.md` : ce fichier

## ⚙️ Prérequis

- Linux (Kali recommandé)
- Python 3
- `scapy`, `netfilterqueue`, `mitmproxy`
- Accès root (ou sudo)

## 🧪 Utilisation

1. **Configurer les variables** dans `arp_tls.py` : adresses IP, interface, etc.
2. **Lancer le script avec les droits administrateur** :

```bash
sudo python3 arp_tls.py
