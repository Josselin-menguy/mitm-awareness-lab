# MITM Awareness Lab

Ce dépôt propose un environnement de **démonstration pédagogique** visant à sensibiliser aux attaques de type **Man-in-the-Middle (MITM)** et **DNS Spoofing** sur un réseau local. Il illustre comment un attaquant peut intercepter du trafic réseau, même chiffré, afin de collecter des données sensibles comme des identifiants.

## Objectif

Ce projet a pour but de démontrer, dans un environnement de test **isolé**, une attaque combinée de type MITM et DNS spoofing. Il s’inscrit dans une **démarche de sensibilisation à la cybersécurité**, et met en lumière l’importance :

* du chiffrement (HTTPS),
* de la vérification des certificats SSL/TLS,
* de la segmentation réseau et des mécanismes de détection d’anomalies.

## Fonctionnalités

* **Empoisonnement ARP** : usurpation simultanée de la passerelle, du faux site et de la victime.
* **Spoof DNS** : redirection de certains noms de domaines vers un faux serveur (ex: faux PayPal).
* **Proxy HTTPS transparent** : déchiffrement du trafic via `mitmdump` (de la suite mitmproxy).
* **Sniffer HTTP POST** : extraction automatique des données POST (mots de passe, tokens…).
* **Script unique automatisé** : déploiement complet via `arp_tls.py`.

## Architecture du lab

Ce lab repose sur un réseau local virtualisé composé de :

* Une **machine attaquante** (Kali Linux) avec le script principal.
* Une **machine victime** (navigateur utilisateur).
* Une **passerelle** (réelle ou simulée, comme VirtualBox NAT).
* Un **faux site web** hébergé localement (à créer manuellement, non fourni).

## Structure du dépôt

* `arp_tls.py` : script principal lançant l’attaque combinée.
* `post_sniffer.py` : script mitmproxy qui intercepte les requêtes POST.
* `dnsSpoofed.txt` : mapping des domaines à rediriger (ex: `paypal.com:192.168.1.103`).
* `posts.txt` : fichier généré contenant les requêtes POST interceptées.
* `README.md` : ce fichier.

## Prérequis

* Linux (Kali recommandé)
* Python 3.x
* Bibliothèques Python :
  `scapy`, `netfilterqueue`, `mitmproxy`
* Droits administrateur (sudo)

## Instructions

1. **Configurer les variables** dans `arp_tls.py` : interface réseau, IP, MACs, domaine à rediriger.
2. **Créer votre faux site web** (ex: en Flask ou Apache) à l’adresse IP configurée dans `dnsSpoofed.txt`.
3. **Lancer l’attaque** depuis la machine Kali :

```bash
sudo python3 arp_tls.py
```

Les requêtes POST interceptées seront automatiquement enregistrées dans `posts.txt`.

## Avertissement

Ce projet est **strictement réservé à un usage pédagogique** dans un environnement **fermé et contrôlé**. Toute utilisation en dehors d’un cadre légal ou autorisé est strictement interdite et illégale.


