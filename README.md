# Proteus-SMC Chat Client

Client de messagerie chiffrée point-à-point utilisant le protocole SMC.
Chaque session établit un canal sécurisé via un handshake ECDH (X25519), puis
chiffre les échanges avec **SMCCipher**.

Deux interfaces disponibles : terminal (deux processus) et web (Alice + Bob
dans un seul onglet navigateur).

---

## Prérequis

```bash
# Dépôt voisin requis : ../Proteus/  (fournit proteus_smc)
pip install -r requirements.txt
```

Dépendances : `cryptography>=41.0`, `flask>=3.0`, `flask-socketio>=5.3`,
`eventlet>=0.35`.

---

## Interface terminal — deux processus

**Terminal 1** (côté serveur) :

```bash
python chat.py listen --port 5000
```

```
[SMC] En écoute sur le port 5000
[SMC] En attente de connexion...
```

**Terminal 2** (côté client) :

```bash
python chat.py connect --port 5000
```

```
[SMC] ✓ Session établie
[SMC] Empreinte : 90fb49c54bfb9335
[SMC] Tapez vos messages. Ctrl+C ou Ctrl+D pour quitter.
```

Les deux terminaux affichent la même **empreinte de session** (16 caractères
hexadécimaux). Si les empreintes diffèrent, la connexion doit être avortée.

### Connexion entre deux machines

```bash
# Machine A — écoute
python chat.py listen --port 5000

# Machine B — connexion vers A
python chat.py connect --host 192.168.1.42 --port 5000
```

### Options CLI

| Commande  | Option   | Défaut      | Description                       |
|-----------|----------|-------------|-----------------------------------|
| `listen`  | `--port` | `51820`     | Port TCP d'écoute                 |
| `connect` | `--host` | `127.0.0.1` | Adresse IP ou hostname du serveur |
| `connect` | `--port` | `51820`     | Port TCP du serveur               |

---

## Interface web — Alice & Bob dans le navigateur

Démo visuelle : Alice et Bob communiquent via une vraie connexion TCP locale ;
le texte chiffré (hex) est affiché en temps réel entre les deux panneaux.

```bash
python web/app.py
# Ouvrir http://localhost:5000
```

### Architecture

```
Browser (un seul onglet)
  ├── Panneau Alice ──► SocketIO ──► Flask app
  │                                    ├── Alice : écoute sur 127.0.0.1:PORT
  │        (colonne ciphertext)         │         SMCCipher(key, seed)
  │                                    └── Bob   : connecte à 127.0.0.1:PORT
  └── Panneau Bob  ──► SocketIO ──►            SMCCipher(key, seed)
```

- Connexion TCP réelle en localhost, handshake X25519 complet à chaque session.
- Deux instances `SMCCipher` dérivées du même échange ECDH.
- L'empreinte de session est affichée en haut de page.
- Appuyer sur **Entrée** ou cliquer **Send** pour envoyer un message.

---

## Ce qui se passe sous le capot

```
Connexion TCP établie
        │
        ▼
Handshake ECDH (X25519)
  ┌─────────────────────────────────────────┐
  │  Alice ──[HELLO: nonce_A, pub_A]──► Bob │
  │  Alice ◄─[HELLO_ACK: nonce_B, pub_B]── │
  │  shared_dh = X25519(priv, pub_other)    │
  │  session_key, session_seed              │
  │    = PBKDF2(shared_dh, nonces, 100k)   │
  │  Alice ──[ACK_CONFIRM: HMAC tag]──► Bob │
  │  Bob vérifie le tag (hmac.compare)      │
  └─────────────────────────────────────────┘
        │
        ▼
SMCCipher(key=session_key, seed=session_seed)
  Chaque message = encrypt(texte) → longueur (4B) + ciphertext sur le fil
```

Aucune clé ne transite sur le réseau — seules les clés publiques éphémères
et les nonces (non secrets) sont échangés pendant le handshake.

---

## Structure du projet

```
Proteus-client/
├── chat.py          # CLI deux-terminaux
├── handshake.py     # Handshake ECDH X25519 (initiator + responder)
├── requirements.txt
├── proposition.md   # Spécification du protocole de handshake
└── web/
    ├── app.py               # Serveur Flask-SocketIO
    ├── templates/
    │   └── index.html       # UI deux panneaux
    └── static/
        ├── style.css
        └── app.js
```

---

## Quitter

- **Terminal** : `Ctrl+C` ou `Ctrl+D`
- **Web** : fermer l'onglet, puis `Ctrl+C` dans le terminal serveur
