# Proteus-SMC Chat Client

Terminal de messagerie chiffrée point-à-point. Chaque session établit un canal
sécurisé via un handshake ECDH (X25519), puis chiffre les échanges avec
**SMCCipher**.

---

## Prérequis

```bash
pip install -e ".[client]"   # depuis la racine du dépôt
```

La dépendance ajoutée est `cryptography>=41.0` (pour X25519).
Le reste repose sur la stdlib Python.

---

## Démarrage rapide — deux terminaux sur la même machine

**Terminal 1** (côté serveur) :

```bash
python client/chat.py listen --port 5000
```

```
[SMC] En écoute sur le port 5000
[SMC] Session ID : 5000  (partagez ce numéro avec votre pair)
[SMC] En attente de connexion...
```

**Terminal 2** (côté client) :

```bash
python client/chat.py connect --port 5000
```

```
[SMC] Connexion à 127.0.0.1:5000...
[SMC] Handshake ECDH (X25519)...
[SMC] ✓ Session établie
[SMC] Empreinte    : 90fb49c54bfb9335
[SMC] Vérifiez que votre pair affiche la même empreinte.
[SMC] Tapez vos messages. Ctrl+C ou Ctrl+D pour quitter.

>
```

Les deux terminaux affichent la même **empreinte de session** (16 caractères
hexadécimaux). Si les empreintes diffèrent, la connexion doit être avortée.

---

## Connexion entre deux machines

```bash
# Machine A — écoute
python client/chat.py listen --port 5000

# Machine B — connexion vers A
python client/chat.py connect --host 192.168.1.42 --port 5000
```

Le **Session ID** est simplement `HOST:PORT`. Partagez-le avec votre pair
par n'importe quel canal (texto, voix…) — il ne contient aucun secret.

---

## Options

| Commande  | Option   | Défaut      | Description                        |
|-----------|----------|-------------|------------------------------------|
| `listen`  | `--port` | `51820`     | Port TCP d'écoute                  |
| `connect` | `--host` | `127.0.0.1` | Adresse IP ou hostname du serveur  |
| `connect` | `--port` | `51820`     | Port TCP du serveur                |

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
        │
        ▼
Boucle de messagerie
  Thread réception  ──► déchiffre + affiche
  Thread principal  ──► lit stdin + chiffre + envoie
```

Aucune clé ne transite sur le réseau — seules les clés publiques éphémères
et les nonces (non secrets) sont échangés pendant le handshake.

---

## Quitter

`Ctrl+C` ou `Ctrl+D` ferme proprement la session des deux côtés.
