# Proposition : Protocole de Handshake Initial pour Proteus-SMC

## Contexte

`SMCCipher` nécessite que les deux parties partagent **avant tout échange** :
- `key` : un secret maître (≥ 16 octets)
- `seed` : un identifiant de session

Actuellement, ce partage est supposé acquis hors-bande. Le handshake proposé
ici résout ce problème en établissant ces deux valeurs de manière sécurisée
sur un canal non sécurisé, en deux variantes selon le modèle de confiance.

---

## Deux Variantes

### Variante A — PSK (Pre-Shared Key)

Les deux parties partagent déjà un secret hors-bande (mot de passe, passphrase).
Aucune dépendance externe. Implémentable avec la stdlib Python uniquement.

### Variante B — ECDH Éphémère (X25519)

Aucun secret préalable requis. Fournit la **confidentialité persistante
(Forward Secrecy)** : compromettre la clé longue durée après la session ne
révèle pas les échanges passés.
Nécessite la bibliothèque `cryptography`.

---

## Flux de Messages

```
Alice (initiateur)                          Bob (répondeur)
──────────────────                          ────────────────

  [1] Génère nonce_A (32B)
      Génère paire éphémère
      (priv_A, pub_A) [ECDH seulement]

  ──── HELLO ─────────────────────────────►
       type=0x01
       nonce_A  (32B)
       pub_A    (32B)  [ECDH seulement]

                                            [2] Génère nonce_B (32B)
                                                Génère paire éphémère
                                                (priv_B, pub_B) [ECDH seulement]

  ◄─── HELLO_ACK ──────────────────────────
       type=0x02
       nonce_B  (32B)
       pub_B    (32B)  [ECDH seulement]

  [3] Dérive session_key + session_seed      [3] Dérive session_key + session_seed
      (voir §Dérivation)                         (idem, résultat identique)

  ──── ACK_CONFIRM ────────────────────────►
       type=0x03
       verify_tag (16B)   ← preuve de possession de session_key

                                            [4] Vérifie verify_tag
                                                Confirme ou rejette

  ▼                                          ▼
SMCCipher(key=session_key,                 SMCCipher(key=session_key,
          seed=session_seed)                         seed=session_seed)
```

---

## Format Binaire des Messages

```
HELLO (PSK)       : [ 0x01 | nonce_A (32B) ]                    = 33 octets
HELLO (ECDH)      : [ 0x01 | nonce_A (32B) | pub_A (32B) ]      = 65 octets

HELLO_ACK (PSK)   : [ 0x02 | nonce_B (32B) ]                    = 33 octets
HELLO_ACK (ECDH)  : [ 0x02 | nonce_B (32B) | pub_B (32B) ]      = 65 octets

ACK_CONFIRM       : [ 0x03 | verify_tag (16B) ]                  = 17 octets
```

---

## Dérivation de session_key et session_seed

### Variante A — PSK

```
material   = PBKDF2-SHA256(
                 password = psk,
                 salt     = nonce_A ∥ nonce_B ∥ b"proteus-smc-hs",
                 iter     = 100_000,
                 dklen    = 48
             )

session_key  = material[:32]          # 32 octets → clé SMCCipher
session_seed = material[32:]          # 16 octets → seed SMCCipher
```

### Variante B — ECDH

```
shared_dh  = X25519(priv_self, pub_other)   # 32 octets, identique des deux côtés

material   = PBKDF2-SHA256(
                 password = shared_dh,
                 salt     = nonce_A ∥ nonce_B ∥ b"proteus-smc-hs",
                 iter     = 100_000,
                 dklen    = 48
             )

session_key  = material[:32]
session_seed = material[32:]
```

> La séparation de domaine `b"proteus-smc-hs"` dans le sel empêche la
> réutilisation de ce matériau pour un autre protocole.

---

## verify_tag — Confirmation Mutuelle

Avant d'activer le cipher, Alice prouve à Bob qu'elle a dérivé la même clé :

```
verify_tag = HMAC-SHA256(
                 key  = session_key,
                 msg  = b"handshake-confirm" ∥ nonce_A ∥ nonce_B
             )[:16]
```

Bob recalcule le tag de son côté et compare en temps constant
(`hmac.compare_digest`). Si les tags diffèrent, la session est avortée.

> Cette étape transforme le handshake en un protocole **authentifié** :
> elle garantit que les deux parties ont convergé vers les mêmes valeurs
> dérivées, détectant toute attaque Man-in-the-Middle ou corruption réseau.

---

## Propriétés de Sécurité

| Propriété                  | PSK | ECDH |
|----------------------------|-----|------|
| Isolation de session       | ✓   | ✓    |
| Protection rejeu (nonces)  | ✓   | ✓    |
| Authentification mutuelle  | ✓   | ✗ *  |
| Forward Secrecy            | ✗   | ✓    |
| Sans secret préalable      | ✗   | ✓    |
| Stdlib uniquement          | ✓   | ✗    |

> \* La variante ECDH éphémère seule n'authentifie pas l'identité des parties.
> Pour l'authentification en mode ECDH, les clés publiques éphémères doivent
> être signées avec une clé longue durée (ex. Ed25519), ou le PSK peut être
> combiné à l'ECDH (mode 1-RTT hybride).

---

## Intégration avec SMCCipher

À l'issue du handshake, les deux parties initialisent leur instance :

```python
# Résultat du handshake
session_key  : bytes  # 32 octets
session_seed : bytes  # 16 octets

# Activation du cipher
cipher = SMCCipher(key=session_key, seed=session_seed)
```

Les échanges chiffrés débutent immédiatement après réception du
`ACK_CONFIRM` validé par Bob.

---

## Dépendances

| Variante | Module requis                                                      |
|----------|--------------------------------------------------------------------|
| PSK      | `hashlib`, `hmac`, `secrets` (stdlib uniquement)                   |
| ECDH     | `cryptography.hazmat.primitives.asymmetric.x25519` (`pip install cryptography`) |

---

## Recommandation

Pour le papier de recherche, la **Variante B (ECDH)** est préférable car :
1. Elle n'impose pas de secret préalable, ce qui la rend applicable à des
   scenarios d'établissement de canal entre inconnus.
2. La Forward Secrecy est directement liée à l'axe de recherche MTD :
   chaque session génère un algorithme différent *et* une clé différente,
   rendant la corrélation inter-sessions mathématiquement négligeable.
3. Elle constitue un argument fort pour la section "Résistance Side-Channel" :
   même si une trace physique est capturée sur une session, elle ne
   compromet aucune autre session passée ou future.
