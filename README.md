# secret-sharing

Partage de secrets à usage unique avec chiffrement AES-256-GCM côté client. Le serveur ne stocke que des fragments XOR'd et mélangés — il ne peut pas reconstruire le secret.

## Comment ça marche

1. Le client chiffre le secret avec AES-256-GCM + PBKDF2 (250 000 itérations)
2. Le ciphertext est découpé en 4 shards de taille aléatoire
3. Chaque shard est XOR avec une clé dérivée d'un seed aléatoire
4. Les shards sont mélangés (Fisher-Yates) puis envoyés au serveur
5. Le seed reste dans le fragment `#hash` de l'URL — jamais envoyé au serveur

Le destinataire reçoit le lien + un mot de passe séparé.

## Install

```bash
git clone <repo>
cd secret-sharing
npm install
cp .env.example .env.local
```

Remplir `.env.local` avec des valeurs réelles.

## Config

Variables obligatoires :

| Variable         | Description                              |
|------------------|------------------------------------------|
| `ADMIN_USERNAME` | Identifiant pour accéder à `/create`     |
| `ADMIN_PASSWORD` | Mot de passe admin                       |
| `JWT_SECRET`     | Clé de signature des tokens (min 32 chars) |

Variables optionnelles :

| Variable      | Description                                  | Défaut                      |
|---------------|----------------------------------------------|-----------------------------|
| `REDIS_URL`   | URL Redis pour rate limiting persistant      | In-memory (reset au restart) |
| `SITE_NAME`   | Nom affiché dans l'interface                 | `Secret Data`               |
| `SITE_DOMAIN` | Domaine de l'instance                        | —                           |
| `APP_PORT`    | Port d'écoute                                | `3000`                      |

## Dev

```bash
npm run dev          # Next.js + Turbopack
npm run test         # Vitest
npm run test:watch   # Vitest en watch
npm run lint         # ESLint
```

## Déploiement

```bash
npm run build
pm2 start ecosystem.config.js
```

Les headers de sécurité (CSP nonce, HSTS, COEP, COOP) sont dans `middleware.ts` et `next.config.ts`.

## Routes

| Route              | Accès  | Description                  |
|--------------------|--------|------------------------------|
| `/login`           | Public | Authentification admin       |
| `/create`          | Auth   | Créer un secret chiffré      |
| `/s/[id]`          | Public | Lire et déchiffrer un secret |
| `/health`          | Public | Health check                 |

## License

[MIT](LICENSE) — Studio Kiss
