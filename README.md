# Stocks Cuisine — Déploiement gratuit (Cloudflare Pages + Workers + D1)

Ce dépôt contient :
- `api/` : l'API (Cloudflare Worker) + base D1
- `web/` : le site (Cloudflare Pages) en HTML/JS (statique)

## Prérequis (1 fois)
1) Un compte **GitHub**
2) Un compte **Cloudflare** (gratuit)
3) Installer **Node.js LTS** sur ton PC (pour avoir `npm`)
4) Installer **Wrangler** (outil Cloudflare) : `npm i -g wrangler`

---

## Étape 1 — Déployer l'API (Worker + D1)

### 1. Ouvre un terminal dans `api/`
```bash
cd api
npm install
wrangler login
```

### 2. Crée la base D1
```bash
wrangler d1 create stock-kitchen-db
```
Wrangler va afficher un **database_id**. Copie-le dans `api/wrangler.toml` :
```toml
database_id = "ICI_TON_DATABASE_ID"
```

### 3. Crée les tables (migration)
```bash
wrangler d1 migrations apply stock-kitchen-db --remote
```

### 4. Ajoute le secret JWT (obligatoire pour la connexion)
```bash
wrangler secret put JWT_SECRET
```
→ colle une longue phrase aléatoire (ex: 40+ caractères).

### 5. Déploie l'API
```bash
wrangler deploy
```
Tu obtiens une URL du type :
`https://stock-kitchen-api.<ton-sous-domaine>.workers.dev`

---

## Étape 2 — Créer le 1er compte ADMIN

### A) Générer salt + hash (sur ton PC)
Dans un terminal Python (ou via un site PBKDF2), tu peux utiliser ce script :
```python
import os, base64, hashlib

password = "ChangeMoi123!"
salt = os.urandom(16)
salt_b64 = base64.b64encode(salt).decode()

dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000, dklen=32)
hash_b64 = base64.b64encode(dk).decode()

print("salt_b64 =", salt_b64)
print("hash_b64 =", hash_b64)
```

### B) Insérer l'admin dans D1
Remplace les valeurs puis exécute :
```bash
wrangler d1 execute stock-kitchen-db --remote --command "
INSERT INTO users (name,email,role,password_hash_b64,salt_b64,active,created_at)
VALUES ('Admin','admin@example.com','ADMIN','HASH_B64_ICI','SALT_B64_ICI',1,datetime('now'));
"
```

---

## Étape 3 — Déployer le site (Cloudflare Pages)

### 1. Mettre l'URL de l'API dans le site
Ouvre `web/config.js` et remplace `REPLACE_ME` par l'URL Worker :
```js
window.APP_CONFIG = { API_BASE: "https://stock-kitchen-api.<ton-sous-domaine>.workers.dev" };
```

### 2. Déployer avec Cloudflare Pages (via GitHub)
- Pousse ce projet sur GitHub
- Cloudflare Dashboard → **Workers & Pages** → **Pages** → **Create project**
- Connecte ton repo GitHub
- **Build command** : (laisser vide)
- **Output directory** : `web`

Cloudflare te donne une URL du type :
`https://ton-projet.pages.dev`

### 3. Autoriser CORS (important)
Dans `api/wrangler.toml`, remplis :
```toml
WEB_ORIGIN = "https://ton-projet.pages.dev"
```
Puis redéploie l'API :
```bash
cd api
wrangler deploy
```

---

## Étape 4 — Connexion
Va sur l'URL Pages → connecte-toi avec l'admin que tu as créé.

---

## QR Demande (MVP)
Pour créer un token QR :
```bash
wrangler d1 execute stock-kitchen-db --remote --command "
INSERT INTO qr_tokens (token,label,active,expires_at)
VALUES ('TON_TOKEN','Cuisine',1,NULL);
"
```
Puis l'URL QR :
`https://ton-projet.pages.dev/qr.html?token=TON_TOKEN`

---

## Notes
- C'est un MVP simple et propre (auth email+mdp, produits, mouvements, demandes, à commander).
- On peut ensuite améliorer : page QR avec liste produits, validation fine des demandes, exports CSV/PDF, etc.
