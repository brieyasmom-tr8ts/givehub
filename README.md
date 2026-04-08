# GiveHub

Multi-tenant nonprofit fundraising hub built on GiveSendGo. Think "Squarespace for fundraising hubs" — nonprofits create a branded landing page that curates multiple GiveSendGo campaigns. Donations still flow to GSG; GiveHub tracks attribution and performance.

## Stack
- **Backend**: Cloudflare Workers (`src/worker.js`)
- **Database**: Cloudflare D1 (`schema.sql`)
- **Frontend**: Static HTML on Cloudflare Pages (`public/`)
- **Auth**: JWT (HS256) + PBKDF2 password hashing

## Setup

```bash
# 1. Install wrangler
npm install

# 2. Log in to Cloudflare
npx wrangler login

# 3. Create D1 database
npx wrangler d1 create givehub-db
# → paste the returned database_id into wrangler.toml

# 4. Apply schema
npm run db:init

# 5. Set secrets
npx wrangler secret put JWT_SECRET
npx wrangler secret put ADMIN_SECRET
npx wrangler secret put GSG_API_KEY
npx wrangler secret put GSG_WEBHOOK_SECRET

# 6. Deploy worker
npm run deploy

# 7. Deploy frontend (Pages)
npx wrangler pages project create givehub
npm run deploy:pages
```

After deploy, update the `API` constant in `public/index.html` and `public/admin.html` to point at your Worker URL.

## Local dev

```bash
npm run dev          # worker at localhost:8787
npm run db:local     # apply schema to local D1
```

Open `public/index.html` or `public/admin.html` directly — they auto-detect localhost.

## Routes

### Public
- `GET  /api/hub/:slug` — hub config + campaigns
- `POST /api/hub/:slug/track` — log view/click event
- `GET  /r/:slug/:campaignId` — attribution redirect to GSG

### Auth
- `POST /api/auth/signup` — create org + owner user
- `POST /api/auth/login` — `{ token }`

### Admin (JWT)
- `GET/PATCH /api/admin/hub` — hub config
- `GET /api/admin/campaigns`
- `POST /api/admin/campaigns/import`
- `PATCH/DELETE /api/admin/campaigns/:id`
- `GET /api/admin/stats/overview`

### Webhooks
- `POST /webhooks/gsg/donation` — GSG notifies on donation, GiveHub credits the hub

## Attribution flow

```
Visitor → hub.givesendgo.com/:slug
   ↓ clicks Donate
/r/:slug/:campaignId  (logs click)
   ↓ 302 → givesendgo.com/:campaign?ref=:slug
Visitor donates on GSG
   ↓
GSG webhook → POST /webhooks/gsg/donation
   ↓ match ref → credit org → insert donation event
```

## Roadmap
- [ ] Real GSG API integration (`fetchGsgCampaign` is stubbed)
- [ ] Webhook signature verification
- [ ] Categories management UI
- [ ] Custom domain support
- [ ] Team members / invites
- [ ] Nightly stats rollup cron
- [ ] CSV export
- [ ] Multiple hub themes
