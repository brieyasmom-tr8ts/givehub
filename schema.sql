-- GiveHub D1 schema
-- Run: npx wrangler d1 execute givehub-db --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  plan TEXT DEFAULT 'free',
  gsg_org_id TEXT,
  status TEXT DEFAULT 'active',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hubs (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  logo_url TEXT,
  hero_image_url TEXT,
  primary_color TEXT DEFAULT '#1a73e8',
  secondary_color TEXT DEFAULT '#34a853',
  headline TEXT,
  tagline TEXT,
  about_html TEXT,
  custom_domain TEXT,
  theme TEXT DEFAULT 'default',
  layout_json TEXT,
  published INTEGER DEFAULT 0,
  updated_at INTEGER,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS categories (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  description TEXT,
  icon TEXT,
  sort_order INTEGER DEFAULT 0,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  gsg_campaign_id TEXT NOT NULL,
  title TEXT,
  description TEXT,
  image_url TEXT,
  goal_amount INTEGER,
  raised_amount INTEGER DEFAULT 0,
  donor_count INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  category_id TEXT,
  is_featured INTEGER DEFAULT 0,
  sort_order INTEGER DEFAULT 0,
  allow_p2p INTEGER DEFAULT 0,
  last_synced_at INTEGER,
  UNIQUE(org_id, gsg_campaign_id),
  FOREIGN KEY (org_id) REFERENCES organizations(id),
  FOREIGN KEY (category_id) REFERENCES categories(id)
);

-- Peer-to-peer fundraising pages. Supporters create their own page
-- tied to a campaign; donations flow to GSG with a ref+fr attribution
-- tag so the webhook can credit the fundraiser.
CREATE TABLE IF NOT EXISTS fundraisers (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  campaign_id TEXT NOT NULL,
  slug TEXT NOT NULL,
  supporter_name TEXT NOT NULL,
  supporter_email TEXT,
  story TEXT,
  image_url TEXT,
  goal_amount INTEGER DEFAULT 0,
  raised_amount INTEGER DEFAULT 0,
  donor_count INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  is_featured INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  UNIQUE(org_id, slug),
  FOREIGN KEY (org_id) REFERENCES organizations(id),
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS referral_events (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  campaign_id TEXT,
  fundraiser_id TEXT,
  event_type TEXT NOT NULL,
  referrer_url TEXT,
  utm_source TEXT,
  utm_medium TEXT,
  utm_campaign TEXT,
  session_id TEXT,
  amount INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hub_stats_daily (
  org_id TEXT NOT NULL,
  date TEXT NOT NULL,
  views INTEGER DEFAULT 0,
  clicks INTEGER DEFAULT 0,
  attributed_donations INTEGER DEFAULT 0,
  attributed_amount INTEGER DEFAULT 0,
  PRIMARY KEY (org_id, date)
);

CREATE TABLE IF NOT EXISTS hub_users (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  email TEXT NOT NULL,
  password_hash TEXT,
  role TEXT DEFAULT 'admin',
  created_at INTEGER NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);

CREATE INDEX IF NOT EXISTS idx_campaigns_org ON campaigns(org_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_featured ON campaigns(org_id, is_featured);
CREATE INDEX IF NOT EXISTS idx_referral_org_date ON referral_events(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_referral_campaign ON referral_events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_hub_users_email ON hub_users(email);
