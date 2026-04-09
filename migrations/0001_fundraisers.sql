-- Chunk 1: Peer-to-peer fundraisers
-- Run: npx wrangler d1 execute givehub-db --remote --file=./migrations/0001_fundraisers.sql

ALTER TABLE campaigns ADD COLUMN allow_p2p INTEGER DEFAULT 0;
ALTER TABLE referral_events ADD COLUMN fundraiser_id TEXT;

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

CREATE INDEX IF NOT EXISTS idx_fundraisers_org ON fundraisers(org_id);
CREATE INDEX IF NOT EXISTS idx_fundraisers_campaign ON fundraisers(campaign_id);
