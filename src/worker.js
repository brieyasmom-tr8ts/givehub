// GiveHub — Cloudflare Worker API
// Multi-tenant fundraising hub built on GiveSendGo
// v0.1.2 — auto-deploy via GitHub Actions
//
// Routes:
//   GET  /api/hub/:slug                public hub config + campaigns
//   GET  /api/hub/:slug/campaigns      campaign list
//   POST /api/hub/:slug/track          log view/click event
//   GET  /r/:slug/:campaignId          attribution redirect to GSG
//   POST /webhooks/gsg/donation        GSG donation webhook
//   POST /api/auth/signup              create org + owner user
//   POST /api/auth/login               → { token }
//   GET  /api/admin/hub                (auth) current hub config
//   PATCH /api/admin/hub               (auth) update hub
//   GET  /api/admin/campaigns          (auth) list
//   POST /api/admin/campaigns/import   (auth) import from GSG
//   PATCH /api/admin/campaigns/:id     (auth) feature/category/sort
//   DELETE /api/admin/campaigns/:id    (auth)
//   GET  /api/admin/stats/overview     (auth)

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });

const err = (message, status = 400) => json({ error: message }, status);

const uuid = () => crypto.randomUUID();
const now = () => Math.floor(Date.now() / 1000);

// ---------- JWT (HS256) ----------
async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = (o) =>
    btoa(JSON.stringify(o)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const data = `${enc(header)}.${enc(payload)}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${data}.${sigB64}`;
}

async function verifyJWT(token, secret) {
  try {
    const [h, p, s] = token.split('.');
    if (!h || !p || !s) return null;
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sig = Uint8Array.from(
      atob(s.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0)
    );
    const ok = await crypto.subtle.verify(
      'HMAC',
      key,
      sig,
      new TextEncoder().encode(`${h}.${p}`)
    );
    if (!ok) return null;
    return JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
  } catch {
    return null;
  }
}

async function requireAuth(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload || !payload.org_id) return null;
  return payload;
}

// ---------- Password hashing (PBKDF2) ----------
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
  return `${b64(salt)}:${b64(bits)}`;
}

async function verifyPassword(password, stored) {
  const [saltB64, hashB64] = stored.split(':');
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  const newHash = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return newHash === hashB64;
}

// ---------- GiveSendGo helpers ----------

// Accepts either a full URL or a raw campaign slug, returns just the slug.
function parseGsgCampaignId(input) {
  const raw = String(input || '').trim();
  if (!raw) return '';
  const match = raw.match(/^(?:https?:\/\/)?(?:www\.)?givesendgo\.com\/([^/?#]+)/i);
  if (match) return match[1];
  return raw.replace(/^\/+|\/+$/g, '').split(/[?#/]/)[0];
}

function decodeHtmlEntities(s) {
  if (!s) return s;
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)));
}

function extractMeta(html, property) {
  // Handles both: <meta property="og:foo" content="..."> and <meta content="..." property="og:foo">
  const patterns = [
    new RegExp(`<meta[^>]+property=["']${property}["'][^>]+content=["']([^"']*)["']`, 'i'),
    new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+property=["']${property}["']`, 'i'),
    new RegExp(`<meta[^>]+name=["']${property}["'][^>]+content=["']([^"']*)["']`, 'i'),
  ];
  for (const p of patterns) {
    const m = html.match(p);
    if (m) return decodeHtmlEntities(m[1]);
  }
  return null;
}

// Scrapes public GSG campaign page for title, image, description, goal, raised, donors.
// Returns what it can find; falls back to placeholders for anything missing.
async function fetchGsgCampaign(gsgCampaignId, env) {
  const id = parseGsgCampaignId(gsgCampaignId);
  const base = {
    gsg_campaign_id: id,
    title: id,
    description: 'Imported from GiveSendGo',
    image_url: null,
    goal_amount: 0,
    raised_amount: 0,
    donor_count: 0,
    status: 'active',
  };
  if (!id) return base;

  try {
    const res = await fetch(`https://www.givesendgo.com/${id}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; GiveHub/0.1; +https://givehub-bty.pages.dev)',
        'Accept': 'text/html,application/xhtml+xml',
      },
      cf: { cacheTtl: 300, cacheEverything: true },
    });
    if (!res.ok) return base;
    const html = await res.text();

    const ogTitle = extractMeta(html, 'og:title');
    if (ogTitle) base.title = ogTitle.replace(/\s*\|\s*GiveSendGo.*$/i, '').trim() || id;

    const ogDesc = extractMeta(html, 'og:description');
    if (ogDesc) base.description = ogDesc;

    const ogImage = extractMeta(html, 'og:image');
    if (ogImage) base.image_url = ogImage;

    // Goal: look for "$X,XXX" following or preceding "goal"
    const goalPatterns = [
      /goal[^$]{0,60}\$\s*([0-9,]+(?:\.\d{1,2})?)/i,
      /\$\s*([0-9,]+(?:\.\d{1,2})?)[^$]{0,30}goal/i,
      /"goal(?:Amount)?"\s*:\s*"?([0-9.]+)"?/i,
    ];
    for (const p of goalPatterns) {
      const m = html.match(p);
      if (m) { base.goal_amount = Math.round(parseFloat(m[1].replace(/,/g, '')) * 100); break; }
    }

    // Raised: look for "$X,XXX" near "raised"
    const raisedPatterns = [
      /\$\s*([0-9,]+(?:\.\d{1,2})?)[^$]{0,30}raised/i,
      /raised[^$]{0,60}\$\s*([0-9,]+(?:\.\d{1,2})?)/i,
      /"(?:raised|totalRaised|amountRaised)"\s*:\s*"?([0-9.]+)"?/i,
    ];
    for (const p of raisedPatterns) {
      const m = html.match(p);
      if (m) { base.raised_amount = Math.round(parseFloat(m[1].replace(/,/g, '')) * 100); break; }
    }

    // Donor count
    const donorPatterns = [
      /([0-9,]+)\s*(?:donors?|supporters?|backers?|givers?|people\s+have\s+given)/i,
      /"donor(?:Count|s)"\s*:\s*"?([0-9]+)"?/i,
    ];
    for (const p of donorPatterns) {
      const m = html.match(p);
      if (m) { base.donor_count = parseInt(m[1].replace(/,/g, ''), 10); break; }
    }
  } catch (_) {
    // Network error — return base placeholder
  }

  return base;
}

// ---------- Route handlers ----------

async function handleSignup(request, env) {
  const body = await request.json();
  const { org_name, email, password } = body;
  // Normalize slug: lowercase, strip invalid chars
  const slug = (body.slug || '').toLowerCase().trim().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  if (!org_name || !slug || !email || !password)
    return err('Missing required fields');

  const existing = await env.DB.prepare(
    'SELECT id FROM organizations WHERE slug = ?'
  ).bind(slug).first();
  if (existing) return err('Slug already taken', 409);

  const orgId = uuid();
  const hubId = uuid();
  const userId = uuid();
  const pw = await hashPassword(password);
  const ts = now();

  await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO organizations (id, slug, name, email, created_at) VALUES (?,?,?,?,?)'
    ).bind(orgId, slug, org_name, email, ts),
    env.DB.prepare(
      'INSERT INTO hubs (id, org_id, headline, updated_at) VALUES (?,?,?,?)'
    ).bind(hubId, orgId, org_name, ts),
    env.DB.prepare(
      'INSERT INTO hub_users (id, org_id, email, password_hash, role, created_at) VALUES (?,?,?,?,?,?)'
    ).bind(userId, orgId, email, pw, 'owner', ts),
  ]);

  const token = await signJWT(
    { sub: userId, org_id: orgId, role: 'owner', iat: ts },
    env.JWT_SECRET
  );
  return json({ token, org_id: orgId, slug });
}

async function handleLogin(request, env) {
  const { email, password } = await request.json();
  const user = await env.DB.prepare(
    'SELECT id, org_id, password_hash, role FROM hub_users WHERE email = ?'
  ).bind(email || '').first();
  if (!user) return err('Invalid credentials', 401);
  const ok = await verifyPassword(password || '', user.password_hash);
  if (!ok) return err('Invalid credentials', 401);
  const token = await signJWT(
    { sub: user.id, org_id: user.org_id, role: user.role, iat: now() },
    env.JWT_SECRET
  );
  return json({ token, org_id: user.org_id });
}

async function handlePublicHub(slug, env) {
  const normalized = (slug || '').toLowerCase();
  const org = await env.DB.prepare(
    'SELECT id, slug, name FROM organizations WHERE slug = ? AND status = "active"'
  ).bind(normalized).first();
  if (!org) return err('Hub not found', 404);

  const hub = await env.DB.prepare(
    'SELECT * FROM hubs WHERE org_id = ?'
  ).bind(org.id).first();

  const campaigns = await env.DB.prepare(
    `SELECT id, gsg_campaign_id, title, description, image_url, goal_amount,
            raised_amount, donor_count, category_id, is_featured, sort_order
     FROM campaigns WHERE org_id = ? AND status = 'active'
     ORDER BY is_featured DESC, sort_order ASC`
  ).bind(org.id).all();

  const categories = await env.DB.prepare(
    'SELECT * FROM categories WHERE org_id = ? ORDER BY sort_order ASC'
  ).bind(org.id).all();

  return json({
    org: { slug: org.slug, name: org.name },
    hub,
    campaigns: campaigns.results || [],
    categories: categories.results || [],
  });
}

async function handleTrackEvent(slug, request, env) {
  const body = await request.json().catch(() => ({}));
  const org = await env.DB.prepare(
    'SELECT id FROM organizations WHERE slug = ?'
  ).bind((slug || '').toLowerCase()).first();
  if (!org) return err('Hub not found', 404);

  await env.DB.prepare(
    `INSERT INTO referral_events
     (id, org_id, campaign_id, event_type, referrer_url, utm_source, utm_medium, utm_campaign, session_id, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    uuid(),
    org.id,
    body.campaign_id || null,
    body.event_type || 'view',
    body.referrer_url || null,
    body.utm_source || null,
    body.utm_medium || null,
    body.utm_campaign || null,
    body.session_id || null,
    now()
  ).run();

  return json({ ok: true });
}

async function handleAttributionRedirect(slug, campaignId, url, env) {
  const normalized = (slug || '').toLowerCase();
  const org = await env.DB.prepare(
    'SELECT id FROM organizations WHERE slug = ?'
  ).bind(normalized).first();
  if (!org) return err('Hub not found', 404);

  const campaign = await env.DB.prepare(
    'SELECT gsg_campaign_id FROM campaigns WHERE id = ? AND org_id = ?'
  ).bind(campaignId, org.id).first();
  if (!campaign) return err('Campaign not found', 404);

  // Log click
  await env.DB.prepare(
    `INSERT INTO referral_events (id, org_id, campaign_id, event_type, created_at)
     VALUES (?,?,?,?,?)`
  ).bind(uuid(), org.id, campaignId, 'click', now()).run();

  const dest = `https://www.givesendgo.com/${campaign.gsg_campaign_id}?ref=${normalized}`;
  return Response.redirect(dest, 302);
}

async function handleGetAdminHub(auth, env) {
  const hub = await env.DB.prepare(
    'SELECT * FROM hubs WHERE org_id = ?'
  ).bind(auth.org_id).first();
  return json({ hub });
}

async function handlePatchAdminHub(auth, request, env) {
  const body = await request.json();
  const fields = [
    'logo_url', 'hero_image_url', 'primary_color', 'secondary_color',
    'headline', 'tagline', 'about_html', 'custom_domain', 'theme',
    'layout_json', 'published',
  ];
  const updates = [];
  const values = [];
  for (const f of fields) {
    if (f in body) {
      updates.push(`${f} = ?`);
      values.push(body[f] ?? null);
    }
  }
  if (!updates.length) return err('Nothing to update');
  updates.push('updated_at = ?');
  values.push(now());
  values.push(auth.org_id);
  await env.DB.prepare(
    `UPDATE hubs SET ${updates.join(', ')} WHERE org_id = ?`
  ).bind(...values).run();
  return json({ ok: true });
}

async function handleListAdminCampaigns(auth, env) {
  const rows = await env.DB.prepare(
    'SELECT * FROM campaigns WHERE org_id = ? ORDER BY is_featured DESC, sort_order ASC'
  ).bind(auth.org_id).all();
  return json({ campaigns: rows.results || [] });
}

async function handleImportCampaign(auth, request, env) {
  const { gsg_campaign_id, category_id, is_featured } = await request.json();
  if (!gsg_campaign_id) return err('Missing gsg_campaign_id');

  const gsg = await fetchGsgCampaign(gsg_campaign_id, env);
  const id = uuid();
  const ts = now();
  await env.DB.prepare(
    `INSERT INTO campaigns
     (id, org_id, gsg_campaign_id, title, description, image_url,
      goal_amount, raised_amount, donor_count, status, category_id,
      is_featured, last_synced_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    id, auth.org_id, gsg.gsg_campaign_id, gsg.title, gsg.description,
    gsg.image_url, gsg.goal_amount, gsg.raised_amount, gsg.donor_count,
    gsg.status, category_id || null, is_featured ? 1 : 0, ts
  ).run();

  return json({ id, ...gsg });
}

async function handlePatchCampaign(auth, id, request, env) {
  const body = await request.json();
  const fields = ['is_featured', 'category_id', 'sort_order', 'status'];
  const updates = [];
  const values = [];
  for (const f of fields) {
    if (f in body) {
      updates.push(`${f} = ?`);
      values.push(body[f] ?? null);
    }
  }
  if (!updates.length) return err('Nothing to update');
  values.push(id, auth.org_id);
  await env.DB.prepare(
    `UPDATE campaigns SET ${updates.join(', ')} WHERE id = ? AND org_id = ?`
  ).bind(...values).run();
  return json({ ok: true });
}

async function handleDeleteCampaign(auth, id, env) {
  await env.DB.prepare(
    'DELETE FROM campaigns WHERE id = ? AND org_id = ?'
  ).bind(id, auth.org_id).run();
  return json({ ok: true });
}

async function handleSyncCampaigns(auth, env) {
  const rows = await env.DB.prepare(
    'SELECT id, gsg_campaign_id FROM campaigns WHERE org_id = ?'
  ).bind(auth.org_id).all();
  const campaigns = rows.results || [];
  const ts = now();
  let updated = 0;
  for (const c of campaigns) {
    try {
      const gsg = await fetchGsgCampaign(c.gsg_campaign_id, env);
      await env.DB.prepare(
        `UPDATE campaigns
         SET title = ?, description = ?, image_url = ?,
             goal_amount = ?, raised_amount = ?, donor_count = ?,
             status = ?, last_synced_at = ?
         WHERE id = ? AND org_id = ?`
      ).bind(
        gsg.title, gsg.description, gsg.image_url,
        gsg.goal_amount, gsg.raised_amount, gsg.donor_count,
        gsg.status, ts, c.id, auth.org_id
      ).run();
      updated++;
    } catch (_) { /* skip and continue */ }
  }
  return json({ ok: true, updated, total: campaigns.length });
}

async function handleStatsOverview(auth, env) {
  const since = now() - 30 * 86400;
  const [totals, events, campaigns] = await Promise.allSettled([
    env.DB.prepare(
      `SELECT COALESCE(SUM(raised_amount),0) AS total_raised,
              COALESCE(SUM(donor_count),0) AS total_donors,
              COUNT(*) AS campaign_count
       FROM campaigns WHERE org_id = ?`
    ).bind(auth.org_id).first(),
    env.DB.prepare(
      `SELECT event_type, COUNT(*) AS n
       FROM referral_events
       WHERE org_id = ? AND created_at >= ?
       GROUP BY event_type`
    ).bind(auth.org_id, since).all(),
    env.DB.prepare(
      `SELECT id, title, raised_amount, goal_amount, donor_count
       FROM campaigns WHERE org_id = ?
       ORDER BY raised_amount DESC LIMIT 5`
    ).bind(auth.org_id).all(),
  ]);

  return json({
    totals: totals.status === 'fulfilled' ? totals.value : {},
    events_30d: events.status === 'fulfilled' ? events.value.results : [],
    top_campaigns: campaigns.status === 'fulfilled' ? campaigns.value.results : [],
  });
}

async function handleGsgWebhook(request, env) {
  // TODO: verify signature with env.GSG_WEBHOOK_SECRET
  const body = await request.json().catch(() => ({}));
  const { gsg_campaign_id, amount, ref } = body;
  if (!gsg_campaign_id || !ref) return err('Invalid payload');

  const org = await env.DB.prepare(
    'SELECT id FROM organizations WHERE slug = ?'
  ).bind(ref).first();
  if (!org) return json({ ok: true, attributed: false });

  const campaign = await env.DB.prepare(
    'SELECT id FROM campaigns WHERE org_id = ? AND gsg_campaign_id = ?'
  ).bind(org.id, gsg_campaign_id).first();

  await env.DB.prepare(
    `INSERT INTO referral_events
     (id, org_id, campaign_id, event_type, amount, created_at)
     VALUES (?,?,?,?,?,?)`
  ).bind(
    uuid(), org.id, campaign?.id || null, 'donation',
    Math.round((amount || 0) * 100), now()
  ).run();

  return json({ ok: true, attributed: true });
}

// ---------- Router ----------
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);
    const p = url.pathname;
    const m = request.method;

    try {
      // Public
      if (m === 'GET' && p === '/') return json({ service: 'givehub', ok: true });

      // Auth
      if (m === 'POST' && p === '/api/auth/signup') return handleSignup(request, env);
      if (m === 'POST' && p === '/api/auth/login') return handleLogin(request, env);

      // Public hub
      let match = p.match(/^\/api\/hub\/([^/]+)$/);
      if (m === 'GET' && match) return handlePublicHub(match[1], env);

      match = p.match(/^\/api\/hub\/([^/]+)\/track$/);
      if (m === 'POST' && match) return handleTrackEvent(match[1], request, env);

      // Attribution redirect
      match = p.match(/^\/r\/([^/]+)\/([^/]+)$/);
      if (m === 'GET' && match) return handleAttributionRedirect(match[1], match[2], url, env);

      // Webhook
      if (m === 'POST' && p === '/webhooks/gsg/donation') return handleGsgWebhook(request, env);

      // --- Authenticated admin routes ---
      if (p.startsWith('/api/admin/')) {
        const auth = await requireAuth(request, env);
        if (!auth) return err('Unauthorized', 401);

        if (m === 'GET' && p === '/api/admin/hub') return handleGetAdminHub(auth, env);
        if (m === 'PATCH' && p === '/api/admin/hub') return handlePatchAdminHub(auth, request, env);
        if (m === 'GET' && p === '/api/admin/campaigns') return handleListAdminCampaigns(auth, env);
        if (m === 'POST' && p === '/api/admin/campaigns/import')
          return handleImportCampaign(auth, request, env);
        if (m === 'POST' && p === '/api/admin/campaigns/sync')
          return handleSyncCampaigns(auth, env);

        match = p.match(/^\/api\/admin\/campaigns\/([^/]+)$/);
        if (m === 'PATCH' && match) return handlePatchCampaign(auth, match[1], request, env);
        if (m === 'DELETE' && match) return handleDeleteCampaign(auth, match[1], env);

        if (m === 'GET' && p === '/api/admin/stats/overview') return handleStatsOverview(auth, env);
      }

      return err('Not found', 404);
    } catch (e) {
      return err(e.message || 'Server error', 500);
    }
  },
};
