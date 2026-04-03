export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cronCheck(env));
  },

  async fetch(request, env) {
    const allowedOrigins = [
      'https://art-bot5000.github.io',
      'http://localhost',
      'http://127.0.0.1',
    ];
    const origin = request.headers.get('Origin') || '';
    const corsOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];
    const corsHeaders = {
      'Access-Control-Allow-Origin':  corsOrigin,
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age':       '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);

    // ── Health check ──────────────────────────────────
    if (url.pathname === '/ping') {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // ── Google Drive OAuth code exchange ──────────────
    if (url.pathname === '/auth/google' && request.method === 'GET') {
      const code        = url.searchParams.get('code');
      const appUrl      = env.APP_URL || 'https://art-bot5000.github.io/stockroom/';
      const redirectUri = `${env.WORKER_URL}/auth/google`;

      console.log('auth/google hit - code present:', !!code, '- WORKER_URL:', env.WORKER_URL, '- CLIENT_ID present:', !!env.GOOGLE_CLIENT_ID, '- CLIENT_SECRET present:', !!env.GOOGLE_CLIENT_SECRET);

      if (!code) return Response.redirect(`${appUrl}?drive_auth=error&reason=no_code`, 302);

      try {
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            client_id:     env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET,
            redirect_uri:  redirectUri,
            grant_type:    'authorization_code',
          }),
        });
        const tokens = await tokenRes.json();
        if (!tokenRes.ok || !tokens.access_token) {
          console.error('Google token exchange failed:', JSON.stringify(tokens));
          const reason = tokens.error_description || tokens.error || 'token_exchange';
          return Response.redirect(`${appUrl}?drive_auth=error&reason=${encodeURIComponent(reason)}`, 302);
        }
        if (tokens.refresh_token) {
          await env.STOCKROOM_USERS.put('drive_refresh_token', tokens.refresh_token);
        }
        await env.STOCKROOM_USERS.put('drive_access_token_temp', tokens.access_token, { expirationTtl: 3600 });
        return Response.redirect(`${appUrl}?drive_auth=success`, 302);
      } catch (err) {
        return Response.redirect(`${appUrl}?drive_auth=error&reason=${encodeURIComponent(err.message)}`, 302);
      }
    }

    // ── Dropbox PKCE code exchange ────────────────────
    if (url.pathname === '/auth/dropbox' && request.method === 'GET') {
      const code        = url.searchParams.get('code');
      const appUrl      = env.APP_URL || 'https://art-bot5000.github.io/stockroom/';
      const redirectUri = `${env.WORKER_URL}/auth/dropbox`;

      if (!code) return Response.redirect(`${appUrl}?dropbox_auth=error&reason=no_code`, 302);

      // The PKCE verifier was stored in sessionStorage by the app before redirecting.
      // The app passes it as a state param so the Worker can use it for exchange.
      const verifier = url.searchParams.get('state');
      if (!verifier) return Response.redirect(`${appUrl}?dropbox_auth=error&reason=no_verifier`, 302);

      try {
        const tokenRes = await fetch('https://api.dropbox.com/oauth2/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            grant_type:    'authorization_code',
            client_id:     env.DROPBOX_APP_KEY,
            redirect_uri:  redirectUri,
            code_verifier: verifier,
          }),
        });
        const tokens = await tokenRes.json();
        if (!tokenRes.ok || !tokens.access_token) {
          console.error('Dropbox token exchange failed:', tokens);
          return Response.redirect(`${appUrl}?dropbox_auth=error&reason=token_exchange`, 302);
        }
        // Dropbox offline tokens are long-lived refresh tokens
        const refreshToken = tokens.refresh_token || tokens.access_token;
        await env.STOCKROOM_USERS.put('dropbox_refresh_token', refreshToken);
        await env.STOCKROOM_USERS.put('dropbox_access_token_temp', tokens.access_token, { expirationTtl: 14400 });
        return Response.redirect(`${appUrl}?dropbox_auth=success`, 302);
      } catch (err) {
        return Response.redirect(`${appUrl}?dropbox_auth=error&reason=${encodeURIComponent(err.message)}`, 302);
      }
    }

    // ── Retrieve temp Google access token ─────────────
    if (url.pathname === '/auth/token' && request.method === 'GET') {
      try {
        const token = await env.STOCKROOM_USERS.get('drive_access_token_temp');
        if (token) {
          await env.STOCKROOM_USERS.delete('drive_access_token_temp');
          return new Response(JSON.stringify({ access_token: token }),
            { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
        }
        return new Response(JSON.stringify({ error: 'No token available' }),
          { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
    }

    // ── Retrieve temp Dropbox access token ────────────
    if (url.pathname === '/auth/dropbox-token' && request.method === 'GET') {
      try {
        const token = await env.STOCKROOM_USERS.get('dropbox_access_token_temp');
        if (token) {
          await env.STOCKROOM_USERS.delete('dropbox_access_token_temp');
          return new Response(JSON.stringify({ access_token: token }),
            { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
        }
        return new Response(JSON.stringify({ error: 'No token available' }),
          { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
    }

    // ── Store schedule + items ────────────────────────
    if (url.pathname === '/set-schedule' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { email, startDate, startTime, intervalDays, urgent = [], upcoming = [] } = body;
        if (!email || !startDate) {
          return new Response(JSON.stringify({ error: 'Missing email or startDate' }),
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
        }
        await env.STOCKROOM_USERS.put('user_email', email);
        await env.STOCKROOM_USERS.put('schedule', JSON.stringify({
          startDate, startTime: startTime || '09:00', intervalDays: intervalDays ?? 30,
        }));
        if (urgent.length || upcoming.length) {
          await env.STOCKROOM_USERS.put('user_items', JSON.stringify({ urgent, upcoming }));
        }
        return new Response(JSON.stringify({ ok: true }),
          { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
    }

    // ── Reset last sent ───────────────────────────────
    if (url.pathname === '/reset-schedule' && request.method === 'POST') {
      try {
        await env.STOCKROOM_USERS.delete('last_sent');
        return new Response(JSON.stringify({ ok: true }),
          { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
    }

    // ── Unsubscribe ───────────────────────────────────
    if (url.pathname === '/unsubscribe' && request.method === 'POST') {
      try {
        await env.STOCKROOM_USERS.delete('schedule');
        await env.STOCKROOM_USERS.delete('last_sent');
        await env.STOCKROOM_USERS.delete('user_email');
        await env.STOCKROOM_USERS.delete('user_items');
        return new Response(JSON.stringify({ ok: true }),
          { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
    }

    // ── Manual send ───────────────────────────────────
    if (url.pathname === '/send-reminder' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { to, urgent = [], upcoming = [], items = [] } = body;
        const urgentItems   = urgent.length   ? urgent   : items.filter(i => i.daysLeft <= 7);
        const upcomingItems = upcoming.length ? upcoming : items.filter(i => i.daysLeft > 7);
        if (to) await env.STOCKROOM_USERS.put('user_email', to);
        if (urgentItems.length || upcomingItems.length) {
          await env.STOCKROOM_USERS.put('user_items', JSON.stringify({ urgent: urgentItems, upcoming: upcomingItems }));
        }
        const result = await sendEmail(to, urgentItems, upcomingItems, env);
        if (result.ok) await env.STOCKROOM_USERS.put('last_sent', new Date().toISOString());
        return new Response(
          JSON.stringify(result.ok ? { ok: true } : { error: result.error }),
          { status: result.ok ? 200 : 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
    }

    return new Response('Not found', { status: 404, headers: corsHeaders });
  }
};

// ── Cron ──────────────────────────────────────────────────────
async function cronCheck(env) {
  try {
    const email       = await env.STOCKROOM_USERS.get('user_email');
    const scheduleRaw = await env.STOCKROOM_USERS.get('schedule');
    const lastSentAt  = await env.STOCKROOM_USERS.get('last_sent');

    if (!email || !scheduleRaw) { console.log('Cron: no schedule'); return; }

    const { startDate, startTime, intervalDays } = JSON.parse(scheduleRaw);
    const now      = new Date();
    const nextSend = !lastSentAt
      ? new Date(`${startDate}T${startTime || '09:00'}:00`)
      : new Date(new Date(lastSentAt).getTime() + intervalDays * 86400000);

    if (now < nextSend) {
      console.log(`Cron: next send in ${Math.round((nextSend - now) / 60000)} mins`);
      return;
    }

    let urgentItems = [], upcomingItems = [], usedCloud = false;

    // ── Try Google Drive first ──
    const driveRefresh = await env.STOCKROOM_USERS.get('drive_refresh_token');
    if (driveRefresh) {
      try {
        const fresh = await getItemsFromDrive(driveRefresh, env);
        if (fresh) {
          urgentItems   = fresh.filter(i => i.daysLeft <= 7);
          upcomingItems = fresh.filter(i => i.daysLeft > 7 && i.daysLeft <= 30);
          usedCloud = 'drive';
          console.log(`Cron: ${fresh.length} items from Drive`);
        }
      } catch (err) { console.warn('Cron: Drive failed:', err.message); }
    }

    // ── Try Dropbox if Drive not available ──
    if (!usedCloud) {
      const dropboxRefresh = await env.STOCKROOM_USERS.get('dropbox_refresh_token');
      if (dropboxRefresh) {
        try {
          const fresh = await getItemsFromDropbox(dropboxRefresh, env);
          if (fresh) {
            urgentItems   = fresh.filter(i => i.daysLeft <= 7);
            upcomingItems = fresh.filter(i => i.daysLeft > 7 && i.daysLeft <= 30);
            usedCloud = 'dropbox';
            console.log(`Cron: ${fresh.length} items from Dropbox`);
          }
        } catch (err) { console.warn('Cron: Dropbox failed:', err.message); }
      }
    }

    // ── Fallback to KV snapshot ──
    if (!usedCloud) {
      const itemsRaw = await env.STOCKROOM_USERS.get('user_items');
      if (!itemsRaw) { console.log('Cron: no items'); return; }
      const { urgent = [], upcoming = [] } = JSON.parse(itemsRaw);
      urgentItems = urgent; upcomingItems = upcoming;
      console.log('Cron: using KV snapshot');
    }

    if (!urgentItems.length && !upcomingItems.length) {
      await env.STOCKROOM_USERS.put('last_sent', now.toISOString());
      return;
    }

    const result = await sendEmail(email, urgentItems, upcomingItems, env);
    if (result.ok) {
      await env.STOCKROOM_USERS.put('last_sent', now.toISOString());
      console.log(`Cron: sent to ${email} via ${usedCloud || 'KV'}`);
    } else {
      console.error('Cron send failed:', result.error);
    }
  } catch (err) {
    console.error('Cron error:', err.message);
  }
}

// ── Google Drive helpers ──────────────────────────────────────
async function getGoogleAccessToken(refreshToken, env) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      client_id:     env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      grant_type:    'refresh_token',
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) throw new Error(`Google token refresh failed: ${data.error}`);
  return data.access_token;
}

async function getItemsFromDrive(refreshToken, env) {
  const accessToken = await getGoogleAccessToken(refreshToken, env);
  const searchRes   = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=name='stockroom_data.json'+and+trashed=false&fields=files(id)`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  const searchData = await searchRes.json();
  if (!searchData.files?.length) throw new Error('File not found in Drive');
  const fileId  = searchData.files[0].id;
  const fileRes = await fetch(
    `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  if (!fileRes.ok) throw new Error(`Drive read failed: ${fileRes.status}`);
  const data = await fileRes.json();
  if (!Array.isArray(data.items)) throw new Error('Invalid Drive file');
  return computeDaysLeft(data.items);
}

// ── Dropbox helpers ───────────────────────────────────────────
async function getDropboxAccessToken(refreshToken, env) {
  // Dropbox offline tokens are long-lived — try using directly first
  // If expired, refresh via the token endpoint
  const res = await fetch('https://api.dropbox.com/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      grant_type:    'refresh_token',
      client_id:     env.DROPBOX_APP_KEY,
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) throw new Error(`Dropbox token refresh failed: ${JSON.stringify(data)}`);
  return data.access_token;
}

async function getItemsFromDropbox(refreshToken, env) {
  const accessToken = await getDropboxAccessToken(refreshToken, env);
  const res = await fetch('https://content.dropboxapi.com/2/files/download', {
    method: 'POST',
    headers: {
      'Authorization':   `Bearer ${accessToken}`,
      'Dropbox-API-Arg': JSON.stringify({ path: '/stockroom_data.json' }),
    },
  });
  if (!res.ok) throw new Error(`Dropbox read failed: ${res.status}`);
  const data = await res.json();
  if (!Array.isArray(data.items)) throw new Error('Invalid Dropbox file');
  return computeDaysLeft(data.items);
}

// ── Shared: compute daysLeft for email ───────────────────────
function computeDaysLeft(itemsArr) {
  const now = Date.now();
  return itemsArr
    .filter(item => item.logs?.length)
    .map(item => {
      const last      = item.logs[item.logs.length - 1];
      const refDate   = item.startedUsing || last.date;
      const daysSince = (now - new Date(refDate + 'T12:00:00').getTime()) / 86400000;
      const totalDays = (item.months || 1) * 30.5 * (last.qty || 1);
      const daysLeft  = Math.round(Math.max(0, totalDays - daysSince));
      if (daysLeft > 30) return null;
      const prices    = (item.logs || []).map(l => parseFloat(String(l.price || '').replace(/[^0-9.]/g, ''))).filter(v => !isNaN(v) && v > 0);
      return {
        name:        item.name,
        daysLeft,
        store:       item.store || '',
        url:         item.url   || '',
        lastPrice:   prices.length ? `£${prices[prices.length - 1].toFixed(2)}` : null,
        storePrices: item.storePrices || [],
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.daysLeft - b.daysLeft);
}

// ── Email ─────────────────────────────────────────────────────
async function sendEmail(to, urgentItems, upcomingItems, env) {
  const appUrl     = env.APP_URL || 'https://art-bot5000.github.io/stockroom/';
  const totalItems = urgentItems.length + upcomingItems.length;

  const makeRows = items => items.map(item => {
    const priceCell = item.lastPrice ? `<span style="font-family:monospace;font-weight:700;color:#111">${escHtml(item.lastPrice)}</span>` : '<span style="color:#999">—</span>';
    const buyCell   = item.url ? `<a href="${escHtml(item.url)}" style="display:inline-block;background:#5b8dee;color:#fff;padding:4px 12px;border-radius:6px;text-decoration:none;font-size:12px;font-weight:600">Buy ↗</a>` : '<span style="color:#999">—</span>';
    const spHtml    = (item.storePrices || []).filter(sp => sp.store && sp.price).length > 1
      ? `<div style="margin-top:4px;display:flex;gap:6px;flex-wrap:wrap">${(item.storePrices).map(sp => `<span style="font-size:11px;font-family:monospace;padding:2px 7px;border-radius:99px;background:#f0f0f0;color:#555">${escHtml(sp.store)}: ${escHtml(sp.price)}</span>`).join('')}</div>` : '';
    const daysColor = item.daysLeft <= 7 ? '#e85050' : '#e8a838';
    return `<tr>
      <td style="padding:12px 14px;border-bottom:1px solid #eee;vertical-align:top">
        <div style="font-weight:600;color:#111;margin-bottom:2px">${escHtml(item.name)}</div>
        ${item.store ? `<div style="font-size:12px;color:#666">${escHtml(item.store)}</div>` : ''}${spHtml}
      </td>
      <td style="padding:12px 14px;border-bottom:1px solid #eee;color:${daysColor};font-family:monospace;font-weight:700;white-space:nowrap;vertical-align:top">${item.daysLeft}d</td>
      <td style="padding:12px 14px;border-bottom:1px solid #eee;vertical-align:top">${priceCell}</td>
      <td style="padding:12px 14px;border-bottom:1px solid #eee;vertical-align:top">${buyCell}</td>
    </tr>`;
  }).join('');

  const tableWrap = rows => `<table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:24px">
    <thead><tr style="background:#f9f9f9">
      <th style="padding:10px 14px;text-align:left;font-size:11px;color:#999;text-transform:uppercase;border-bottom:2px solid #eee">Item</th>
      <th style="padding:10px 14px;text-align:left;font-size:11px;color:#999;text-transform:uppercase;border-bottom:2px solid #eee">Left</th>
      <th style="padding:10px 14px;text-align:left;font-size:11px;color:#999;text-transform:uppercase;border-bottom:2px solid #eee">Price</th>
      <th style="padding:10px 14px;text-align:left;font-size:11px;color:#999;text-transform:uppercase;border-bottom:2px solid #eee">Order</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;

  const urgentSection = urgentItems.length ? `
    <div style="background:#fff5f5;border-left:4px solid #e85050;border-radius:4px;padding:12px 16px;margin-bottom:12px">
      <div style="font-weight:700;color:#e85050">🔴 Order immediately — ${urgentItems.length} item${urgentItems.length !== 1 ? 's' : ''} within 7 days</div>
    </div>${tableWrap(makeRows(urgentItems))}` : '';

  const upcomingSection = upcomingItems.length ? `
    <div style="background:#fffbf0;border-left:4px solid #e8a838;border-radius:4px;padding:12px 16px;margin-bottom:12px${urgentItems.length ? ';margin-top:8px' : ''}">
      <div style="font-weight:700;color:#c8861a">🟡 Order soon — ${upcomingItems.length} item${upcomingItems.length !== 1 ? 's' : ''} within 30 days</div>
    </div>${tableWrap(makeRows(upcomingItems))}` : '';

  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:system-ui,sans-serif">
  <div style="max-width:600px;margin:32px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)">
    <div style="background:#0f1117;padding:24px 28px">
      <div style="font-family:monospace;font-size:16px;letter-spacing:3px;color:#e8a838;font-weight:700">📦 STOCKROOM</div>
      <div style="font-size:12px;color:#7880a0;margin-top:4px">Household Consumables Tracker</div>
    </div>
    <div style="padding:28px">
      <h2 style="margin:0 0 8px;font-size:20px;color:#111">Your stock reminder</h2>
      <p style="margin:0 0 24px;color:#666;font-size:14px">${totalItems} item${totalItems !== 1 ? 's' : ''} need attention.${urgentItems.length ? ` <strong style="color:#e85050">${urgentItems.length} urgent.</strong>` : ''}</p>
      ${urgentSection}${upcomingSection}
      <div style="margin-top:28px;text-align:center">
        <a href="${appUrl}" style="display:inline-block;background:#e8a838;color:#111;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px">Open STOCKROOM</a>
      </div>
    </div>
    <div style="background:#f9f9f9;padding:16px 28px;font-size:12px;color:#999;text-align:center;border-top:1px solid #eee">
      Sent from STOCKROOM &nbsp;·&nbsp; <a href="${appUrl}" style="color:#999">${appUrl}</a> &nbsp;·&nbsp; <a href="${appUrl}?action=unsubscribe" style="color:#999">Unsubscribe</a>
    </div>
  </div>
</body></html>`;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from:    env.FROM_EMAIL || 'onboarding@resend.dev',
      to:      [to],
      subject: `📦 STOCKROOM — ${urgentItems.length ? `${urgentItems.length} urgent, ` : ''}${totalItems} item${totalItems !== 1 ? 's' : ''} running low`,
      html,
    }),
  });
  const data = await res.json();
  return res.ok ? { ok: true } : { ok: false, error: data.message || JSON.stringify(data) };
}

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
