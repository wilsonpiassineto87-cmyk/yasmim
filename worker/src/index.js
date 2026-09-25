// API de cadastro/login + progresso para o app Bússola Naval.
// Roda como Cloudflare Worker, usando o banco D1 "yasmim-usuarios".

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const saltBytes = saltHex
    ? Uint8Array.from(saltHex.match(/.{2}/g).map((h) => parseInt(h, 16)))
    : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return { hash: bytesToHex(derived), salt: bytesToHex(saltBytes) };
}

async function signToken(username, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(username));
  return btoa(username) + '.' + bytesToHex(sig);
}

async function verifyToken(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [b64user, sig] = token.split('.');
  let username;
  try { username = atob(b64user); } catch (e) { return null; }
  const expected = await signToken(username, secret);
  return expected === token ? username : null;
}

async function readJson(request) {
  try { return await request.json(); } catch (e) { return null; }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    // --- Cadastro ---
    if (path === '/register' && request.method === 'POST') {
      const body = await readJson(request);
      if (!body) return json({ error: 'JSON inválido.' }, 400);
      const name = (body.name || '').trim();
      const username = (body.username || '').trim().toLowerCase();
      const password = body.password || '';
      if (!name || !username || !password) return json({ error: 'Preencha todos os campos.' }, 400);

      const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
      if (existing) return json({ error: 'Este usuário já existe.' }, 409);

      const { hash, salt } = await hashPassword(password);
      const result = await env.DB.prepare(
        'INSERT INTO users (username, name, pass_hash, salt) VALUES (?, ?, ?, ?)'
      ).bind(username, name, hash, salt).run();
      const userId = result.meta.last_row_id;
      await env.DB.prepare('INSERT INTO user_progress (user_id, data) VALUES (?, ?)').bind(userId, '{}').run();

      const token = await signToken(username, env.TOKEN_SECRET);
      return json({ ok: true, name, username, token });
    }

    // --- Login ---
    if (path === '/login' && request.method === 'POST') {
      const body = await readJson(request);
      if (!body) return json({ error: 'JSON inválido.' }, 400);
      const username = (body.username || '').trim().toLowerCase();
      const password = body.password || '';
      if (!username || !password) return json({ error: 'Preencha usuário e senha.' }, 400);

      const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      if (!user) return json({ error: 'Usuário não encontrado.' }, 404);

      const { hash } = await hashPassword(password, user.salt);
      if (hash !== user.pass_hash) return json({ error: 'Senha incorreta.' }, 401);

      const token = await signToken(username, env.TOKEN_SECRET);
      return json({ ok: true, name: user.name, username, token });
    }

    // --- Buscar progresso ---
    if (path === '/progress' && request.method === 'GET') {
      const token = url.searchParams.get('token');
      const username = await verifyToken(token, env.TOKEN_SECRET);
      if (!username) return json({ error: 'Token inválido.' }, 401);

      const user = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
      if (!user) return json({ error: 'Usuário não encontrado.' }, 404);
      const row = await env.DB.prepare('SELECT data FROM user_progress WHERE user_id = ?').bind(user.id).first();
      return json({ ok: true, data: row ? row.data : '{}' });
    }

    // --- Salvar progresso ---
    if (path === '/progress' && request.method === 'POST') {
      const body = await readJson(request);
      if (!body) return json({ error: 'JSON inválido.' }, 400);
      const username = await verifyToken(body.token, env.TOKEN_SECRET);
      if (!username) return json({ error: 'Token inválido.' }, 401);

      const user = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
      if (!user) return json({ error: 'Usuário não encontrado.' }, 404);
      await env.DB.prepare(
        "UPDATE user_progress SET data = ?, updated_at = datetime('now') WHERE user_id = ?"
      ).bind(JSON.stringify(body.data || {}), user.id).run();
      return json({ ok: true });
    }

    return json({ error: 'Rota não encontrada.' }, 404);
  },
};
