export interface Env {
  DB: D1Database;
  JWT_SECRET: string;
  WEB_ORIGIN: string;
}

/** --- util: CORS --- */
function corsHeaders(env: Env) {
  return {
    "Access-Control-Allow-Origin": env.WEB_ORIGIN === "REPLACE_ME" ? "*" : env.WEB_ORIGIN,
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function json(data: unknown, env: Env, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders(env) },
  });
}

function bad(msg: string, env: Env, status = 400) {
  return json({ error: msg }, env, status);
}

/** --- util: password hashing (PBKDF2) --- */
async function pbkdf2Hash(password: string, saltB64: string) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  const out = new Uint8Array(bits);
  let s = "";
  out.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}

function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}

/** --- util: minimal JWT (HMAC SHA-256) --- */
function base64url(input: string) {
  return btoa(input).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function base64urlBytes(bytes: Uint8Array) {
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function decodeBase64urlToString(b64url: string) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  return atob(b64);
}

async function hmacSha256(secret: string, msg: string) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return new Uint8Array(sig);
}

async function signJwt(payload: Record<string, unknown>, env: Env) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64url(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const sig = await hmacSha256(env.JWT_SECRET, data);
  return `${data}.${base64urlBytes(sig)}`;
}

async function verifyJwt(token: string, env: Env) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const data = `${h}.${p}`;
  const sig = await hmacSha256(env.JWT_SECRET, data);
  const expected = base64urlBytes(sig);
  if (!timingSafeEqual(expected, s)) return null;
  const payload = JSON.parse(decodeBase64urlToString(p));
  if (typeof payload.exp === "number" && Date.now() / 1000 > payload.exp) return null;
  return payload;
}

/** --- Auth & RBAC --- */
type Role = "ADMIN" | "PERM_ORD" | "PERM_CUI" | "GRADE_RHL";

function hasAnyRole(userRole: Role, allowed: Role[]) {
  return allowed.includes(userRole);
}

async function requireAuth(req: Request, env: Env) {
  const auth = req.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/);
  if (!m) return null;
  const payload = await verifyJwt(m[1], env);
  if (!payload || typeof payload.sub !== "string" || typeof payload.role !== "string") return null;
  return { userId: payload.sub, role: payload.role as Role };
}

/** --- Adelya import helper (simple OG/meta parsing) --- */
function pickMeta(html: string, property: string) {
  // matches: <meta property="og:image" content="...">
  const re = new RegExp(`<meta\\s+[^>]*property=["']${property}["'][^>]*content=["']([^"']+)["'][^>]*>`, "i");
  const m = html.match(re);
  return m ? m[1] : "";
}
function pickTitle(html: string) {
  const m = html.match(/<title>([^<]+)<\/title>/i);
  return m ? m[1].trim() : "";
}
function cleanName(name: string) {
  return name.replace(/\s*\|\s*Boutique.*$/i, "").trim();
}

/** --- Routing --- */
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders(env) });

    const url = new URL(req.url);
    const path = url.pathname;

    // Health
    if (path === "/api/health") return json({ ok: true }, env);

    // Login
    if (path === "/api/auth/login" && req.method === "POST") {
      const body = (await req.json().catch(() => null)) as any;
      if (!body?.email || !body?.password) return bad("email et password requis", env);

      const row = await env.DB.prepare(
        "SELECT id, email, role, password_hash_b64, salt_b64, active FROM users WHERE email = ?"
      )
        .bind(body.email)
        .first<any>();

      if (!row || row.active !== 1) return bad("identifiants invalides", env, 401);

      const computed = await pbkdf2Hash(String(body.password), String(row.salt_b64));
      if (!timingSafeEqual(computed, String(row.password_hash_b64))) return bad("identifiants invalides", env, 401);

      const token = await signJwt(
        {
          sub: String(row.id),
          role: String(row.role),
          exp: Math.floor(Date.now() / 1000) + 60 * 60 * 12, // 12h
        },
        env
      );

      return json({ token, role: row.role, email: row.email }, env);
    }

    // Me
    if (path === "/api/me" && req.method === "GET") {
      const auth = await requireAuth(req, env);
      if (!auth) return bad("non authentifié", env, 401);

      const u = await env.DB.prepare("SELECT id, name, email, role FROM users WHERE id = ?")
        .bind(auth.userId)
        .first();
      return json({ user: u }, env);
    }

    // Import from Adelya (ADMIN + PERM_ORD)
    // GET /api/adelya/import?url=https://shop.ath.adelya.net/produit/xxx
    if (path === "/api/adelya/import" && req.method === "GET") {
      const auth = await requireAuth(req, env);
      if (!auth) return bad("non authentifié", env, 401);
      if (!hasAnyRole(auth.role, ["ADMIN", "PERM_ORD"])) return bad("interdit", env, 403);

      const target = url.searchParams.get("url") || "";
      if (!target.startsWith("http")) return bad("url invalide", env);

      const r = await fetch(target, {
        headers: {
          "User-Agent": "stock-kitchen-bot/1.0",
          Accept: "text/html,*/*",
        },
      });

      if (!r.ok) return bad("Impossible de charger la page fournisseur", env, 400);

      const html = await r.text();

      const ogTitle = pickMeta(html, "og:title");
      const ogImage = pickMeta(html, "og:image");
      const title = cleanName(ogTitle || pickTitle(html) || "");

      // best effort category: often in <meta property="product:category" ...>
      const cat = pickMeta(html, "product:category");

      return json(
        {
          name: title,
          category: cat || "",
          unit: "pcs",
          image_url: ogImage || "",
          supplier_url: target,
        },
        env
      );
    }

    // Products list
    if (path === "/api/products" && req.method === "GET") {
      const auth = await requireAuth(req, env);
      if (!auth) return bad("non authentifié", env, 401);

      const q = url.searchParams.get("q")?.trim() || "";
      const stmt = q
        ? env.DB.prepare(
            "SELECT id,name,category,unit,stock_current,stock_min,location,image_url,supplier_url,active,created_at FROM products WHERE active = 1 AND name LIKE ? ORDER BY name"
          ).bind(`%${q}%`)
        : env.DB.prepare(
            "SELECT id,name,category,unit,stock_current,stock_min,location,image_url,supplier_url,active,created_at FROM products WHERE active = 1 ORDER BY name"
          );

      const rows = await stmt.all();
      return json({ products: rows.results }, env);
    }

    // Create product (ADMIN, PERM_ORD)
    if (path === "/api/products" && req.method === "POST") {
      const auth = await requireAuth(req, env);
      if (!auth) return bad("non authentifié", env, 401);
      if (!hasAnyRole(auth.role, ["ADMIN", "PERM_ORD"])) return bad("interdit", env, 403);

      const body = (await req.json().catch(() => null)) as any;

      const name = String(body?.name || "").trim();
      if (!name) return bad("name requis", env);

      const category = String(body?.category || "").trim();
      const unit = String(body?.unit || "pcs").trim();
      const stockMin = Number(body?.stock_min ?? 0);
      const location = String(body?.location || "").trim();

      const imageUrl = String(body?.image_url || "").trim();
      const supplierUrl = String(body?.supplier_url || "").trim();

      const res = await env.DB.prepare(
        "INSERT INTO products (name, category, unit, stock_current, stock_min, location, image_url, supplier_url, active, created_at) VALUES (?,?,?,?,?,?,?,?,1,datetime('now'))"
      )
        .bind(name, category, unit, 0, stockMin, location, imageUrl || null, supplierUrl || null)
        .run();

      return json({ ok: true, id: res.meta.last_row_id }, env, 201);
    }

    // Soft delete product (ADMIN only) => active=0
    const delMatch = path.match(/^\/api\/products\/(\d+)$/);
    if (delMatch && req.method === "DELETE") {
      const auth = await requireAuth(req, env);
      if (!auth) return bad("non authentifié", env, 401);
      if (!hasAnyRole(auth.role, ["ADMIN"])) return bad("interdit", env, 403);

      const id = Number(delMatch[1]);
      if (!id) return bad("id invalide", env);

      await env.DB.prepare("UPDATE products SET active=0 WHERE id=?").bind(id).run();
      return json({ ok: true }, env);
    }

    // Stock movement IN/OUT (ADMIN, PERM_ORD)
    if ((path === "/api/stock/in" || path === "/api/stock/out") && req.method === "POST") {
      const auth = await requireAuth(req, env);
      if (!auth) return bad("non authentifié", env, 401);
      if (!hasAnyRole(auth.role, ["ADMIN", "PERM_ORD"])) return bad("interdit", env, 403);

      const body = (await req.json().catch(() => null)) as any;
      const productId = Number(body?.product_id);
      const qty = Number(body?.qty);
      if (!productId || !Number.isFinite(qty) || qty <= 0) return bad("product_id et qty > 0 requis", env);

      const reason = String(body?.reason || (path.endsWith("/in") ? "IN" : "OUT")).trim();
      const type = path.endsWith("/in") ? "IN" : "OUT";

      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO stock_movements (product_id,type,qty,reason,user_id,request_id,created_at) VALUES (?,?,?,?,?,NULL,datetime('now'))"
        ).bind(productId, type, qty, reason, auth.userId),
        env.DB.prepare(
          type === "IN"
            ? "UPDATE products SET stock_current = stock_current + ? WHERE id = ?"
            : "UPDATE products SET stock_current = MAX(stock_current - ?, 0) WHERE id = ?"
        ).bind(qty, productId),
      ]);

      return json({ ok: true }, env);
    }

    // Requests list (auth required)
    if (path === "/api/requests" && req.method === "GET") {
      const auth = await requireAuth(req, env);
      if (!auth) return bad("non authentifié", env, 401);

      const status = url.searchParams.get("status") || "";
      const stmt = status
        ? env.DB.prepare("SELECT * FROM requests WHERE status = ? ORDER BY created_at DESC").bind(status)
        : env.DB.prepare("SELECT * FROM requests ORDER BY created_at DESC");

      const reqs = await stmt.all();
      return json({ requests: reqs.results }, env);
    }

    // Create request (QR token OR authenticated)
    if (path === "/api/requests" && req.method === "POST") {
      const body = (await req.json().catch(() => null)) as any;

      const qrToken = String(body?.qr_token || "").trim();
      let createdByUserId: string | null = null;
      let createdByQrId: number | null = null;

      if (qrToken) {
        const tok = await env.DB.prepare("SELECT id, active, expires_at FROM qr_tokens WHERE token = ?")
          .bind(qrToken)
          .first<any>();
        if (!tok || tok.active !== 1) return bad("QR token invalide", env, 401);

        if (tok.expires_at && String(tok.expires_at).length > 0) {
          const chk = await env.DB.prepare("SELECT CASE WHEN datetime(?) > datetime('now') THEN 1 ELSE 0 END AS ok")
            .bind(String(tok.expires_at))
            .first<any>();
          if (chk?.ok !== 1) return bad("QR token expiré", env, 401);
        }
        createdByQrId = Number(tok.id);
      } else {
        const auth = await requireAuth(req, env);
        if (!auth) return bad("non authentifié", env, 401);
        createdByUserId = auth.userId;
      }

      const note = String(body?.note || "").trim();
      const items = Array.isArray(body?.items) ? body.items : [];
      if (items.length === 0) return bad("items requis", env);

      const r = await env.DB.prepare(
        "INSERT INTO requests (created_by_user_id, created_by_qr_token_id, status, note, created_at) VALUES (?,?, 'PENDING', ?, datetime('now'))"
      )
        .bind(createdByUserId, createdByQrId, note)
        .run();
      const requestId = Number(r.meta.last_row_id);

      const stmts: D1PreparedStatement[] = [];
      for (const it of items) {
        const pid = Number(it.product_id);
        const q = Number(it.qty_requested);
        if (!pid || !Number.isFinite(q) || q <= 0) continue;
        stmts.push(
          env.DB.prepare("INSERT INTO request_items (request_id, product_id, qty_requested, qty_approved) VALUES (?,?,?,NULL)").bind(
            requestId,
            pid,
            q
          )
        );
      }
      if (stmts.length === 0) return bad("items invalides", env);
      await env.DB.batch(stmts);

      return json({ ok: true, request_id: requestId }, env, 201);
    }

    // Serve request -> decrements stock
    const serveMatch = path.match(/^\/api\/requests\/(\d+)\/serve$/);
    if (serveMatch && req.method === "POST") {
      const auth = await requireAuth(req, env);
      if (!auth) return bad("non authentifié", env, 401);
      if (!hasAnyRole(auth.role, ["ADMIN", "PERM_ORD", "PERM_CUI", "GRADE_RHL"])) return bad("interdit", env, 403);

      const requestId = Number(serveMatch[1]);
      const items = await env.DB.prepare("SELECT id, product_id, qty_approved FROM request_items WHERE request_id = ?")
        .bind(requestId)
        .all<any>();

      const stmts: D1PreparedStatement[] = [];
      for (const it of items.results) {
        const qty = Number(it.qty_approved ?? 0);
        if (!qty || qty <= 0) continue;

        stmts.push(
          env.DB.prepare(
            "INSERT INTO stock_movements (product_id,type,qty,reason,user_id,request_id,created_at) VALUES (?,?,?,?,?,?,datetime('now'))"
          ).bind(it.product_id, "OUT", qty, "REQUEST_SERVE", auth.userId, requestId)
        );
        stmts.push(env.DB.prepare("UPDATE products SET stock_current = MAX(stock_current - ?, 0) WHERE id = ?").bind(qty, it.product_id));
      }
      stmts.push(env.DB.prepare("UPDATE requests SET status='SERVED' WHERE id = ?").bind(requestId));

      await env.DB.batch(stmts);
      return json({ ok: true }, env);
    }

    // Reorder list (ADMIN, PERM_ORD)
    if (path === "/api/reorder" && req.method === "GET") {
      const auth = await requireAuth(req, env);
      if (!auth) return bad("non authentifié", env, 401);
      if (!hasAnyRole(auth.role, ["ADMIN", "PERM_ORD"])) return bad("interdit", env, 403);

      const rows = await env.DB.prepare(
        "SELECT id, name, unit, stock_current, stock_min, image_url, supplier_url, (stock_min*2 - stock_current) AS suggested_qty FROM products WHERE active=1 AND stock_current <= stock_min ORDER BY name"
      ).all();

      return json({ reorder: rows.results }, env);
    }

    return bad("route inconnue", env, 404);
  },
};
