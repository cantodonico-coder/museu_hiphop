// Servidor do Painel ADM — Museu da Cultura Hip Hop RS
// Cole TODO este código no editor do Worker na Cloudflare.
// Precisa de: KV com nome de variável ADM, segredos GH_TOKEN e ADMIN_PIN.

const OWNER = "cantodonico-coder";
const REPO = "museu_hiphop";
const BRANCH = "main";
const ORIGINS = ["https://cantodonico-coder.github.io"];
const MAX_FAILS = 5;          // tentativas erradas
const BLOCK_MIN = 15;         // minutos bloqueado
const SESSION_H = 12;         // horas logado

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
const safeEq = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };

function cors(req) {
  const o = req.headers.get("Origin") || "";
  return {
    "Access-Control-Allow-Origin": ORIGINS.includes(o) ? o : ORIGINS[0],
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin",
  };
}
const json = (req, data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...cors(req) } });

async function users(env) { return JSON.parse((await env.ADM.get("users")) || "[]"); }
async function saveUsers(env, list) { await env.ADM.put("users", JSON.stringify(list)); }

async function makeSession(env, name, master) {
  const exp = Date.now() + SESSION_H * 3600e3;
  const body = btoa(JSON.stringify({ name, master, exp }));
  return body + "." + (await hmac(env.GH_TOKEN, body));
}
async function readSession(env, req) {
  const t = (req.headers.get("Authorization") || "").replace(/^Bearer /, "");
  const [body, sig] = t.split(".");
  if (!body || !sig || !safeEq(sig, await hmac(env.GH_TOKEN, body))) return null;
  const s = JSON.parse(atob(body));
  if (s.exp < Date.now()) return null;
  if (!s.master && !(await users(env)).some((u) => u.name === s.name)) return null; // PIN removido
  return s;
}

function gh(env, path, opt = {}) {
  return fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}` + (opt.method ? "" : `?ref=${BRANCH}`), {
    ...opt,
    headers: { Authorization: "Bearer " + env.GH_TOKEN, Accept: "application/vnd.github+json", "User-Agent": "museu-adm" },
  });
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(req) });
    if (req.method !== "POST") return json(req, { ok: true, servico: "museu-adm" });
    if (!env.ADM || !env.GH_TOKEN || !env.ADMIN_PIN) return json(req, { erro: "Servidor sem configuração (KV ADM, GH_TOKEN ou ADMIN_PIN)." }, 500);

    const url = new URL(req.url);
    let b = {};
    try { b = await req.json(); } catch (e) {}

    // ---------- LOGIN ----------
    if (url.pathname === "/login") {
      const ip = req.headers.get("CF-Connecting-IP") || "x";
      const fk = "fail:" + ip;
      const f = JSON.parse((await env.ADM.get(fk)) || '{"n":0,"t":0}');
      if (f.n >= MAX_FAILS && Date.now() - f.t < BLOCK_MIN * 60e3) {
        const min = Math.ceil((BLOCK_MIN * 60e3 - (Date.now() - f.t)) / 60e3);
        return json(req, { erro: `Muitas tentativas. Tente de novo em ${min} min.` }, 429);
      }
      const pin = String(b.pin || "").replace(/\D/g, "");
      let who = null;
      if (pin && safeEq(pin, String(env.ADMIN_PIN).replace(/\D/g, ""))) who = { name: "Administrador", master: true };
      else if (pin) {
        const h = await hmac(env.GH_TOKEN, "pin:" + pin);
        const u = (await users(env)).find((x) => safeEq(x.h, h));
        if (u) who = { name: u.name, master: false };
      }
      if (!who) {
        await env.ADM.put(fk, JSON.stringify({ n: f.n + 1, t: Date.now() }), { expirationTtl: BLOCK_MIN * 60 + 60 });
        const rest = MAX_FAILS - f.n - 1;
        return json(req, { erro: rest > 0 ? `PIN incorreto. Restam ${rest} tentativa(s).` : `PIN incorreto. Bloqueado por ${BLOCK_MIN} min.` }, 401);
      }
      await env.ADM.delete(fk);
      return json(req, { sessao: await makeSession(env, who.name, who.master), nome: who.name, master: who.master });
    }

    const s = await readSession(env, req);
    if (!s) return json(req, { erro: "Sessão expirada. Entre de novo." }, 401);

    // ---------- LER DADOS ----------
    if (url.pathname === "/ler") {
      const r = await gh(env, "dados.json");
      if (r.status === 404) return json(req, { dados: null, sha: null });
      if (!r.ok) return json(req, { erro: "GitHub respondeu " + r.status }, 502);
      const j = await r.json();
      const txt = new TextDecoder().decode(Uint8Array.from(atob(j.content.replace(/\n/g, "")), (c) => c.charCodeAt(0)));
      return json(req, { dados: JSON.parse(txt), sha: j.sha });
    }

    // ---------- SALVAR (dados.json ou fotos/*.jpg) ----------
    if (url.pathname === "/salvar") {
      const path = String(b.path || "");
      if (!(path === "dados.json" || /^fotos\/[a-z0-9-]+\.jpg$/.test(path))) return json(req, { erro: "Caminho não permitido." }, 400);
      const body = { message: `${b.message || "Atualização pelo painel"} (${s.name})`, content: b.content, branch: BRANCH };
      if (b.sha) body.sha = b.sha;
      let r = await gh(env, path, { method: "PUT", body: JSON.stringify(body) });
      if ((r.status === 409 || r.status === 422) && path === "dados.json") {
        const g = await gh(env, path);
        if (g.ok) { body.sha = (await g.json()).sha; r = await gh(env, path, { method: "PUT", body: JSON.stringify(body) }); }
      }
      if (!r.ok) return json(req, { erro: "GitHub respondeu " + r.status }, 502);
      return json(req, { sha: (await r.json()).content.sha });
    }

    // ---------- PESSOAS (só Administrador) ----------
    if (url.pathname.startsWith("/pessoas")) {
      if (!s.master) return json(req, { erro: "Só o Administrador gerencia PINs." }, 403);
      let list = await users(env);
      if (url.pathname === "/pessoas/add") {
        const name = String(b.nome || "").trim().slice(0, 40);
        const pin = String(b.pin || "").replace(/\D/g, "");
        if (!name || pin.length < 4) return json(req, { erro: "Informe nome e PIN de pelo menos 4 números." }, 400);
        if (pin === String(env.ADMIN_PIN).replace(/\D/g, "")) return json(req, { erro: "Esse PIN já é do Administrador." }, 400);
        const h = await hmac(env.GH_TOKEN, "pin:" + pin);
        if (list.some((u) => u.h === h)) return json(req, { erro: "Esse PIN já está em uso. Escolha outro." }, 400);
        list = list.filter((u) => u.name !== name).concat({ name, h, criado: new Date().toISOString() });
        await saveUsers(env, list);
      }
      if (url.pathname === "/pessoas/del") {
        list = list.filter((u) => u.name !== b.nome);
        await saveUsers(env, list);
      }
      return json(req, { pessoas: list.map((u) => ({ nome: u.name, criado: u.criado })) });
    }

    return json(req, { erro: "Rota não encontrada." }, 404);
  },
};
