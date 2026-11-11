
import http from "node:http";
import dns from "node:dns/promises";
import net from "node:net";

const PORT = Number(process.env.PORT || 3000);
const ALLOWED_HOSTS = new Set(
  (process.env.ALLOWED_HOSTS || "example.com")
    .split(",").map(s => s.trim().toLowerCase()).filter(Boolean)
);
const FRONTEND_ORIGINS = new Set(
  (process.env.FRONTEND_ORIGINS || "http://localhost:3000")
    .split(",").map(s => s.trim()).filter(Boolean)
);

function send(res, status, data, origin, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": type,
    "Access-Control-Allow-Origin": origin || "null",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"
  });
  res.end(data);
}

function publicAddress(ip) {
  if (net.isIP(ip) === 4) {
    const p = ip.split(".").map(Number);
    return !(
      p[0] === 0 || p[0] === 10 || p[0] === 127 ||
      p[0] >= 224 || p[0] === 169 && p[1] === 254 ||
      p[0] === 172 && p[1] >= 16 && p[1] <= 31 ||
      p[0] === 192 && p[1] === 168 ||
      p[0] === 100 && p[1] >= 64 && p[1] <= 127 ||
      p[0] === 192 && p[1] === 0 && p[2] === 0 ||
      p[0] === 192 && p[1] === 0 && p[2] === 2 ||
      p[0] === 198 && p[1] >= 18 && p[1] <= 19 ||
      p[0] === 198 && p[1] === 51 && p[2] === 100 ||
      p[0] === 203 && p[1] === 0 && p[2] === 113
    );
  }
  if (net.isIP(ip) === 6) {
    const v = ip.toLowerCase();
    return !(v === "::1" || v === "::" ||
      v.startsWith("fc") || v.startsWith("fd") ||
      v.startsWith("fe8") || v.startsWith("fe9") ||
      v.startsWith("fea") || v.startsWith("feb") ||
      v.startsWith("::ffff:"));
  }
  return false;
}

async function validateTarget(raw) {
  const url = new URL(raw);
  if (url.protocol !== "https:" || url.port ||
      url.username || url.password ||
      !ALLOWED_HOSTS.has(url.hostname.toLowerCase())) {
    throw new Error("Website is not allowed");
  }
  const addresses = await dns.lookup(url.hostname, { all: true });
  if (!addresses.length || addresses.some(a => !publicAddress(a.address))) {
    throw new Error("Website address is blocked");
  }
  return url;
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  const cors = FRONTEND_ORIGINS.has(origin) ? origin : null;

  if (req.method === "GET" && req.url === "/health") {
    return send(res, 200, JSON.stringify({ status: "ok", service: "Feather Proxy" }), cors);
  }

  if (!cors) return send(res, 403, '{"error":"Origin not allowed"}', null);
  if (req.method !== "GET") return send(res, 405, '{"error":"Method not allowed"}', cors);

  try {
    const requestUrl = new URL(req.url, "http://localhost");
    if (requestUrl.pathname !== "/proxy") {
      return send(res, 404, '{"error":"Not found"}', cors);
    }

    const target = await validateTarget(requestUrl.searchParams.get("url") || "");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    let response;
    try {
      response = await fetch(target, {
        signal: controller.signal,
        redirect: "error",
        headers: { "Accept": "text/html" }
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) throw new Error("Remote website returned " + response.status);

    const type = response.headers.get("content-type") || "";
    if (!type.toLowerCase().includes("text/html")) {
      throw new Error("Only HTML pages are supported");
    }

    const length = Number(response.headers.get("content-length") || 0);
    if (length > 1024 * 1024) throw new Error("Page too large");

    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > 1024 * 1024) {
        await response.body.cancel().catch(() => {});
        throw new Error("Page too large");
      }
      chunks.push(chunk);
    }

    const html = Buffer.concat(chunks).toString("utf8")
      .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, "")
      .replace(/<script\b[^>]*\/>/gi, "")
      .replace(/<form\b[^>]*>[\s\S]*?<\/form\s*>/gi, "")
      .replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe\s*>/gi, "")
      .replace(/<object\b[^>]*>[\s\S]*?<\/object\s*>/gi, "")
      .replace(/<embed\b[^>]*>/gi, "")
      .replace(/<base\b[^>]*>/gi, "");

    send(res, 200, html, cors, "text/html; charset=utf-8");
  } catch (err) {
    send(res, 400, JSON.stringify({ error: err.message }), cors);
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Feather proxy running on port ${PORT}`);
});
