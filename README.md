[index.js](https://github.com/user-attachments/files/26149495/index.js)
const WebSocket = require('ws'),
      tls = require('tls'),
      extractJson = require('extract-json-string'),
      fs = require('fs'),
      https = require('https'),
      { URL } = require('url');

const config = {
  token: "",
  serverid: "",
  webhook: ""
};

let guilds = {},
    lastSeq = null,
    hbInterval = null,
    mfaToken = null,
    lastMfaFileTime = 0;

function mask(str) {
  return str ? str.slice(0,5) + "..." + str.slice(-5) : "";
}

function log(...args) {
  const time = new Date().toISOString();
  console.log(`\x1b[36m[${time}]\x1b[0m`, ...args);
}

function safeExtract(d) {
  if (typeof d !== "string") {
    try { return JSON.stringify(d); } catch { return null; }
  }
  try { return extractJson.extract(d); } catch { return null; }
}

function readMfaToken(force = false) {
  try {
    const stats = fs.statSync("mfatoken.json");
    if (!force && mfaToken && stats.mtimeMs <= lastMfaFileTime) return mfaToken;
    lastMfaFileTime = stats.mtimeMs;
    const data = fs.readFileSync("mfatoken.json", "utf8");
    const tokenData = JSON.parse(data);
    if (tokenData.token && tokenData.token !== mfaToken) {
      mfaToken = tokenData.token;
      log("MFA:", mask(mfaToken));
    }
  } catch {}
  return mfaToken;
}

fs.watchFile("mfatoken.json", { interval: 1000 }, () => readMfaToken(true));

async function sendWebhook({ results, vanityCode, sourceServerId }) {
  if (!config.webhook) return;
  const claimServerId = config.serverid;
  const now = new Date();
  const timeString = now.toTimeString().slice(0,8);

  const lines = [
    `Source Server: ${sourceServerId}`,
    `Claim Server: ${claimServerId}`,
    `URL: discord.gg/${vanityCode}`,
    `Time: ${timeString}`,
    `Attempts:`,
    ...results.map((r,i) => `#${i+1}: ${r.status || r.error || ""} — ${r.time}ms`)
  ];

  const body = {
    content: "@everyone",
    embeds: [{
      title: "Vanity Patch Attempts",
      color: 0x000000,
      description: "```\n" + lines.join("\n") + "\n```"
    }]
  };

  const bodyStr = JSON.stringify(body);
  const u = new URL(config.webhook);
  const opts = {
    hostname: u.hostname,
    port: u.port || 443,
    path: u.pathname + (u.search || ""),
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(bodyStr)
    }
  };

  return new Promise(resolve => {
    const req = https.request(opts, res => {
      res.on("data", () => {});
      res.on("end", () => resolve());
    });
    req.on("error", e => { log("WEBHOOK ERROR", e); resolve(); });
    req.write(bodyStr);
    req.end();
  });
}

async function fastPatchVanity(url, body, sourceServerId) {
  const makePatch = async () => {
    const start = Date.now();
    try {
      const res = await req("PATCH", url, JSON.stringify(body));
      const time = Date.now() - start;
      let status = (typeof res === "string" && res.includes("code"))
        ? res
        : (res && res.code)
          ? JSON.stringify(res)
          : JSON.stringify(res);
      return { status, time };
    } catch (e) {
      return { status: e + "", time: Date.now() - start };
    }
  };

  const attempts = [makePatch(), makePatch(), makePatch(), makePatch()];
  await Promise.race(attempts.map(p => p.then(r => r.time>=0?r:Promise.reject(r)))).catch(() => {});
  const results = await Promise.all(attempts);

  await sendWebhook({ results, vanityCode: body.code, sourceServerId });
  return results.some(r => r.status.includes("code"));
}

async function req(method, path, body = null) {
  return new Promise(resolve => {
    const socket = tls.connect({ host: "canary.discord.com", port: 443, rejectUnauthorized: false }, () => {
      const headers = [
        `${method} ${path} HTTP/1.1`,
        "Host: canary.discord.com",
        `Authorization: ${config.token}`,
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        `X-Super-Properties: eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRmlyZWZveCIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJ0ci1UUiIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEzMy4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEzMy4wIiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMzLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6Imh0dHBzOi8vd3d3Lmdvb2dsZS5jb20vIiwicmVmZXJyaW5nX2RvbWFpbiI6Ind3dy5nb29nbGUuY29tIiwic2VhcmNoX2VuZ2luZSI6Imdvb2dsZSIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNTYxNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGwsImhhc19jbGllbnRfbW9kcyI6ZmFsc2V9`
      ];
      if (mfaToken) headers.push(`X-Discord-MFA-Authorization: ${mfaToken}`);
      if (body) {
        headers.push("Content-Type: application/json", `Content-Length: ${Buffer.byteLength(body)}`);
      }
      headers.push("Connection: close", "", body || "");
      socket.write(headers.join("\r\n"));
    });

    let data = "";
    socket.on("data", chunk => data += chunk.toString());
    socket.on("end", () => {
      const split = data.indexOf("\r\n\r\n");
      let resp = split < 0 ? "{}" : data.slice(split + 4);
      if (data.toLowerCase().includes("transfer-encoding: chunked")) {
        let out = "", pos = 0;
        while (pos < resp.length) {
          const e = resp.indexOf("\r\n", pos);
          if (e < 0) break;
          const len = parseInt(resp.substring(pos, e), 16);
          if (len === 0) break;
          out += resp.substr(e + 2, len);
          pos = e + 2 + len + 2;
        }
        resp = out || "{}";
      }
      if (!path.includes("/vanity-url")) {
        const ext = safeExtract(resp);
        if (ext) resp = ext;
      }
      try { resolve(JSON.parse(resp)); }
      catch { resolve(resp); }
      socket.destroy();
    });

    socket.on("error", err => { log("TLS ERROR", err); resolve({}); socket.destroy(); });
    socket.setTimeout(2000, () => { log("TLS TIMEOUT"); resolve({}); socket.destroy(); });
  });
}

function formatGuilds(obj) {
  return "{\n" + Object.entries(obj).map(([k,v]) => `  '${k}': '${v}'`).join(",\n") + "\n}";
}

function connect() {
  req("GET","/api/v9/gateway").then(res => {
    let gw;
    try { gw = res.url || JSON.parse(res).url; }
    catch { gw = "wss://gateway.discord.gg/?v=9&encoding=json"; }

    const ws = new WebSocket(gw);
    ws.on("open", () => {
      log("ws OPEN");
      ws.send(JSON.stringify({
        op: 2,
        d: { token: config.token, intents: 513, properties: { os: "Windows", browser: "Discord.js", device: "Desktop" } }
      }));
    });

    ws.on("message", async d => {
      let p;
      try { p = JSON.parse(typeof d === "string" ? d : d.toString()); }
      catch {
        const ext = safeExtract(d.toString());
        if (ext) p = JSON.parse(ext);
        else return;
      }
      if (p.s) lastSeq = p.s;
      if (p.op === 10) {
        clearInterval(hbInterval);
        hbInterval = setInterval(() => ws.send(JSON.stringify({ op: 1, d: lastSeq })), p.d.heartbeat_interval);
      }
      if (p.t === "READY") {
        p.d.guilds.filter(g => g.vanity_url_code).forEach(g => guilds[g.id] = g.vanity_url_code);
        log("READY guilds", formatGuilds(guilds));
      }
      if (p.t === "GUILD_UPDATE") {
        const id = p.d.id || p.d.guild_id,
              oldCode = guilds[id],
              newCode = p.d.vanity_url_code;
        if (oldCode && oldCode !== newCode) {
          readMfaToken();
          if (mfaToken) {
            fastPatchVanity(`/api/v9/guilds/${config.serverid}/vanity-url`, { code: oldCode }, id);
          }
        }
        if (newCode) guilds[id] = newCode;
        else delete guilds[id];
      }
    });

    ws.on("close", () => {
      log("WebSocket CLOSE");
      clearInterval(hbInterval);
      setTimeout(connect, 5000);
    });

    ws.on("error", err => {
      log("WebSocket ERROR", err);
      ws.close();
    });
  }).catch(e => {
    log("GATEWAY ERROR", e);
    setTimeout(connect, 5000);
  });
}

(async () => {
  if (!config.token || !config.serverid) {
    log("config doldurulmamis");
    process.exit(1);
  }
  readMfaToken(true);
  connect();
  setInterval(() => readMfaToken(false), 30000);
})();

process.on("uncaughtException", err => { log("UNCAUGHT EXCEPTION", err); });
process.on("unhandledRejection", err => { log("UNHANDLED REJECTION", err); });
