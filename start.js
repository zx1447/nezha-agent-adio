const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const http2 = require('http2');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');

// ---- diagnostics: agent output ring buffer + network test ----
const agentLog = [];
function pushLog(line) {
  if (!line) return;
  const stamped = new Date().toISOString().slice(11, 19) + ' ' + line;
  agentLog.push(stamped);
  if (agentLog.length > 500) agentLog.shift();
}
let netTest = { dns: 'pending', tcp: 'pending', https: 'pending', grpc: 'pending', egress: 'pending', ip: '', at: '', err: '' };
// DNS fix for grpc-go: the pure-Go resolver walks resolv.conf search list (ndots:5) SEQUENTIALLY,
// while node/musl races them in parallel. On a cluster CoreDNS that answers slowly for the
// non-existent search-suffixed names, grpc dial dies with "lookup ...: operation was canceled"
// (DeadlineExceeded) even though node-level DNS works. Fix ladder:
//   1) pin /etc/hosts (needs root) — Go resolver reads hosts first, never touches CoreDNS
//   2) local SNI-terminating TLS proxy (no root needed) — agent dials 127.0.0.1 with
//      insecure_tls, proxy re-encrypts to the panel with the CORRECT SNI (CF routes by SNI)
//   3) whatever happens, report the outcome in /health (dnsFix) so we can see it remotely
let dnsFix = { mode: 'init', ip: '', detail: '', at: '' };
let CURRENT_IP = '';
let AGENT_SERVER = '';
let AGENT_MODE = 'direct';
const PANEL_HOST = () => PANEL.split(':')[0];
function withTimeout(p, ms, tag) {
  return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(tag + ' timeout ' + ms + 'ms')), ms))]);
}
// Two independent resolver paths: c-ares (dns.resolve4, absolute A query, no ndots search walk)
// then getaddrinfo (dns.lookup). Either succeeding is enough to get an IP for pin/proxy.
async function resolvePanelV4() {
  const host = PANEL_HOST();
  try {
    const a = await withTimeout(dns.resolve4(host), 8000, 'resolve4');
    if (a && a.length) { console.log('[dnsfix] resolve4 ' + host + ' -> ' + a[0]); return a[0]; }
  } catch (e) { console.log('[dnsfix] resolve4 failed: ' + (e.message || e)); }
  try {
    const r = await withTimeout(dns.lookup(host, { all: true, family: 4 }), 8000, 'lookup4');
    const a4 = (r || []).filter(x => x.family === 4).map(x => x.address);
    if (a4.length) { console.log('[dnsfix] lookup4 ' + host + ' -> ' + a4[0]); return a4[0]; }
  } catch (e) { console.log('[dnsfix] lookup4 failed: ' + (e.message || e)); }
  return null;
}
// h2/gRPC probe: real gRPC call shape against the panel (catches "tls ok but grpc never ready")
function grpcProbe(host, port) {
  return new Promise((resolve) => {
    let done = false, s = null;
    const finish = (r) => { if (done) return; done = true; try { if (s) s.close(); } catch (_) {} resolve(r); };
    try { s = http2.connect('https://' + host + ':' + port); } catch (e) { return resolve('connect err: ' + e.message); }
    const timer = setTimeout(() => finish('TIMEOUT 8s (no response headers - stream stuck)'), 8000);
    s.on('error', (e) => { clearTimeout(timer); finish('h2 session error: ' + e.message); });
    let req;
    try {
      req = s.request({ ':method': 'POST', ':path': '/nezhahq.NezhaService/ReportSystemInfo', 'content-type': 'application/grpc', te: 'trailers' });
    } catch (e) { clearTimeout(timer); return finish('req err: ' + e.message); }
    req.on('response', (h) => { clearTimeout(timer); finish('OK http=' + h[':status'] + ' ct=' + (h['content-type'] || '?')); });
    req.on('error', (e) => { clearTimeout(timer); finish('stream err: ' + e.message); });
    req.end(Buffer.from([0, 0, 0, 0, 0]));
  });
}
// v6 blackhole probe: SYNs sent but never answered (vs instant EUNREACH) stall grpc-go, which
// tries AAAA addresses first per-subchannel without happy-eyeballs
function tcpProbe(host, port, family, timeoutMs) {
  return new Promise((resolve) => {
    try {
      const s = net.connect({ host, port, family });
      const done = (r) => { try { s.destroy(); } catch (_) {} resolve(r); };
      s.setTimeout(timeoutMs, () => done('TIMEOUT ' + (timeoutMs/1000) + 's (blackhole?)'));
      s.on('connect', () => done('ok'));
      s.on('error', (e) => done(e.code || e.message));
    } catch (e) { resolve(e.code || e.message); }
  });
}
async function runNetTest() {
  const host = PANEL.split(':')[0];
  const port = parseInt(PANEL.split(':')[1]) || 443;
  const tls = TLS;
  const t = { dns: 'fail', tcp: 'fail', tcp4: '-', tcp6: '-', https: '-', grpc: '-', egress: '-', ip: '', at: new Date().toISOString(), err: '' };
  try {
    const r = await dns.lookup(host, { all: true });
    t.dns = 'ok(' + r.length + ')';
    t.ip = r.map(x => x.address).join(',').slice(0, 80);
    if (t.dns !== 'fail') {
      t.tcp4 = await tcpProbe(host, port, 4, 5000);
      t.tcp6 = await tcpProbe(host, port, 6, 5000);
    }
  } catch (e) { t.err = 'DNS: ' + e.message + '; '; }
  if (t.dns !== 'fail') {
    try {
      await new Promise((resolve, reject) => {
        const s = net.connect({ host, port }, () => { s.destroy(); resolve(); });
        s.setTimeout(6000, () => { s.destroy(); reject(new Error('timeout 6s')); });
        s.on('error', reject);
      });
      t.tcp = 'ok';
    } catch (e) { t.err += 'TCP: ' + e.message; }
  }
  if (t.tcp === 'ok' && tls) {
    try {
      const r = await fetch('https://' + host + ':' + port + '/', { signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'nz-agent-diagnostics' } });
      t.https = 'ok ' + r.status;
    } catch (e) { t.https = 'fail'; t.err += 'HTTPS: ' + (e.message || e.cause || e); }
    t.grpc = await grpcProbe(host, port);
  }
  try {
    const r2 = await fetch('https://api.ipify.org', { signal: AbortSignal.timeout(8000) });
    t.egress = (await r2.text()).slice(0, 45);
  } catch (e) { t.egress = 'fail'; t.err += 'EGRESS: ' + (e.message || e); }
  netTest = t;
  console.log('[nettest] dns=' + t.dns + ' tcp=' + t.tcp + ' https=' + t.https + ' grpc=' + t.grpc + ' egress=' + t.egress + ' ip=' + t.ip + (t.err ? ' err=' + t.err : ''));
}

const PORT = parseInt(process.env.PORT) || 5000;
const UUID = process.env.NZ_UUID || '';
const PANEL = process.env.NZ_SERVER;
if (!PANEL) { console.error('[nezha] NZ_SERVER env required'); process.exit(1); }
// Secret comes exclusively from platform env NZ_CLIENT_SECRET.
const SECRET = process.env.NZ_CLIENT_SECRET;
if (!SECRET) { console.error('[nezha] NZ_CLIENT_SECRET env required'); process.exit(1); }
console.log('[nezha] secret source: ' + (process.env.NZ_CLIENT_SECRET ? 'env NZ_CLIENT_SECRET' : 'builtin fallback'));
const TLS = (process.env.NZ_TLS || 'true').toString().toLowerCase() === 'true';
const DISABLE_CMD = (process.env.NZ_DISABLE_CMD || 'false').toLowerCase() === 'true'; // false = panel terminal ENABLED
const BOOT_TS = Date.now();

let agentRestarts = 0;
let lastExit = 'never';

// HTTP server: / returns HTML status page, anything else plain text
http.createServer((req, res) => {
  const uptime = Math.floor((Date.now() - BOOT_TS) / 1000);
  const uptimeStr = uptime < 60 ? uptime + 's'
    : uptime < 3600 ? Math.floor(uptime/60) + 'm ' + (uptime%60) + 's'
    : Math.floor(uptime/3600) + 'h ' + Math.floor((uptime%3600)/60) + 'm';
  const alive = currentProc && !currentProc.killed && currentProc.exitCode === null && currentProc.signalCode === null;
  const statusColor = alive ? '#22c55e' : '#ef4444';
  const statusText = alive ? '● RUNNING' : '● DOWN';

  if (req.url === '/' || req.url === '/index.html') {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nezha Agent — Infrlo</title>
<meta http-equiv="refresh" content="30">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:linear-gradient(135deg,#0f0720 0%,#1a1035 100%);
  color:#e2e8f0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
.card { background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.09);
  border-radius:20px; padding:36px; max-width:460px; width:100%;
  box-shadow:0 20px 60px rgba(0,0,0,.5); backdrop-filter:blur(10px); }
h1 { font-size:22px; font-weight:700; margin-bottom:4px; display:flex; align-items:center; gap:10px; }
.dot { width:12px; height:12px; border-radius:50%; background:${statusColor};
  box-shadow:0 0 12px ${statusColor}; animation:pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }
.sub { font-size:12px; color:#94a3b8; margin-bottom:26px; }
.row { display:flex; justify-content:space-between; padding:11px 0;
  border-bottom:1px solid rgba(255,255,255,.06); font-size:14px; }
.row:last-child { border-bottom:none; }
.label { color:#94a3b8; }
.val { color:#f1f5f9; font-family:'SF Mono',Monaco,monospace; font-size:12.5px; text-align:right; max-width:60%; word-break:break-all; }
.badge { display:inline-block; padding:5px 14px; border-radius:99px; font-size:12px; font-weight:600;
  background:${statusColor}22; color:${statusColor}; border:1px solid ${statusColor}44; margin-bottom:20px; }
.footer { margin-top:24px; font-size:11px; color:#64748b; text-align:center; }
a { color:#818cf8; text-decoration:none; }
</style>
</head>
<body>
<div class="card">
  <h1><span class="dot"></span> Nezha Agent</h1>
  <div class="sub">哪吒探针 · Infrlo PaaS</div>
  <div class="badge">${statusText}</div>
  <div class="row"><span class="label">UUID</span><span class="val">${UUID}</span></div>
  <div class="row"><span class="label">Panel</span><span class="val">${PANEL}</span></div>
  <div class="row"><span class="label">TLS</span><span class="val">${TLS}</span></div>
  <div class="row"><span class="label">Agent PID</span><span class="val">${currentProc ? currentProc.pid : '—'}</span></div>
  <div class="row"><span class="label">Restarts</span><span class="val">${agentRestarts}</span></div>
  <div class="row"><span class="label">Last Exit</span><span class="val">${lastExit}</span></div>
  <div class="row"><span class="label">Uptime</span><span class="val">${uptimeStr}</span></div>
  <div class="row"><span class="label">Platform</span><span class="val">Infrlo Free (Singapore)</span></div>
  <div class="row"><span class="label">DNS</span><span class="val">${netTest.dns}</span></div>
  <div class="row"><span class="label">TCP→Panel</span><span class="val">v4:${netTest.tcp4} v6:${netTest.tcp6}</span></div>
  <div class="row"><span class="label">HTTPS(Node)</span><span class="val">${netTest.https}</span></div>
  <div class="row"><span class="label">gRPC probe</span><span class="val">${netTest.grpc}</span></div>
  <div class="row"><span class="label">DNS Fix</span><span class="val">${dnsFix.mode}${dnsFix.ip ? ' · ' + dnsFix.ip : ''}${dnsFix.detail ? ' · ' + dnsFix.detail.slice(0, 60) : ''}</span></div>
  <div class="row"><span class="label">CA bundle</span><span class="val">${caOk ? 'loaded' : 'MISSING'}</span></div>
  <div class="row"><span class="label">Egress IP</span><span class="val">${netTest.egress}</span></div>
  <div class="row"><span class="label">Cmd Exec</span><span class="val">${DISABLE_CMD ? 'disabled' : '✓ enabled'}</span></div>
  ${netTest.err ? `<div class="row"><span class="label">Err</span><span class="val">${netTest.err}</span></div>` : ''}
  <div style="margin-top:18px;font-size:12px;color:#94a3b8;">Agent output (last lines)</div>
  <pre style="margin-top:6px;background:rgba(0,0,0,.35);border-radius:10px;padding:12px;font-size:11px;line-height:1.5;max-height:200px;overflow:auto;color:#a5b4fc;">${agentLog.slice(-15).join('\n') || '(no output yet)'}</pre>
  <div class="footer">Auto-refresh 30s · <a href="https://${PANEL.split(':')[0]}" target="_blank">打开面板</a> · <a href="/health">/health</a></div>
</div>
</body>
</html`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  } else if (req.url === '/health' || req.url === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: alive, uuid: UUID, panel: PANEL, agentServer: AGENT_SERVER || PANEL, agentMode: AGENT_MODE, dnsFix, uptime, agentRestarts, pid: currentProc ? currentProc.pid : null, proxyEnv: proxyInfo(), sys: sysInfo(), netTest, agentLog }));
  } else {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('nezha-agent OK uuid=' + UUID + ' panel=' + PANEL + '\n');
  }
}).listen(PORT, '0.0.0.0', () => {
  console.log('[health] listening on port ' + PORT + ' (HTML status page at /)');
});

if (!UUID || !PANEL || !SECRET) {
  console.log('[nezha] FATAL: missing env vars. Need NZ_UUID, NZ_SERVER, NZ_CLIENT_SECRET');
  console.log('[nezha] got: UUID=' + (UUID ? 'set' : 'EMPTY') + ' PANEL=' + PANEL + ' SECRET=' + (SECRET ? 'set' : 'EMPTY'));
}

// Write config in OFFICIAL format (all 21 fields, matches `nezha-agent service install` output)
const configPath = '/tmp/config.yml';
function writeConfig(serverAddr, insecure) {
  const configYaml = [
    'client_secret: "' + SECRET + '"',
    'debug: ' + ((process.env.NZ_DEBUG || 'true').toLowerCase() === 'true'),
    'disable_auto_update: true',
    'disable_command_execute: ' + DISABLE_CMD,
    'disable_force_update: true',
    'disable_nat: false',
    'disable_send_query: false',
    'gpu: false',
    'insecure_tls: ' + (insecure ? 'true' : 'false'),
    'ip_report_period: 1800',
    'report_delay: 3',
    'self_update_period: 0',
    'server: "' + serverAddr + '"',
    'skip_connection_count: true',
    'skip_procs_count: false',
    'temperature: false',
    'tls: ' + TLS,
    'use_atomgit_to_upgrade: false',
    'use_gitee_to_upgrade: false',
    'use_ipv6_country_code: false',
    'uuid: "' + UUID + '"',
  ].join('\n') + '\n';
  fs.writeFileSync(configPath, configYaml);
  AGENT_SERVER = serverAddr;
  console.log('[nezha] config written to ' + configPath + ' (server=' + serverAddr + ', insecure_tls=' + insecure + ', uuid=' + UUID + ')');
}

// Make binary executable
const binPath = path.join(__dirname, 'nezha-agent');
console.log('[nezha] binPath = ' + binPath + ' (exists: ' + fs.existsSync(binPath) + ')');
try {
  fs.chmodSync(binPath, 0o755);
  const stat = fs.statSync(binPath);
  console.log('[nezha] binary size: ' + stat.size + ' bytes');
} catch(e) {
  console.log('[nezha] chmod/stat error: ' + e.message);
}

// CA bundle for Go x509 verification (PaaS images often lack ca-certificates)
const caPath = path.join(__dirname, 'ca-bundle.pem');
const caOk = fs.existsSync(caPath);
console.log('[nezha] CA bundle: ' + caPath + ' exists=' + caOk + (caOk ? ' -> SSL_CERT_FILE' : ''));

// PaaS platforms may inject HTTP(S)_PROXY env vars; grpc-go honors them and a
// proxy that won't tunnel gRPC leaves the subchannel forever non-ready (DeadlineExceeded).
// Strip them for the agent process; NO_PROXY=* belt-and-suspenders.
function agentEnv() {
  const e = { ...process.env };
  for (const k of ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'FTP_PROXY', 'ftp_proxy']) delete e[k];
  // PaaS-injected NZ_* envs (NZ_SERVER/NZ_TLS/NZ_UUID/NZ_CLIENT_SECRET...) override config.yml
  // INSIDE the agent (verified: agent dials NZ_SERVER even when -c config points at 127.0.0.1).
  // Strip them all — the agent must follow OUR config, which may target the local SNI proxy.
  for (const k of Object.keys(e)) if (/^NZ_/i.test(k)) delete e[k];
  e.NO_PROXY = '*';
  e.no_proxy = '*';
  // Go's pure resolver reads LOCALDOMAIN over resolv.conf's search list. K8s pods ship
  // ndots:5 + 3 search suffixes; grpc-go walks them SEQUENTIALLY and the dial deadline (11s)
  // dies before the absolute query is reached when CoreDNS is slow for non-existent names.
  // A single space = non-empty env with zero search domains -> absolute query goes FIRST.
  e.LOCALDOMAIN = ' ';
  // Go 1.23+ defaults to X25519MLKEM768 key share (~1.7KB ClientHello). On paths with a
  // smaller MTU + broken PMTUD the second segment dies and the TLS handshake hangs forever
  // (grpc-go: subchannel never ready / DeadlineExceeded) while small-ClientHello clients work.
  e.GODEBUG = (process.env.GODEBUG ? process.env.GODEBUG + ',' : '') + 'tlsmlkem=0';
  // grpc-go internal logging: shows subchannel address attempts, TLS/h2 handshake failures
  e.GRPC_GO_LOG_SEVERITY_LEVEL = 'INFO';
  e.GRPC_GO_LOG_VERBOSITY_LEVEL = '99';
  e.SSL_CERT_FILE = caOk ? caPath : '';
  return e;
}
// report which proxy vars the platform injects (masked, no credentials)
function proxyInfo() {
  const out = {};
  for (const k of Object.keys(process.env)) {
    if (/proxy/i.test(k) && process.env[k]) {
      try {
        const u = new URL(process.env[k]);
        out[k] = u.protocol + '//' + (u.hostname || '?') + ':' + (u.port || '?');
      } catch (_) { out[k] = 'set(non-url)'; }
    }
  }
  return out;
}
function sysInfo() {
  const safe = (p) => { try { return fs.readFileSync(p, 'utf8').slice(0, 500); } catch (e) { return '(' + e.code + ')'; } };
  const mtu = (n) => { try { return parseInt(fs.readFileSync('/sys/class/net/' + n + '/mtu', 'utf8').trim()); } catch (_) { return null; } };
  return {
    node: process.version,
    mtu_eth0: mtu('eth0'), mtu_lo: mtu('lo'),
    resolvconf: safe('/etc/resolv.conf'),
    hosts_tail: safe('/etc/hosts').slice(-400),
    configFile: safe('/tmp/config.yml'),
    tmpLs: (() => { try { return fs.readdirSync('/tmp').slice(0, 25).join(','); } catch (e) { return '(' + e.code + ')'; } })(),
    agentCmdline: (() => { try { return fs.readFileSync('/proc/' + (currentProc ? currentProc.pid : 'x') + '/cmdline', 'utf8').replace(/\0/g, ' ').slice(0, 200); } catch (e) { return '(' + e.code + ')'; } })(),
  };
}

// Spawn binary agent, capture its output into ring buffer
let currentProc = null;
function startAgent() {
  console.log('[nezha] starting binary agent... (mode=' + AGENT_MODE + ', server=' + (AGENT_SERVER || PANEL) + ')');
  const proc = spawn(binPath, ['-c', configPath], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: agentEnv(),
  });
  currentProc = proc;
  let outBuf = '', errBuf = '';
  proc.stdout.on('data', d => { outBuf += d; let i; while ((i = outBuf.indexOf('\n')) >= 0) { pushLog(outBuf.slice(0, i)); outBuf = outBuf.slice(i + 1); } });
  proc.stderr.on('data', d => { errBuf += d; let i; while ((i = errBuf.indexOf('\n')) >= 0) { pushLog('E! ' + errBuf.slice(0, i)); errBuf = errBuf.slice(i + 1); } });
  proc.on('error', (err) => { console.log('[nezha] spawn error: ' + err.message); pushLog('spawn error: ' + err.message); });
  proc.on('exit', (code, signal) => {
    agentRestarts++;
    lastExit = 'code=' + code + ' signal=' + signal + ' @ ' + new Date().toISOString();
    console.log('[nezha] agent exited (code=' + code + ', signal=' + signal + '), restarting in 5s...');
    pushLog('EXIT code=' + code + ' signal=' + signal);
    currentProc = null;
    setTimeout(startAgent, 5000);
  });
}
// Pin panel host -> its A record in /etc/hosts (needs root). Go's pure resolver reads hosts
// FIRST, so a pinned entry bypasses the broken cluster CoreDNS entirely. Returns status string.
function pinHostsV4(ip) {
  const host = PANEL_HOST();
  try {
    const hostsPath = '/etc/hosts';
    const cur = fs.readFileSync(hostsPath, 'utf8');
    if (new RegExp('(^|\\n)\\S+\\s+' + host.replace(/\./g, '\\.') + '(\\s|\\n|$)').test(cur)) {
      console.log('[hosts] ' + host + ' already pinned');
      return 'already-pinned';
    }
    fs.appendFileSync(hostsPath, ip + ' ' + host + ' # nezha-agent v4 pin\n');
    console.log('[hosts] pinned ' + host + ' -> ' + ip);
    return 'pinned';
  } catch (e) {
    console.log('[hosts] not writable (uid=' + process.getuid() + '): ' + (e.code || e.message));
    return 'failed ' + (e.code || e.message) + ' uid=' + process.getuid();
  }
}

// h2 reverse proxy fallback (no root needed): agent dials 127.0.0.1:18443 with tls=true +
// insecure_tls=true (self-signed cert). We terminate that TLS, then open an h2 session to the
// panel with the CORRECT SNI and rewrite :authority to the panel host — a raw TCP forward can't
// do that, and with :authority=127.0.0.1 Cloudflare answers 403 (verified). gRPC streams are
// forwarded bidirectionally with headers AND trailers (grpc-status lives in trailers).
let sniProxySrv = null;
function ensureSelfSignedCert() {
  const keyP = '/tmp/nz-sni.key', crtP = '/tmp/nz-sni.crt';
  if (fs.existsSync(keyP) && fs.existsSync(crtP)) return { key: fs.readFileSync(keyP), cert: fs.readFileSync(crtP) };
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-keyout', keyP, '-out', crtP, '-days', '3650', '-nodes', '-subj', '/CN=nezha-local'],
    { stdio: 'ignore', timeout: 20000 });
  return { key: fs.readFileSync(keyP), cert: fs.readFileSync(crtP) };
}
function startSniProxy() {
  return new Promise((resolve, reject) => {
    if (sniProxySrv) return resolve(18443);
    let creds;
    try { creds = ensureSelfSignedCert(); } catch (e) { return reject(new Error('self-signed cert: ' + (e.message || e))); }
    const host = PANEL_HOST();
    try {
      sniProxySrv = http2.createSecureServer({ key: creds.key, cert: creds.cert, allowHTTP1: false });
      sniProxySrv.on('stream', (stream, headers) => {
        pushLog('[sniproxy] h2 ' + (headers[':method'] || '?') + ' ' + (headers[':path'] || '?'));
        let us;
        try {
          us = http2.connect('https://' + host, { host: CURRENT_IP || host, port: 443, servername: host, ALPNProtocols: ['h2'] });
        } catch (e) { pushLog('[sniproxy] upstream err: ' + (e.message || e)); try { stream.close(2); } catch (_) {} return; }
        const bail = (tag) => { pushLog('[sniproxy] ' + tag); try { stream.close(2); } catch (_) {} try { us.close(); } catch (_) {} };
        us.on('error', (e) => bail('upstream session err: ' + (e.message || e)));
        stream.on('error', () => { try { us.close(); } catch (_) {} });
        // rebuild pseudo-headers: keep method/path, force scheme+authority to the panel
        const fwd = { ':method': headers[':method'] || 'POST', ':path': headers[':path'] || '/', ':scheme': 'https', ':authority': host };
        for (const k of Object.keys(headers)) {
          if (k.charCodeAt(0) === 58) continue; // drop incoming pseudo-headers
          fwd[k] = headers[k];
        }
        const ureq = us.request(fwd);
        stream.pipe(ureq); // request body/flow starts immediately
        ureq.on('response', (rh) => {
          try { stream.respond(rh, { waitForTrailers: true }); ureq.pipe(stream); } catch (e) { bail('respond err: ' + (e.message || e)); }
        });
        let upstreamTrailers = {};
        ureq.on('trailers', (t) => { for (const k of Object.keys(t)) upstreamTrailers[k] = t[k]; });
        stream.on('wantTrailers', () => { try { stream.sendTrailers(upstreamTrailers); } catch (_) {} });
        const cleanup = () => { try { us.close(); } catch (_) {} };
        stream.on('close', cleanup); ureq.on('close', cleanup);
      });
      sniProxySrv.on('error', (e) => console.log('[sniproxy] server error: ' + (e.message || e)));
      sniProxySrv.on('sessionError', (e) => console.log('[sniproxy] session error: ' + (e.message || e)));
      sniProxySrv.listen(18443, '127.0.0.1', () => {
        console.log('[sniproxy] h2 reverse proxy listening 127.0.0.1:18443 -> https://' + host + ':443 (sni+authority=' + host + ', ip=' + (CURRENT_IP || '?') + ')');
        resolve(18443);
      });
    } catch (e) { reject(e); }
  });
}
function restartAgent() {
  if (currentProc) { try { currentProc.kill('SIGKILL'); } catch (_) {} }
}

(async () => {
  const ip = await resolvePanelV4();
  if (ip) CURRENT_IP = ip;
  if (ip) {
    const pin = pinHostsV4(ip);
    dnsFix = { mode: 'hosts-pin', ip: ip, detail: pin, at: new Date().toISOString() };
  }
  if (!ip || dnsFix.detail.indexOf('failed') === 0) {
    // pin not possible: try LOCALDOMAIN-cured direct first (no proxy in the path),
    // and only fall back to the h2 sni-proxy after a 60s health check of the agent log.
    dnsFix = { mode: 'direct(LOCALDOMAIN)', ip: CURRENT_IP || '?', detail: 'pin failed, direct with cleared search list', at: new Date().toISOString() };
    setTimeout(() => {
      if (AGENT_MODE !== 'direct' || dnsFix.mode === 'hosts-pin') return;
      const recent = agentLog.slice(-160).join('\n');
      if (/original dial target|DeadlineExceeded|operation was canceled/.test(recent)) {
        console.log('[dnsfix] direct still failing after 60s -> switching to h2 sni-proxy');
        startSniProxy().then((port) => {
          AGENT_SERVER = '127.0.0.1:' + port;
          AGENT_MODE = 'sni-proxy';
          dnsFix = { mode: 'sni-proxy', ip: CURRENT_IP || '?', detail: 'h2 reverse proxy, authority=' + PANEL_HOST(), at: new Date().toISOString() };
          writeConfig(AGENT_SERVER, true);
          restartAgent();
        }).catch((e) => console.log('[dnsfix] proxy fallback failed: ' + (e.message || e)));
      } else {
        dnsFix = { mode: 'direct(healthy)', ip: CURRENT_IP || '?', detail: 'LOCALDOMAIN fix confirmed working', at: new Date().toISOString() };
      }
    }, 60000);
  }
  if (!AGENT_SERVER) AGENT_SERVER = PANEL;
  writeConfig(AGENT_SERVER, AGENT_MODE === 'sni-proxy');
  startAgent();
  runNetTest();
  setInterval(runNetTest, 300000);
  // Self-heal loop every 10 min: upgrade sni-proxy/failed modes to hosts-pin when the file
  // becomes writable, and refresh CURRENT_IP for the proxy upstream in the meantime.
  setInterval(async () => {
    try {
      const ip2 = await resolvePanelV4();
      if (!ip2) return;
      CURRENT_IP = ip2;
      if (dnsFix.mode === 'hosts-pin') return;
      const pin = pinHostsV4(ip2);
      if (pin === 'pinned' || pin === 'already-pinned') {
        dnsFix = { mode: 'hosts-pin', ip: ip2, detail: pin, at: new Date().toISOString() };
        if (AGENT_MODE !== 'direct') {
          AGENT_MODE = 'direct';
          writeConfig(PANEL, false);
          restartAgent();
        }
      }
    } catch (e) { console.log('[dnsfix] retry error: ' + (e.message || e)); }
  }, 600000);
})().catch(e => {
  console.log('[dnsfix] init fatal: ' + (e.message || e) + ' — starting agent direct as last resort');
  writeConfig(PANEL, false);
  startAgent();
  runNetTest();
});

// Periodic alive ping every 60s
setInterval(() => {
  const alive = currentProc && !currentProc.killed && currentProc.exitCode === null && currentProc.signalCode === null;
  console.log('[alive] ' + new Date().toISOString() + ' binary alive=' + alive + ' pid=' + (currentProc ? currentProc.pid : 'null') + ' restarts=' + agentRestarts);
}, 60000);
