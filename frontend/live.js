/* Vela live data: connects to the backend WebSocket and maps node / flow messages onto the page's star map.
 *
 * Both frontend styles share this file. A page only provides a few callbacks (create node / remove node /
 * create lane / update lane); everything else lives here: reconnecting, rate smoothing, merging this
 * machine's many addresses, node slot allocation, recycling idle nodes, and routing internet traffic
 * through the gateway.
 *
 * Live mode is entered when the page URL has ?ws=HOST:PORT&token=TOKEN (the backend prints full links on startup).
 * Loaded with a plain script tag (not an ES module) so pages opened by double-click as file:// still work.
 */
(() => {
const STORE = 'vela.live';
const FLOW_TTL = 2000;    // ms: a connection with no new window data for this long is considered finished
const NODE_IDLE = 90000;  // ms: a node idle this long is recycled, freeing its slot for new nodes
const MERGED = {local:'This machine', gateway:'Gateway', multicast:'Multicast / broadcast'};

/* ---------- config: URL parameters / pasted ws address / remembered locally ---------- */
function fromURL(){
  const q = new URLSearchParams(location.search);
  const host = q.get('ws'), token = q.get('token');
  if (!host || !token) return null;
  try { localStorage.setItem(STORE, wsUrl({host, token})); } catch {}  // prefill the address box after returning to simulated mode
  return {host, token};
}
function parseWs(text){
  try {
    const u = new URL(String(text).trim());
    const token = u.searchParams.get('token');
    return u.protocol === 'ws:' && u.host && token ? {host:u.host, token} : null;
  } catch { return null; }
}
const wsUrl = cfg => `ws://${cfg.host}/?token=${encodeURIComponent(cfg.token)}`;
function saved(){ try { return localStorage.getItem(STORE) || ''; } catch { return ''; } }
function enter(cfg){
  try { localStorage.setItem(STORE, wsUrl(cfg)); } catch {}
  const u = new URL(location.href);
  u.search = '';
  u.searchParams.set('ws', cfg.host);
  u.searchParams.set('token', cfg.token);
  location.href = u.toString();
}
function leave(){ const u = new URL(location.href); u.search = ''; location.href = u.toString(); }

/* ---------- map backend messages onto the page ----------
 * page = {
 *   lanSlots, extSlots,                     how many positions the LAN / internet rings have
 *   createNode({group, slot, ip, name, source, asn, org}) → page node   group: local|gateway|lan|external|multicast
 *                                           source = where the name came from: dns | sni | asn | null (IP only)
 *   renameNode(node, {name, ip, source, asn, org})   called when the name or its source changes
 *   removeNode(node)
 *   addFlow({path:[page nodes...], proto, port, l4, up, down}) → page lane   up/down in bytes/s
 *   updateFlow(flow, up, down, fresh)       fresh = new data arrived in this window
 *   removeFlow(flow)
 *   status(state, text)                     state: connecting|open|closed|error
 * }
 * Returns {tick()}: the page calls it every 200 ms (matching the backend aggregation window).
 */
function attach(cfg, page){
  const info = new Map();    // ip → latest node message
  const nodes = new Map();   // node key → {key, group, slot, last, ref}
  const flows = new Map();   // connection key → {src, dst, proto, port, l4, up, down, rawUp, rawDown, seen, fresh, path, ref}
  const slots = {lan:new Array(page.lanSlots).fill(null), external:new Array(page.extSlots).fill(null)};

  // this machine's addresses (IPv4, IPv6, link-local), the gateway, and all multicast addresses each merge into one node
  const kindOf = ip => (info.get(ip) || {}).kind || 'external';
  const keyOf = ip => MERGED[kindOf(ip)] ? kindOf(ip) : ip;
  const nameOf = (key, m) => MERGED[key] || (m && m.name) || (m && m.ip) || key;
  const describe = (key, m) => ({name:nameOf(key, m), ip:m.ip, source:MERGED[key] ? null : m.name_source || null,
                                 asn:m.asn || null, org:m.org || null});

  function ensureNode(ip, now){
    const key = keyOf(ip);
    let n = nodes.get(key);
    if (n){ n.last = now; return n; }
    let m = info.get(ip) || {ip, name:null, asn:null, kind:'external'};
    // merged nodes (this machine) prefer showing the IPv4 address, much shorter than IPv6
    if (MERGED[key]) m = [...info.values()].find(x => x.kind === key && !x.ip.includes(':')) || m;
    const group = MERGED[key] ? key : m.kind;
    let slot = null;
    if (slots[group]){
      slot = slots[group].indexOf(null);
      if (slot < 0) slot = evict(group);
      if (slot < 0) return null;   // every slot is taken and active; don't show it for now
    }
    n = {key, group, slot, last:now};
    n.ref = page.createNode({group, slot, ...describe(key, m)});
    if (slots[group]) slots[group][slot] = n;
    nodes.set(key, n);
    return n;
  }

  function busyKeys(){
    const busy = new Set();
    for (const f of flows.values()) if (f.path) for (const k of f.path) busy.add(k);
    return busy;
  }
  function evict(group){
    const busy = busyKeys();
    let victim = null;
    for (const n of slots[group]) if (n && !busy.has(n.key) && (!victim || n.last < victim.last)) victim = n;
    if (!victim) return -1;
    const slot = victim.slot;
    retire(victim);
    return slot;
  }
  function retire(n){
    for (const [k, f] of flows) if (f.path && f.path.includes(n.key)){ page.removeFlow(f.ref); flows.delete(k); }
    page.removeNode(n.ref);
    if (slots[n.group]) slots[n.group][n.slot] = null;
    nodes.delete(n.key);
  }

  function onNode(m){
    info.set(m.ip, m);
    // the gateway is always on the page; show its address as soon as its info arrives
    if (m.kind === 'gateway' && !nodes.has('gateway')){ ensureNode(m.ip, Date.now()); return; }
    const n = nodes.get(keyOf(m.ip));
    if (n && (n.group === 'lan' || n.group === 'external' || (n.group === 'gateway' && !m.ip.includes(':'))))
      page.renameNode(n.ref, describe(n.key, m));
  }
  function onFlow(m){
    const key = `${m.src}|${m.dst}|${m.proto}|${m.port}`;
    let f = flows.get(key);
    if (!f){
      f = {src:m.src, dst:m.dst, proto:m.proto, port:m.port, l4:m.l4, up:0, down:0, path:null, ref:null};
      flows.set(key, f);
    }
    const perSec = 1000/(m.window_ms || 200);
    f.rawUp = m.bytes_up*perSec;
    f.rawDown = m.bytes_down*perSec;
    f.seen = Date.now();
    f.fresh = true;
  }

  function tick(){
    const now = Date.now();
    for (const [key, f] of flows){
      if (now - f.seen > FLOW_TTL){
        if (f.ref) page.removeFlow(f.ref);
        flows.delete(key);
        continue;
      }
      // smooth rates across windows; decay exponentially in windows without new data
      if (f.fresh){
        f.up = f.ref ? f.up*.5 + f.rawUp*.5 : f.rawUp;
        f.down = f.ref ? f.down*.5 + f.rawDown*.5 : f.rawDown;
      } else { f.up *= .5; f.down *= .5; }

      if (!f.ref){
        const a = ensureNode(f.src, now), b = ensureNode(f.dst, now);
        if (!a || !b || a === b){ f.fresh = false; continue; }
        const path = [a, b];
        // draw internet-bound traffic through the gateway
        const ext = n => n.group === 'external';
        if ((ext(a) || ext(b)) && a.group !== 'gateway' && b.group !== 'gateway'){
          const gw = nodes.get('gateway') || ensureGatewayNode(now);
          path.splice(1, 0, gw);
        }
        f.path = path.map(n => n.key);
        f.ref = page.addFlow({path:path.map(n => n.ref), proto:f.proto, port:f.port, l4:f.l4, up:f.up, down:f.down});
      } else {
        page.updateFlow(f.ref, f.up, f.down, f.fresh);
      }
      if (f.fresh) for (const k of f.path) nodes.get(k).last = now;
      f.fresh = false;
    }
    const busy = busyKeys();
    for (const n of [...nodes.values()])
      if (slots[n.group] && now - n.last > NODE_IDLE && !busy.has(n.key)) retire(n);
  }
  function ensureGatewayNode(now){
    const m = [...info.values()].find(x => x.kind === 'gateway');
    const n = {key:'gateway', group:'gateway', slot:null, last:now};
    n.ref = page.createNode({group:'gateway', slot:null, ...describe('gateway', m || {ip:null})});
    nodes.set('gateway', n);
    return n;
  }

  /* ---------- WebSocket connection and reconnect ---------- */
  let retry = 0, opened = false;
  function connect(){
    page.status('connecting', `Connecting to ${cfg.host}`);
    let ws;
    try { ws = new WebSocket(wsUrl(cfg)); }
    catch {
      page.status('error', location.protocol === 'https:'
        ? 'An HTTPS page cannot connect to a LAN ws:// address; open the page locally'
        : `Invalid address ${cfg.host}`);
      return;
    }
    ws.onopen = () => { retry = 0; opened = true; page.status('open', `Connected to ${cfg.host}`); };
    ws.onmessage = e => {
      let m;
      try { m = JSON.parse(e.data); } catch { return; }
      if (m.type === 'flow') onFlow(m);
      else if (m.type === 'node') onNode(m);
    };
    ws.onclose = () => {
      const wait = Math.min(10, 2**retry++);
      page.status('closed', opened
        ? `Disconnected, reconnecting in ${wait}s`
        : `Can't reach ${cfg.host} (backend not running or wrong token), retrying in ${wait}s`);
      setTimeout(connect, wait*1000);
    };
  }
  connect();
  return {tick};
}

window.VelaLive = {fromURL, parseWs, saved, enter, leave, attach};
})();
