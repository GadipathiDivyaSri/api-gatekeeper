/**
 * API Gatekeeper — SOC Defense Dashboard Application
 * Manages WebSocket live updates, Chart.js visualizations,
 * forensic incident drawer, and payload testing.
 */

(() => {
  // ---------------------------------------------------------------------------
  // State & Token Management
  // ---------------------------------------------------------------------------
  const params = new URLSearchParams(window.location.search);
  if (params.has('token')) {
    sessionStorage.setItem('gk_admin_token', params.get('token'));
  }
  const adminToken = sessionStorage.getItem('gk_admin_token') || '';

  const state = {
    mode: 'block',
    wsConnected: false,
    wsReconnectAttempts: 0,
    categoryChart: null,
    timelineChart: null,
    recentEvents: [],
  };

  // ---------------------------------------------------------------------------
  // API Fetch Helper with Admin Token
  // ---------------------------------------------------------------------------
  async function apiFetch(endpoint, options = {}) {
    const headers = { ...options.headers };
    if (adminToken) {
      headers['X-Admin-Token'] = adminToken;
    }
    const response = await fetch(endpoint, { ...options, headers });
    if (!response.ok) {
      throw new Error(`API error ${response.status}: ${response.statusText}`);
    }
    return response.json();
  }

  // ---------------------------------------------------------------------------
  // DOM References
  // ---------------------------------------------------------------------------
  const dom = {
    dot: document.getElementById('connection-dot'),
    connText: document.getElementById('connection-text'),
    modeBtn: document.getElementById('mode-btn'),
    modeLabel: document.getElementById('mode-label'),
    valTotal: document.getElementById('val-total'),
    valBlocked: document.getElementById('val-blocked'),
    valBlockRate: document.getElementById('val-block-rate'),
    valRatelimit: document.getElementById('val-ratelimit'),
    valAllowed: document.getElementById('val-allowed'),
    valAttackers: document.getElementById('val-attackers'),
    valUniqueIps: document.getElementById('val-unique-ips'),
    valBans: document.getElementById('val-bans'),
    valLatency: document.getElementById('val-latency'),
    valLatencyP50: document.getElementById('val-latency-p50'),
    feedList: document.getElementById('attack-feed'),
    feedCount: document.getElementById('feed-count'),
    valReachedBackend: document.getElementById('val-reached-backend'),
    bannerModeBanner: document.getElementById('mode-comparison-banner'),
    bannerModePill: document.getElementById('banner-mode-pill'),
    bannerModeText: document.getElementById('banner-mode-text'),
    bannerTotal60s: document.getElementById('banner-total-60s'),
    bannerBlocked60s: document.getElementById('banner-blocked-60s'),
    bannerFlagged60s: document.getElementById('banner-flagged-60s'),
    bannerReached60s: document.getElementById('banner-reached-60s'),
    bannerInsightText: document.getElementById('banner-insight-text'),
    rulesPanel: document.getElementById('rules-panel'),
    rulesTbody: document.getElementById('rules-tbody'),
    rulesCountBadge: document.getElementById('rules-count-badge'),
    ruleSearchInput: document.getElementById('rule-search-input'),
    btnReloadRules: document.getElementById('btn-reload-rules'),
    toastContainer: document.getElementById('toast-container'),
    attackersTbody: document.getElementById('attackers-tbody'),
    bansTbody: document.getElementById('bans-tbody'),
    bansBadge: document.getElementById('bans-badge'),
    drawerOverlay: document.getElementById('drawer-overlay'),
    drawer: document.getElementById('incident-drawer'),
    drawerContent: document.getElementById('drawer-content'),
    drawerCloseBtn: document.getElementById('drawer-close-btn'),
    btnSimulate: document.getElementById('btn-simulate'),
    btnScorecard: document.getElementById('btn-scorecard'),
    btnInspectTest: document.getElementById('btn-inspect-test'),
    testMethod: document.getElementById('test-method'),
    testPath: document.getElementById('test-path'),
    testQuery: document.getElementById('test-query'),
    testHeaders: document.getElementById('test-headers'),
    testBody: document.getElementById('test-body'),
    testResults: document.getElementById('test-results'),
  };

  // ---------------------------------------------------------------------------
  // Charts Initialization
  // ---------------------------------------------------------------------------
  function initCharts() {
    // 1. Attack Categories Doughnut Chart
    const ctxCat = document.getElementById('categoryChart').getContext('2d');
    state.categoryChart = new Chart(ctxCat, {
      type: 'doughnut',
      data: {
        labels: ['SQLi', 'XSS', 'CMDi', 'NoSQL', 'SSRF', 'Traversal', 'Bot', 'Other'],
        datasets: [{
          data: [0, 0, 0, 0, 0, 0, 0, 0],
          backgroundColor: [
            '#ef4444', '#f97316', '#dc2626', '#a855f7',
            '#eab308', '#14b8a6', '#3b82f6', '#64748b'
          ],
          borderWidth: 1,
          borderColor: '#0e1526'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: '#8b9bb4', font: { size: 10 } } }
        },
        cutout: '65%'
      }
    });

    // 2. Timeline Line Chart
    const ctxTime = document.getElementById('timelineChart').getContext('2d');
    state.timelineChart = new Chart(ctxTime, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Blocked',
            data: [],
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 2
          },
          {
            label: 'Allowed',
            data: [],
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: '#54657e', font: { size: 9 }, maxRotation: 0 }, grid: { display: false } },
          y: { ticks: { color: '#54657e', font: { size: 9 } }, grid: { color: 'rgba(255, 255, 255, 0.04)' } }
        },
        plugins: {
          legend: { position: 'top', align: 'end', labels: { color: '#8b9bb4', font: { size: 10 } } }
        }
      }
    });
  }

  // ---------------------------------------------------------------------------
  // KPI Metrics Updating
  // ---------------------------------------------------------------------------
  function updateKPIs(stats) {
    if (!stats) return;
    dom.valTotal.textContent = stats.total_requests || 0;
    dom.valBlocked.textContent = stats.blocked_requests || 0;
    dom.valBlockRate.textContent = ((stats.block_rate || 0) * 100).toFixed(1);
    dom.valRatelimit.textContent = stats.rate_limited_requests || 0;
    dom.valAllowed.textContent = stats.allowed_requests || 0;
    dom.valAttackers.textContent = stats.unique_attackers || 0;
    dom.valUniqueIps.textContent = stats.unique_ips || 0;
    dom.valBans.textContent = stats.banned_requests || 0;
    dom.valLatency.innerHTML = `${stats.latency_p95_ms || 0.0}<span style="font-size: 1rem;">ms</span>`;
    dom.valLatencyP50.textContent = stats.latency_p50_ms || 0.0;
    if (dom.valReachedBackend) {
      dom.valReachedBackend.textContent = stats.reached_backend_count || 0;
    }

    // Update Category Chart
    if (state.categoryChart && stats.by_category) {
      const cats = stats.by_category;
      const mapping = {
        'sqli': 0, 'xss': 1, 'cmdi': 2, 'nosql': 3,
        'ssrf': 4, 'traversal': 5, 'bot': 6
      };
      const data = [0, 0, 0, 0, 0, 0, 0, 0];
      let other = 0;
      for (const [k, v] of Object.entries(cats)) {
        const idx = mapping[k.toLowerCase()];
        if (idx !== undefined) {
          data[idx] += v;
        } else {
          other += v;
        }
      }
      data[7] = other;
      state.categoryChart.data.datasets[0].data = data;
      state.categoryChart.update();
    }
  }

  // ---------------------------------------------------------------------------
  // Live Feed Management (DOM XSS-Safe with textContent)
  // ---------------------------------------------------------------------------
  function renderFeedCard(event) {
    const card = document.createElement('div');
    const sev = (event.severity || 'low').toLowerCase();
    card.className = `feed-card ${sev}`;
    card.addEventListener('click', () => openIncidentDrawer(event));

    // Top Row
    const topRow = document.createElement('div');
    topRow.className = 'feed-top';

    const meta = document.createElement('div');
    meta.className = 'feed-meta';

    const catBadge = document.createElement('span');
    const cat = event.primary_category || 'general';
    catBadge.className = `badge badge-${cat.toLowerCase()}`;
    catBadge.textContent = cat.toUpperCase();

    const sevPill = document.createElement('span');
    sevPill.style.fontSize = '0.65rem';
    sevPill.style.fontWeight = '700';
    sevPill.style.color = sev === 'critical' ? '#ef4444' : (sev === 'high' ? '#f97316' : '#93c5fd');
    sevPill.textContent = `[${sev.toUpperCase()}]`;

    const ipSpan = document.createElement('span');
    ipSpan.className = 'feed-ip';
    ipSpan.textContent = event.client_ip || '127.0.0.1';

    meta.appendChild(catBadge);
    meta.appendChild(sevPill);
    meta.appendChild(ipSpan);

    const timeSpan = document.createElement('span');
    timeSpan.className = 'feed-time';
    const date = new Date((event.ts || Date.now() / 1000) * 1000);
    timeSpan.textContent = date.toLocaleTimeString();

    topRow.appendChild(meta);
    topRow.appendChild(timeSpan);
    card.appendChild(topRow);

    // Route Row
    const routeRow = document.createElement('div');
    routeRow.className = 'feed-route';
    routeRow.textContent = `${event.method} ${event.path}${event.query ? '?' + event.query : ''}`;
    card.appendChild(routeRow);

    // Rule / Snippet Preview
    if (event.findings && event.findings.length > 0) {
      const f = event.findings[0];
      const snip = document.createElement('div');
      snip.className = 'feed-snippet';
      snip.textContent = `Rule: ${f.name || f.rule_id} • Matched: "${f.matched || ''}"`;
      card.appendChild(snip);
    } else if (event.action === 'rate_limited' || event.action === 'banned') {
      const snip = document.createElement('div');
      snip.className = 'feed-snippet';
      snip.textContent = `Status: ${event.action.toUpperCase()} (Throttle Defense)`;
      card.appendChild(snip);
    }

    return card;
  }

  function addFeedEvent(event) {
    if (dom.feedList.children.length === 1 && dom.feedList.children[0].textContent.includes('Awaiting')) {
      dom.feedList.innerHTML = '';
    }

    state.recentEvents.unshift(event);
    if (state.recentEvents.length > 50) {
      state.recentEvents.pop();
    }

    const card = renderFeedCard(event);
    dom.feedList.prepend(card);

    if (dom.feedList.children.length > 50) {
      dom.feedList.removeChild(dom.feedList.lastChild);
    }
  }

  // ---------------------------------------------------------------------------
  // Forensic Incident Drawer
  // ---------------------------------------------------------------------------
  function openIncidentDrawer(event) {
    dom.drawerContent.innerHTML = '';

    function addBlock(label, val, isMono = true) {
      const b = document.createElement('div');
      b.className = 'detail-block';
      const l = document.createElement('span');
      l.className = 'detail-label';
      l.textContent = label;
      const v = document.createElement('div');
      v.className = isMono ? 'detail-val' : '';
      v.textContent = val || 'None';
      b.appendChild(l);
      b.appendChild(v);
      dom.drawerContent.appendChild(b);
    }

    // Incident ID & Status
    addBlock('Incident ID', event.incident_id);
    addBlock('Timestamp', new Date(event.ts * 1000).toISOString());
    addBlock('Client IP', event.client_ip);
    addBlock('Request Target', `${event.method} ${event.path}${event.query ? '?' + event.query : ''}`);
    addBlock('Action Taken', `${event.action ? event.action.toUpperCase() : 'UNKNOWN'} (HTTP ${event.status_code || 200})`);

    // Risk Score Meter
    const scoreBlock = document.createElement('div');
    scoreBlock.className = 'detail-block';
    const sLabel = document.createElement('span');
    sLabel.className = 'detail-label';
    sLabel.textContent = `Risk Score: ${event.score || 0} / Threshold: 5`;
    const sMeter = document.createElement('div');
    sMeter.className = 'score-bar-container';
    const sBar = document.createElement('div');
    sBar.className = 'score-bar';
    const pct = Math.min(100, ((event.score || 0) / 5) * 100);
    sBar.style.width = `${pct}%`;
    sBar.style.background = (event.score || 0) >= 5 ? '#ef4444' : '#10b981';
    sMeter.appendChild(sBar);
    scoreBlock.appendChild(sLabel);
    scoreBlock.appendChild(sMeter);
    dom.drawerContent.appendChild(scoreBlock);

    // Payload Excerpts
    if (event.body_excerpt) {
      addBlock('Body Excerpt', event.body_excerpt);
    }

    // Detailed Findings
    if (event.findings && event.findings.length > 0) {
      const fContainer = document.createElement('div');
      fContainer.className = 'detail-block';
      const fTitle = document.createElement('span');
      fTitle.className = 'detail-label';
      fTitle.textContent = `Matched Findings (${event.findings.length})`;
      fContainer.appendChild(fTitle);

      event.findings.forEach(f => {
        const fBox = document.createElement('div');
        fBox.className = 'detail-val';
        fBox.style.marginBottom = '6px';
        fBox.textContent = `[${f.rule_id}] ${f.name} (Score: +${f.score}) • Matched: "${f.matched}" | Target: ${f.target} | CWE: ${f.cwe || 'N/A'}`;
        fContainer.appendChild(fBox);
      });
      dom.drawerContent.appendChild(fContainer);
    }

    // Performance
    addBlock('Performance', `Gateway: ${event.latency_ms || 0}ms | Upstream: ${event.upstream_ms || 0}ms | Reached Backend: ${event.reached_backend ? 'YES' : 'NO'}`);

    dom.drawerOverlay.classList.add('active');
    dom.drawerOverlay.setAttribute('aria-hidden', 'false');
    dom.drawer.classList.add('active');
    dom.drawer.setAttribute('aria-hidden', 'false');
    if (dom.drawerCloseBtn) {
      dom.drawerCloseBtn.focus();
    }
  }

  function closeDrawer() {
    dom.drawerOverlay.classList.remove('active');
    dom.drawerOverlay.setAttribute('aria-hidden', 'true');
    dom.drawer.classList.remove('active');
    dom.drawer.setAttribute('aria-hidden', 'true');
  }

  dom.drawerCloseBtn.addEventListener('click', closeDrawer);
  dom.drawerOverlay.addEventListener('click', closeDrawer);

  // Keyboard accessibility: Escape closes drawer, '/' focuses rule search
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (dom.drawer.classList.contains('active')) {
        closeDrawer();
      }
    } else if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      e.preventDefault();
      if (dom.ruleSearchInput) {
        dom.ruleSearchInput.focus();
      }
    }
  });

  // ---------------------------------------------------------------------------
  // Tables: Top Attackers & Active Bans
  // ---------------------------------------------------------------------------
  function updateAttackersTable(attackers) {
    dom.attackersTbody.innerHTML = '';
    if (!attackers || attackers.length === 0) {
      dom.attackersTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-dim);">No attackers recorded</td></tr>';
      return;
    }

    attackers.forEach(atk => {
      const tr = document.createElement('tr');

      const tdIp = document.createElement('td');
      tdIp.style.fontFamily = 'var(--font-mono)';
      tdIp.textContent = atk.client_ip;

      const tdCount = document.createElement('td');
      tdCount.style.fontWeight = '700';
      tdCount.style.color = 'var(--status-blocked)';
      tdCount.textContent = atk.total_attacks;

      const tdCats = document.createElement('td');
      tdCats.textContent = (atk.categories || []).join(', ') || 'N/A';

      const tdSeen = document.createElement('td');
      tdSeen.style.color = 'var(--text-dim)';
      tdSeen.textContent = new Date(atk.last_seen * 1000).toLocaleTimeString();

      tr.appendChild(tdIp);
      tr.appendChild(tdCount);
      tr.appendChild(tdCats);
      tr.appendChild(tdSeen);
      dom.attackersTbody.appendChild(tr);
    });
  }

  function updateBansTable(bans) {
    dom.bansTbody.innerHTML = '';
    const count = bans ? bans.length : 0;
    dom.bansBadge.textContent = `${count} ACTIVE`;

    if (!bans || bans.length === 0) {
      dom.bansTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-dim);">No active bans</td></tr>';
      return;
    }

    bans.forEach(ban => {
      const tr = document.createElement('tr');

      const tdIp = document.createElement('td');
      tdIp.style.fontFamily = 'var(--font-mono)';
      tdIp.textContent = ban.ip;

      const tdReason = document.createElement('td');
      tdReason.textContent = ban.reason || 'Strikes threshold';

      const tdRem = document.createElement('td');
      tdRem.style.fontWeight = '700';
      tdRem.style.color = '#fbbf24';
      tdRem.textContent = `${ban.remaining_sec || 0}s`;

      const tdAction = document.createElement('td');
      const unbanBtn = document.createElement('button');
      unbanBtn.className = 'unban-btn';
      unbanBtn.textContent = 'Unban';
      unbanBtn.addEventListener('click', async () => {
        try {
          await apiFetch(`/_gk/api/bans/${encodeURIComponent(ban.ip)}`, { method: 'DELETE' });
          loadBans();
        } catch (e) {
          alert('Failed to unban IP: ' + e.message);
        }
      });
      tdAction.appendChild(unbanBtn);

      tr.appendChild(tdIp);
      tr.appendChild(tdReason);
      tr.appendChild(tdRem);
      tr.appendChild(tdAction);
      dom.bansTbody.appendChild(tr);
    });
  }

  // ---------------------------------------------------------------------------
  // Data Loaders
  // ---------------------------------------------------------------------------
  async function loadStats() {
    try {
      const stats = await apiFetch('/_gk/api/stats');
      updateKPIs(stats);
    } catch (e) {
      console.warn('Stats fetch error:', e);
    }
  }

  async function loadEvents() {
    try {
      const events = await apiFetch('/_gk/api/events?limit=50');
      dom.feedList.innerHTML = '';
      state.recentEvents = events;
      events.forEach(e => {
        dom.feedList.appendChild(renderFeedCard(e));
      });
    } catch (e) {
      console.warn('Events fetch error:', e);
    }
  }

  async function loadTimeline() {
    try {
      const timeline = await apiFetch('/_gk/api/timeline?bucket=10&window=900');
      if (state.timelineChart && timeline) {
        state.timelineChart.data.labels = timeline.map(b => new Date(b.timestamp * 1000).toLocaleTimeString());
        state.timelineChart.data.datasets[0].data = timeline.map(b => b.blocked);
        state.timelineChart.data.datasets[1].data = timeline.map(b => b.allowed);
        state.timelineChart.update();
      }
    } catch (e) {
      console.warn('Timeline fetch error:', e);
    }
  }

  async function loadAttackers() {
    try {
      const attackers = await apiFetch('/_gk/api/top-attackers?limit=10');
      updateAttackersTable(attackers);
    } catch (e) {
      console.warn('Attackers fetch error:', e);
    }
  }

  async function loadBans() {
    try {
      const bans = await apiFetch('/_gk/api/bans');
      updateBansTable(bans);
    } catch (e) {
      console.warn('Bans fetch error:', e);
    }
  }

  // ---------------------------------------------------------------------------
  // Toast Notifications Helper
  // ---------------------------------------------------------------------------
  function showToast(message, type = 'info') {
    if (!dom.toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icon = type === 'success' ? '✅' : type === 'warning' ? '⚠️' : type === 'error' ? '❌' : 'ℹ️';
    toast.innerHTML = `<span style="font-size: 1.1rem;">${icon}</span><span>${message}</span>`;
    dom.toastContainer.appendChild(toast);
    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // ---------------------------------------------------------------------------
  // Mode Comparison Banner (Rolling 60s Window)
  // ---------------------------------------------------------------------------
  function updateModeComparison(comp) {
    if (!comp) return;
    if (dom.bannerTotal60s) dom.bannerTotal60s.textContent = comp.total_60s || 0;
    if (dom.bannerBlocked60s) dom.bannerBlocked60s.textContent = comp.blocked_60s || 0;
    if (dom.bannerFlagged60s) dom.bannerFlagged60s.textContent = comp.flagged_60s || 0;
    if (dom.bannerReached60s) dom.bannerReached60s.textContent = comp.reached_backend_60s || 0;

    const currentMode = (comp.current_mode || state.mode || 'block').toLowerCase();
    if (dom.bannerModeBanner) {
      if (currentMode === 'monitor') {
        dom.bannerModeBanner.className = 'mode-comparison-banner monitor-mode';
        if (dom.bannerModeText) dom.bannerModeText.textContent = 'MONITOR / AUDIT MODE ACTIVE';
        if (dom.bannerInsightText) {
          dom.bannerInsightText.innerHTML = '⚠️ <strong>Monitor / Audit Mode Active:</strong> Malicious requests are detected and flagged, but allowed to reach backend DemoShop (reached_backend = true).';
        }
      } else {
        dom.bannerModeBanner.className = 'mode-comparison-banner block-mode';
        if (dom.bannerModeText) dom.bannerModeText.textContent = 'BLOCK MODE ACTIVE';
        if (dom.bannerInsightText) {
          dom.bannerInsightText.innerHTML = '🛡️ <strong>Perimeter Defense Enforced:</strong> All attacks meeting threat score threshold are intercepted at the gateway (HTTP 403) and dropped before reaching DemoShop (reached_backend = false).';
        }
      }
    }
  }

  async function loadModeComparison() {
    try {
      const comp = await apiFetch('/_gk/api/mode-comparison?window=60');
      updateModeComparison(comp);
    } catch (e) {
      console.warn('Mode comparison fetch error:', e);
    }
  }

  // ---------------------------------------------------------------------------
  // Signature Rules Management
  // ---------------------------------------------------------------------------
  let allRules = [];

  async function loadRules() {
    try {
      allRules = await apiFetch('/_gk/api/rules');
      renderRulesTable(allRules);
      if (dom.rulesCountBadge) {
        dom.rulesCountBadge.textContent = `${allRules.length} RULES`;
      }
    } catch (e) {
      console.warn('Rules fetch error:', e);
      if (dom.rulesTbody) {
        dom.rulesTbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--status-blocked); padding: 1.5rem;">Failed to load rules: ${e.message}</td></tr>`;
      }
    }
  }

  function renderRulesTable(rules) {
    if (!dom.rulesTbody) return;
    dom.rulesTbody.innerHTML = '';
    const filter = (dom.ruleSearchInput ? dom.ruleSearchInput.value : '').toLowerCase().trim();
    const filtered = rules.filter(r =>
      !filter ||
      r.id.toLowerCase().includes(filter) ||
      r.name.toLowerCase().includes(filter) ||
      r.category.toLowerCase().includes(filter)
    );

    if (filtered.length === 0) {
      dom.rulesTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No rules matching filter</td></tr>';
      return;
    }

    filtered.forEach(rule => {
      const tr = document.createElement('tr');
      tr.className = rule.enabled ? 'rule-row' : 'rule-row disabled';

      const tdId = document.createElement('td');
      tdId.style.fontFamily = 'var(--font-mono)';
      tdId.style.fontWeight = '700';
      tdId.textContent = rule.id;

      const tdName = document.createElement('td');
      tdName.textContent = rule.name;

      const tdCat = document.createElement('td');
      const catBadge = document.createElement('span');
      catBadge.className = 'badge badge-primary';
      catBadge.textContent = rule.category.toUpperCase();
      tdCat.appendChild(catBadge);

      const tdScore = document.createElement('td');
      tdScore.style.fontWeight = '700';
      tdScore.textContent = rule.score;

      const tdSev = document.createElement('td');
      const sevBadge = document.createElement('span');
      sevBadge.className = `badge badge-${rule.severity.toLowerCase()}`;
      sevBadge.textContent = rule.severity.toUpperCase();
      tdSev.appendChild(sevBadge);

      const tdAction = document.createElement('td');
      tdAction.style.textAlign = 'center';
      const switchLabel = document.createElement('label');
      switchLabel.className = 'switch';
      switchLabel.title = `Toggle rule ${rule.id} on or off`;

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.checked = rule.enabled;
      checkbox.id = `toggle-${rule.id}`;

      checkbox.addEventListener('change', async () => {
        const nextState = checkbox.checked;
        try {
          await apiFetch(`/_gk/api/rules/${encodeURIComponent(rule.id)}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: nextState })
          });
          rule.enabled = nextState;
          tr.className = nextState ? 'rule-row' : 'rule-row disabled';
          showToast(`Rule ${rule.id} ${nextState ? 'enabled' : 'disabled'}`, nextState ? 'success' : 'warning');
        } catch (e) {
          checkbox.checked = !nextState; // Revert switch on error
          showToast(`Failed to toggle rule: ${e.message}`, 'error');
        }
      });

      const sliderSpan = document.createElement('span');
      sliderSpan.className = 'slider';
      switchLabel.appendChild(checkbox);
      switchLabel.appendChild(sliderSpan);
      tdAction.appendChild(switchLabel);

      tr.appendChild(tdId);
      tr.appendChild(tdName);
      tr.appendChild(tdCat);
      tr.appendChild(tdScore);
      tr.appendChild(tdSev);
      tr.appendChild(tdAction);
      dom.rulesTbody.appendChild(tr);
    });
  }

  // ---------------------------------------------------------------------------
  // Mode Toggle with Confirmation Dialog & Action Buttons
  // ---------------------------------------------------------------------------
  dom.modeBtn.addEventListener('click', async () => {
    const nextMode = state.mode === 'block' ? 'monitor' : 'block';
    const confirmMsg = nextMode === 'monitor'
      ? '⚠️ Switch gateway to MONITOR mode?\n\nMalicious traffic will be detected and flagged, but forwarded to DemoShop backend without blocking.'
      : '🛡️ Switch gateway to BLOCK mode?\n\nMalicious traffic will be intercepted at the gateway and dropped with HTTP 403.';

    if (!confirm(confirmMsg)) {
      return;
    }

    try {
      await apiFetch('/_gk/api/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: nextMode })
      });
      state.mode = nextMode;
      dom.modeLabel.textContent = nextMode.toUpperCase();
      if (nextMode === 'monitor') {
        dom.modeBtn.classList.add('monitor');
      } else {
        dom.modeBtn.classList.remove('monitor');
      }
      showToast(`Gateway mode switched to ${nextMode.toUpperCase()}`, nextMode === 'monitor' ? 'warning' : 'success');
      await loadModeComparison();
      await loadStats();
    } catch (e) {
      showToast('Failed to toggle mode: ' + e.message, 'error');
    }
  });

  if (dom.btnReloadRules) {
    dom.btnReloadRules.addEventListener('click', async () => {
      dom.btnReloadRules.textContent = '⏳ Reloading...';
      try {
        const res = await apiFetch('/_gk/api/rules/reload', { method: 'POST' });
        showToast(`Rules reloaded successfully (${res.loaded_rules_count} signature rules active, contract ${res.contract_active ? 'active' : 'inactive'})`, 'success');
        await loadRules();
        await loadStats();
      } catch (e) {
        showToast('Rule reload failed: ' + e.message, 'error');
      } finally {
        dom.btnReloadRules.textContent = '🔄 Hot Reload Rules';
      }
    });
  }

  if (dom.ruleSearchInput) {
    dom.ruleSearchInput.addEventListener('input', () => {
      renderRulesTable(allRules);
    });
  }

  dom.btnSimulate.addEventListener('click', async () => {
    dom.btnSimulate.textContent = '⏳ Running...';
    try {
      const res = await apiFetch('/_gk/api/simulate', { method: 'POST' });
      showToast(res.message || 'Simulator started in background.', 'info');
    } catch (e) {
      showToast('Simulator trigger error: ' + e.message, 'error');
    } finally {
      dom.btnSimulate.textContent = '⚡ Run Simulator';
    }
  });

  dom.btnScorecard.addEventListener('click', async () => {
    dom.btnScorecard.textContent = '⏳ Benchmarking...';
    try {
      const res = await apiFetch('/_gk/api/benchmark', { method: 'POST' });
      showToast('Scorecard execution complete! Check Benchmark tab or report.', 'success');
    } catch (e) {
      showToast('Scorecard trigger error: ' + e.message, 'error');
    } finally {
      dom.btnScorecard.textContent = '📊 Run Scorecard';
    }
  });

  // ---------------------------------------------------------------------------
  // Interactive Payload Tester
  // ---------------------------------------------------------------------------
  dom.btnInspectTest.addEventListener('click', async () => {
    dom.btnInspectTest.textContent = '🔍 Inspecting...';
    dom.testResults.innerHTML = '';

    let headersObj = {};
    if (dom.testHeaders.value.trim()) {
      try {
        headersObj = JSON.parse(dom.testHeaders.value.trim());
      } catch {
        alert('Invalid JSON in Custom Headers');
        dom.btnInspectTest.textContent = '🔍 Inspect Payload';
        return;
      }
    }

    const payload = {
      method: dom.testMethod.value,
      path: dom.testPath.value,
      query: dom.testQuery.value,
      headers: headersObj,
      body: dom.testBody.value,
    };

    try {
      const res = await apiFetch('/_gk/api/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      // Render Result Card
      const resContainer = document.createElement('div');
      resContainer.style.display = 'flex';
      resContainer.style.flexDirection = 'column';
      resContainer.style.gap = '0.75rem';

      // Action Header
      const headerRow = document.createElement('div');
      headerRow.style.display = 'flex';
      headerRow.style.alignItems = 'center';
      headerRow.style.justifyContent = 'space-between';

      const dBadge = document.createElement('span');
      dBadge.className = `decision-badge ${res.action === 'blocked' ? 'blocked' : 'allowed'}`;
      dBadge.textContent = `${res.action.toUpperCase()} (Score: ${res.score})`;

      const reasonSpan = document.createElement('span');
      reasonSpan.style.fontSize = '0.8rem';
      reasonSpan.style.color = 'var(--text-muted)';
      reasonSpan.textContent = res.reason;

      headerRow.appendChild(dBadge);
      headerRow.appendChild(reasonSpan);
      resContainer.appendChild(headerRow);

      // Findings
      if (res.findings && res.findings.length > 0) {
        const fSec = document.createElement('div');
        const fTitle = document.createElement('div');
        fTitle.className = 'detail-label';
        fTitle.textContent = `Matched Rules (${res.findings.length})`;
        fSec.appendChild(fTitle);

        res.findings.forEach(f => {
          const item = document.createElement('div');
          item.className = 'feed-snippet';
          item.style.marginTop = '4px';
          item.textContent = `[${f.rule_id}] ${f.name} • Matched "${f.matched}" in target [${f.target}]`;
          fSec.appendChild(item);
        });
        resContainer.appendChild(fSec);
      }

      // Decode Provenance Chains
      if (res.decode_chains) {
        const dSec = document.createElement('div');
        const dTitle = document.createElement('div');
        dTitle.className = 'detail-label';
        dTitle.textContent = 'Multi-Decode Provenance Chain';
        dSec.appendChild(dTitle);

        for (const [target, variants] of Object.entries(res.decode_chains)) {
          variants.forEach(v => {
            if (v.chain && v.chain.length > 1) {
              const chainTag = document.createElement('span');
              chainTag.className = 'decode-chain-tag';
              chainTag.textContent = `${target}: ${v.chain.join(' → ')} ⇒ "${v.text}"`;
              dSec.appendChild(chainTag);
            }
          });
        }
        resContainer.appendChild(dSec);
      }

      dom.testResults.appendChild(resContainer);
    } catch (e) {
      dom.testResults.textContent = 'Inspection failed: ' + e.message;
    } finally {
      dom.btnInspectTest.textContent = '🔍 Inspect Payload';
    }
  });

  // ---------------------------------------------------------------------------
  // WebSocket Live Event Stream with Auto-Reconnect
  // ---------------------------------------------------------------------------
  function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    let wsUrl = `${protocol}//${location.host}/_gk/ws`;
    if (adminToken) {
      wsUrl += `?token=${encodeURIComponent(adminToken)}`;
    }

    dom.connText.textContent = 'CONNECTING...';
    dom.dot.className = 'status-dot';

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      state.wsConnected = true;
      state.wsReconnectAttempts = 0;
      dom.dot.className = 'status-dot';
      dom.connText.textContent = 'ONLINE (LIVE FEED)';
      // Periodic ping every 25s
      const pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send('ping');
        } else {
          clearInterval(pingInterval);
        }
      }, 25000);
    };

    ws.onmessage = (evt) => {
      if (evt.data === 'pong') return;
      try {
        const msg = JSON.parse(evt.data);

        // Control plane real-time messages
        if (msg.type === 'mode_changed') {
          state.mode = (msg.mode || 'block').toLowerCase();
          dom.modeLabel.textContent = state.mode.toUpperCase();
          if (state.mode === 'monitor') {
            dom.modeBtn.classList.add('monitor');
          } else {
            dom.modeBtn.classList.remove('monitor');
          }
          loadModeComparison();
          showToast(`Gateway mode: ${state.mode.toUpperCase()}`, 'info');
          return;
        }

        if (msg.type === 'rule_toggled') {
          const rule = allRules.find(r => r.id === msg.rule_id);
          if (rule) {
            rule.enabled = msg.enabled;
            renderRulesTable(allRules);
          }
          return;
        }

        if (msg.type === 'rules_reloaded') {
          loadRules();
          loadStats();
          return;
        }

        if (msg.type === 'unbanned') {
          loadBans();
          loadStats();
          return;
        }

        // Standard security audit event
        addFeedEvent(msg);
        loadStats();
        loadModeComparison();
        if (msg.action !== 'allowed') {
          loadAttackers();
          loadBans();
        }
      } catch (e) {
        console.warn('WS message parse error:', e);
      }
    };

    ws.onclose = () => {
      state.wsConnected = false;
      dom.dot.className = 'status-dot disconnected';
      dom.connText.textContent = 'DISCONNECTED (RETRYING)';
      const delay = Math.min(10000, 1000 * Math.pow(1.5, state.wsReconnectAttempts++));
      setTimeout(connectWebSocket, delay);
    };

    ws.onerror = () => {
      ws.close();
    };
  }

  // ---------------------------------------------------------------------------
  // Initialization Routine
  // ---------------------------------------------------------------------------
  async function init() {
    initCharts();
    await loadMode();
    await loadModeComparison();
    await loadRules();
    await loadStats();
    await loadEvents();
    await loadTimeline();
    await loadAttackers();
    await loadBans();
    connectWebSocket();

    // Periodic refresh for timeline, mode comparison, and ban countdowns
    setInterval(() => {
      loadTimeline();
      loadModeComparison();
      loadBans();
    }, 10000);
  }

  // Boot on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
