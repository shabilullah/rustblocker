
    const API = '/api';
    const PAGE_SIZE = 50;
    const state = { blocklist: {offset:0, search:''}, allowlist: {offset:0, search:''} };

    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => {
                b.classList.remove('border-emerald-400', 'text-emerald-400');
                b.classList.add('border-transparent', 'text-gray-400');
            });
            btn.classList.add('border-emerald-400', 'text-emerald-400');
            btn.classList.remove('border-transparent', 'text-gray-400');
            document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
            document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
            loadTab(btn.dataset.tab);
        });
    });

    async function loadTab(tab) {
        if (tab !== 'stats') disconnectSSE();
        stopDashboardPoll();
        switch(tab) {
            case 'dashboard': loadDashboard(); startDashboardPoll(); return;
            case 'upstreams': return loadUpstreams();
            case 'sources': return loadSources();
            case 'blocklist': return loadDomainList('blocklist');
            case 'allowlist': return loadDomainList('allowlist');
            case 'rewrites': return loadRewrites();
            case 'settings': loadSettings(); loadSyncConfig(); autoCheckUpdate(); return;
            case 'https': return loadHTTPSTab();
            case 'stats': return loadStats();
        }
    }

    // --- Dashboard ---

    async function loadDashboard() {
        const [blocklist, allowlist, rewrites, upstreams] = await Promise.all([
            fetch(API + '/blocklist?limit=0').then(r => r.json()),
            fetch(API + '/allowlist?limit=0').then(r => r.json()),
            fetch(API + '/rewrites').then(r => r.json()),
            fetch(API + '/upstreams').then(r => r.json()),
        ]);
        document.getElementById('stat-blocked').textContent = blocklist.total;
        document.getElementById('stat-allowed').textContent = allowlist.total;
        document.getElementById('stat-rewrites').textContent = rewrites.length;
        document.getElementById('stat-upstreams').textContent = upstreams.length;
        await refreshDashboardStats();
        await refreshHeaderVersion();
        autoCheckUpdate();
    }

    async function refreshHeaderVersion() {
        try {
            const v = await fetch(API + '/version').then(r => r.json());
            document.getElementById('version').textContent = 'v' + v.version + ' (' + v.target + ')';
        } catch {}
    }

    async function refreshDashboardStats() {
        const stats = await fetch(API + '/stats?limit=10').then(r => r.json());
        document.getElementById('stat-total-queries').textContent = stats.total_queries.toLocaleString();
        document.getElementById('stat-q-blocked').textContent = stats.blocked.toLocaleString();
        document.getElementById('stat-q-allowed').textContent = stats.allowed.toLocaleString();
        document.getElementById('stat-q-rewritten').textContent = stats.rewritten.toLocaleString();
        document.getElementById('stat-q-forwarded').textContent = stats.forwarded.toLocaleString();

        const clientsDiv = document.getElementById('stats-top-clients');
        clientsDiv.innerHTML = stats.top_clients.length
            ? stats.top_clients.map(c => `<div class="flex justify-between text-xs"><span class="font-mono text-gray-300">${c.ip}</span><span class="text-gray-400">${c.count.toLocaleString()}</span></div>`).join('')
            : '<div class="text-gray-500 text-xs">No data yet</div>';

        const blockedDiv = document.getElementById('stats-top-blocked-domains');
        blockedDiv.innerHTML = stats.top_blocked_domains.length
            ? stats.top_blocked_domains.map(d => `<div class="flex justify-between text-xs gap-2"><span class="font-mono text-gray-300 truncate max-w-[140px] sm:max-w-xs">${d.domain}</span><span class="text-gray-400 flex-shrink-0">${d.count.toLocaleString()}</span></div>`).join('')
            : '<div class="text-gray-500 text-xs">No data yet</div>';

        const upstreamDiv = document.getElementById('stats-upstream-resolvers');
        upstreamDiv.innerHTML = stats.upstream_stats.length
            ? `<div class="overflow-x-auto"><table class="w-full text-xs">
                <thead><tr class="text-gray-400 border-b border-gray-700">
                    <th class="text-left py-1.5 px-2">Resolver</th>
                    <th class="text-right py-1.5 px-2">Queries</th>
                    <th class="text-right py-1.5 px-2">Avg</th>
                    <th class="text-right py-1.5 px-2">Min</th>
                    <th class="text-right py-1.5 px-2">Max</th>
                </tr></thead>
                <tbody>${stats.upstream_stats.map(u => `
                    <tr class="border-b border-gray-700/50">
                        <td class="py-1.5 px-2 font-mono">${u.resolver}</td>
                        <td class="py-1.5 px-2 text-right">${u.count.toLocaleString()}</td>
                        <td class="py-1.5 px-2 text-right text-gray-300">${formatLatency(u.avg_latency_us)}</td>
                        <td class="py-1.5 px-2 text-right text-gray-400">${formatLatency(u.min_latency_us)}</td>
                        <td class="py-1.5 px-2 text-right text-gray-400">${formatLatency(u.max_latency_us)}</td>
                    </tr>`).join('')}
                </tbody>
            </table></div>`
            : '<div class="text-gray-500 text-xs">No upstream queries yet</div>';
    }

    // --- Upstreams ---

    async function loadUpstreams() {
        const data = await fetch(API + '/upstreams').then(r => r.json());
        document.getElementById('upstream-count').textContent = data.length + ' servers';
        const list = document.getElementById('upstream-list');
        if (!data.length) {
            list.innerHTML = '<div class="p-4 text-gray-500 text-sm">No upstream servers configured</div>';
            return;
        }
        list.innerHTML = data.map(u =>
            `<div class="flex items-center justify-between px-4 py-2 border-b border-gray-700 last:border-0 gap-2">
                <span class="font-mono text-sm break-all">${u.address}:${u.port}</span>
                <button class="delete-upstream-btn text-red-400 hover:text-red-300 text-xs whitespace-nowrap flex-shrink-0" data-id="${u.id}">Remove</button>
            </div>`
        ).join('');
    }

    async function addUpstream() {
        const address = document.getElementById('upstream-address').value.trim();
        const port = parseInt(document.getElementById('upstream-port').value) || 53;
        if (!address) return;
        await fetch(API + '/upstreams', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({address, port})
        });
        document.getElementById('upstream-address').value = '';
        document.getElementById('upstream-port').value = '53';
        loadUpstreams();
    }

    async function deleteUpstream(id) {
        await fetch(API + '/upstreams/' + id, {method: 'DELETE'});
        loadUpstreams();
    }

    // --- Sources ---

    async function loadSources() {
        const data = await fetch(API + '/sources').then(r => r.json());
        document.getElementById('source-count').textContent = data.length + ' source(s)';
        const list = document.getElementById('source-list');
        if (!data.length) {
            list.innerHTML = '<div class="p-4 text-gray-500 text-sm">No sources configured.</div>';
            return;
        }
        list.innerHTML = data.map(s =>
            `<div class="px-4 py-3 border-b border-gray-700 last:border-0">
                <div class="flex items-center justify-between mb-1">
                    <span class="font-mono text-sm truncate max-w-[150px] sm:max-w-lg">${s.url}</span>
                    <button class="delete-source-btn text-red-400 hover:text-red-300 text-xs ml-2" data-id="${s.id}">Remove</button>
                </div>
                <div class="flex flex-wrap gap-x-3 gap-y-1 text-xs text-gray-400">
                    <span>Type: <span class="text-gray-300">${s.list_type}</span></span>
                    <span>Every: <span class="text-gray-300">${s.update_interval_hours}h</span></span>
                    <span>Last: <span class="${s.last_status && s.last_status.startsWith('ok') ? 'text-green-400' : s.last_status ? 'text-red-400' : 'text-gray-500'}">${s.last_updated || 'never'}</span></span>
                    <span>Status: <span class="${s.last_status && s.last_status.startsWith('ok') ? 'text-green-400' : s.last_status ? 'text-red-400' : 'text-gray-500'}">${s.last_status || 'pending'}</span></span>
                </div>
            </div>`
        ).join('');
    }

    async function addSource() {
        const url = document.getElementById('source-url').value.trim();
        if (!url) return;
        const list_type = document.getElementById('source-type').value;
        const interval = parseInt(document.getElementById('source-interval').value) || 24;
        const btn = document.getElementById('add-source-btn');
        const status = document.getElementById('source-status');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Adding...';
        status.innerHTML = '<span class="spinner spinner-lg"></span> Fetching and importing...';
        status.className = 'text-sm text-emerald-400 mb-2';
        const resp = await fetch(API + '/sources', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url, list_type, update_interval_hours: interval})
        });
        const result = await resp.json();
        btn.disabled = false;
        btn.innerHTML = 'Add Source';
        status.innerHTML = '';
        status.className = 'text-sm mb-2';
        showSourceStatus(resp.ok ? `Added! ${result.status}` : `Error: ${result.error || 'failed'}`, resp.ok);
        document.getElementById('source-url').value = '';
        loadSources();
    }

    async function deleteSource(id) {
        await fetch(API + '/sources/' + id, {method: 'DELETE'});
        loadSources();
    }

    async function refreshAllSources() {
        const btn = document.getElementById('refresh-all-btn') || document.getElementById('refresh-sources-btn');
        if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Refreshing...'; }
        const status = document.getElementById('source-status');
        if (status) { status.innerHTML = '<span class="spinner spinner-lg"></span> Refreshing all sources...'; status.className = 'text-sm text-emerald-400 mb-2'; }
        const resp = await fetch(API + '/sources/refresh', {method: 'POST'});
        const result = await resp.json();
        if (btn) { btn.disabled = false; btn.innerHTML = 'Refresh All Now'; }
        if (status) { status.innerHTML = ''; status.className = 'text-sm mb-2'; }
        showSourceStatus(`Refreshed ${result.refreshed} source(s)`, true);
        loadSources();
    }

    function showSourceStatus(msg, ok) {
        const status = document.getElementById('source-status');
        if (!status) return;
        status.textContent = msg;
        status.className = 'text-sm mb-2 ' + (ok ? 'text-emerald-400' : 'text-red-400');
        setTimeout(() => { status.textContent = ''; status.className = 'text-sm mb-2'; }, 5000);
    }

    // --- Domains (blocklist / allowlist) ---

    async function loadDomainList(type) {
        const s = state[type];
        const params = new URLSearchParams({limit: PAGE_SIZE, offset: s.offset});
        if (s.search) params.set('search', s.search);
        const resp = await fetch(API + '/' + type + '?' + params);
        const data = await resp.json();
        const domains = data.domains || [];
        const total = data.total || 0;

        document.getElementById(type + '-count').textContent =
            s.search ? `${domains.length} matches (${total} total)` : `${total} domains`;

        const list = document.getElementById(type + '-list');
        if (!domains.length) {
            list.innerHTML = `<div class="p-4 text-gray-500 text-sm">${s.search ? 'No matches' : 'No domains'}</div>`;
        } else {
            list.innerHTML = domains.map(d =>
                `<div class="flex items-center justify-between px-4 py-2 border-b border-gray-700 last:border-0 gap-2">
                    <span class="font-mono text-sm break-all">${d.domain}</span>
                    <button class="delete-domain-btn text-red-400 hover:text-red-300 text-xs whitespace-nowrap flex-shrink-0" data-type="${type}" data-id="${d.id}">Remove</button>
                </div>`
            ).join('');
        }

        const pag = document.getElementById(type + '-pagination');
        const prevDisabled = s.offset <= 0 ? 'disabled opacity-50' : '';
        const nextDisabled = s.offset + PAGE_SIZE >= total ? 'disabled opacity-50' : '';
        pag.innerHTML = `
            <button class="page-prev-btn bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-sm ${prevDisabled}" data-type="${type}" data-delta="${-PAGE_SIZE}">Prev</button>
            <span class="text-sm text-gray-400">${s.offset + 1}–${Math.min(s.offset + PAGE_SIZE, total)} of ${total}</span>
            <button class="page-next-btn bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-sm ${nextDisabled}" data-type="${type}" data-delta="${PAGE_SIZE}">Next</button>
        `;
    }

    function pageDomain(type, delta) {
        state[type].offset = Math.max(0, state[type].offset + delta);
        loadDomainList(type);
    }

    async function addDomain(type) {
        const input = document.getElementById(type + '-input');
        const domain = input.value.trim();
        if (!domain) return;
        await fetch(API + '/' + type, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        input.value = '';
        state[type].offset = 0;
        state[type].search = '';
        loadDomainList(type);
    }

    async function deleteDomain(type, id) {
        await fetch(API + '/' + type + '/' + id, {method: 'DELETE'});
        loadDomainList(type);
    }

    async function importFile(type, input) {
        const file = input.files[0];
        if (!file) return;
        const status = document.getElementById(type + '-status');
        status.innerHTML = '<span class="spinner"></span> Importing file...';
        status.className = 'text-sm text-emerald-400 mb-2';
        const content = await file.text();
        const resp = await fetch(API + '/' + type + '/import', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({content})
        });
        const result = await resp.json();
        status.innerHTML = '';
        status.className = 'text-sm mb-2';
        showStatus(type, 'Imported ' + (result.imported || 0) + ' domains');
        input.value = '';
        state[type].offset = 0;
        loadDomainList(type);
    }

    async function importUrl(type) {
        const urlInput = document.getElementById(type + '-url');
        const url = urlInput.value.trim();
        if (!url) return;
        const btn = document.getElementById(type + '-url-btn');
        const status = document.getElementById(type + '-status');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Fetching...';
        status.innerHTML = '<span class="spinner spinner-lg"></span> Fetching blocklist from URL...';
        status.className = 'text-sm text-emerald-400 mb-2';
        const resp = await fetch(API + '/' + type + '/import', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url})
        });
        const result = await resp.json();
        btn.disabled = false;
        btn.innerHTML = 'Import URL';
        status.innerHTML = '';
        status.className = 'text-sm mb-2';
        if (resp.ok) {
            showStatus(type, 'Imported ' + (result.imported || 0) + ' domains from URL');
            urlInput.value = '';
        } else {
            showStatus(type, 'Error: ' + (result.error || 'import failed'), true);
        }
        state[type].offset = 0;
        loadDomainList(type);
    }

    function showStatus(type, msg, isError) {
        const status = document.getElementById(type + '-status');
        if (!status) return;
        status.textContent = msg;
        status.className = 'text-sm mb-2 ' + (isError ? 'text-red-400' : 'text-emerald-400');
        setTimeout(() => { status.textContent = ''; status.className = 'text-sm mb-2'; }, 5000);
    }

    let searchTimers = {};
    function onSearch(type) {
        clearTimeout(searchTimers[type]);
        searchTimers[type] = setTimeout(() => {
            state[type].search = document.getElementById(type + '-search').value.trim();
            state[type].offset = 0;
            loadDomainList(type);
        }, 300);
    }

    // --- Rewrites ---

    async function loadRewrites() {
        const data = await fetch(API + '/rewrites').then(r => r.json());
        const list = document.getElementById('rewrites-list');
        if (!data.length) {
            list.innerHTML = '<div class="p-4 text-gray-500 text-sm">No rewrites</div>';
            return;
        }
        list.innerHTML = data.map(r =>
            `<div class="flex items-center justify-between px-4 py-2 border-b border-gray-700 last:border-0 gap-2">
                <span class="font-mono text-sm break-all">${r.domain} &rarr; ${r.ipv4 || '-'} ${r.ipv6 || ''}</span>
                <button class="delete-rewrite-btn text-red-400 hover:text-red-300 text-xs whitespace-nowrap flex-shrink-0" data-id="${r.id}">Remove</button>
            </div>`
        ).join('');
    }

    async function addRewrite() {
        const domain = document.getElementById('rewrite-domain').value.trim();
        const ipv4 = document.getElementById('rewrite-ipv4').value.trim() || null;
        const ipv6 = document.getElementById('rewrite-ipv6').value.trim() || null;
        if (!domain) return;
        await fetch(API + '/rewrites', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain, ipv4, ipv6})
        });
        document.getElementById('rewrite-domain').value = '';
        document.getElementById('rewrite-ipv4').value = '';
        document.getElementById('rewrite-ipv6').value = '';
        loadRewrites();
    }

    async function deleteRewrite(id) {
        await fetch(API + '/rewrites/' + id, {method: 'DELETE'});
        loadRewrites();
    }

    // --- HTTPS ---

    async function loadHTTPSTab() {
        await Promise.all([loadCertificateStatus(), loadHTTPSSettings()]);
    }

    async function loadCertificateStatus() {
        const container = document.getElementById('cert-status-container');
        try {
            const status = await fetch(API + '/acme/status').then(r => r.json());
            
            if (!status.has_certificate) {
                container.innerHTML = '<p class="text-sm text-yellow-400">No certificate found. Configure settings below and request a certificate.</p>';
                return;
            }

            const daysRemaining = status.days_remaining;
            const color = daysRemaining > 30 ? 'text-green-400' : daysRemaining > 15 ? 'text-yellow-400' : 'text-red-400';
            
            const issuedDate = new Date(status.issued_at * 1000).toLocaleDateString();
            const expiresDate = new Date(status.expires_at * 1000).toLocaleDateString();
            const renewedDate = status.last_renewed ? new Date(status.last_renewed * 1000).toLocaleDateString() : 'Never';
            
            container.innerHTML = `
                <div class="space-y-2 text-sm">
                    <div><span class="text-gray-400">Domain:</span> <span class="font-mono">${status.domain}</span></div>
                    <div><span class="text-gray-400">Issued:</span> ${issuedDate}</div>
                    <div><span class="text-gray-400">Expires:</span> ${expiresDate}</div>
                    <div><span class="text-gray-400">Days Remaining:</span> <span class="${color} font-semibold">${daysRemaining} days</span></div>
                    <div><span class="text-gray-400">Last Renewed:</span> ${renewedDate}</div>
                </div>
            `;
        } catch (e) {
            container.innerHTML = `<p class="text-sm text-red-400">Error loading certificate status: ${e.message}</p>`;
        }
    }

    async function loadHTTPSSettings() {
        try {
            const settings = await fetch(API + '/settings').then(r => r.json());
            document.getElementById('https-domain').value = settings.domain || '';
            document.getElementById('https-email').value = settings.acme_email || '';
            document.getElementById('https-wildcard').checked = settings.wildcard_cert === 'true';
        } catch (e) {
            console.error('Failed to load HTTPS settings:', e);
        }
    }

    document.getElementById('save-https-settings').addEventListener('click', async () => {
        const domain = document.getElementById('https-domain').value.trim();
        const email = document.getElementById('https-email').value.trim();
        const token = document.getElementById('https-cloudflare-token').value.trim();
        const wildcard = document.getElementById('https-wildcard').checked;

        if (!domain || !email) {
            alert('Domain and email are required');
            return;
        }

        try {
            await fetch(API + '/settings', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({key: 'domain', value: domain})
            });
            await fetch(API + '/settings', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({key: 'acme_email', value: email})
            });
            if (token) {
                await fetch(API + '/settings', {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key: 'cloudflare_api_token', value: token})
                });
            }
            await fetch(API + '/settings', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({key: 'wildcard_cert', value: wildcard ? 'true' : 'false'})
            });
            alert('Settings saved successfully');
            document.getElementById('https-cloudflare-token').value = '';
        } catch (e) {
            alert('Failed to save settings: ' + e.message);
        }
    });

    document.getElementById('request-cert-btn').addEventListener('click', async () => {
        const domain = document.getElementById('https-domain').value.trim();
        const wildcard = document.getElementById('https-wildcard').checked;
        const statusDiv = document.getElementById('cert-action-status');

        if (!domain) {
            statusDiv.innerHTML = '<p class="text-red-400">Please set domain in settings first</p>';
            return;
        }

        statusDiv.innerHTML = '<p class="text-blue-400">Requesting certificate... This may take 1-2 minutes.</p>';
        document.getElementById('request-cert-btn').disabled = true;

        try {
            const response = await fetch(API + '/acme/request', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain, wildcard})
            });
            const result = await response.json();
            
            if (response.ok) {
                statusDiv.innerHTML = '<p class="text-green-400">Certificate request started in background. Check status in a few minutes.</p>';
                setTimeout(() => loadCertificateStatus(), 60000);
            } else {
                statusDiv.innerHTML = `<p class="text-red-400">Error: ${result.error || 'Request failed'}</p>`;
            }
        } catch (e) {
            statusDiv.innerHTML = `<p class="text-red-400">Request failed: ${e.message}</p>`;
        } finally {
            document.getElementById('request-cert-btn').disabled = false;
        }
    });

    document.getElementById('renew-cert-btn').addEventListener('click', async () => {
        const domain = document.getElementById('https-domain').value.trim();
        const wildcard = document.getElementById('https-wildcard').checked;
        const statusDiv = document.getElementById('cert-action-status');

        if (!domain) {
            statusDiv.innerHTML = '<p class="text-red-400">Please set domain in settings first</p>';
            return;
        }

        if (!confirm('Force certificate renewal?')) return;

        statusDiv.innerHTML = '<p class="text-blue-400">Renewing certificate... This may take 1-2 minutes.</p>';
        document.getElementById('renew-cert-btn').disabled = true;

        try {
            const response = await fetch(API + '/acme/renew', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain, wildcard})
            });
            const result = await response.json();
            
            if (response.ok) {
                statusDiv.innerHTML = '<p class="text-green-400">Certificate renewal started in background. Check status in a few minutes.</p>';
                setTimeout(() => loadCertificateStatus(), 60000);
            } else {
                statusDiv.innerHTML = `<p class="text-red-400">Error: ${result.error || 'Renewal failed'}</p>`;
            }
        } catch (e) {
            statusDiv.innerHTML = `<p class="text-red-400">Renewal failed: ${e.message}</p>`;
        } finally {
            document.getElementById('renew-cert-btn').disabled = false;
        }
    });


    // --- Activity Log ---

    const activityState = { entries: [], maxEntries: 200, expanded: false, unread: 0 };
    let activitySSE = null;

    function connectActivitySSE() {
        if (activitySSE) return;
        activitySSE = new EventSource(API + '/activity/stream');
        activitySSE.onmessage = (e) => {
            if (e.data === '') return;
            try {
                const entry = JSON.parse(e.data);
                addActivityEntry(entry);
            } catch {}
        };
        activitySSE.onerror = () => {
            activitySSE.close();
            activitySSE = null;
            setTimeout(connectActivitySSE, 5000);
        };
    }

    function addActivityEntry(entry) {
        activityState.entries.push(entry);
        if (activityState.entries.length > activityState.maxEntries) {
            activityState.entries.shift();
        }
        if (!activityState.expanded) {
            activityState.unread++;
            updateActivityBadge();
        }
        renderActivityEntry(entry);
    }

    function renderActivityEntry(entry) {
        const container = document.getElementById('activity-entries');
        const color = {info:'text-blue-300',success:'text-emerald-300',warning:'text-yellow-300',error:'text-red-300'}[entry.level] || 'text-gray-300';
        const bg = {error:'bg-red-900/30',warning:'bg-yellow-900/30',success:'bg-emerald-900/30'}[entry.level] || '';
        const time = new Date(entry.ts * 1000).toLocaleTimeString();
        const div = document.createElement('div');
        div.className = `flex gap-2 py-1 px-2 rounded ${bg}`;
        div.setAttribute('data-op-id', entry.op_id);
        div.innerHTML = `<span class="text-gray-500 shrink-0">${time}</span><span class="${color} shrink-0 font-medium">${entry.op}</span><span class="text-gray-300">${entry.message}</span>`;
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
    }

    function updateActivityBadge() {
        const badge = document.getElementById('activity-badge');
        if (activityState.unread > 0) {
            badge.textContent = activityState.unread > 9 ? '9+' : activityState.unread;
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
    }

    document.getElementById('activity-toggle').addEventListener('click', () => {
        activityState.expanded = !activityState.expanded;
        const body = document.getElementById('activity-body');
        const chevron = document.getElementById('activity-chevron');
        if (activityState.expanded) {
            body.classList.remove('hidden');
            chevron.style.transform = 'rotate(180deg)';
            activityState.unread = 0;
            updateActivityBadge();
        } else {
            body.classList.add('hidden');
            chevron.style.transform = '';
        }
    });

    connectActivitySSE();

    // --- Cloudflare Test Connection ---

    document.getElementById('test-cloudflare-btn').addEventListener('click', async () => {
        const tokenInput = document.getElementById('https-cloudflare-token');
        const resultSpan = document.getElementById('cf-test-result');
        const token = tokenInput.value.trim();
        if (!token) {
            resultSpan.textContent = 'Enter a token first';
            resultSpan.className = 'ml-2 text-xs text-yellow-400';
            return;
        }
        resultSpan.textContent = 'Testing...';
        resultSpan.className = 'ml-2 text-xs text-blue-400';
        try {
            const resp = await fetch(API + '/cloudflare/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({api_token: token})
            });
            const result = await resp.json();
            if (result.ok) {
                resultSpan.textContent = '✓ Token valid!';
                resultSpan.className = 'ml-2 text-xs text-emerald-400';
            } else {
                resultSpan.textContent = '✗ ' + (result.error || 'Invalid token');
                resultSpan.className = 'ml-2 text-xs text-red-400';
            }
        } catch (e) {
            resultSpan.textContent = '✗ ' + e.message;
            resultSpan.className = 'ml-2 text-xs text-red-400';
        }
    });

    // --- HTTPS Request Certificate - wire up activity progress ---

    const origRequestBtn = document.getElementById('request-cert-btn');
    const origRenewBtn = document.getElementById('renew-cert-btn');

    // Expand activity panel when cert request starts
    function expandActivity() {
        if (!activityState.expanded) {
            document.getElementById('activity-toggle').click();
        }
    }

    origRequestBtn.addEventListener('click', () => setTimeout(expandActivity, 200));
    origRenewBtn.addEventListener('click', () => setTimeout(expandActivity, 200));

    // --- Settings ---

    async function loadSettings() {
        const data = await fetch(API + '/settings').then(r => r.json());
        const form = document.getElementById('settings-form');
        const fields = [
            {key: 'listen_address', label: 'Listen Address'},
            {key: 'listen_port', label: 'DNS Port'},
            {key: 'sinkhole_ipv4', label: 'Sinkhole IPv4'},
            {key: 'sinkhole_ipv6', label: 'Sinkhole IPv6'},
            {key: 'log_level', label: 'Log Level'},
            {key: 'upstream_timeout_secs', label: 'Upstream Timeout (s)'},
            {key: 'allowed_networks', label: 'Allowed Networks (CIDR, comma-separated)'},
            {key: 'stats_retention_days', label: 'Stats Retention (days, 0 = forever)'},
        ];
        form.innerHTML = fields.map(f => {
            if (f.key === 'allowed_networks') {
                return `<div class="md:col-span-2">
                    <label class="block text-sm text-gray-400 mb-1">${f.label}</label>
                    <textarea id="setting-${f.key}" rows="2" placeholder="192.168.0.0/24, 10.0.0.0/22 (empty = allow all)"
                        class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm focus:outline-none focus:border-emerald-500">${data[f.key] || ''}</textarea>
                </div>`;
            }
            return `<div>
                <label class="block text-sm text-gray-400 mb-1">${f.label}</label>
                <input id="setting-${f.key}" type="text" value="${data[f.key] || ''}"
                    class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm focus:outline-none focus:border-emerald-500">
            </div>`;
        }).join('');
        window._originalSettings = data;
    }

    async function saveSettings() {
        const keys = ['listen_address', 'listen_port', 'sinkhole_ipv4', 'sinkhole_ipv6', 'log_level', 'upstream_timeout_secs', 'allowed_networks', 'stats_retention_days'];
        const restartKeys = ['listen_address', 'listen_port', 'log_level'];
        let needsRestart = false;
        let restartPending = false;
        for (const key of keys) {
            const el = document.getElementById('setting-' + key);
            if (el) {
                if (restartKeys.includes(key)) {
                    const orig = (window._originalSettings && window._originalSettings[key]) || '';
                    if (el.value !== orig) needsRestart = true;
                }
                try {
                    const resp = await fetch(API + '/settings', {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({key, value: el.value})
                    });
                    const data = await resp.json().catch(() => ({}));
                    if (data.restart_pending) restartPending = true;
                } catch {}
            }
        }
        const status = document.getElementById('settings-status');
        if (restartPending) {
            status.textContent = 'Saved. Restarting to apply changes...';
            status.className = 'text-sm text-amber-400';
            waitForRestart('Settings applied and restarted');
        } else if (needsRestart) {
            status.textContent = 'Saved. Changes to listen address, port, or log level require manually restarting the process.';
            status.className = 'text-sm text-amber-400';
        } else {
            status.textContent = 'Saved (applied live).';
            status.className = 'text-sm text-emerald-400';
            setTimeout(() => { status.textContent = ''; status.className = 'text-sm mb-2'; }, 5000);
        }
    }

    // --- Sync config ---

    async function loadSyncConfig() {
        try {
            const data = await fetch(API + '/sync/config').then(r => r.json());
            document.getElementById('sync-enabled').checked = !!data.enabled;
            document.getElementById('sync-master-url').value = data.master_url || '';
            document.getElementById('sync-interval').value = data.interval_secs || 30;
            const hint = document.getElementById('sync-password-hint');
            hint.textContent = data.password_set ? '(password saved)' : '(not set)';
            // Re-enable Save if this node is already configured — no need to re-verify
            const saveBtn = document.getElementById('save-sync-btn');
            if (saveBtn && data.enabled && data.master_url) {
                saveBtn.disabled = false;
            }
        } catch (e) {
            console.warn('Failed to load sync config', e);
        }
    }

    async function saveSyncConfig() {
        const enabled = document.getElementById('sync-enabled').checked;
        const master_url = document.getElementById('sync-master-url').value.trim();
        const password = document.getElementById('sync-password').value;
        const interval_secs = parseInt(document.getElementById('sync-interval').value, 10) || 30;
        const status = document.getElementById('sync-status');
        const saveBtn = document.getElementById('save-sync-btn');

        if (enabled && !master_url) {
            status.textContent = 'Master URL is required when sync is enabled.';
            status.className = 'text-sm text-red-400';
            return;
        }

        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';
        status.textContent = '';

        try {
            const resp = await fetch(API + '/sync/config', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({enabled, master_url, password, interval_secs})
            });
            const data = await resp.json().catch(() => ({}));
            if (!resp.ok) {
                status.textContent = data.error || 'Failed to save.';
                status.className = 'text-sm text-red-400';
                saveBtn.disabled = false;
                saveBtn.textContent = 'Save & Restart';
                return;
            }
            // Clear password field and refresh hint
            document.getElementById('sync-password').value = '';
            const hint = document.getElementById('sync-password-hint');
            if (password) hint.textContent = '(password saved)';
            // Trigger restart then poll until back up
            status.textContent = 'Saved. Restarting...';
            status.className = 'text-sm text-amber-400';
            try {
                await fetch(API + '/restart', {method: 'POST'});
            } catch (_) { /* server may close the connection immediately */ }
            await syncWaitForRestart();
        } catch (e) {
            status.textContent = 'Request failed: ' + e.message;
            status.className = 'text-sm text-red-400';
            saveBtn.disabled = false;
            saveBtn.textContent = 'Save & Restart';
        }
    }

    async function verifySyncConnection() {
        const btn = document.getElementById('test-sync-btn');
        const saveBtn = document.getElementById('save-sync-btn');
        const status = document.getElementById('sync-status');
        const masterUrl = document.getElementById('sync-master-url').value.trim();
        const password = document.getElementById('sync-password').value;

        if (!masterUrl) {
            status.textContent = 'Enter a Master URL first.';
            status.className = 'text-sm text-red-400';
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Testing...';
        status.textContent = '';
        saveBtn.disabled = true;

        try {
            const resp = await fetch(API + '/sync/verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({master_url: masterUrl, password: password || null})
            });
            const data = await resp.json().catch(() => ({}));
            if (resp.ok && data.ok) {
                status.textContent = 'Connection successful.';
                status.className = 'text-sm text-emerald-400';
                saveBtn.disabled = false;
            } else {
                status.textContent = 'Connection failed: ' + (data.error || 'Unknown error');
                status.className = 'text-sm text-red-400';
                saveBtn.disabled = true;
            }
        } catch (e) {
            status.textContent = 'Request failed: ' + e.message;
            status.className = 'text-sm text-red-400';
            saveBtn.disabled = true;
        } finally {
            btn.disabled = false;
            btn.textContent = 'Test Connection';
        }
    }

    async function syncWaitForRestart() {
        const status = document.getElementById('sync-status');
        let attempts = 0;
        const maxAttempts = 60;
        while (attempts < maxAttempts) {
            await new Promise(r => setTimeout(r, 2000));
            attempts++;
            try {
                const r = await fetch(API + '/health');
                if (r.ok) {
                    status.textContent = 'Restarted. Reloading...';
                    status.className = 'text-sm text-emerald-400';
                    setTimeout(() => window.location.reload(), 1500);
                    return;
                }
            } catch (_) { /* server down, keep polling */ }
            status.textContent = 'Restarting... (' + attempts + ')';
            status.className = 'text-sm text-amber-400';
        }
        status.textContent = 'Restart timed out \u2014 please refresh manually.';
        status.className = 'text-sm text-red-400';
    }

    // --- Sync status polling ---
    let _syncPollTimer = null;

    function startSyncStatusPoll() {
        if (_syncPollTimer) return;
        updateSyncStatus(); // immediate
        _syncPollTimer = setInterval(updateSyncStatus, 15000);
    }

    function stopSyncStatusPoll() {
        if (_syncPollTimer) { clearInterval(_syncPollTimer); _syncPollTimer = null; }
    }

    async function updateSyncStatus() {
        try {
            const data = await fetch(API + '/sync/status').then(r => r.json());
            renderSyncUI(data);
        } catch { /* silent — network error, don't flash error state */ }
    }

    function renderSyncUI(data) {
        // status: 'ok' | 'connecting' | 'error' | 'disabled'
        const pill     = document.getElementById('sync-pill');
        const pillDot  = document.getElementById('sync-pill-dot');
        const pillLabel = document.getElementById('sync-pill-label');
        const badge     = document.getElementById('sync-connection-badge');
        const badgeDot  = document.getElementById('sync-badge-dot');
        const badgeLabel = document.getElementById('sync-badge-label');

        if (data.status === 'disabled') {
            pill.classList.add('hidden');  pill.classList.remove('flex');
            badge.classList.add('hidden'); badge.classList.remove('flex');
            return;
        }

        const scheme = {
            ok:         { dot: 'bg-emerald-400', border: 'border-emerald-700', text: 'text-emerald-400', pulse: true,  label: 'Replica' },
            connecting: { dot: 'bg-amber-400',   border: 'border-amber-700',   text: 'text-amber-400',   pulse: true,  label: 'Connecting…' },
            error:      { dot: 'bg-red-400',     border: 'border-red-700',     text: 'text-red-400',     pulse: false, label: 'Sync error' },
        }[data.status] || { dot: 'bg-gray-400', border: 'border-gray-600', text: 'text-gray-400', pulse: false, label: data.status };

        function applyScheme(el, dot, label, extraLabel) {
            el.className = el.className.replace(/\b(border-\S+|text-\S+)\b/g, '').trim();
            el.classList.add('flex', 'items-center', 'gap-1.5', 'text-xs', 'font-medium', 'px-2', 'py-0.5', 'rounded-full', 'border', scheme.border, scheme.text);
            el.classList.remove('hidden');
            dot.className = 'inline-block w-2 h-2 rounded-full ' + scheme.dot + (scheme.pulse ? ' animate-pulse' : '');
            label.textContent = extraLabel || scheme.label;
        }

        // header pill
        const pillText = (data.status === 'ok' && data.master_url) ? 'Replica' : scheme.label;
        applyScheme(pill, pillDot, pillLabel, pillText);
        pill.title = (data.status === 'ok' && data.last_sync)
            ? 'Last sync: ' + Math.round((Date.now() / 1000 - data.last_sync)) + 's ago'
            : (data.error || 'Replica sync ' + data.status);

        // settings badge
        let badgeText = scheme.label;
        if (data.status === 'ok' && data.last_sync) {
            const ago = Math.round((Date.now() / 1000 - data.last_sync));
            badgeText = 'Connected · ' + (ago < 60 ? ago + 's ago' : Math.round(ago / 60) + 'm ago');
        } else if (data.status === 'error' && data.error) {
            badgeText = data.error;
        }
        applyScheme(badge, badgeDot, badgeLabel, badgeText);
    }

    function formatLatency(us) {
        if (us == null) return '-';
        if (us >= 1000) return (us / 1000).toFixed(1) + ' ms';
        return us + ' μs';
    }


    // --- Update ---

    function setHeaderRefreshSpinning(spin) {
        const icon = document.getElementById('header-refresh-icon');
        if (!icon) return;
        if (spin) icon.classList.add('animate-spin');
        else icon.classList.remove('animate-spin');
    }

    function renderHeaderUpdate(available, info) {
        const headerBtn = document.getElementById('header-update-btn');
        if (!headerBtn) return;
        if (available && info) {
            headerBtn.classList.remove('hidden');
            headerBtn.title = 'Update to ' + info.version;
            headerBtn.disabled = false;
            headerBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="h-4 w-4 animate-bounce"><path stroke-linecap="round" stroke-linejoin="round" d="M5 10l7-7m0 0l7 7m-7-7v18" /></svg>';
        } else {
            headerBtn.classList.add('hidden');
        }
    }

    function setHeaderUpdating() {
        const headerBtn = document.getElementById('header-update-btn');
        if (headerBtn) {
            headerBtn.disabled = true;
            headerBtn.innerHTML = '<span class="spinner"></span>';
        }
    }

    async function checkForUpdates() {
        await autoCheckUpdate();
    }

    function applyUpdateFromHeader() {
        setHeaderUpdating();
        applyUpdate();
    }

    async function autoCheckUpdate() {
        const status = document.getElementById('update-status');
        const btn = document.getElementById('update-apply-btn');
        const notes = document.getElementById('update-notes');
        if (!status) return;
        status.textContent = 'Checking for updates...';
        status.className = 'text-sm text-gray-400';
        btn.classList.add('hidden');
        notes.classList.add('hidden');
        setHeaderRefreshSpinning(true);
        try {
            const r = await fetch(API + '/update/check');
            const data = await r.json();
            if (data.update_available) {
                window._updateInfo = data;
                status.textContent = 'Update available: ' + data.version;
                status.className = 'text-sm text-emerald-400';
                notes.textContent = data.notes ? data.notes.substring(0, 500) : '';
                notes.classList.remove('hidden');
                btn.classList.remove('hidden');
                renderHeaderUpdate(true, data);
            } else {
                window._updateInfo = null;
                status.textContent = 'Up to date (' + data.current_version + ')';
                status.className = 'text-sm text-gray-400';
                renderHeaderUpdate(false);
            }
        } catch {
            status.textContent = 'Update check failed';
            status.className = 'text-sm text-red-400';
            window._updateInfo = null;
            renderHeaderUpdate(false);
        } finally {
            setHeaderRefreshSpinning(false);
        }
    }

    async function waitForRestart(afterText) {
        const status = document.getElementById('update-status');
        const btn = document.getElementById('update-apply-btn');
        const notes = document.getElementById('update-notes');
        let attempts = 0;
        const maxAttempts = 60;
        while (attempts < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, 2000));
            attempts++;
            try {
                const r = await fetch(API + '/health');
                if (r.ok) {
                    status.textContent = (afterText || 'Restart complete') + '. Reloading...';
                    status.className = 'text-sm text-emerald-400';
                    btn.classList.add('hidden');
                    notes.classList.add('hidden');
                    btn.disabled = false;
                    setTimeout(() => window.location.reload(), 1500);
                    return;
                }
            } catch {}
            status.textContent = 'Restarting... (' + attempts + ')';
            status.className = 'text-sm text-amber-400';
        }
        status.textContent = 'Restart timed out; please refresh manually';
        status.className = 'text-sm text-red-400';
    }

    async function applyUpdate() {
        const status = document.getElementById('update-status');
        const btn = document.getElementById('update-apply-btn');
        if (!status || !btn) return;
        status.textContent = 'Updating...';
        status.className = 'text-sm text-amber-400';
        btn.disabled = true;
        setHeaderUpdating();
        try {
            const r = await fetch(API + '/update/apply', { method: 'POST' });
            const data = await r.json();
            if (data.status === 'updated') {
                status.textContent = 'Updated to ' + data.version + '. Restarting...';
                status.className = 'text-sm text-emerald-400';
                waitForRestart('Updated to ' + data.version + ' and restarted');
            } else {
                throw new Error(data.error || 'Unknown error');
            }
        } catch (e) {
            status.textContent = 'Update failed: ' + (e.message || 'Network error');
            status.className = 'text-sm text-red-400';
            btn.disabled = false;
            btn.classList.remove('hidden');
            renderHeaderUpdate(false);
        }
    }
    // --- Health ---

    async function checkHealth() {
        try {
            const r = await fetch(API + '/health');
            await r.json();
            document.getElementById('status').textContent = 'Online';
            document.getElementById('status').className = 'text-sm text-green-400';
        } catch {
            document.getElementById('status').textContent = 'Offline';
            document.getElementById('status').className = 'text-sm text-red-400';
        }
    }

    // --- Stats (Live SSE) ---

    let statsOffset = 0;
    const STATS_PAGE = 50;
    let liveEnabled = true;
    let eventSource = null;
    let reconnectTimer = null;
    let dashboardInterval = null;
    const actionColors = {blocked:'text-red-400', allowed:'text-green-400', rewritten:'text-blue-400', forwarded:'text-yellow-400'};
    function renderQueryRow(q) {
        const now = new Date();
        const ts = q.timestamp || now.toISOString().slice(0, 19).replace('T', ' ');
        return `<tr class="border-b border-gray-700/50 hover:bg-gray-700/30 live-row">
            <td class="py-1.5 px-2 text-gray-400 whitespace-nowrap">${ts}</td>
            <td class="py-1.5 px-2 font-mono">${q.client_ip}</td>
            <td class="py-1.5 px-2 font-mono truncate max-w-xs">${q.domain}</td>
            <td class="py-1.5 px-2 text-gray-400">${q.query_type}</td>
            <td class="py-1.5 px-2 font-medium ${actionColors[q.action] || 'text-gray-400'}">${q.action}</td>
            <td class="py-1.5 px-2 font-mono text-gray-400">${q.resolver || '-'}</td>
        </tr>`;
    }

    function connectSSE() {
        if (eventSource) { eventSource.close(); eventSource = null; }
        if (!liveEnabled) return;
        eventSource = new EventSource(API + '/stats/live');
        eventSource.onmessage = (e) => {
            try {
                const q = JSON.parse(e.data);
                const tbody = document.getElementById('stats-query-log');
                if (tbody.querySelector('td[colspan]')) tbody.innerHTML = '';
                tbody.insertAdjacentHTML('afterbegin', renderQueryRow(q));
                // Cap live rows to avoid unbounded growth.
                while (tbody.children.length > STATS_PAGE) tbody.removeChild(tbody.lastChild);
            } catch {}
        };
        eventSource.onerror = () => {
            // Reconnect after 3s on error.
            eventSource.close();
            eventSource = null;
            if (liveEnabled) reconnectTimer = setTimeout(connectSSE, 3000);
        };
    }

    function disconnectSSE() {
        if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
        if (eventSource) { eventSource.close(); eventSource = null; }
    }

    function toggleLive() {
        liveEnabled = !liveEnabled;
        const btn = document.getElementById('live-btn');
        const dot = document.getElementById('live-dot');
        const label = document.getElementById('live-label');
        if (liveEnabled) {
            btn.classList.remove('bg-gray-600', 'hover:bg-gray-500');
            btn.classList.add('bg-emerald-600', 'hover:bg-emerald-700');
            dot.classList.remove('bg-gray-400', 'animate-pulse');
            dot.classList.add('bg-emerald-300', 'animate-pulse');
            label.textContent = 'Live';
            connectSSE();
        } else {
            btn.classList.remove('bg-emerald-600', 'hover:bg-emerald-700');
            btn.classList.add('bg-gray-600', 'hover:bg-gray-500');
            dot.classList.remove('bg-emerald-300', 'animate-pulse');
            dot.classList.add('bg-gray-400');
            label.textContent = 'Paused';
            disconnectSSE();
        }
    }
    function startDashboardPoll() {
        if (dashboardInterval) clearInterval(dashboardInterval);
        dashboardInterval = setInterval(() => { refreshDashboardStats(); }, 3000);
    }

    function stopDashboardPoll() {
        if (dashboardInterval) {
            clearInterval(dashboardInterval);
            dashboardInterval = null;
        }
    }

    async function loadStats() {
        // Load historical page from DB.
        const queries = await fetch(API + `/stats/queries?limit=${STATS_PAGE}&offset=${statsOffset}`).then(r => r.json());
        const tbody = document.getElementById('stats-query-log');
        tbody.innerHTML = queries.length
            ? queries.map(q => renderQueryRow(q)).join('')
            : '<tr><td colspan="6" class="py-4 text-center text-gray-500">No queries logged yet</td></tr>';

        document.getElementById('stats-prev').disabled = statsOffset === 0;
        document.getElementById('stats-next').disabled = queries.length < STATS_PAGE;
        document.getElementById('stats-page-info').textContent = statsOffset === 0
            ? 'Live feed — newest first'
            : `Page ${Math.floor(statsOffset / STATS_PAGE) + 1}`;

        // Connect SSE only on page 0 (live feed).
        if (statsOffset === 0 && liveEnabled) {
            connectSSE();
        } else {
            disconnectSSE();
        }
    }

    function statsPrevPage() {
        statsOffset = Math.max(0, statsOffset - STATS_PAGE);
        loadStats();
    }

    function statsNextPage() {
        statsOffset += STATS_PAGE;
        loadStats();
    }

    async function clearStats() {
        if (!confirm('Clear all query statistics? This cannot be undone.')) return;
        await fetch(API + '/stats', {method: 'DELETE'});
        statsOffset = 0;
        loadStats();
    }

    const _rawFetch = window.fetch;
    window.fetch = async function(...args) {
        const resp = await _rawFetch.apply(this, args);
        if (resp.status === 401) {
            const url = String(args[0]);
            if (!url.includes('/api/auth/')) showLogin();
        }
        return resp;
    };

    function showLogin() {
        stopDashboardPoll();
        stopSyncStatusPoll();
        disconnectSSE();
        document.getElementById('app-content').classList.add('hidden');
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('login-password').value = '';
        document.getElementById('login-error').classList.add('hidden');
    }

    function showApp() {
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('app-content').classList.remove('hidden');
        startSyncStatusPoll();
    }

    async function init() {
        try {
            const resp = await fetch(API + '/auth/check');
            const data = await resp.json();
            if (data.authenticated) {
                showApp();
                checkHealth();
                loadDashboard();
            } else {
                showLogin();
            }
        } catch {
            showLogin();
        }
    }

    async function submitLogin(e) {
        e.preventDefault();
        const password = document.getElementById('login-password').value;
        const error = document.getElementById('login-error');
        const resp = await fetch(API + '/auth/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({password})
        });
        if (resp.ok) {
            error.classList.add('hidden');
            showApp();
            checkHealth();
            loadDashboard();
        } else {
            error.textContent = 'Invalid password';
            error.classList.remove('hidden');
        }
    }

    async function logout() {
        await fetch(API + '/auth/logout', {method: 'POST'});
        showLogin();
    }

    async function changePassword() {
        const current = document.getElementById('current-password').value;
        const newPass = document.getElementById('new-password').value;
        const confirm = document.getElementById('confirm-password').value;
        const status = document.getElementById('password-status');
        if (newPass !== confirm) {
            status.textContent = 'New passwords do not match';
            status.className = 'text-sm text-red-400';
            return;
        }
        if (newPass.length < 6) {
            status.textContent = 'Password must be at least 6 characters';
            status.className = 'text-sm text-red-400';
            return;
        }
        const resp = await fetch(API + '/auth/password', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({current_password: current, new_password: newPass})
        });
        if (resp.ok) {
            status.textContent = 'Password changed successfully';
            status.className = 'text-sm text-emerald-400';
            document.getElementById('current-password').value = '';
            document.getElementById('new-password').value = '';
            document.getElementById('confirm-password').value = '';
        } else {
            const data = await resp.json().catch(() => ({}));
            status.textContent = data.error || 'Failed to change password';
            status.className = 'text-sm text-red-400';
        }
        setTimeout(() => { status.textContent = ''; status.className = 'text-sm'; }, 5000);
    }

    // --- Key bindings ---

    document.getElementById('blocklist-input').addEventListener('keydown', e => { if (e.key === 'Enter') addDomain('blocklist'); });
    document.getElementById('allowlist-input').addEventListener('keydown', e => { if (e.key === 'Enter') addDomain('allowlist'); });
    document.getElementById('upstream-address').addEventListener('keydown', e => { if (e.key === 'Enter') addUpstream(); });
    document.getElementById('blocklist-url').addEventListener('keydown', e => { if (e.key === 'Enter') importUrl('blocklist'); });
    document.getElementById('allowlist-url').addEventListener('keydown', e => { if (e.key === 'Enter') importUrl('allowlist'); });
    document.getElementById('source-url').addEventListener('keydown', e => { if (e.key === 'Enter') addSource(); });
    document.getElementById('blocklist-search').addEventListener('input', () => onSearch('blocklist'));
    document.getElementById('allowlist-search').addEventListener('input', () => onSearch('allowlist'));
// Attach event listeners now that DOM is ready (script is deferred).
function attachListeners() {
    document.getElementById('login-form')?.addEventListener('submit', submitLogin);
    document.getElementById('logout-btn')?.addEventListener('click', logout);
    document.getElementById('header-update-btn')?.addEventListener('click', applyUpdateFromHeader);
    document.getElementById('header-refresh-btn')?.addEventListener('click', checkForUpdates);
    document.getElementById('add-upstream-btn')?.addEventListener('click', addUpstream);
    document.getElementById('add-source-btn')?.addEventListener('click', addSource);
    document.getElementById('refresh-sources-btn')?.addEventListener('click', refreshAllSources);
    document.getElementById('blocklist-add-btn')?.addEventListener('click', () => addDomain('blocklist'));
    document.getElementById('blocklist-url-btn')?.addEventListener('click', () => importUrl('blocklist'));
    document.getElementById('allowlist-add-btn')?.addEventListener('click', () => addDomain('allowlist'));
    document.getElementById('allowlist-url-btn')?.addEventListener('click', () => importUrl('allowlist'));
    document.getElementById('add-rewrite-btn')?.addEventListener('click', addRewrite);
    document.getElementById('save-settings-btn')?.addEventListener('click', saveSettings);
    document.getElementById('save-sync-btn')?.addEventListener('click', saveSyncConfig);
    document.getElementById('test-sync-btn')?.addEventListener('click', verifySyncConnection);

    // Re-disable Save & Restart when credentials change — forces re-verify
    ['sync-master-url', 'sync-password'].forEach(id => {
        document.getElementById(id)?.addEventListener('input', () => {
            document.getElementById('save-sync-btn').disabled = true;
        });
    });
    document.getElementById('update-apply-btn')?.addEventListener('click', applyUpdate);
    document.getElementById('change-password-btn')?.addEventListener('click', changePassword);
    document.getElementById('live-btn')?.addEventListener('click', toggleLive);
    document.getElementById('clear-stats-btn')?.addEventListener('click', clearStats);
    document.getElementById('stats-prev')?.addEventListener('click', statsPrevPage);
    document.getElementById('stats-next')?.addEventListener('click', statsNextPage);

    document.querySelectorAll('.import-file-input').forEach(input => {
        input.addEventListener('change', () => importFile(input.dataset.type, input));
    });

    // Delegated listeners for dynamically generated list buttons
    document.getElementById('upstream-list')?.addEventListener('click', (e) => {
        const btn = e.target.closest('.delete-upstream-btn');
        if (btn) deleteUpstream(parseInt(btn.dataset.id));
    });
    document.getElementById('source-list')?.addEventListener('click', (e) => {
        const btn = e.target.closest('.delete-source-btn');
        if (btn) deleteSource(parseInt(btn.dataset.id));
    });
    document.getElementById('blocklist-list')?.addEventListener('click', handleDomainClick);
    document.getElementById('allowlist-list')?.addEventListener('click', handleDomainClick);
    document.getElementById('blocklist-pagination')?.addEventListener('click', handleDomainClick);
    document.getElementById('allowlist-pagination')?.addEventListener('click', handleDomainClick);
    document.getElementById('rewrites-list')?.addEventListener('click', (e) => {
        const btn = e.target.closest('.delete-rewrite-btn');
        if (btn) deleteRewrite(parseInt(btn.dataset.id));
    });
}

function handleDomainClick(e) {
    const del = e.target.closest('.delete-domain-btn');
    if (del) {
        deleteDomain(del.dataset.type, parseInt(del.dataset.id));
        return;
    }
    const prev = e.target.closest('.page-prev-btn');
    if (prev) {
        pageDomain(prev.dataset.type, parseInt(prev.dataset.delta));
        return;
    }
    const next = e.target.closest('.page-next-btn');
    if (next) {
        pageDomain(next.dataset.type, parseInt(next.dataset.delta));
    }
}

attachListeners();

init();
