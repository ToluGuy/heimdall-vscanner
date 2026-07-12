
        
         function goToResult(resultId) {
            resultTab = 'active';
            switchTab('dashboard');
            setTimeout(async () => {
                // First do a full load to get all results into pageData
                await loadResults();

                // Find which page the result is on and jump to it
                const allResults = pageData.results;
                const idx = allResults.findIndex(r => r.id === resultId);
                if (idx >= 0) {
                    const targetPage = Math.floor(idx / PAGE_SIZES.results) + 1;
                    if (pages.results !== targetPage) {
                        pages.results = targetPage;
                        renderResults();
                    }
                }

                setTimeout(() => {
                    const cards = document.querySelectorAll('#results > div');
                    let targetCard = null;
                    for (const c of cards) {
                        if (c.querySelector('#result-body-' + resultId)) {
                            targetCard = c;
                            break;
                        }
                    }
                    if (targetCard) {
                        targetCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        targetCard.style.transition = 'box-shadow 0.2s';
                        targetCard.style.boxShadow  = '0 0 0 2px #4ade80';
                        setTimeout(() => {
                            targetCard.style.boxShadow  = '';
                            targetCard.style.transition = '';
                        }, 1800);
                        const bodyEl  = document.getElementById('result-body-'  + resultId);
                        const arrowEl = document.getElementById('result-arrow-' + resultId);
                        if (bodyEl && bodyEl.classList.contains('hidden')) {
                            bodyEl.classList.remove('hidden');
                            if (arrowEl) arrowEl.innerText = '▲';
                        }
                    }
                }, 400);
            }, 100);
        }
        
        // ── STATE ──────────────────────────────────────────────────────────
        let jobFilter = "all";
        let showJobHistory = false;
        let resultTab = "active";
        let authCredentials = "";
        let confirmCallback = null;
        let exploitWarningCallback = null;
        let showStaleAgents = false;
        let activeTab = "dashboard";
        let exploitBannerDismissed = false;
        let topoData = null;
        let mapFilter = 'all';

        // Tracks job statuses from last poll — used to detect completions
        let lastJobStatuses = {};

        // ── PAGINATION STATE ──────────────────────────────────────────────
        // Each tab has its own current page. Page size is shared but can be
        // overridden per tab. All are 1-indexed.
        const PAGE_SIZES = { results: 10, jobs: 20, agents: 20, sweeps: 10 };
        let pages = { results: 1, jobs: 1, agents: 1, sweeps: 1 };
        // Store the last-fetched data so pagination can re-render without re-fetching
        let pageData = { results: [], jobs: [], agents: [], sweeps: [] };
        
        // Friendly display names for scan types
        const SCAN_TYPE_LABELS = {
            nmap_scan:   'Open Port Scan',
            nikto_scan:  'Web Scan',
            nse_scan:    'Vulnerability Scan',
        };
        function scanTypeLabel(type) {
            return SCAN_TYPE_LABELS[type] || type;
        }

        // ── PAGINATION HELPERS ─────────────────────────────────────────────
        /**
         * Returns the slice of `items` for the current page of `tab`.
         */
        function getPage(tab, items) {
            const size  = PAGE_SIZES[tab];
            const start = (pages[tab] - 1) * size;
            return items.slice(start, start + size);
        }

        /**
         * Builds and returns the pagination bar HTML for a given tab.
         * `total` is the total number of items (before slicing).
         * Calls `goPage_<tab>(n)` on click.
         */
        function paginationBar(tab, total) {
            const size     = PAGE_SIZES[tab];
            const numPages = Math.ceil(total / size);
            if (numPages <= 1) return '';

            const cur = pages[tab];
            const fn  = `goPage_${tab}`;

            // Build page number buttons — show at most 5 around current page
            let pageNums = '';
            const lo = Math.max(1, cur - 2);
            const hi = Math.min(numPages, cur + 2);
            if (lo > 1) pageNums += `<button onclick="${fn}(1)" class="pagination-num px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition">1</button>`;
            if (lo > 2) pageNums += `<span class="text-gray-600 text-xs px-1">…</span>`;
            for (let p = lo; p <= hi; p++) {
                const active = p === cur ? 'bg-gray-700 text-gray-100' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700';
                pageNums += `<button onclick="${fn}(${p})" class="pagination-num px-2 py-1 rounded text-xs ${active} transition">${p}</button>`;
            }
            if (hi < numPages - 1) pageNums += `<span class="text-gray-600 text-xs px-1">…</span>`;
            if (hi < numPages) pageNums += `<button onclick="${fn}(${numPages})" class="pagination-num px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition">${numPages}</button>`;

            const start = (cur - 1) * size + 1;
            const end   = Math.min(cur * size, total);

            return `<div class="flex items-center justify-between mt-4 pt-3 border-t border-gray-800">
                <span class="text-xs text-gray-600">${start}–${end} of ${total}</span>
                <div class="flex items-center gap-1">
                    <button onclick="${fn}(${cur - 1})" ${cur === 1 ? 'disabled' : ''} class="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition disabled:opacity-30 disabled:cursor-not-allowed">‹</button>
                    ${pageNums}
                    <button onclick="${fn}(${cur + 1})" ${cur === numPages ? 'disabled' : ''} class="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition disabled:opacity-30 disabled:cursor-not-allowed">›</button>
                </div>
                <select onchange="changePageSize('${tab}', parseInt(this.value))" class="text-xs bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-400 focus:outline-none">
                    ${[10, 20, 50].map(n => `<option value="${n}" ${n === size ? 'selected' : ''}>${n} per page</option>`).join('')}
                </select>
            </div>`;
        }

        function goPage_results(n) { pages.results = n; renderResults(); }
        function goPage_jobs(n)    { pages.jobs    = n; renderJobs();    }
        function goPage_agents(n)  { pages.agents  = n; renderAgents();  }
        function goPage_sweeps(n)  { pages.sweeps  = n; renderSweeps();  }

        function changePageSize(tab, size) {
            PAGE_SIZES[tab] = size;
            pages[tab] = 1;  // reset to page 1 on size change
            if (tab === 'results') renderResults();
            if (tab === 'jobs')    renderJobs();
            if (tab === 'agents')  renderAgents();
            if (tab === 'sweeps')  renderSweeps();
        }

        // Pending sweep payload (hosts + params) waiting for user confirmation
        let pendingSweepPayload = null;

        // ── SETTINGS ──────────────────────────────────────────────────────────

        // Server settings cache
        let serverSettings = {};
 
        // ── Panel open/close ──────────────────────────────────────────────────
        function openSettings() {
            loadServerSettings();
            applyClientSettingsToPanel();
            document.getElementById('settingsPanel').classList.remove('translate-x-full');
            document.getElementById('settingsBackdrop').classList.remove('hidden');
        }
 
        function closeSettings() {
            document.getElementById('settingsPanel').classList.add('translate-x-full');
            document.getElementById('settingsBackdrop').classList.add('hidden');
        }

        function openPluginsPanel() {
            loadPlugins();
            document.getElementById('pluginsPanel').classList.remove('translate-x-full');
            document.getElementById('pluginsBackdrop').classList.remove('hidden');
        }

        function closePluginsPanel() {
            document.getElementById('pluginsPanel').classList.add('translate-x-full');
            document.getElementById('pluginsBackdrop').classList.add('hidden');
        }
 
        // Close on Escape key
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') { closeSettings(); closePluginsPanel(); }
        });
 
        // ── Theme ─────────────────────────────────────────────────────────────
        function setTheme(theme) {
            document.body.classList.toggle('theme-light', theme === 'light');
            localStorage.setItem('heimdall_theme', theme);
 
            // Update toggle buttons
            document.querySelectorAll('.theme-btn').forEach(b => {
                b.classList.remove('bg-gray-700', 'text-white');
                b.classList.add('text-gray-400');
            });
            const active = document.getElementById('theme-' + theme);
            if (active) {
                active.classList.add('bg-gray-700', 'text-white');
                active.classList.remove('text-gray-400');
            }
        }
 
        function applyStoredTheme() {
            const stored = localStorage.getItem('heimdall_theme') || 'dark';
            setTheme(stored);
        }
 
        // ── Client-side settings (localStorage) ──────────────────────────────
        function saveClientSetting(key, value) {
            localStorage.setItem('heimdall_' + key, value);
        }
 
        function getClientSetting(key, defaultValue) {
            return localStorage.getItem('heimdall_' + key) || defaultValue;
        }
 
        function applyClientSettingsToPanel() {
            // Theme
            const theme = getClientSetting('theme', 'dark');
            document.querySelectorAll('.theme-btn').forEach(b => {
                b.classList.remove('bg-gray-700', 'text-white');
                b.classList.add('text-gray-400');
            });
            const activeTheme = document.getElementById('theme-' + theme);
            if (activeTheme) {
                activeTheme.classList.add('bg-gray-700', 'text-white');
                activeTheme.classList.remove('text-gray-400');
            }
 
            // Scan defaults — also apply to the actual form dropdowns
            const profile = getClientSetting('defaultProfile', 'standard');
            const mode    = getClientSetting('defaultMode', 'remote');
            const prio    = getClientSetting('defaultPriority', 'medium');
            const refresh = getClientSetting('refreshInterval', '5000');
 
            const sp = document.getElementById('setting-default-profile');
            const sm = document.getElementById('setting-default-mode');
            const sr = document.getElementById('setting-default-priority');
            const si = document.getElementById('setting-refresh-interval');
            if (sp) sp.value = profile;
            if (sm) sm.value = mode;
            if (sr) sr.value = prio;
            if (si) si.value = refresh;
 
            // Apply defaults to the Create Job form
            const fp = document.getElementById('profile');
            const fm = document.getElementById('mode');
            const fr = document.getElementById('priority');
            if (fp && !fp.dataset.userChanged) fp.value = profile;
            if (fm && !fm.dataset.userChanged) fm.value = mode;
            if (fr && !fr.dataset.userChanged) fr.value = prio;
        }
 
        // ── Auto-refresh interval ─────────────────────────────────────────────
        let autoRefreshTimer = null;
 
        function applyRefreshInterval() {
            if (autoRefreshTimer) {
                clearInterval(autoRefreshTimer);
                autoRefreshTimer = null;
            }
            const ms = parseInt(getClientSetting('refreshInterval', '5000'));
            if (ms > 0) {
                autoRefreshTimer = setInterval(() => {
                    refreshAgents();
                    refreshJobs();
                }, ms);
            }
        }
 
        // ── Server settings ───────────────────────────────────────────────────
        async function loadServerSettings() {
            const res = await apiFetch('/settings');
            if (!res) return;
            serverSettings = await res.json();
            renderServerSettings();
        }
 
        function renderServerSettings() {
            function applyToggle(btnId, knobId, isOn) {
                const btn  = document.getElementById(btnId);
                const knob = document.getElementById(knobId);
                if (!btn || !knob) return;

                // Track classes (button)
                const onClasses  = ['bg-green-600', 'border', 'border-green-500'];
                const offClasses = ['bg-gray-700',  'border', 'border-gray-600'];
                if (isOn) {
                    offClasses.forEach(c => btn.classList.remove(c));
                    onClasses.forEach(c  => btn.classList.add(c));
                } else {
                    onClasses.forEach(c  => btn.classList.remove(c));
                    offClasses.forEach(c => btn.classList.add(c));
                }

                // Knob position and colour
                knob.style.transform = isOn ? 'translateX(20px)' : 'translateX(0)';
                knob.classList.remove('bg-white', 'bg-gray-400');
                knob.classList.add(isOn ? 'bg-white' : 'bg-gray-400');
            }

            applyToggle('setting-ai-toggle',    'setting-ai-knob',    serverSettings['ai_auto_analyse'] === 'true');
            applyToggle('setting-nikto-toggle', 'setting-nikto-knob', serverSettings['auto_nikto'] !== 'false');

            const staleInput = document.getElementById('setting-stale-hours');
            if (staleInput) staleInput.value = serverSettings['stale_agent_hours'] || '24';

            const authHoursInput = document.getElementById('setting-auth-max-hours');
            if (authHoursInput) authHoursInput.value = serverSettings['high_risk_auth_max_hours'] || '4';
        }
 
        async function toggleServerSetting(key) {
            const current = serverSettings[key] === 'true';
            const newVal  = (!current).toString();
            await saveServerSetting(key, newVal);
        }
 
        async function saveServerSetting(key, value) {
            const res = await apiFetch('/settings', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ [key]: value }),
            });
            if (!res) return;
            serverSettings[key] = value;
            renderServerSettings();
        }
 
        // ── Initialise on load ────────────────────────────────────────────────
        function initSettings() {
            applyStoredTheme();
            applyClientSettingsToPanel();
            applyRefreshInterval();
        }

        // ── TAB SWITCHING ──────────────────────────────────────────────────
        function switchTab(tab) {
            activeTab = tab;
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
            document.getElementById('tab-' + tab).classList.add('active');
            document.getElementById('nav-' + tab).classList.add('active');

            if (tab === 'discovery') { loadSweepHistory(); }
            if (tab === 'schedules') { loadSchedules(); }
            if (tab === 'insights') { loadInsights(); }
            if (tab === 'topology') { setTimeout(loadTopology, 50); }
            if (tab === 'pentest') { loadPentestTab(); }
        }

        // ── AUTH ───────────────────────────────────────────────────────────
        function submitLogin() {
            const username = document.getElementById("loginUsername").value;
            const password = document.getElementById("loginPassword").value;
            if (!username || !password) return;
            authCredentials = 'Basic ' + btoa(username + ':' + password);
            fetch('/agents', { headers: { 'Authorization': authCredentials } }).then(res => {
                if (res.status === 401) {
                    authCredentials = "";
                    document.getElementById("loginError").classList.remove('hidden');
                } else {
                    document.getElementById("loginOverlay").classList.add('hidden');
                    loadAll();
                    loadServerSettings();
                    loadJobTypes();
                }
            });
        }
        document.getElementById("loginPassword").addEventListener('keydown', e => { if (e.key === 'Enter') submitLogin(); });
        document.getElementById("loginUsername").addEventListener('keydown', e => { if (e.key === 'Enter') submitLogin(); });

        async function apiFetch(url, options = {}) {
            options.headers = { ...options.headers, 'Authorization': authCredentials };
            const res = await fetch(url, options);
            if (res.status === 401) {
                authCredentials = "";
                document.getElementById("loginOverlay").classList.remove('hidden');
                return null;
            }
            return res;
        }

        // ── DIALOGS ────────────────────────────────────────────────────────
        function showConfirm(message, onConfirm, okLabel = 'Confirm') {
            document.getElementById("confirmMsg").textContent = message;
            document.getElementById("confirmOkBtn").textContent = okLabel;
            document.getElementById("confirmDialog").classList.remove('hidden');
            document.getElementById("confirmOkBtn").onclick = () => {
                document.getElementById("confirmDialog").classList.add('hidden');
                if (onConfirm) onConfirm();
            };
        }
        function cancelConfirm() { document.getElementById("confirmDialog").classList.add('hidden'); }

        function showExploitWarning(onConfirm) {
            exploitWarningCallback = onConfirm;
            document.getElementById("exploitWarningDialog").classList.remove('hidden');
        }
        function cancelExploitWarning() { document.getElementById("exploitWarningDialog").classList.add('hidden'); exploitWarningCallback = null; }
        function confirmExploitWarning() { document.getElementById("exploitWarningDialog").classList.add('hidden'); if (exploitWarningCallback) exploitWarningCallback(); }

        // ── LOAD ALL ───────────────────────────────────────────────────────
        async function loadAll() {
            loadAgents();
            loadJobs();
            loadResults();
            if (activeTab === 'discovery') loadSweepHistory();
            if (activeTab === 'schedules') loadSchedules();
        }

        // ── JOB TYPE CHANGE ────────────────────────────────────────────────
        function onJobTypeChange() {
            const type = document.getElementById("job_type").value;
            document.getElementById("portField").style.display = type === "nikto_scan" ? "flex" : "none";
            document.getElementById("portsField").style.display = type === "nse_scan" ? "flex" : "none";
            // Hide ports field when custom profile is active (port derivation is automatic)
            if (type === 'nse_scan' && document.getElementById('profile').value === 'custom') {
                document.getElementById("portsField").style.display = "none";
            }
            // Update target placeholder — Nikto accepts URLs, nmap/nse do not
            const targetInput = document.getElementById('target');
            if (targetInput) {
                targetInput.placeholder = type === 'nikto_scan' ? 'IP, hostname, or URL' : 'IP or hostname';
            }
            renderPluginFieldsForCreateJob(type);
            updateNseExploitBanner();
            onProfileChange();
        }
        function dismissExploitBanner() {
            exploitBannerDismissed = true;
            document.getElementById('nseExploitBanner').classList.add('hidden');
        }
        function updateNseExploitBanner() {
            const type = document.getElementById("job_type").value;
            const profile = document.getElementById("profile").value;
            const should  = type === "nse_scan" && profile === "full";
            if (!should || exploitBannerDismissed) {
                document.getElementById('nseExploitBanner').classList.add('hidden');
            } else {
                document.getElementById('nseExploitBanner').classList.remove('hidden');
            }
        }
        
        // ── CUSTOM PROFILE CAPABILITY DATA ────────────────────────────────────
        const CUSTOM_CAPABILITIES = [
            {
                id: "auth",
                label: "Authentication & Access Control",
                tooltip: "Checks for anonymous access, weak auth methods, and insecure credential handling across common services.",
                scripts: [
                    { id: "ftp-anon",               label: "FTP Anonymous",          desc: "Checks if the FTP server allows anonymous login.",                                     default: true  },
                    { id: "http-auth-finder",        label: "HTTP Auth Finder",       desc: "Discovers HTTP authentication methods in use (Basic, Digest, NTLM, etc.).",           default: true  },
                    { id: "ssh-auth-methods",        label: "SSH Auth Methods",       desc: "Lists authentication methods accepted by the SSH server.",                             default: true  },
                    { id: "snmp-brute",              label: "SNMP Brute",             desc: "Attempts to guess SNMP community strings using default values only.",                  default: true  },
                    { id: "smb-security-mode",       label: "SMB Security Mode",      desc: "Reports whether SMB message signing and plaintext auth are in use.",                   default: true  },
                    { id: "http-open-proxy",         label: "HTTP Open Proxy",        desc: "Tests whether the HTTP server is acting as an open proxy.",                            default: false },
                    { id: "irc-unrealircd-backdoor", label: "UnrealIRCd Backdoor",    desc: "Checks for the UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075).",                        default: false },
                ],
            },
            {
                id: "smb",
                label: "Windows & SMB Enumeration",
                tooltip: "Enumerates Windows host information, SMB shares, and checks for critical SMB vulnerabilities including EternalBlue.",
                scripts: [
                    { id: "smb-os-discovery",   label: "OS Discovery",       desc: "Attempts to determine the OS, computer name, domain, and workgroup via SMB.",    default: true  },
                    { id: "smb-system-info",    label: "System Info",        desc: "Retrieves system information from the SMB server (OS version, build, etc.).",   default: true  },
                    { id: "smb-enum-shares",    label: "Enum Shares",        desc: "Enumerates SMB shares and their access permissions.",                            default: true  },
                    { id: "smb-security-mode",  label: "Security Mode",      desc: "Reports whether SMB signing is enabled and if plaintext passwords are used.",   default: true  },
                    { id: "smb-vuln-ms17-010",  label: "EternalBlue",        desc: "Checks for MS17-010 (EternalBlue) — the vulnerability exploited by WannaCry.", default: true  },
                    { id: "smb-vuln-ms10-054",  label: "MS10-054",           desc: "Checks for MS10-054, a remote memory corruption vulnerability in SMBv1.",       default: true  },
                    { id: "smb-enum-users",     label: "Enum Users",         desc: "Enumerates local user accounts via SMB (may require credentials).",             default: false },
                    { id: "smb-enum-groups",    label: "Enum Groups",        desc: "Enumerates local groups via SMB (may require credentials).",                    default: false },
                    { id: "smb-enum-sessions",  label: "Enum Sessions",      desc: "Lists active SMB sessions on the server.",                                      default: false },
                    { id: "smb-enum-domains",   label: "Enum Domains",       desc: "Enumerates domains visible through SMB.",                                       default: false },
                ],
            },
            {
                id: "snmp",
                label: "SNMP & Network Device Enumeration",
                tooltip: "Queries SNMP-enabled devices for system information, interface details, and running processes.",
                scripts: [
                    { id: "snmp-info",          label: "SNMP Info",          desc: "Retrieves basic system info from SNMP (sysDescr, sysUpTime, etc.).",            default: true  },
                    { id: "snmp-sysdescr",      label: "System Description", desc: "Fetches the SNMP sysDescr OID — often reveals OS and firmware version.",       default: true  },
                    { id: "snmp-interfaces",    label: "Interfaces",         desc: "Lists network interfaces and their IP addresses via SNMP.",                     default: true  },
                    { id: "snmp-netstat",       label: "Netstat",            desc: "Retrieves the TCP/UDP connection table via SNMP.",                              default: false },
                    { id: "snmp-processes",     label: "Processes",          desc: "Lists running processes on the target via SNMP.",                               default: false },
                    { id: "snmp-win32-users",   label: "Win32 Users",        desc: "Enumerates Windows local user accounts via SNMP (Windows targets only).",      default: false },
                    { id: "snmp-win32-shares",  label: "Win32 Shares",       desc: "Lists Windows file shares via SNMP (Windows targets only).",                   default: false },
                ],
            },
            {
                id: "ssl",
                label: "SSL/TLS Analysis",
                tooltip: "Analyses SSL/TLS configuration for weak ciphers, expired certificates, and known protocol vulnerabilities.",
                scripts: [
                    { id: "ssl-cert",           label: "Certificate",        desc: "Retrieves and displays the server's SSL certificate details.",                  default: true  },
                    { id: "ssl-enum-ciphers",   label: "Cipher Suites",      desc: "Enumerates supported SSL/TLS cipher suites and grades their strength.",        default: true  },
                    { id: "ssl-heartbleed",     label: "Heartbleed",         desc: "Tests for the OpenSSL Heartbleed vulnerability (CVE-2014-0160).",              default: true  },
                    { id: "ssl-poodle",         label: "POODLE",             desc: "Checks for the POODLE vulnerability in SSLv3 (CVE-2014-3566).",               default: true  },
                    { id: "ssl-dh-params",      label: "DH Parameters",      desc: "Checks Diffie-Hellman parameters for weaknesses (Logjam vulnerability).",      default: true  },
                    { id: "ssl-ccs-injection",  label: "CCS Injection",      desc: "Tests for the OpenSSL CCS Injection vulnerability (CVE-2014-0224).",          default: true  },
                    { id: "tls-ticketbleed",    label: "Ticketbleed",        desc: "Checks for the Ticketbleed vulnerability in F5 TLS session tickets.",          default: false },
                    { id: "ssl-known-key",      label: "Known Key",          desc: "Checks whether the SSL key is in a known-compromised key database.",           default: false },
                ],
            },
            {
                id: "discovery",
                label: "Network Service Discovery",
                tooltip: "Probes common network services for misconfigurations — DNS zone transfers, NFS exports, RDP settings, and more.",
                scripts: [
                    { id: "dns-zone-transfer",       label: "DNS Zone Transfer",  desc: "Attempts a DNS zone transfer — reveals all DNS records if misconfigured.",    default: true  },
                    { id: "dns-recursion",           label: "DNS Recursion",      desc: "Checks if the DNS server allows recursive queries (open resolver).",          default: true  },
                    { id: "nfs-ls",                  label: "NFS List",           desc: "Lists files on NFS exports accessible without authentication.",               default: true  },
                    { id: "nfs-showmount",           label: "NFS Showmount",      desc: "Shows the NFS server's export list.",                                        default: true  },
                    { id: "rdp-enum-encryption",     label: "RDP Encryption",     desc: "Enumerates RDP security settings and supported encryption protocols.",        default: true  },
                    { id: "telnet-encryption",       label: "Telnet Encryption",  desc: "Checks whether Telnet is offering encryption (rare — usually it isn't).",    default: true  },
                    { id: "vnc-info",                label: "VNC Info",           desc: "Retrieves VNC server information including protocol version and auth type.",  default: true  },
                    { id: "finger",                  label: "Finger",             desc: "Queries the finger service to enumerate user accounts.",                      default: false },
                    { id: "broadcast-dhcp-discover", label: "DHCP Discover",      desc: "Sends a broadcast DHCP discover packet to identify DHCP servers.",           default: false },
                    { id: "ldap-rootdse",            label: "LDAP Root DSE",      desc: "Retrieves the LDAP root DSE entry — reveals domain and server info.",        default: false },
                ],
            },
        ];

        // ── CUSTOM PROFILE STATE ───────────────────────────────────────────────
        // capabilityState[capId][scriptId] = true/false
        // Tracks individual script toggles independently of the top-level toggle.
        let capabilityState = {};

        function initCapabilityState() {
            capabilityState = {};
            CUSTOM_CAPABILITIES.forEach(cap => {
                capabilityState[cap.id] = {};
                cap.scripts.forEach(s => {
                    capabilityState[cap.id][s.id] = false;
                });
            });
        }

        function isCapabilityOn(capId) {
            // A capability is "on" if at least one script in it is checked
            return Object.values(capabilityState[capId] || {}).some(v => v);
        }

        function areAllScriptsOn(capId) {
            return Object.values(capabilityState[capId] || {}).every(v => v);
        }

        function getSelectedScripts() {
            const selected = [];
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => {
                    if (capabilityState[cap.id] && capabilityState[cap.id][s.id]) {
                        selected.push(s.id);
                    }
                });
            });
            return [...new Set(selected)];
        }

        function updateScriptCount() {
            const n = getSelectedScripts().length;
            const el = document.getElementById('customScriptCount');
            if (el) el.textContent = n === 1 ? '1 script selected' : `${n} scripts selected`;
        }

        // ── CAPABILITY CARD RENDERING ──────────────────────────────────────────

        function renderCapabilityCards() {
            const container = document.getElementById('capabilityCards');
            if (!container) return;

            container.innerHTML = CUSTOM_CAPABILITIES.map(cap => {
                const capOn = isCapabilityOn(cap.id);
                const allOn = areAllScriptsOn(cap.id);

                // Top-level toggle state
                const toggleBg    = allOn ? 'bg-green-600 border-green-500' : (capOn ? 'bg-green-900 border-green-700' : 'bg-gray-700 border-gray-600');
                const toggleKnob  = (allOn || capOn) ? 'translate-x-5' : 'translate-x-0';
                const knobColor   = (allOn || capOn) ? 'bg-white' : 'bg-gray-400';

                // Script rows (collapsed by default)
                const scriptRows = cap.scripts.map(s => {
                    const checked = capabilityState[cap.id][s.id];
                    const defaultTag = s.default
                        ? ''
                        : '<span class="ml-1.5 text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-600 border border-gray-700 font-mono leading-none">sensitive</span>';
                    return `
                    <div class="flex items-center justify-between py-1.5 border-b border-gray-800 last:border-0 group">
                        <div class="flex items-center gap-2 min-w-0">
                            <span class="text-xs text-gray-300 font-mono truncate" title="${escHtmlAttr(s.desc)}">${s.label}</span>
                            ${defaultTag}
                            <span class="hidden group-hover:inline text-xs text-gray-600 ml-1 truncate">${escHtmlAttr(s.desc)}</span>
                        </div>
                        <button
                            onclick="toggleScript('${cap.id}', '${s.id}')"
                            id="script-toggle-${cap.id}-${s.id}"
                            class="flex-shrink-0 ml-3 relative w-8 h-4 rounded-full transition-colors duration-150 focus:outline-none ${checked ? 'bg-green-600 border border-green-500' : 'bg-gray-700 border border-gray-600'}"
                            title="${escHtmlAttr(s.desc)}">
                            <span class="absolute top-0.5 left-0.5 w-3 h-3 rounded-full transition-transform duration-150 ${checked ? 'bg-white translate-x-4' : 'bg-gray-400 translate-x-0'}"></span>
                        </button>
                    </div>`;
                }).join('');

                return `
                <div class="capability-card bg-gray-800 border border-gray-700 rounded-xl overflow-hidden" id="cap-card-${cap.id}">

                    <!-- Card header: top-level toggle + label + expand -->
                    <div class="flex items-center gap-3 px-4 py-3">
                        <!-- Top-level capability toggle -->
                        <button
                            onclick="toggleCapability('${cap.id}')"
                            id="cap-toggle-${cap.id}"
                            class="flex-shrink-0 relative w-10 h-5 rounded-full transition-colors duration-150 focus:outline-none border ${toggleBg}"
                            title="${escHtmlAttr(cap.tooltip)}">
                            <span class="absolute top-0.5 left-0.5 w-4 h-4 rounded-full transition-transform duration-150 ${knobColor} ${toggleKnob}"></span>
                        </button>

                        <!-- Label + tooltip -->
                        <div class="flex-1 min-w-0 cursor-pointer" onclick="expandCapability('${cap.id}')" title="${escHtmlAttr(cap.tooltip)}">
                            <span class="text-sm font-medium text-gray-200">${cap.label}</span>
                            <span class="ml-2 text-xs text-gray-600">${Object.values(capabilityState[cap.id]).filter(v => v).length}/${cap.scripts.length} scripts</span>
                        </div>

                        <!-- Expand/collapse chevron -->
                        <button onclick="expandCapability('${cap.id}')" class="text-gray-600 hover:text-gray-400 transition text-xs flex-shrink-0 px-1" id="cap-chevron-${cap.id}">▼</button>
                    </div>

                    <!-- Collapsible script list -->
                    <div id="cap-scripts-${cap.id}" class="hidden px-4 pb-3 border-t border-gray-700 pt-3">
                        ${scriptRows}
                    </div>
                </div>`;
            }).join('');

            updateScriptCount();
        }

        function escHtmlAttr(s) {
            return String(s || '').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        // ── CAPABILITY INTERACTIONS ────────────────────────────────────────────

        function toggleCapability(capId) {
            const cap = CUSTOM_CAPABILITIES.find(c => c.id === capId);
            if (!cap) return;

            const allOn = areAllScriptsOn(capId);

            if (allOn) {
                // All on → turn all off
                cap.scripts.forEach(s => { capabilityState[capId][s.id] = false; });
            } else {
                // Some or none on → turn all defaults on
                // (if already had some on, turn ALL on; if fresh toggle, use defaults)
                const anyOn = isCapabilityOn(capId);
                cap.scripts.forEach(s => {
                    capabilityState[capId][s.id] = anyOn ? true : s.default;
                });
            }

            renderCapabilityCards();
        }

        function toggleScript(capId, scriptId) {
            if (capabilityState[capId] === undefined) return;
            capabilityState[capId][scriptId] = !capabilityState[capId][scriptId];
            renderCapabilityCards();
            // Keep the script list open after toggling
            const scriptsEl = document.getElementById(`cap-scripts-${capId}`);
            if (scriptsEl) scriptsEl.classList.remove('hidden');
            const chevron = document.getElementById(`cap-chevron-${capId}`);
            if (chevron) chevron.textContent = '▲';
        }

        function expandCapability(capId) {
            const scriptsEl = document.getElementById(`cap-scripts-${capId}`);
            const chevron   = document.getElementById(`cap-chevron-${capId}`);
            if (!scriptsEl) return;
            const isHidden = scriptsEl.classList.contains('hidden');
            scriptsEl.classList.toggle('hidden', !isHidden);
            if (chevron) chevron.textContent = isHidden ? '▲' : '▼';
        }

        function selectAllCapabilities() {
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => { capabilityState[cap.id][s.id] = true; });
            });
            renderCapabilityCards();
        }

        function clearAllCapabilities() {
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => { capabilityState[cap.id][s.id] = false; });
            });
            renderCapabilityCards();
        }
        
        // ── SWEEP DIALOG: CUSTOM CAPABILITY STATE ─────────────────────────────
        // Separate state from the Create Job panel — the sweep dialog has its
        // own independent capability selections.
        let sweepCapabilityState = {};

        function initSweepCapabilityState() {
            sweepCapabilityState = {};
            CUSTOM_CAPABILITIES.forEach(cap => {
                sweepCapabilityState[cap.id] = {};
                cap.scripts.forEach(s => {
                    sweepCapabilityState[cap.id][s.id] = false;
                });
            });
        }

        function getSweepSelectedScripts() {
            const selected = [];
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => {
                    if (sweepCapabilityState[cap.id] && sweepCapabilityState[cap.id][s.id]) {
                        selected.push(s.id);
                    }
                });
            });
            return selected;
        }

        function updateSweepScriptCount() {
            const n = getSweepSelectedScripts().length;
            const el = document.getElementById('sweepScriptCount');
            if (el) el.textContent = n === 1 ? '1 script selected' : `${n} scripts selected`;
        }

        function isSweepCapabilityOn(capId) {
            return Object.values(sweepCapabilityState[capId] || {}).some(v => v);
        }

        function areAllSweepScriptsOn(capId) {
            return Object.values(sweepCapabilityState[capId] || {}).every(v => v);
        }

        function renderSweepCapabilityCards() {
            const container = document.getElementById('sweepCapabilityCards');
            if (!container) return;

            container.innerHTML = CUSTOM_CAPABILITIES.map(cap => {
                const capOn = isSweepCapabilityOn(cap.id);
                const allOn = areAllSweepScriptsOn(cap.id);

                const toggleBg   = allOn ? 'bg-green-600 border-green-500' : (capOn ? 'bg-green-900 border-green-700' : 'bg-gray-700 border-gray-600');
                const toggleKnob = (allOn || capOn) ? 'translate-x-5' : 'translate-x-0';
                const knobColor  = (allOn || capOn) ? 'bg-white' : 'bg-gray-400';

                const scriptRows = cap.scripts.map(s => {
                    const checked = sweepCapabilityState[cap.id][s.id];
                    const defaultTag = s.default ? '' : '<span class="ml-1.5 text-xs px-1 py-0.5 rounded bg-gray-800 text-gray-600 border border-gray-700 font-mono leading-none">sensitive</span>';
                    return `
                    <div class="flex items-center justify-between py-1 border-b border-gray-800 last:border-0">
                        <span class="text-xs text-gray-300 font-mono" title="${escHtmlAttr(s.desc)}">${s.label}${defaultTag}</span>
                        <button
                            onclick="toggleSweepScript('${cap.id}', '${s.id}')"
                            class="flex-shrink-0 ml-2 relative w-7 h-3.5 rounded-full transition-colors duration-150 focus:outline-none border ${checked ? 'bg-green-600 border-green-500' : 'bg-gray-700 border-gray-600'}">
                            <span class="absolute top-0.5 left-0.5 w-2.5 h-2.5 rounded-full transition-transform duration-150 ${checked ? 'bg-white translate-x-3' : 'bg-gray-400 translate-x-0'}"></span>
                        </button>
                    </div>`;
                }).join('');

                const selectedCount = Object.values(sweepCapabilityState[cap.id]).filter(v => v).length;

                return `
                <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                    <div class="flex items-center gap-2 px-3 py-2">
                        <button onclick="toggleSweepCapability('${cap.id}')"
                            class="flex-shrink-0 relative w-9 h-4.5 rounded-full transition-colors duration-150 focus:outline-none border ${toggleBg}"
                            style="width:2.25rem;height:1.25rem"
                            title="${escHtmlAttr(cap.tooltip)}">
                            <span class="absolute top-0.5 left-0.5 w-3.5 h-3.5 rounded-full transition-transform duration-150 ${knobColor} ${toggleKnob}" style="width:0.875rem;height:0.875rem"></span>
                        </button>
                        <div class="flex-1 min-w-0 cursor-pointer" onclick="expandSweepCapability('${cap.id}')">
                            <span class="text-xs font-medium text-gray-200">${cap.label}</span>
                            <span class="ml-2 text-xs text-gray-600">${selectedCount}/${cap.scripts.length}</span>
                        </div>
                        <button onclick="expandSweepCapability('${cap.id}')" class="text-gray-600 hover:text-gray-400 transition text-xs" id="sweep-chevron-${cap.id}">▼</button>
                    </div>
                    <div id="sweep-scripts-${cap.id}" class="hidden px-3 pb-2 border-t border-gray-700 pt-2">
                        ${scriptRows}
                    </div>
                </div>`;
            }).join('');

            updateSweepScriptCount();
        }

        function toggleSweepCapability(capId) {
            const cap = CUSTOM_CAPABILITIES.find(c => c.id === capId);
            if (!cap) return;
            const allOn = areAllSweepScriptsOn(capId);
            if (allOn) {
                cap.scripts.forEach(s => { sweepCapabilityState[capId][s.id] = false; });
            } else {
                const anyOn = isSweepCapabilityOn(capId);
                cap.scripts.forEach(s => {
                    sweepCapabilityState[capId][s.id] = anyOn ? true : s.default;
                });
            }
            renderSweepCapabilityCards();
        }

        function toggleSweepScript(capId, scriptId) {
            if (!sweepCapabilityState[capId]) return;
            sweepCapabilityState[capId][scriptId] = !sweepCapabilityState[capId][scriptId];
            renderSweepCapabilityCards();
            // Keep expanded after toggle
            const el = document.getElementById(`sweep-scripts-${capId}`);
            if (el) el.classList.remove('hidden');
            const chevron = document.getElementById(`sweep-chevron-${capId}`);
            if (chevron) chevron.textContent = '▲';
        }

        function expandSweepCapability(capId) {
            const el      = document.getElementById(`sweep-scripts-${capId}`);
            const chevron = document.getElementById(`sweep-chevron-${capId}`);
            if (!el) return;
            const isHidden = el.classList.contains('hidden');
            el.classList.toggle('hidden', !isHidden);
            if (chevron) chevron.textContent = isHidden ? '▲' : '▼';
        }

        function sweepSelectAll() {
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => { sweepCapabilityState[cap.id][s.id] = true; });
            });
            renderSweepCapabilityCards();
        }

        function sweepClearAll() {
            CUSTOM_CAPABILITIES.forEach(cap => {
                cap.scripts.forEach(s => { sweepCapabilityState[cap.id][s.id] = false; });
            });
            renderSweepCapabilityCards();
        }

        // ── SWEEP DIALOG: TYPE/PROFILE CHANGE HANDLERS ────────────────────────

        function onSweepJobTypeChange() {
            onSweepProfileChange();
            updateSweepConfirmNote();
        }

        function onSweepProfileChange() {
            const type    = document.getElementById('sweepJobType').value;
            const profile = document.getElementById('sweepProfile').value;
            const isCustom = type === 'nse_scan' && profile === 'custom';
            const isFull   = type === 'nse_scan' && profile === 'full';

            // Custom profile panel
            const customPanel = document.getElementById('sweepCustomPanel');
            if (customPanel) {
                customPanel.classList.toggle('hidden', !isCustom);
                if (isCustom && Object.keys(sweepCapabilityState).length === 0) {
                    initSweepCapabilityState();
                    renderSweepCapabilityCards();
                }
            }

            // Custom option only meaningful for nse_scan — disable it for other types
            const profileSel = document.getElementById('sweepProfile');
            const customOpt  = profileSel ? profileSel.querySelector('option[value="custom"]') : null;
            if (customOpt) {
                customOpt.disabled = type !== 'nse_scan';
                // If switching away from nse_scan while custom is selected, revert to standard
                if (type !== 'nse_scan' && profile === 'custom') {
                    profileSel.value = 'standard';
                }
            }

            // Full + Vulnerability Scanintrusive warning
            const fullWarn = document.getElementById('sweepFullWarning');
            if (fullWarn) fullWarn.classList.toggle('hidden', !isFull);

            updateSweepConfirmNote();
        }

        function updateSweepConfirmNote() {
            const type    = document.getElementById('sweepJobType')?.value || 'nmap_scan';
            const profile = document.getElementById('sweepProfile')?.value || 'standard';
            const label   = SCAN_TYPE_LABELS[type] || type;
            const note    = document.getElementById('sweepConfirmNote');
            if (!note) return;
            const profileLabel = profile === 'custom' ? 'Custom' : profile.charAt(0).toUpperCase() + profile.slice(1);
            note.textContent = `Confirming will create a ${profileLabel} ${label} job for each host above.`;
        }

        // ── NIKTO CUSTOM PROFILE ───────────────────────────────────────────
        const NIKTO_CATEGORIES = [
            { id: '0', label: 'File Upload',                  desc: 'Tests for arbitrary file upload vulnerabilities.' },
            { id: '1', label: 'Interesting Files',            desc: 'Looks for files commonly seen in server logs or left by developers.' },
            { id: '2', label: 'Misconfiguration',             desc: 'Checks for default files, default credentials, and misconfigurations.' },
            { id: '3', label: 'Information Disclosure',       desc: 'Identifies responses that leak server or application information.' },
            { id: '4', label: 'Injection (XSS/HTML/Script)',  desc: 'Tests for cross-site scripting and script/HTML injection.' },
            { id: '5', label: 'Remote File Retrieval (Web)',  desc: 'Attempts to retrieve files from inside the web root.' },
            { id: '6', label: 'Denial of Service',            desc: 'Tests for DoS vectors — use with caution in production.' },
            { id: '7', label: 'Remote File Retrieval (Wide)', desc: 'Attempts to retrieve files from anywhere on the server.' },
            { id: '8', label: 'Command Execution',            desc: 'Tests for remote command execution and shell upload vectors.' },
            { id: '9', label: 'SQL Injection',                desc: 'Tests for SQL injection vulnerabilities in parameters.' },
            { id: 'a', label: 'Authentication Bypass',        desc: 'Checks for authentication bypass and weak credential issues.' },
            { id: 'b', label: 'Software Identification',      desc: 'Identifies server software, CMS, and framework versions.' },
            { id: 'c', label: 'Remote Source Inclusion',      desc: 'Tests for remote file/source inclusion vulnerabilities.' },
            { id: 'x', label: 'Reverse Tuning',               desc: 'Run all test categories EXCEPT those additionally selected.' },
        ];

        // Default: all enabled except DoS (6) and Reverse Tuning (x)
        let niktoCategoryState = {};
        function initNiktoCategoryState() {
            niktoCategoryState = {};
            NIKTO_CATEGORIES.forEach(c => {
                niktoCategoryState[c.id] = (c.id !== '6' && c.id !== 'x');
            });
        }

        function renderNiktoCategoryCards() {
            const container = document.getElementById('niktoCategoryCards');
            if (!container) return;
            container.innerHTML = NIKTO_CATEGORIES.map(c => {
                const checked = niktoCategoryState[c.id];
                const danger  = c.id === '6';
                const border  = checked ? (danger ? 'border-red-600' : 'border-purple-600') : 'border-gray-700';
                const bg      = checked ? (danger ? 'bg-red-950' : 'bg-gray-800') : 'bg-gray-900';
                return `<div class="rounded-lg border ${border} ${bg} p-3 transition cursor-pointer" onclick="toggleNiktoCategory('${c.id}')">
                    <div class="flex items-start gap-2">
                        <input type="checkbox" ${checked ? 'checked' : ''} onchange="toggleNiktoCategory('${c.id}')" onclick="event.stopPropagation()" class="mt-0.5 accent-purple-500 flex-shrink-0">
                        <div>
                            <p class="text-xs font-medium text-gray-200">${c.label} <span class="text-gray-600 font-mono">[${c.id}]</span></p>
                            <p class="text-xs text-gray-500 mt-0.5">${c.desc}</p>
                        </div>
                    </div>
                </div>`;
            }).join('');
            updateNiktoCategoryCount();
        }

        function toggleNiktoCategory(id) {
            niktoCategoryState[id] = !niktoCategoryState[id];
            renderNiktoCategoryCards();
        }

        function updateNiktoCategoryCount() {
            const count = Object.values(niktoCategoryState).filter(Boolean).length;
            const el = document.getElementById('niktoCategoryCount');
            if (el) el.textContent = `${count} categor${count === 1 ? 'y' : 'ies'} selected`;
        }

        function getSelectedNiktoCategories() {
            return NIKTO_CATEGORIES.filter(c => niktoCategoryState[c.id]).map(c => c.id);
        }

        function selectAllNiktoCategories() {
            NIKTO_CATEGORIES.forEach(c => { niktoCategoryState[c.id] = true; });
            renderNiktoCategoryCards();
        }

        function clearAllNiktoCategories() {
            NIKTO_CATEGORIES.forEach(c => { niktoCategoryState[c.id] = false; });
            renderNiktoCategoryCards();
        }

        // ── PROFILE CHANGE HANDLER (replaces/extends existing) ────────────────
        // Note: the existing profile select doesn't have onchange — we add it above.
        // This function is called from onJobTypeChange() too for the banner check.

        function onProfileChange() {
            const type    = document.getElementById('job_type').value;
            const profile = document.getElementById('profile').value;
            const isCustomNse   = profile === 'custom' && type === 'nse_scan';
            const isCustomNikto = profile === 'custom' && type === 'nikto_scan';

            // Show/hide NSE custom panel
            const panel = document.getElementById('customProfilePanel');
            if (panel) {
                panel.classList.toggle('hidden', !isCustomNse);
                if (isCustomNse && Object.keys(capabilityState).length === 0) {
                    initCapabilityState();
                    renderCapabilityCards();
                }
            }

            // Show/hide Nikto custom panel
            const niktoPanel = document.getElementById('niktoCustomPanel');
            if (niktoPanel) {
                niktoPanel.classList.toggle('hidden', !isCustomNikto);
                if (isCustomNikto && Object.keys(niktoCategoryState).length === 0) {
                    initNiktoCategoryState();
                    renderNiktoCategoryCards();
                }
            }

            // Hide exploit banner when switching to custom
            if (profile === 'custom') {
                document.getElementById('nseExploitBanner').classList.add('hidden');
            } else {
                updateNseExploitBanner();
            }
        }
        
        // ── JOB FILTERS ────────────────────────────────────────────────────
        function setJobFilter(filter) {
            jobFilter = filter;
            pages.jobs = 1;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active-filter', 'border-green-500', 'text-green-400'));
            const active = document.getElementById('filter-' + filter);
            if (active) active.classList.add('active-filter', 'border-green-500', 'text-green-400');
            renderJobs();
        }
        function toggleJobHistory() {
            showJobHistory = !showJobHistory;
            document.getElementById("jobHistoryBtn").innerText = showJobHistory ? "Hide History" : "Show History";
            document.getElementById("jobHistoryBtn").classList.toggle('border-purple-500');
            document.getElementById("jobHistoryBtn").classList.toggle('text-purple-400');
            loadJobs();
        }
        function toggleStaleAgents() {
            showStaleAgents = !showStaleAgents;
            const btn = document.getElementById("staleAgentsBtn");
            btn.innerText = showStaleAgents ? "Hide Stale" : "Show Stale";
            btn.classList.toggle('border-yellow-500');
            btn.classList.toggle('text-yellow-400');
            loadAgents();
        }

        // ── RESULT TABS ────────────────────────────────────────────────────
        function setResultTab(tab) {
            resultTab = tab;
            pages.results = 1;
            document.querySelectorAll('.result-tab').forEach(b => { b.classList.remove('bg-gray-700', 'text-white'); b.classList.add('text-gray-400'); });
            document.getElementById('tab-' + tab).classList.add('bg-gray-700', 'text-white');
            document.getElementById('tab-' + tab).classList.remove('text-gray-400');
            document.getElementById('historyToolbar').classList.toggle('hidden', tab !== 'history');
            document.getElementById('activeToolbar').classList.toggle('hidden', tab === 'history');
            document.getElementById('selectAllCheckbox').checked = false;
            document.getElementById('selectAllActiveCheckbox').checked = false;
            loadResults();
        }
        function toggleSelectAll() {
            const checked = document.getElementById('selectAllCheckbox').checked;
            document.querySelectorAll('.result-checkbox').forEach(cb => cb.checked = checked);
        }
        function toggleSelectAllActive() {
            const checked = document.getElementById('selectAllActiveCheckbox').checked;
            document.querySelectorAll('.result-checkbox').forEach(cb => cb.checked = checked);
        }
        function getSelectedIds() {
            return Array.from(document.querySelectorAll('.result-checkbox:checked')).map(cb => parseInt(cb.dataset.id));
        }

        async function clearSelected() {
            const ids = getSelectedIds();
            if (!ids.length) { alert("No results selected."); return; }
            showConfirm(`Clear ${ids.length} result(s)? They will move to History.`, async () => {
                await Promise.all(ids.map(id => apiFetch(`/results/${id}/clear`, { method: 'POST' })));
                document.getElementById('selectAllActiveCheckbox').checked = false;
                loadResults(); loadJobs();
            }, 'Clear');
        }
        async function deleteSelected() {
            const ids = getSelectedIds();
            if (!ids.length) { alert("No results selected."); return; }
            showConfirm(`Permanently delete ${ids.length} result(s) and their jobs? This cannot be undone.`, async () => {
                await apiFetch('/results/bulk', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) });
                document.getElementById('selectAllCheckbox').checked = false;
                loadResults(); loadJobs();
            }, 'Delete');
        }
        async function clearAllHistory() {
            showConfirm('Permanently delete ALL archived results and their jobs? This cannot be undone.', async () => {
                const res = await apiFetch('/results/clear-all-history', { method: 'DELETE' });
                if (!res) return;
                const data = await res.json();
                loadResults(); loadJobs();
            }, 'Clear All');
        }

        async function exportResults() {
            const selectedIds = getSelectedIds();
            const isHistory = resultTab === 'history';
            const url = isHistory ? '/results?show_history=true' : '/results';
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
            const toExport = selectedIds.length ? data.filter(r => selectedIds.includes(r.id)) : data;
            if (!toExport.length) { alert("No results to export."); return; }
            const exportDoc = {
                exported_at: new Date().toISOString(),
                source: "Heimdall V-Scanner",
                tab: resultTab,
                total: toExport.length,
                results: toExport.map(r => ({
                    result_id: r.id,
                    job: r.job_info ? { target: r.job_info.target, type: r.job_info.type, mode: r.job_info.mode, profile: r.job_info.profile, priority: r.job_info.priority, completed_at: r.job_info.completed_at } : { job_id: r.job_id },
                    nmap: r.output.nmap || null,
                    nikto: r.output.nikto || null,
                    nse: r.output.nse || null,
                }))
            };
            const blob = new Blob([JSON.stringify(exportDoc, null, 2)], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `heimdall-export-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.json`;
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            URL.revokeObjectURL(a.href);
        }

        // ── BADGES ─────────────────────────────────────────────────────────
        function statusBadge(status) {
            const map = { pending: 'bg-yellow-900 text-yellow-300 border border-yellow-700', running: 'bg-blue-900 text-blue-300 border border-blue-700', done: 'bg-green-900 text-green-300 border border-green-700', failed: 'bg-red-900 text-red-300 border border-red-700' };
            return `<span class="text-xs px-2 py-0.5 rounded-full font-medium ${map[status] || 'bg-gray-700 text-gray-300'}">${status}</span>`;
        }
        function priorityBadge(priority) {
            const map = { high: 'text-red-400', medium: 'text-yellow-400', low: 'text-gray-400' };
            return `<span class="text-xs font-medium ${map[priority] || 'text-gray-400'}">${priority}</span>`;
        }
        function formatTimestamp(ts) {
            if (!ts) return '—';
            const normalized = ts.endsWith('Z') ? ts : ts + 'Z';
            const d = new Date(normalized);
            return `${d.toISOString().split('T')[0]} at ${d.toTimeString().split(' ')[0]}`;
        }
        function relativeTime(ts) {
            if (!ts) return '';
            const normalized = ts.endsWith('Z') ? ts : ts + 'Z';
            const diff = Math.floor((Date.now() - new Date(normalized).getTime()) / 1000);
            if (diff < 60)    return 'just now';
            if (diff < 3600)  return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            return Math.floor(diff / 86400) + 'd ago';
        }
        function elapsedDisplay(startedAt) {
            if (!startedAt) return 'running…';
            const ts = startedAt.endsWith('Z') ? startedAt : startedAt + 'Z';
            const secs = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
            if (secs < 60) return `${secs}s elapsed`;
            return `${Math.floor(secs / 60)}m ${secs % 60}s elapsed`;
        }

        setInterval(() => {
            document.querySelectorAll('[id^="job-time-"]').forEach(cell => {
                const startedAt = cell.dataset.startedAt;
                if (!startedAt) return;
                const statusCell = cell.closest('tr')?.querySelector('[data-field="status"] span');
                if (statusCell && statusCell.textContent.trim() === 'running') {
                    cell.textContent = elapsedDisplay(startedAt);
                }
            });
        }, 1000);

        // ── AGENTS ─────────────────────────────────────────────────────────
        async function loadAgents() {
            const url = showStaleAgents ? '/agents?show_stale=true' : '/agents';
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
            data.sort((a, b) => a.id - b.id);
            pageData.agents = data;
            pages.agents = 1;   // explicit load — reset to page 1
            renderAgents();
        }

        // Background refresh: updates data but preserves the current page.
        async function refreshAgents() {
            const url = showStaleAgents ? '/agents?show_stale=true' : '/agents';
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
            data.sort((a, b) => a.id - b.id);
            pageData.agents = data;
            // Do NOT reset pages.agents — preserve current page
            renderAgents();
        }

        function renderAgents() {
            const data   = pageData.agents;
            const paged  = getPage('agents', data);
            let html = `<table class="w-full text-sm"><thead><tr class="text-left text-gray-400 border-b border-gray-800"><th class="pb-2 pr-4">ID</th><th class="pb-2 pr-4">Name</th><th class="pb-2 pr-4">Status</th><th class="pb-2 pr-4">Last Seen</th><th class="pb-2">Action</th></tr></thead><tbody>`;
            if (!data.length) html += `<tr><td colspan="5" class="py-4 text-gray-500 text-sm">No agents registered.</td></tr>`;
            paged.forEach((a) => {
                const isStale = a.is_stale;
                const rowClass = isStale ? 'border-b border-gray-800 bg-gray-900 opacity-60' : 'border-b border-gray-800 hover:bg-gray-800 transition';
                const dot = a.status === 'online' ? '<span class="inline-block w-2 h-2 rounded-full bg-green-400 mr-2"></span>' : '<span class="inline-block w-2 h-2 rounded-full bg-red-500 mr-2"></span>';
                const staleTag = isStale ? '<span class="ml-2 text-xs px-1.5 py-0.5 rounded bg-yellow-900 text-yellow-400 border border-yellow-700">stale</span>' : '';
                // Setup button only shown for agents/scanners that have never checked in
                const neverSeen = !a.last_seen;
                const isProtected = (a.name === 'scanner-default');
                const setupBtn = neverSeen
                    ? `<button onclick="showAgentSetup(${a.id}, '${a.name}', '${a.api_key}', '${a.capabilities || ''}')" class="text-xs text-yellow-500 hover:text-yellow-300 transition mr-2" title="Agent not yet seen — show setup commands">Setup ⚠</button>`
                    : '';
                const deleteBtn = !isProtected
                    ? `<button onclick="deleteScanner(${a.id}, '${a.name}')" class="text-xs text-red-500 hover:text-red-400 transition">Delete</button>`
                    : '';
                const noAction = !setupBtn && !deleteBtn ? '<span class="text-xs text-gray-600">—</span>' : '';
                const action = isStale
                    ? `<div class="flex gap-3"><button onclick="restoreAgent(${a.id})" class="text-xs text-blue-400 hover:text-blue-300 transition">Restore</button><button onclick="dismissAgent(${a.id})" class="text-xs text-red-400 hover:text-red-300 transition">Dismiss</button></div>`
                    : `${setupBtn}${deleteBtn}${noAction}`;
                html += `<tr class="${rowClass}"><td class="py-2 pr-4 text-gray-400">#${a.id}</td><td class="py-2 pr-4 font-medium">${a.name}${staleTag}</td><td class="py-2 pr-4">${dot}${a.status}</td><td class="py-2 pr-4 text-gray-400 text-xs">${formatTimestamp(a.last_seen)}</td><td class="py-2">${action}</td></tr>`;
            });
            html += '</tbody></table>';
            html += paginationBar('agents', data.length);
            document.getElementById("agents").innerHTML = html;
        }
        async function dismissAgent(agent_id) {
            showConfirm('Permanently remove this stale agent?', async () => { await apiFetch(`/agents/${agent_id}/dismiss`, { method: 'POST' }); loadAgents(); }, 'Remove');
        }
        async function restoreAgent(agent_id) { await apiFetch(`/agents/${agent_id}/restore`, { method: 'POST' }); loadAgents(); }

        async function deleteScanner(agent_id, name) {
            showConfirm(
                `Delete scanner '${name}'? This will stop its systemd service (if auto-spawn is enabled) and remove it permanently.`,
                async () => {
                    const res = await apiFetch(`/scanners/${agent_id}`, { method: 'DELETE' });
                    if (res && (res.ok || res.status === 200)) {
                        loadAgents();
                    } else if (res) {
                        const err = await res.json().catch(() => ({}));
                        alert(`Delete failed: ${err.detail || 'unknown error'}`);
                    }
                },
                'Delete Scanner'
            );
        }

        // ── SCANNER REGISTRATION ───────────────────────────────────────────
        function openRegisterScanner() {
            document.getElementById('registerScannerBackdrop').classList.remove('hidden');
            document.getElementById('registerScannerModal').classList.remove('hidden');
            document.getElementById('registerScannerForm').classList.remove('hidden');
            document.getElementById('registerScannerResult').classList.add('hidden');

            // Compute next available scanner name from the current agents list
            const existing = new Set((pageData.agents || []).map(a => a.name));
            let nextNum = 2;
            while (existing.has(`scanner-${nextNum}`)) nextNum++;
            const suggested = `scanner-${nextNum}`;

            const nameInput = document.getElementById('scannerName');
            nameInput.value = '';
            nameInput.placeholder = suggested;
            document.getElementById('scannerCaps').value = 'nmap_scan,nikto_scan,nse_scan';
            nameInput.focus();
        }

        function closeRegisterScanner() {
            document.getElementById('registerScannerBackdrop').classList.add('hidden');
            document.getElementById('registerScannerModal').classList.add('hidden');
            loadAgents();
        }

        async function submitRegisterScanner() {
            const nameInput = document.getElementById('scannerName');
            // Use typed value, or fall back to the placeholder suggestion
            const name = nameInput.value.trim() || nameInput.placeholder;
            const caps = document.getElementById('scannerCaps').value.trim();
            if (!name) { alert('Scanner name is required.'); return; }
            const res = await apiFetch('/scanners/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, capabilities: caps }),
            });
            if (!res) return;
            if (res.status === 400 || res.status === 409) {
                const err = await res.json();
                alert(`Registration failed: ${err.detail}`);
                return;
            }
            const data = await res.json();

            const serverUrl = window.location.origin;

            // Status banner
            const statusBannerEl = document.getElementById('registerScannerStatusBanner');
            if (data.spawn_status === 'started') {
                statusBannerEl.className = 'mb-3 p-3 bg-green-950 border border-green-800 rounded-lg text-xs text-green-300';
                statusBannerEl.textContent = `✓ Scanner registered and started as ${data.service_name}. It should appear online in the agents table within 30 seconds.`;
            } else if (data.spawn_status === 'failed') {
                statusBannerEl.className = 'mb-3 p-3 bg-red-950 border border-red-800 rounded-lg text-xs text-red-300';
                statusBannerEl.textContent = `Scanner registered but failed to start automatically: ${data.spawn_error || 'unknown error'}. Use the manual commands below.`;
            } else {
                statusBannerEl.className = 'mb-3 p-3 bg-blue-950 border border-blue-800 rounded-lg text-xs text-blue-300';
                statusBannerEl.textContent = `Scanner registered. Auto-spawn is disabled — use the commands below to start it manually.`;
            }

            const setupCmds = `# Save your API key
echo "${data.api_key}" > ${data.key_file || name + '_key.txt'}

# Run the scanner
VAPT_AGENT_NAME=${name} \
VAPT_SERVER_URL=${serverUrl} \
VAPT_CAPABILITIES=${data.capabilities} \
VAPT_KEY_FILE=${data.key_file || name + '_key.txt'} \
python3 backend/app/scanner.py`;

            const serviceFile = `[Unit]
Description=Heimdall V-Scanner — ${name}
After=network.target vapt-server.service
Wants=vapt-server.service

[Service]
Type=simple
User=$USER
WorkingDirectory=${data.key_file ? data.key_file.replace(/\/[^/]+$/, '') : '/opt/vapt-scanner-project'}
EnvironmentFile=${data.key_file ? data.key_file.replace(/\/[^/]+$/, '') + '/.env' : '/opt/vapt-scanner-project/.env'}
Environment=VAPT_AGENT_NAME=${name}
Environment=VAPT_SERVER_URL=${serverUrl}
Environment=VAPT_CAPABILITIES=${data.capabilities}
Environment=VAPT_KEY_FILE=${data.key_file || name + '_key.txt'}
ExecStart=${data.key_file ? data.key_file.replace(/\/[^/]+$/, '') + '/venv/bin/python ' + data.key_file.replace(/\/[^/]+$/, '') + '/backend/app/scanner.py' : '/opt/vapt-scanner-project/venv/bin/python /opt/vapt-scanner-project/backend/app/scanner.py'}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target`;

            document.getElementById('resultApiKey').textContent    = data.api_key;
            document.getElementById('resultSetupCmds').textContent  = setupCmds;
            document.getElementById('resultServiceFile').textContent = serviceFile;
            document.getElementById('resultServiceName').textContent = name;

            document.getElementById('registerScannerForm').classList.add('hidden');
            document.getElementById('registerScannerResult').classList.remove('hidden');
        }

        function showAgentSetup(id, name, apiKey, caps) {
            // Reuse the modal to show setup for an already-registered agent/scanner
            document.getElementById('registerScannerBackdrop').classList.remove('hidden');
            document.getElementById('registerScannerModal').classList.remove('hidden');
            document.getElementById('registerScannerForm').classList.add('hidden');
            document.getElementById('registerScannerResult').classList.remove('hidden');

            const serverUrl = window.location.origin;
            const setupCmds = `# Save API key
echo "${apiKey}" > ${name}_key.txt

# Run scanner
VAPT_AGENT_NAME=${name} \
VAPT_SERVER_URL=${serverUrl} \
VAPT_CAPABILITIES=${caps} \
VAPT_KEY_FILE=${name}_key.txt \
python3 backend/app/scanner.py`;

            const serviceFile = `[Unit]
Description=Heimdall V-Scanner — ${name}
After=network.target vapt-server.service
Wants=vapt-server.service

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/vapt-scanner-project
EnvironmentFile=/opt/vapt-scanner-project/.env
Environment=VAPT_AGENT_NAME=${name}
Environment=VAPT_SERVER_URL=${serverUrl}
Environment=VAPT_CAPABILITIES=${caps}
Environment=VAPT_KEY_FILE=/opt/vapt-scanner-project/${name}_key.txt
ExecStart=/opt/vapt-scanner-project/venv/bin/python /opt/vapt-scanner-project/backend/app/scanner.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target`;

            document.getElementById('resultApiKey').textContent    = apiKey;
            document.getElementById('resultSetupCmds').textContent  = setupCmds;
            document.getElementById('resultServiceFile').textContent = serviceFile;
            document.getElementById('resultServiceName').textContent = name;
        }

        function copyText(elementId) {
            const el = document.getElementById(elementId);
            navigator.clipboard.writeText(el.textContent).then(() => {
                // Brief visual flash on the element
                el.style.outline = '1px solid #22c55e';
                setTimeout(() => { el.style.outline = ''; }, 800);
            });
        }

        // ── JOBS ───────────────────────────────────────────────────────────
        async function loadJobs() {
            const url = showJobHistory ? '/jobs?show_history=true' : '/jobs';
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
            data.sort((a, b) => b.id - a.id);

            // Detect newly completed jobs — auto-refresh results if any finished
            let anyNewlyDone = false;
            data.forEach(j => {
                const prev = lastJobStatuses[j.id];
                if (prev === 'running' && j.status === 'done') anyNewlyDone = true;
                lastJobStatuses[j.id] = j.status;
            });
            if (anyNewlyDone && resultTab === 'active') loadResults();

            pageData.jobs = data;
            pages.jobs = 1;   // explicit load — reset to page 1
            renderJobs();
        }

        // Background refresh: updates data but preserves the current page.
        // Used by the polling interval so navigating to page 3 doesn't snap back.
        async function refreshJobs() {
            const url = showJobHistory ? '/jobs?show_history=true' : '/jobs';
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
            data.sort((a, b) => b.id - a.id);

            let anyNewlyDone = false;
            data.forEach(j => {
                const prev = lastJobStatuses[j.id];
                if (prev === 'running' && j.status === 'done') anyNewlyDone = true;
                lastJobStatuses[j.id] = j.status;
            });
            if (anyNewlyDone && resultTab === 'active') loadResults();

            pageData.jobs = data;
            // Do NOT reset pages.jobs — preserve current page
            renderJobs();
        }

        function renderJobs() {
            const data     = pageData.jobs;
            const filtered = jobFilter === 'all' ? data : data.filter(j => j.status === jobFilter);
            const paged    = getPage('jobs', filtered);

            if (!filtered.length) { document.getElementById("jobs").innerHTML = '<p class="text-gray-500 text-sm">No jobs found.</p>'; return; }

            let html = `<table class="w-full text-sm"><thead><tr class="text-left text-gray-400 border-b border-gray-800"><th class="pb-2 pr-3">#</th><th class="pb-2 pr-3">DB ID</th><th class="pb-2 pr-3">Type</th><th class="pb-2 pr-3">Target</th><th class="pb-2 pr-3">Status</th><th class="pb-2 pr-3">Priority</th><th class="pb-2 pr-3">Mode</th><th class="pb-2 pr-3">Profile</th><th class="pb-2 pr-3">Agent</th><th class="pb-2 pr-3">Time</th><th class="pb-2">Action</th></tr></thead><tbody>`;
            paged.forEach((j, idx) => {
                const rowNum = (pages.jobs - 1) * PAGE_SIZES.jobs + idx + 1;
                let action;
                if (j.cleared) action = '<span class="text-xs text-gray-500 italic">archived</span>';
                else if (j.status === 'running')  action = `<button onclick="cancelJob(${j.id})" class="text-xs text-orange-400 hover:text-orange-300 transition font-medium">Cancel</button>`;
                else if (j.status === 'pending')  action = `<div class="flex gap-2"><button onclick="cancelJob(${j.id})" class="text-xs text-orange-400 hover:text-orange-300 transition">Cancel</button><button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-red-500 hover:text-red-400 transition font-medium">Delete</button></div>`;
                else if (j.status === 'failed')   action = `<button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-red-500 hover:text-red-400 transition font-medium">Delete</button>`;
                else action = `<button onclick="clearJob(${j.id}, '${j.status}')" class="text-xs text-gray-400 hover:text-red-400 transition">Clear</button>`;
                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition"><td class="py-2 pr-3 text-gray-500 text-xs">${rowNum}</td><td class="py-2 pr-3 text-gray-500 text-xs font-mono">${j.id}</td><td class="py-2 pr-3 text-xs text-blue-300">${scanTypeLabel(j.type)}</td><td class="py-2 pr-3 font-mono text-xs">${j.target}</td><td class="py-2 pr-3" data-field="status">${statusBadge(j.status)}</td><td class="py-2 pr-3">${priorityBadge(j.priority)}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.mode}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.profile}</td><td class="py-2 pr-3 text-xs text-gray-300">${j.agent}</td><td class="py-2 pr-3 text-xs text-gray-400 tabular-nums" id="job-time-${j.id}" data-started-at="${j.started_at || ''}">${j.status === 'running' ? elapsedDisplay(j.started_at) : formatTimestamp(j.completed_at)}</td><td class="py-2">${action}</td></tr>`;
            });
            html += '</tbody></table>';
            html += paginationBar('jobs', filtered.length);
            document.getElementById("jobs").innerHTML = html;
        }
        async function clearJob(job_id, status) {
            if (status === 'pending' || status === 'failed') {
                showConfirm(`Permanently delete this ${status} job?`, async () => { await apiFetch(`/jobs/${job_id}/clear`, { method: 'POST' }); loadJobs(); }, 'Delete');
            } else { await apiFetch(`/jobs/${job_id}/clear`, { method: 'POST' }); loadJobs(); }
        }
        async function cancelJob(job_id) {
            showConfirm('Cancel this job? The scanner will stop after its current tool finishes.', async () => {
                await apiFetch(`/jobs/${job_id}/cancel`, { method: 'POST' });
                loadJobs();
            }, 'Cancel Job');
        }
        async function clearAllByStatus(status) {
            showConfirm(`Permanently delete ALL ${status} jobs?`, async () => {
                const res = await apiFetch('/jobs');
                if (!res) return;
                const jobs = await res.json();
                await Promise.all(jobs.filter(j => j.status === status && !j.cleared).map(j => apiFetch(`/jobs/${j.id}/clear`, { method: 'POST' })));
                loadJobs();
            }, 'Delete All');
        }

        // ── CREATE JOB ─────────────────────────────────────────────────────
        async function createJob() {
            const target   = document.getElementById("target").value.trim();
            const agent_id = document.getElementById("agent_id").value.trim();
            const type     = document.getElementById("job_type").value;
            const mode     = document.getElementById("mode").value;
            const profile  = document.getElementById("profile").value;
            const port     = document.getElementById("port").value.trim();
            const ports    = document.getElementById("ports").value.trim();
            const priority = document.getElementById("priority").value;
            if (!target) { alert("Please enter a target IP."); return; }
            if (type === "nse_scan" && profile === "full") {
                showExploitWarning(() => submitCreateJob(target, agent_id, type, mode, profile, port, ports, priority));
                return;
            }
            await submitCreateJob(target, agent_id, type, mode, profile, port, ports, priority);
        }
        async function submitCreateJob(target, agent_id, type, mode, profile, port, ports, priority) {
            let payload = { type, target, mode, profile, priority };
            if (agent_id) payload.agent_id = parseInt(agent_id);
            if (type === "nikto_scan" && port) payload.port = parseInt(port);
            if (type === "nse_scan" && ports && profile !== 'custom') payload.ports = ports;
            if (type === "nse_scan" && profile === 'custom') {
                const scripts = getSelectedScripts();
                if (!scripts.length) {
                    document.getElementById('customProfileWarning').classList.remove('hidden');
                    return;
                }
                document.getElementById('customProfileWarning').classList.add('hidden');
                payload.custom_scripts = scripts;
            }
            if (type === "nikto_scan" && profile === 'custom') {
                const categories = getSelectedNiktoCategories();
                if (!categories.length) {
                    document.getElementById('niktoCustomWarning').classList.remove('hidden');
                    return;
                }
                document.getElementById('niktoCustomWarning').classList.add('hidden');
                payload.nikto_tuning = categories;
            }
            const pluginExtra = collectPluginExtraParams(type);
            if (pluginExtra && Object.keys(pluginExtra).length) payload.extra_params = pluginExtra;
            const res = await apiFetch('/jobs/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            if (!res) return;
            if (res.status === 400) { const err = await res.json(); alert(`Job creation failed: ${err.detail}`); return; }
            const data = await res.json();
            if (data.warning) alert(`Job created with warning:

${data.warning}`);
            document.getElementById("target").value = "";
            document.getElementById("port").value = "";
            document.getElementById("ports").value = "";
            setTimeout(loadAll, 300);
            // Reset custom NSE profile state
            if (type === 'nse_scan' && profile === 'custom') {
                initCapabilityState();
                renderCapabilityCards();
                document.getElementById('customProfilePanel').classList.add('hidden');
                document.getElementById('profile').value = 'standard';
            }
            // Reset custom Nikto profile state
            if (type === 'nikto_scan' && profile === 'custom') {
                initNiktoCategoryState();
                renderNiktoCategoryCards();
                document.getElementById('niktoCustomPanel').classList.add('hidden');
                document.getElementById('profile').value = 'standard';
            }
        }

        // ── PLUGINS & JOB TYPES ────────────────────────────────────────────
        let availableJobTypes = [];

        async function loadJobTypes() {
            const res = await apiFetch('/plugins/job-types');
            if (!res) return;
            availableJobTypes = await res.json();

            // Extend the Create Job dropdown with plugin types meant for the regular
            // scan flow (tab === 'scan'). Pen Test-tab types render separately.
            const select = document.getElementById('job_type');
            if (select) {
                Array.from(select.querySelectorAll('option[data-plugin-option]')).forEach(o => o.remove());
                availableJobTypes
                    .filter(jt => !jt.builtin && (jt.tab || 'scan') === 'scan')
                    .forEach(jt => {
                        const opt = document.createElement('option');
                        opt.value = jt.type;
                        opt.textContent = jt.label;
                        opt.dataset.pluginOption = 'true';
                        select.appendChild(opt);
                    });
            }

            updatePentestTabVisibility();
        }

        function updatePentestTabVisibility() {
            // The Pen Test tab only exists to hold pentest-tagged plugin job types —
            // no point showing an empty tab before one's actually installed, and it
            // should disappear again the moment the last one is uninstalled/disabled.
            const hasPentestTypes = availableJobTypes.some(jt => jt.tab === 'pentest');
            const navBtn = document.getElementById('nav-pentest');
            if (!navBtn) return;
            navBtn.classList.toggle('hidden', !hasPentestTypes);

            // If we're sitting on the tab when it disappears, don't strand the user on a hidden panel.
            const pentestPanel = document.getElementById('tab-pentest');
            if (!hasPentestTypes && pentestPanel && pentestPanel.classList.contains('active')) {
                switchTab('dashboard');
            }
        }

        function getJobTypeInfo(type) {
            return availableJobTypes.find(jt => jt.type === type) || null;
        }

        function renderFormFieldHtml(field, idPrefix, currentValue) {
            const id = `${idPrefix}_${field.name}`;
            const value = currentValue !== undefined ? currentValue : (field.default ?? '');
            let control;
            if (field.type === 'select') {
                const opts = (field.options || []).map(o =>
                    `<option value="${o}" ${o === value ? 'selected' : ''}>${o}</option>`).join('');
                control = `<select id="${id}" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">${opts}</select>`;
            } else if (field.type === 'multiselect') {
                const selected = Array.isArray(value) ? value : (field.default || []);
                const opts = (field.options || []).map(o => `
                    <label class="flex items-center gap-2 text-xs text-gray-300 py-0.5">
                        <input type="checkbox" class="plugin-multiselect" data-field="${id}" value="${o}" ${selected.includes(o) ? 'checked' : ''}>
                        ${o}
                    </label>`).join('');
                control = `<div id="${id}" class="flex flex-col bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 max-h-32 overflow-y-auto">${opts}</div>`;
            } else if (field.type === 'number') {
                control = `<input id="${id}" type="number" value="${value}" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-24">`;
            } else {
                control = `<input id="${id}" type="text" value="${value}" placeholder="${field.label || field.name}" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-44">`;
            }
            return `<div class="flex flex-col gap-1">
                <label class="text-xs text-gray-400">${field.label || field.name}${field.required ? ' *' : ''}</label>
                ${control}
            </div>`;
        }

        function readFormFieldValue(field, idPrefix) {
            const id = `${idPrefix}_${field.name}`;
            if (field.type === 'multiselect') {
                return Array.from(document.querySelectorAll(`input.plugin-multiselect[data-field="${id}"]:checked`)).map(el => el.value);
            }
            const el = document.getElementById(id);
            if (!el) return undefined;
            if (field.type === 'number') return el.value ? Number(el.value) : undefined;
            return el.value || undefined;
        }

        // ── Create Job — dynamic fields for plugin-provided types ──────────
        function renderPluginFieldsForCreateJob(type) {
            const container = document.getElementById('pluginFields');
            if (!container) return;
            const info = getJobTypeInfo(type);
            if (!info || info.builtin || !(info.form_fields || []).length) {
                container.innerHTML = '';
                container.style.display = 'none';
                return;
            }
            container.innerHTML = info.form_fields
                .filter(f => f.name !== 'target')
                .map(f => renderFormFieldHtml(f, 'cj_plugin')).join('');
            container.style.display = 'flex';
        }

        function collectPluginExtraParams(type) {
            const info = getJobTypeInfo(type);
            if (!info || info.builtin) return null;
            const extra = {};
            (info.form_fields || []).filter(f => f.name !== 'target').forEach(f => {
                const val = readFormFieldValue(f, 'cj_plugin');
                if (val !== undefined && val !== '' && !(Array.isArray(val) && !val.length)) extra[f.name] = val;
            });
            return extra;
        }

        // ── PEN TEST TAB ─────────────────────────────────────────────────
        async function loadPentestTab() {
            if (!availableJobTypes.length) await loadJobTypes();
            await loadAuthorizations();

            const pentestTypes = availableJobTypes.filter(jt => jt.tab === 'pentest');
            const networkTypes = pentestTypes.filter(jt => (jt.section || '').toLowerCase() === 'network');
            const webTypes     = pentestTypes.filter(jt => (jt.section || '').toLowerCase() === 'web');
            const otherTypes   = pentestTypes.filter(jt => !networkTypes.includes(jt) && !webTypes.includes(jt));

            const netEl   = document.getElementById('pentestNetworkSection');
            const webEl   = document.getElementById('pentestWebSection');
            const otherEl = document.getElementById('pentestOtherSection');
            if (netEl)   netEl.innerHTML   = renderPentestSection(networkTypes, 'No Network Pen Test plugins installed yet.');
            if (webEl)   webEl.innerHTML   = renderPentestSection(webTypes, 'No Web Pen Test plugins installed yet.');
            if (otherEl) otherEl.innerHTML = otherTypes.length ? renderPentestSection(otherTypes, '') : '';
        }

        function renderPentestSection(types, emptyMessage) {
            if (!types.length) return `<p class="text-xs text-gray-600 italic">${emptyMessage}</p>`;
            return types.map(jt => renderPentestCard(jt)).join('');
        }

        function riskBadgeClasses(tier) {
            if (tier === 'high') return 'border-red-700 text-red-400 bg-red-950';
            if (tier === 'intrusive') return 'border-yellow-700 text-yellow-400 bg-yellow-950';
            if (tier === 'read_only') return 'border-green-700 text-green-400 bg-green-950';
            return 'border-gray-700 text-gray-400 bg-gray-900';
        }

        function renderPentestCard(jt) {
            const idPrefix = `pentest_${jt.type}`;
            const fields = (jt.form_fields || []).filter(f => f.name !== 'target');
            const needsAuth = jt.risk_tier === 'high';
            const activeAuth = (window.__activeAuthorizations || []).find(a => a.job_type === jt.type && a.active);

            return `
                <div class="bg-gray-950 border border-gray-800 rounded-lg p-4 mb-3">
                    <div class="flex items-center justify-between mb-2">
                        <div>
                            <p class="text-sm font-semibold text-gray-200">${jt.label}</p>
                            <p class="text-xs text-gray-600">${jt.plugin_name ? 'Plugin: ' + jt.plugin_name : ''}</p>
                        </div>
                        <span class="text-xs px-2 py-0.5 rounded-full border ${riskBadgeClasses(jt.risk_tier)}">${jt.risk_tier}</span>
                    </div>
                    <div class="flex flex-wrap gap-3 items-end mt-2">
                        <div class="flex flex-col gap-1">
                            <label class="text-xs text-gray-400">Target</label>
                            <input id="${idPrefix}_target" placeholder="IP or hostname"
                                class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-44">
                        </div>
                        ${fields.map(f => renderFormFieldHtml(f, idPrefix)).join('')}
                    </div>
                    ${needsAuth ? renderAuthorizationStatus(jt.type, activeAuth, idPrefix) : ''}
                    <div class="mt-3">
                        <button onclick="submitPentestJob('${jt.type}')"
                            class="text-xs px-4 py-2 rounded-lg bg-red-900 hover:bg-red-800 text-red-200 border border-red-800 transition font-medium">
                            ${needsAuth ? 'Run (requires active authorization)' : 'Run'}
                        </button>
                    </div>
                </div>`;
        }

        function renderAuthorizationStatus(jobType, activeAuth, idPrefix) {
            if (activeAuth) {
                return `<div class="mt-3 flex items-center justify-between gap-3 bg-green-950 border border-green-800 rounded-lg px-3 py-2">
                    <p class="text-xs text-green-300">Authorized for ${activeAuth.target} until ${new Date(activeAuth.expires_at).toLocaleString()}</p>
                    <button onclick="revokeAuthorization(${activeAuth.id})" class="text-xs text-red-400 hover:text-red-300 underline">Revoke</button>
                </div>`;
            }
            return `<div class="mt-3 flex items-center gap-2 bg-gray-900 border border-gray-800 rounded-lg px-3 py-2">
                <p class="text-xs text-gray-500 flex-1">No active authorization for this job type.</p>
                <button onclick="openAuthorizeModal('${jobType}', document.getElementById('${idPrefix}_target').value)"
                    class="text-xs px-3 py-1.5 rounded-lg bg-yellow-900 hover:bg-yellow-800 text-yellow-200 border border-yellow-800 transition font-medium">
                    Authorize Target
                </button>
            </div>`;
        }

        async function submitPentestJob(jobType) {
            const idPrefix = `pentest_${jobType}`;
            const targetEl = document.getElementById(`${idPrefix}_target`);
            const target = targetEl ? targetEl.value.trim() : '';
            if (!target) { alert('Please enter a target.'); return; }

            const info = getJobTypeInfo(jobType);
            const extra = {};
            (info?.form_fields || []).filter(f => f.name !== 'target').forEach(f => {
                const val = readFormFieldValue(f, idPrefix);
                if (val !== undefined && val !== '' && !(Array.isArray(val) && !val.length)) extra[f.name] = val;
            });

            const payload = { type: jobType, target, mode: 'remote', extra_params: extra };
            const res = await apiFetch('/jobs/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            if (!res) return;
            if (res.status === 403 || res.status === 400) {
                const err = await res.json();
                alert(`Blocked: ${err.detail}`);
                return;
            }
            alert('Job created — check the Dashboard tab for progress.');
            targetEl.value = '';
            setTimeout(loadAll, 300);
        }

        // ── TARGET AUTHORIZATIONS ───────────────────────────────────────────
        async function loadAuthorizations() {
            const res = await apiFetch('/authorizations');
            if (!res) return;
            window.__activeAuthorizations = await res.json();
        }

        let pendingAuthJobType = null;

        function openAuthorizeModal(jobType, prefillTarget) {
            pendingAuthJobType = jobType;
            document.getElementById('authorizeJobType').textContent = jobType;
            document.getElementById('authorizeTarget').value = prefillTarget || '';
            const maxHours = serverSettings['high_risk_auth_max_hours'] || '4';
            document.getElementById('authorizeHours').value = maxHours;
            document.getElementById('authorizeHours').max = maxHours;
            document.getElementById('authorizeMaxNote').textContent = `Max ${maxHours}h (set in Settings → Server)`;
            document.getElementById('authorizeBackdrop').classList.remove('hidden');
            document.getElementById('authorizeModal').classList.remove('hidden');
        }

        function closeAuthorizeModal() {
            document.getElementById('authorizeBackdrop').classList.add('hidden');
            document.getElementById('authorizeModal').classList.add('hidden');
            pendingAuthJobType = null;
        }

        async function submitAuthorization() {
            const target = document.getElementById('authorizeTarget').value.trim();
            const hours  = document.getElementById('authorizeHours').value;
            if (!target || !pendingAuthJobType) return;

            const res = await apiFetch('/authorizations', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, job_type: pendingAuthJobType, hours: parseFloat(hours) }),
            });
            if (!res) return;
            if (res.status !== 200) {
                const err = await res.json();
                alert(`Authorization failed: ${err.detail}`);
                return;
            }
            closeAuthorizeModal();
            await loadPentestTab();
        }

        function revokeAuthorization(authId) {
            showConfirm('Revoke this authorization now?', async () => {
                const res = await apiFetch(`/authorizations/${authId}`, { method: 'DELETE' });
                if (!res) return;
                await loadPentestTab();
            });
        }

        // ── PLUGINS MANAGEMENT (Settings panel) ─────────────────────────────
        async function loadPlugins() {
            const [pluginsRes, agentsRes] = await Promise.all([apiFetch('/plugins'), apiFetch('/agents')]);
            if (!pluginsRes) return;
            const plugins = await pluginsRes.json();
            const agents = agentsRes ? await agentsRes.json() : [];
            window.__lastLoadedPlugins = plugins;
            renderPluginsList(plugins, agents);
        }

        function renderPluginsList(plugins, agents) {
            const container = document.getElementById('pluginsList');
            if (!container) return;
            if (!plugins.length) {
                container.innerHTML = '<p class="text-xs text-gray-600 italic">No plugins installed.</p>';
                return;
            }
            container.innerHTML = plugins.map(p => `
                <div class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 mb-2">
                    <div class="flex items-center justify-between gap-3">
                        <div class="min-w-0">
                            <p class="text-sm text-gray-200 truncate">${p.display_name} <span class="text-gray-600">v${p.version}</span></p>
                            <p class="text-xs text-gray-600">${p.job_types.length} job type(s), ${p.hooks.length} hook(s)</p>
                        </div>
                        <div class="flex items-center gap-2 flex-shrink-0">
                            <button onclick="togglePlugin('${p.name}', ${!p.enabled})"
                                class="text-xs px-2 py-1 rounded-lg border transition ${p.enabled ? 'border-green-700 text-green-400 hover:bg-green-950' : 'border-gray-600 text-gray-500 hover:bg-gray-700'}">
                                ${p.enabled ? 'Enabled' : 'Disabled'}
                            </button>
                            <button onclick="uninstallPlugin('${p.name}')" class="text-xs text-red-500 hover:text-red-400">Remove</button>
                        </div>
                    </div>
                    ${(p.config_schema || []).length ? renderPluginConfigForm(p) : ''}
                    ${(p.job_types || []).map(jt => renderDeploymentStatus(jt, agents)).join('')}
                </div>`).join('');
        }

        function renderPluginConfigForm(plugin) {
            const idPrefix = `pluginconfig_${plugin.name}`;
            const fields = plugin.config_schema.map(f => renderFormFieldHtml(f, idPrefix, plugin.config?.[f.name])).join('');
            return `<div class="mt-2 pt-2 border-t border-gray-700">
                <div class="flex flex-wrap gap-3 items-end">${fields}</div>
                <button onclick="savePluginConfig('${plugin.name}')"
                    class="mt-2 text-xs px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-200 transition">
                    Save config
                </button>
            </div>`;
        }

        async function savePluginConfig(pluginName) {
            const plugin = (window.__lastLoadedPlugins || []).find(p => p.name === pluginName);
            if (!plugin) return;
            const idPrefix = `pluginconfig_${pluginName}`;
            const config = {};
            plugin.config_schema.forEach(f => {
                const val = readFormFieldValue(f, idPrefix);
                if (val !== undefined && val !== '' && !(Array.isArray(val) && !val.length)) config[f.name] = val;
            });
            const res = await apiFetch(`/plugins/${pluginName}/config`, {
                method: 'PATCH', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
            });
            if (!res) return;
            if (res.status !== 200) {
                const err = await res.json();
                alert(`Save failed: ${err.detail}`);
                return;
            }
            await loadPlugins();
        }

        function renderDeploymentStatus(jobType, agents) {
            if (!agents.length) {
                return `<div class="mt-2 pt-2 border-t border-gray-700">
                    <p class="text-xs text-gray-600">No registered agents to check deployment against.</p>
                </div>`;
            }
            const rows = agents.map(a => {
                const caps = (a.capabilities || '').split(',').map(c => c.trim());
                const deployed = caps.includes(jobType.type);
                const cmdId = `deploycmd_${jobType.type}_${a.id}`;
                const cmd = `./install_plugin.sh <path-to-plugin-source> ${jobType.type} scanner:${a.name}`;
                return `<div class="flex items-center justify-between gap-2 text-xs py-1">
                    <span class="text-gray-400">${a.name}</span>
                    ${deployed
                        ? `<span class="text-green-400">✓ deployed</span>`
                        : `<button onclick="copyDeployCommand('${cmdId}')" class="text-gray-500 hover:text-gray-300 underline" title="${cmd}">
                               <span id="${cmdId}-label">copy deploy command</span>
                               <span id="${cmdId}" class="hidden">${cmd}</span>
                           </button>`}
                </div>`;
            }).join('');
            return `<div class="mt-2 pt-2 border-t border-gray-700">
                <p class="text-xs text-gray-500 font-mono mb-1">${jobType.type}</p>
                ${rows}
            </div>`;
        }

        function copyDeployCommand(cmdId) {
            const text = document.getElementById(cmdId).textContent;
            navigator.clipboard.writeText(text).then(() => {
                const label = document.getElementById(`${cmdId}-label`);
                const original = label.textContent;
                label.textContent = 'copied!';
                setTimeout(() => { label.textContent = original; }, 1500);
            });
        }

        async function togglePlugin(name, enabled) {
            const res = await apiFetch(`/plugins/${name}/enable`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled }),
            });
            if (!res) return;
            await loadPlugins();
            await loadJobTypes();
        }

        function uninstallPlugin(name) {
            showConfirm(`Uninstall '${name}'? Any pending jobs of its type will be cancelled. Past results are kept.`, async () => {
                const res = await apiFetch(`/plugins/${name}`, { method: 'DELETE' });
                if (!res) return;
                const data = await res.json();
                if (data.cancelled_pending_jobs) alert(`${data.cancelled_pending_jobs} pending job(s) were cancelled.`);
                await loadPlugins();
                await loadJobTypes();
            });
        }

        function readPluginManifestFile(fileInput) {
            const file = fileInput.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = e => { document.getElementById('pluginManifestText').value = e.target.result; };
            reader.readAsText(file);
        }

        async function installPluginFromTextarea() {
            const raw = document.getElementById('pluginManifestText').value.trim();
            if (!raw) { alert('Paste a plugin.json, or choose a file first.'); return; }
            let manifest;
            try {
                manifest = JSON.parse(raw);
            } catch (e) {
                alert(`Invalid JSON: ${e.message}`);
                return;
            }
            const res = await apiFetch('/plugins/install', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(manifest),
            });
            if (!res) return;
            if (res.status !== 200) {
                const err = await res.json();
                alert(`Install failed: ${err.detail}`);
                return;
            }
            document.getElementById('pluginManifestText').value = '';
            await loadPlugins();
            await loadJobTypes();
            alert('Plugin installed.');
        }

        // ── RESULTS ────────────────────────────────────────────────────────
        function toggleResult(id) {
            const body = document.getElementById(`result-body-${id}`);
            const arrow = document.getElementById(`result-arrow-${id}`);
            body.classList.toggle('hidden');
            arrow.innerText = body.classList.contains('hidden') ? '▼' : '▲';
        }

        // ── Result card hover tooltip ──────────────────────────────────────
        let _tooltipTimer = null;
 
        function showResultTooltip(event, id) {
            const body = document.getElementById('result-body-' + id);
            if (body && !body.classList.contains('hidden')) return;
            clearTimeout(_tooltipTimer);
            _tooltipTimer = setTimeout(() => {
                const tip = document.getElementById('tip-' + id);
                if (tip) tip.classList.add('visible');
            }, 500);
        }
 
        function hideResultTooltip(id) {
            clearTimeout(_tooltipTimer);
            const tip = document.getElementById('tip-' + id);
            if (tip) tip.classList.remove('visible');
        }
        function renderNmapResult(nmap) {
            if (!nmap || !nmap.length) return '<p class="text-gray-500 text-xs">No hosts found.</p>';
            return nmap.map(host => {
                const ports = host.ports && host.ports.length
                    ? host.ports.map(p => `<tr class="border-b border-gray-700"><td class="py-1 pr-4 font-mono text-blue-300">${p.port}</td><td class="py-1 pr-4 text-green-400">${p.state}</td><td class="py-1 text-gray-300">${p.service}</td></tr>`).join('')
                    : '<tr><td colspan="3" class="py-2 text-gray-500">No open ports found</td></tr>';
                return `<div class="mb-2"><p class="text-xs text-gray-400 mb-1">Host: <span class="text-white font-mono">${host.host}</span></p><table class="w-full text-xs"><thead><tr class="text-gray-500"><th class="text-left pb-1 pr-4">Port</th><th class="text-left pb-1 pr-4">State</th><th class="text-left pb-1">Service</th></tr></thead><tbody>${ports}</tbody></table></div>`;
            }).join('');
        }
        function renderNiktoResult(nikto) {
            if (!nikto) return '';
            return Object.entries(nikto).map(([port, result]) => {
                if (result.error) return `<div class="mt-2"><p class="text-xs text-gray-400">Nikto port ${port}:</p><p class="text-xs text-red-400 break-all">${result.error}</p></div>`;
                if (result.raw) {
                    const findings = result.raw.split('\n').filter(l => l.match(/^\+ \[/));
                    if (!findings.length) return `<div class="mt-2"><p class="text-xs text-gray-500">Nikto port ${port}: no findings.</p></div>`;
                    return `<div class="mt-2"><p class="text-xs text-gray-400 mb-2">Nikto port ${port} — ${findings.length} finding(s):</p><div class="space-y-1">${findings.map(line => { const m = line.match(/^\+ \[(\w+)\] (.+?):\s*(.+)$/); return m ? `<div class="bg-gray-950 rounded p-2 text-xs break-all"><span class="text-yellow-400 font-mono">[${m[1]}]</span><span class="text-gray-400 font-mono ml-2">${m[2]}:</span><span class="text-gray-200 ml-1">${m[3]}</span></div>` : `<div class="bg-gray-950 rounded p-2 text-xs text-gray-300 break-all">${line.replace(/^\+ /, '')}</div>`; }).join('')}</div></div>`;
                }
                const vulns = result[0]?.vulnerabilities || [];
                if (!vulns.length) return `<p class="text-xs text-gray-500 mt-2">Nikto port ${port}: no vulnerabilities found.</p>`;
                return `<div class="mt-2"><p class="text-xs text-gray-400 mb-1">Nikto port ${port} — ${vulns.length} finding(s):</p><div class="space-y-1">${vulns.map(v => `<div class="bg-gray-950 rounded p-2 text-xs break-all"><span class="text-yellow-400 font-mono">[${v.id}]</span><span class="text-gray-200 ml-2">${v.msg}</span>${v.url ? `<span class="text-gray-500 ml-2"><a href="${v.url}" target="_blank" class="hover:text-blue-400">${v.url}</a></span>` : ''}</div>`).join('')}</div></div>`;
            }).join('');
        }
        function renderNseResult(nse) {
            if (!nse) return '';
            let warningHtml = nse.warning ? `<div class="mb-3 flex items-start gap-2 bg-yellow-950 border border-yellow-800 rounded-lg px-3 py-2"><span class="text-yellow-400 text-xs mt-0.5">⚠</span><p class="text-xs text-yellow-300">${nse.warning}</p></div>` : '';
            const findings = nse.findings || [];
            if (!findings.length) return `${warningHtml}<p class="text-xs text-gray-500">No NSE findings.</p>`;
            const rows = findings.map(f => {
                const portLabel = f.port !== null ? `<span class="font-mono text-blue-300">${f.port}</span>${f.service ? `<span class="text-gray-500 ml-1">(${f.service})</span>` : ''}` : '<span class="text-gray-500 italic">host-level</span>';
                const outputId = `nse-output-${Math.random().toString(36).slice(2)}`;
                const shortOutput = f.output.length > 200 ? f.output.slice(0, 200) + '...' : f.output;
                const hasMore = f.output.length > 200;
                return `<div class="bg-gray-950 rounded-lg p-3 text-xs space-y-1 break-all"><div class="flex items-center gap-3 flex-wrap"><span class="text-purple-400 font-mono font-semibold">${f.script_id}</span><span class="text-gray-500">on</span>${portLabel}<span class="text-gray-600 font-mono">${f.host}</span></div><div class="text-gray-300 whitespace-pre-wrap leading-relaxed" id="${outputId}-short">${shortOutput}</div>${hasMore ? `<div class="text-gray-300 whitespace-pre-wrap leading-relaxed hidden" id="${outputId}-full">${f.output}</div><button onclick="document.getElementById('${outputId}-short').classList.toggle('hidden');document.getElementById('${outputId}-full').classList.toggle('hidden');this.textContent=this.textContent==='Show more'?'Show less':'Show more';" class="text-xs text-gray-500 hover:text-gray-300 underline transition">Show more</button>` : ''}</div>`;
            }).join('');
            return `${warningHtml}<p class="text-xs text-gray-400 mb-2">${findings.length} NSE finding(s):</p><div class="space-y-2">${rows}</div>`;
        }
        function renderAnalysis(analysis) {
            if (!analysis) return '';

            // Parse risk level for badge colour
            const riskMatch = analysis.match(/##\s*Risk Level\s*\n+(\w+)/i);
            const risk = riskMatch ? riskMatch[1].toUpperCase() : null;
            const riskColour = {
                CRITICAL: 'bg-red-900 text-red-200 border-red-700',
                HIGH:     'bg-orange-900 text-orange-200 border-orange-700',
                MEDIUM:   'bg-yellow-900 text-yellow-200 border-yellow-700',
                LOW:      'bg-blue-900 text-blue-200 border-blue-700',
                INFO:     'bg-gray-800 text-gray-300 border-gray-600',
            }[risk] || 'bg-gray-800 text-gray-300 border-gray-600';

            // Convert markdown to simple HTML
            const html = analysis
                .replace(/^## (.+)$/gm, '<h4 class="text-xs font-bold uppercase tracking-wider text-gray-400 mt-4 mb-2 border-b border-gray-700 pb-1">$1</h4>')
                .replace(/^\*\*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\*\* (.+)$/gm, (_, sev, rest) => {
                    const c = {CRITICAL:'text-red-400',HIGH:'text-orange-400',MEDIUM:'text-yellow-400',LOW:'text-blue-400',INFO:'text-gray-400'}[sev] || 'text-gray-400';
                    return `<p class="text-xs mt-2"><span class="font-bold ${c}">[${sev}]</span> <span class="text-gray-200 font-semibold">${rest}</span></p>`;
                })
                .replace(/^\*\*(.+?)\*\*/gm, '<strong class="text-gray-200">$1</strong>')
                .replace(/^(\d+\.) (.+)$/gm, '<div class="flex gap-2 text-xs mt-1"><span class="text-gray-500 flex-shrink-0">$1</span><span class="text-gray-300">$2</span></div>')
                .replace(/^- (.+)$/gm, '<div class="flex gap-2 text-xs mt-1"><span class="text-gray-500 flex-shrink-0">•</span><span class="text-gray-300">$1</span></div>')
                .replace(/\n\n/g, '<div class="mt-2"></div>')
                .replace(/\n/g, ' ');

            return `
            <div class="mt-2 bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
                <div class="flex items-center gap-3 px-4 py-3 border-b border-gray-700">
                    <span class="text-xs font-bold uppercase tracking-wider text-purple-400">Analysis</span>
                    ${risk ? `<span class="text-xs px-2 py-0.5 rounded-full border font-semibold ${riskColour}">${risk}</span>` : ''}
                    <span class="text-xs text-gray-600 ml-auto">Powered by ${serverSettings.ai_provider || 'none'}</span>
                </div>
                <div class="px-4 py-3 text-xs text-gray-300 leading-relaxed">${html}</div>
            </div>`;
        }
        async function triggerAnalysis(result_id) {
            await apiFetch(`/results/${result_id}/analyse`, { method: 'POST' });
            setTimeout(() => loadResults(), 4000);
        }
        function renderJobInfo(job_info) {
            if (!job_info) return '';
            return `<div class="mb-4 bg-gray-900 rounded-lg p-3 border border-gray-700"><p class="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-2">Associated Job</p><div class="grid grid-cols-2 gap-x-6 gap-y-1 text-xs"><div><span class="text-gray-500">Job ID:</span> <span class="text-gray-200 font-mono">#${job_info.id}</span></div><div><span class="text-gray-500">Target:</span> <span class="text-gray-200 font-mono">${job_info.target}</span></div><div><span class="text-gray-500">Type:</span> <span class="text-gray-200">${job_info.type}</span></div><div><span class="text-gray-500">Mode:</span> <span class="text-gray-200">${job_info.mode}</span></div><div><span class="text-gray-500">Profile:</span> <span class="text-gray-200">${job_info.profile}</span></div><div><span class="text-gray-500">Priority:</span> <span class="text-gray-200">${job_info.priority}</span></div><div class="col-span-2"><span class="text-gray-500">Completed:</span> <span class="text-gray-200">${formatTimestamp(job_info.completed_at)}</span></div></div></div>`;
        }
        async function clearResult(result_id) { await apiFetch(`/results/${result_id}/clear`, { method: 'POST' }); loadResults(); loadJobs(); }
        async function deleteResult(result_id) {
            showConfirm(`Permanently delete Result #${result_id} and its job?`, async () => { await apiFetch(`/results/${result_id}`, { method: 'DELETE' }); loadResults(); loadJobs(); }, 'Delete');
        }
        async function loadResults() {
            const isHistory = resultTab === 'history';
            const res = await apiFetch(isHistory ? '/results?show_history=true' : '/results');
            if (!res) return;
            const data = await res.json();
            pageData.results = data.slice().sort((a, b) => b.id - a.id);
            pages.results = 1;
            renderResults();
        }

        function renderResults() {
            const isHistory = resultTab === 'history';
            const data  = pageData.results;
            const paged = getPage('results', data);

            if (!data.length) {
                document.getElementById("results").innerHTML = `<p class="text-gray-500 text-sm">${isHistory ? 'No archived results.' : 'No results yet.'}</p>`;
                return;
            }

            const html = paged.map(r => {
                const out = r.output;
 
                // ── Counts ────────────────────────────────────────────────
                const nmapCount = out.nmap
                    ? out.nmap.reduce((a, h) => a + (h.ports || []).filter(p => p.state === 'open').length, 0)
                    : 0;
                const niktoCount = out.nikto
                    ? Object.values(out.nikto).reduce((a, v) => {
                        if (v.error) return a;
                        if (v.raw) return a + (v.raw.match(/^\+ \[/gm) || []).length;
                        return a + (v[0]?.vulnerabilities?.length || 0);
                      }, 0)
                    : 0;
                const nseCount = out.nse ? (out.nse.findings || []).length : 0;
 
                // ── Risk badge ────────────────────────────────────────────
                let riskBadge = '';
                if (r.analysis) {
                    const rm = r.analysis.match(/##\s*Risk Level\s*\n+(\w+)/i);
                    const riskLevel = rm ? rm[1].toUpperCase() : 'INFO';
                    const riskStyles = {
                        CRITICAL: 'bg-red-900 text-red-200 border-red-700',
                        HIGH:     'bg-orange-900 text-orange-200 border-orange-700',
                        MEDIUM:   'bg-yellow-900 text-yellow-200 border-yellow-700',
                        LOW:      'bg-blue-900 text-blue-200 border-blue-700',
                        INFO:     'bg-gray-800 text-gray-400 border-gray-600',
                    };
                    const riskCls = riskStyles[riskLevel] || riskStyles.INFO;
                    riskBadge = '<span class="text-xs px-2 py-0.5 rounded-full border font-bold tracking-wide flex-shrink-0 ' + riskCls + '">' + riskLevel + '</span>';
                } else {
                    riskBadge = '<span class="text-xs px-2 py-0.5 rounded-full border border-gray-700 text-gray-600 font-medium animate-pulse flex-shrink-0" title="Click Analyse to generate AI risk assessment">unanalysed</span>';
                }
 
                // ── Target label: hostname > IP ───────────────────────────
                let targetLabel = r.job_info ? r.job_info.target : ('Job #' + r.job_id);
                if (out.nmap && out.nmap.length > 0 && out.nmap[0].hostname) {
                    targetLabel = out.nmap[0].hostname;
                }
                const targetEl = '<span class="font-mono text-xs text-green-400 font-semibold flex-shrink-0">' + targetLabel + '</span>';
 
                // ── Finding pills ─────────────────────────────────────────
                const pills = [];
                if (out.nmap !== undefined) {
                    pills.push('<span class="text-xs px-2 py-0.5 rounded-full bg-blue-950 text-blue-300 border border-blue-900 whitespace-nowrap">' + nmapCount + ' open port' + (nmapCount !== 1 ? 's' : '') + '</span>');
                }
                if (niktoCount > 0) {
                    pills.push('<span class="text-xs px-2 py-0.5 rounded-full bg-orange-950 text-orange-300 border border-orange-900 whitespace-nowrap">' + niktoCount + ' web finding' + (niktoCount !== 1 ? 's' : '') + '</span>');
                }
                if (nseCount > 0) {
                    pills.push('<span class="text-xs px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-900 whitespace-nowrap">' + nseCount + ' NSE finding' + (nseCount !== 1 ? 's' : '') + '</span>');
                }
                if (!pills.length && !out.nmap && !out.nse && !out.nikto) {
                    pills.push('<span class="text-xs text-gray-600 italic">no data</span>');
                }
 
                // ── Timestamp ─────────────────────────────────────────────
                const ts = r.job_info ? relativeTime(r.job_info.completed_at) : '';
 
                // ── Scan type label ───────────────────────────────────────
                const scanLabel = SCAN_TYPE_LABELS[r.job_info?.type] || (r.job_info?.type || '');
 
                // ── Actions ───────────────────────────────────────────────
                const actions = isHistory
                    ? '<div class="flex items-center gap-3">'
                      + '<input type="checkbox" class="result-checkbox accent-red-500" data-id="' + r.id + '">'
                      + '<a href="/report/' + r.id + '" target="_blank" class="text-xs text-cyan-400 hover:text-cyan-300 transition">Report</a>'
                      + '<button onclick="deleteResult(' + r.id + ')" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button>'
                      + '</div>'
                    : '<div class="flex items-center gap-3">'
                      + '<input type="checkbox" class="result-checkbox accent-yellow-500" data-id="' + r.id + '">'
                      + '<a href="/report/' + r.id + '" target="_blank" class="text-xs text-cyan-400 hover:text-cyan-300 transition">Report</a>'
                      + '<button onclick="triggerAnalysis(' + r.id + ')" class="text-xs text-purple-400 hover:text-purple-300 transition">Analyse</button>'
                      + '<button onclick="clearResult(' + r.id + ')" class="text-xs text-gray-400 hover:text-red-400 transition">Clear</button>'
                      + '</div>';

                // Build tooltip content
                const tipRisk = r.analysis
                    ? (() => {
                        const rm = r.analysis.match(/##\s*Risk Level\s*\n+(\w+)/i);
                        return rm ? rm[1].toUpperCase() : 'INFO';
                      })()
                    : null;
                const tipRiskStyles = {
                    CRITICAL: 'background:rgba(239,68,68,0.15);color:#fca5a5;border-color:rgba(239,68,68,0.3)',
                    HIGH:     'background:rgba(249,115,22,0.15);color:#fdba74;border-color:rgba(249,115,22,0.3)',
                    MEDIUM:   'background:rgba(234,179,8,0.15);color:#fde047;border-color:rgba(234,179,8,0.3)',
                    LOW:      'background:rgba(59,130,246,0.15);color:#93c5fd;border-color:rgba(59,130,246,0.3)',
                    INFO:     'background:rgba(107,114,128,0.15);color:#9ca3af;border-color:rgba(107,114,128,0.3)',
                };
                const tipRiskBadge = tipRisk
                    ? `<span style="font-size:10px;padding:1px 7px;border-radius:20px;border:1px solid;font-weight:600;${tipRiskStyles[tipRisk] || tipRiskStyles.INFO}">${tipRisk}</span>`
                    : `<span style="font-size:10px;padding:1px 7px;border-radius:20px;border:1px solid;border-color:#374151;color:#4b5563;font-weight:500">UNANALYSED</span>`;
 
                const tipTarget = r.job_info ? r.job_info.target : ('Job #' + r.job_id);
                const tipType   = SCAN_TYPE_LABELS[r.job_info?.type] || (r.job_info?.type || '—');
                const tipTime   = r.job_info ? relativeTime(r.job_info.completed_at) : '';
                const tipPorts  = nmapCount + ' port' + (nmapCount !== 1 ? 's' : '');
                const tipFinds  = (nseCount + niktoCount) + ' finding' + ((nseCount + niktoCount) !== 1 ? 's' : '');
 
                // Build the useful tooltip content:
                // - Open ports list (not visible without expanding)
                // - First sentence of AI analysis (never visible in collapsed state)
                const openPortsList = out.nmap
                    ? out.nmap.flatMap(h => h.ports.filter(p => p.state === 'open'))
                    : [];
 
                let tipPortsHtml = '';
                if (openPortsList.length) {
                    const shown = openPortsList.slice(0, 6);
                    const more  = openPortsList.length - shown.length;
                    tipPortsHtml = '<div style="margin-bottom:6px">'
                        + '<div style="font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:#4b5563;margin-bottom:4px">Open Ports</div>'
                        + '<div style="display:flex;flex-wrap:wrap;gap:4px">'
                        + shown.map(p =>
                            `<span style="font-family:'IBM Plex Mono',monospace;font-size:10px;background:rgba(59,130,246,0.1);color:#93c5fd;border:1px solid rgba(59,130,246,0.2);border-radius:4px;padding:1px 6px">${p.port}<span style="color:#4b5563;font-size:9px"> ${p.service}</span></span>`
                          ).join('')
                        + (more > 0 ? `<span style="font-size:9px;color:#4b5563;align-self:center">+${more} more</span>` : '')
                        + '</div></div>';
                } else if (out.nmap !== undefined) {
                    tipPortsHtml = '<div style="font-size:10px;color:#4b5563;margin-bottom:6px">No open ports found</div>';
                }
 
                let tipAnalysisHtml = '';
                if (r.analysis) {
                    // Extract the Summary section — first meaningful sentence after ## Summary
                    const summaryMatch = r.analysis.match(/##\s*Summary\s*\n+([\s\S]+?)(?=\n##|\\n\*\*|$)/i);
                    if (summaryMatch) {
                        const summaryText = summaryMatch[1].trim().split(/\.\s+/)[0] + '.';
                        tipAnalysisHtml = '<div style="border-top:1px solid #1e2535;padding-top:6px;margin-top:2px">'
                            + '<div style="font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:#4b5563;margin-bottom:3px">AI Summary</div>'
                            + `<div style="font-size:10px;color:#9ca3af;line-height:1.5;white-space:normal">${summaryText}</div>`
                            + '</div>';
                    }
                }
 
                // Only build the tooltip if there's something useful to show
                const hasTipContent = tipPortsHtml || tipAnalysisHtml;
                const tipHtml = hasTipContent ? `
                    <div id="tip-${r.id}" class="result-tooltip">
                        ${tipPortsHtml}
                        ${tipAnalysisHtml}
                    </div>` : `<div id="tip-${r.id}"></div>`;
   
                return '<div class="bg-gray-800 rounded-xl border border-gray-700" style="position:relative">'
                    + tipHtml

                    // ── Collapsed header ──────────────────────────────────
                    + '<div class="flex items-center justify-between px-5 py-3.5 cursor-pointer hover:bg-gray-750 transition" onclick="toggleResult(' + r.id + ')" onmouseenter="showResultTooltip(event,' + r.id + ')" onmouseleave="hideResultTooltip(' + r.id + ')">'
 
                        // Left: id · risk · target · pills
                        + '<div class="flex items-center gap-2.5 flex-wrap min-w-0 pr-2">'
                        +     '<span class="text-sm font-semibold text-white flex-shrink-0">Result #' + r.id + '</span>'
                        +     riskBadge
                        +     targetEl
                        +     '<div class="flex items-center gap-1.5 flex-wrap">' + pills.join('') + '</div>'
                        + '</div>'
 
                        // Right: timestamp · actions · chevron
                        + '<div class="flex items-center gap-3 flex-shrink-0">'
                        +     (ts ? '<span class="text-xs text-gray-600 hidden md:block">' + ts + '</span>' : '')
                        +     '<div onclick="event.stopPropagation()">' + actions + '</div>'
                        +     '<span id="result-arrow-' + r.id + '" class="text-gray-500 text-xs pointer-events-none">▼</span>'
                        + '</div>'
 
                    + '</div>'
 
                    // ── Expanded body ─────────────────────────────────────
                    + '<div id="result-body-' + r.id + '" class="hidden px-5 pb-5 border-t border-gray-700 pt-4">'
                    +     (isHistory ? renderJobInfo(r.job_info) : '')
                    +     (out.nmap  ? '<div class="mb-4"><p class="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">Open Port Scan</p>'          + renderNmapResult(out.nmap)   + '</div>' : '')
                    +     (out.nikto ? '<div class="mb-4"><p class="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-1">Web Scan</p>'         + renderNiktoResult(out.nikto) + '</div>' : '')
                    +     (out.nse   ? '<div class="mb-4"><p class="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-2">Vulnerability Scan</p>' + renderNseResult(out.nse)    + '</div>' : '')
                    +     (!out.nmap && !out.nikto && !out.nse ? '<pre class="text-xs text-gray-400 overflow-x-auto">' + JSON.stringify(out, null, 2) + '</pre>' : '')
                    +     (r.analysis
                            ? '<div class="mb-4">' + renderAnalysis(r.analysis) + '</div>'
                            : '<div class="mb-2"><span class="text-xs text-gray-600 italic">Analysis pending — click Analyse above to generate assessment</span></div>'
                          )
                    + '</div>'

                + '</div>';
            }).join('');
            document.getElementById("results").innerHTML = html + paginationBar('results', data.length);
        }

        // ── DISCOVERY ──────────────────────────────────────────────────────
        function dismissSweepStatus() { document.getElementById("sweepStatus").classList.add('hidden'); }
        function dismissPingResults() { document.getElementById("pingResults").classList.add('hidden'); }

        async function cancelActiveSweep() {
            if (!activeSweepId) return;
            const sweepId = activeSweepId;
            // Stop polling immediately so we don't race with the status update
            if (sweepPollInterval) { clearInterval(sweepPollInterval); sweepPollInterval = null; }
            activeSweepId = null;
            document.getElementById('cancelSweepBtn').classList.add('hidden');
            showSweepStatus('Cancelling sweep…', 'bg-yellow-400 animate-pulse');
            try {
                const res = await apiFetch(`/discover/${sweepId}/cancel`, { method: 'POST' });
                if (res && res.ok) {
                    showSweepStatus('Sweep cancelled.', 'bg-yellow-400');
                } else {
                    showSweepStatus('Cancel request failed — sweep may have already finished.', 'bg-red-500');
                }
            } catch(e) {
                showSweepStatus('Cancel request failed.', 'bg-red-500');
            }
            loadSweepHistory();
        }

        function showSweepStatus(text, color = 'bg-cyan-400') {
            const el = document.getElementById("sweepStatus");
            const spinner = document.getElementById("sweepSpinner");
            el.classList.remove('hidden');
            spinner.className = `w-3 h-3 rounded-full flex-shrink-0 ${color}`;
            document.getElementById("sweepStatusText").textContent = text;
        }

        async function startPing() {
            const subnet = document.getElementById("discoverSubnet").value.trim();
            if (!subnet) { alert("Please enter a subnet in CIDR format (e.g. 192.168.1.0/24)"); return; }
            const btn = document.getElementById("pingBtn");
            btn.disabled = true;
            btn.textContent = 'Pinging…';
            dismissPingResults();
            showSweepStatus(`Pinging ${subnet}…`, 'bg-cyan-400 animate-pulse');
            try {
                const res = await apiFetch('/discover/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subnet }) });
                if (!res) return;
                const data = await res.json();
                showSweepStatus(`Ping complete — ${data.count} host(s) responded`, 'bg-green-400');
                const listEl = document.getElementById("pingResultsList");
                document.getElementById("pingResultsTitle").textContent = `${data.count} host(s) found in ${subnet}`;
                if (data.hosts.length) {
                    listEl.innerHTML = data.hosts.map(h => `<div class="flex items-center gap-3 text-xs py-1 border-b border-gray-700"><span class="font-mono text-green-400 w-36">${h.ip}</span><span class="text-gray-500">${h.hostname || ''}</span></div>`).join('');
                } else {
                    listEl.innerHTML = '<p class="text-xs text-gray-500">No hosts responded to ping.</p>';
                }
                document.getElementById("pingResults").classList.remove('hidden');
            } catch(e) { showSweepStatus('Ping failed. Check server logs.', 'bg-red-500'); }
            finally { btn.disabled = false; btn.textContent = '⬡ Ping'; }
        }

        let sweepPollInterval = null;
        let activeSweepId = null;

        async function startSweep() {
            const subnet = document.getElementById("discoverSubnet").value.trim();
            const mode   = document.getElementById("discoverMode").value;
            const profile = document.getElementById("discoverProfile").value;
            if (!subnet) { alert("Please enter a subnet in CIDR format (e.g. 192.168.1.0/24)"); return; }

            // First ping to find hosts, then show confirmation dialog
            const btn = document.getElementById("sweepBtn");
            btn.disabled = true;
            btn.textContent = 'Scanning…';
            showSweepStatus(`Discovering hosts in ${subnet}…`, 'bg-cyan-400 animate-pulse');

            try {
                const res = await apiFetch('/discover/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subnet }) });
                if (!res) return;
                const data = await res.json();
                dismissSweepStatus();

                if (!data.count) {
                    showSweepStatus(`No hosts found in ${subnet}.`, 'bg-yellow-400');
                    return;
                }

                // Show confirmation dialog — store hosts list for direct job creation path
                pendingSweepPayload = { subnet, hosts: data.hosts };
                // Reset sweep dialog selectors to sensible defaults
                const sweepJobType = document.getElementById('sweepJobType');
                const sweepProfile = document.getElementById('sweepProfile');
                if (sweepJobType) sweepJobType.value = 'nmap_scan';
                if (sweepProfile) sweepProfile.value = 'standard';
                onSweepProfileChange();
                updateSweepConfirmNote();
                document.getElementById("sweepConfirmMsg").textContent = `${data.count} host(s) found in ${subnet}:`;

                // Large-sweep warning — show if host count is high relative to online scanner count
                const LARGE_SWEEP_THRESHOLD = 20;
                const warningEl  = document.getElementById('sweepLargeWarning');
                const warningMsg = document.getElementById('sweepLargeWarningMsg');
                const onlineScanners = (pageData.agents || []).filter(a => a.status === 'online').length;
                if (data.count >= LARGE_SWEEP_THRESHOLD) {
                    const estTime = onlineScanners > 0
                        ? `With ${onlineScanners} scanner(s) online, this could take ${Math.ceil(data.count / onlineScanners)} sequential batches.`
                        : 'No scanners appear to be online.';
                    warningMsg.textContent = `${data.count} jobs will be created. ${estTime}`;
                    warningEl.classList.remove('hidden');
                } else {
                    warningEl.classList.add('hidden');
                }

                const hostListEl = document.getElementById("sweepHostList");
                hostListEl.innerHTML = data.hosts.map(h => `<div class="flex items-center gap-3 text-xs py-1 border-b border-gray-700 last:border-0"><span class="font-mono text-green-400 w-36">${h.ip}</span><span class="text-gray-500">${h.hostname || ''}</span></div>`).join('');
                document.getElementById("sweepConfirmDialog").classList.remove('hidden');

            } catch(e) { showSweepStatus('Discovery failed. Check server logs.', 'bg-red-500'); }
            finally { btn.disabled = false; btn.textContent = '⌖ Sweep'; }
        }

        function cancelSweepConfirm() {
            document.getElementById("sweepConfirmDialog").classList.add('hidden');
            pendingSweepPayload = null;
        }
        
        async function confirmSweep() {
            const jobType  = document.getElementById('sweepJobType')?.value  || 'nmap_scan';
            const profile  = document.getElementById('sweepProfile')?.value  || 'standard';
            const jobMode  = document.getElementById('sweepJobMode')?.value  || 'remote';
            const priority = document.getElementById('sweepJobPriority')?.value || 'medium';

            // Validate custom profile selection
            if (jobType === 'nse_scan' && profile === 'custom') {
                const scripts = getSweepSelectedScripts();
                if (!scripts.length) {
                    document.getElementById('sweepCustomWarning').classList.remove('hidden');
                    return;
                }
                document.getElementById('sweepCustomWarning').classList.add('hidden');
            }

            document.getElementById("sweepConfirmDialog").classList.add('hidden');
            if (!pendingSweepPayload) return;
            const { subnet, hosts } = pendingSweepPayload;
            pendingSweepPayload = null;

            showSweepStatus(`Assigning ${SCAN_TYPE_LABELS[jobType] || jobType} jobs to ${hosts.length} host(s)…`, 'bg-cyan-400 animate-pulse');

            // For custom profile or non-nmap types, create individual jobs directly
            // rather than using the sweep endpoint (which hardcodes nmap_scan).
            if (jobType !== 'nmap_scan' || profile === 'custom') {
                const customScripts = (jobType === 'nse_scan' && profile === 'custom')
                    ? getSweepSelectedScripts()
                    : undefined;

                const results = await Promise.all(hosts.map(h =>
                    apiFetch('/jobs/create', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            type:           jobType,
                            target:         h.ip,
                            mode:           jobMode,
                            profile:        profile,
                            priority:       priority,
                            custom_scripts: customScripts || undefined,
                        }),
                    })
                ));

                const created = results.filter(r => r && r.ok).length;
                showSweepStatus(`Done — ${created} job(s) created across ${hosts.length} host(s)`, 'bg-green-400');
                loadJobs();

                // Reset sweep custom state
                initSweepCapabilityState();
                return;
            }

            // Standard nmap_scan — use the existing sweep endpoint
            const res = await apiFetch('/discover', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subnet, mode: jobMode, profile }) });
            if (!res) return;
            const data = await res.json();

            // Track the active sweep so cancelActiveSweep() knows which one to cancel
            activeSweepId = data.sweep_id;
            document.getElementById('cancelSweepBtn').classList.remove('hidden');

            sweepPollInterval = setInterval(async () => {
                const r = await apiFetch(`/discover/${data.sweep_id}`);
                if (!r) return;
                const s = await r.json();
                if (s.status === 'done') {
                    clearInterval(sweepPollInterval); sweepPollInterval = null;
                    activeSweepId = null;
                    document.getElementById('cancelSweepBtn').classList.add('hidden');
                    showSweepStatus(`Sweep complete — ${s.hosts_found} host(s) found, ${s.jobs_created} job(s) created`, 'bg-green-400');
                    loadSweepHistory(); loadJobs();
                } else if (s.status === 'failed') {
                    clearInterval(sweepPollInterval); sweepPollInterval = null;
                    activeSweepId = null;
                    document.getElementById('cancelSweepBtn').classList.add('hidden');
                    showSweepStatus('Sweep failed. Check server logs.', 'bg-red-500');
                    loadSweepHistory();
                } else if (s.status === 'cancelled') {
                    clearInterval(sweepPollInterval); sweepPollInterval = null;
                    activeSweepId = null;
                    document.getElementById('cancelSweepBtn').classList.add('hidden');
                    showSweepStatus('Sweep cancelled.', 'bg-yellow-400');
                    loadSweepHistory();
                }
            }, 3000);
        }

        async function loadSweepHistory() {
            const res = await apiFetch('/discover');
            if (!res) return;
            const sweeps = await res.json();
            pageData.sweeps = sweeps;
            pages.sweeps = 1;
            renderSweeps();
        }

        function renderSweeps() {
            const el     = document.getElementById("sweepHistory");
            const sweeps = pageData.sweeps;
            if (!sweeps.length) { el.innerHTML = '<p class="text-gray-600 text-xs">No sweeps yet.</p>'; return; }
            const paged = getPage('sweeps', sweeps);
            const statusColor = { running: 'text-blue-400', done: 'text-green-400', failed: 'text-red-400', cancelled: 'text-yellow-400' };
            const rows = paged.map(s => {
                const viewBtn = (s.status === 'done' && s.jobs_created > 0)
                    ? `<button onclick="viewSweepResults(${s.id})" class="text-xs text-cyan-400 hover:text-cyan-300 transition mr-3">View Results</button>`
                    : '';
                return `<tr class="border-b border-gray-800 hover:bg-gray-800 transition text-xs">
                <td class="py-2 pr-4 text-gray-400">#${s.id}</td>
                <td class="py-2 pr-4 font-mono">${s.subnet}</td>
                <td class="py-2 pr-4 ${statusColor[s.status] || 'text-gray-400'}">${s.status}</td>
                <td class="py-2 pr-4 text-gray-300">${s.hosts_found} host(s)</td>
                <td class="py-2 pr-4 text-gray-300">${s.jobs_created} job(s)</td>
                <td class="py-2 pr-4 text-gray-500">${formatTimestamp(s.started_at)}</td>
                <td class="py-2 whitespace-nowrap">${viewBtn}<button onclick="deleteSweep(${s.id})" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button></td></tr>`;
            }).join('');
            el.innerHTML = `<table class="w-full text-sm"><thead>
            <tr class="text-left text-gray-500 border-b border-gray-800">
            <th class="pb-2 pr-4">ID</th><th class="pb-2 pr-4">Subnet</th><th class="pb-2 pr-4">Status</th><th class="pb-2 pr-4">Hosts</th>
            <th class="pb-2 pr-4">Jobs</th><th class="pb-2 pr-4">Started</th>
            <th class="pb-2">Actions</th></tr></thead><tbody>${rows}</tbody></table>`
            + paginationBar('sweeps', sweeps.length);
        }

        async function viewSweepResults(sweepId) {
            const panel = document.getElementById('sweepResultPanel');
            const body  = document.getElementById('sweepResultBody');
            body.innerHTML = '<p class="text-gray-500 text-xs animate-pulse">Loading…</p>';
            panel.classList.remove('hidden');
            activeSweepResultId = sweepId;

            const res = await apiFetch(`/sweeps/${sweepId}/results`);
            if (!res) { body.innerHTML = '<p class="text-red-400 text-xs">Failed to load results.</p>'; return; }
            const data = await res.json();

            document.getElementById('sweepResultTitle').textContent = `Sweep #${data.sweep_id} — ${data.subnet}`;

            // Show Cancel All Jobs button if any jobs are still pending or running
            const hasActiveJobs = data.hosts && data.hosts.some(h => h.status === 'pending' || h.status === 'running');
            const cancelBtn = document.getElementById('sweepCancelJobsBtn');
            if (cancelBtn) cancelBtn.classList.toggle('hidden', !hasActiveJobs);

            if (!data.hosts || data.hosts.length === 0) {
                body.innerHTML = '<p class="text-gray-500 text-xs">No jobs were created for this sweep.</p>';
                return;
            }

            const statusBadge = s => {
                const map = { done: 'text-green-400', pending: 'text-blue-400', running: 'text-cyan-400', failed: 'text-red-400' };
                return `<span class="${map[s] || 'text-gray-400'}">${s}</span>`;
            };

            const rows = data.hosts.map(h => {
                // Summarise open ports if available
                let portSummary = '—';
                if (h.output && h.output.nmap && h.output.nmap.ports) {
                    const open = h.output.nmap.ports.filter(p => p.state === 'open');
                    portSummary = open.length ? open.map(p => `${p.port}/${p.protocol}`).join(', ') : 'None open';
                }

                // Count findings
                let findings = '—';
                if (h.output && h.output.nse) {
                    const f = h.output.nse.findings;
                    findings = Array.isArray(f) ? `${f.length} finding${f.length !== 1 ? 's' : ''}` : '—';
                }

                const resultLink = h.result_id
                    ? `<button onclick="closeSweepResultPanel(); switchTab('results'); setTimeout(()=>{ const el=document.getElementById('result-${h.result_id}'); if(el){ el.scrollIntoView({behavior:'smooth'}); el.classList.add('ring-1','ring-cyan-500'); setTimeout(()=>el.classList.remove('ring-1','ring-cyan-500'),2000); }},300);" class="text-xs text-cyan-400 hover:text-cyan-300 transition">View</button>`
                    : '<span class="text-gray-600 text-xs">—</span>';

                return `<tr class="border-b border-gray-800 hover:bg-gray-800 transition text-xs">
                    <td class="py-2 pr-4 font-mono text-gray-200">${h.target}</td>
                    <td class="py-2 pr-4">${statusBadge(h.status)}</td>
                    <td class="py-2 pr-4 text-gray-400 font-mono text-xs max-w-xs truncate" title="${portSummary}">${portSummary}</td>
                    <td class="py-2 pr-4 text-gray-400">${findings}</td>
                    <td class="py-2 pr-4 text-gray-500">${h.completed_at ? formatTimestamp(h.completed_at) : '—'}</td>
                    <td class="py-2">${resultLink}</td>
                </tr>`;
            }).join('');

            body.innerHTML = `
                <table class="w-full text-sm">
                    <thead><tr class="text-left text-gray-500 border-b border-gray-800 text-xs">
                        <th class="pb-2 pr-4">Host</th>
                        <th class="pb-2 pr-4">Status</th>
                        <th class="pb-2 pr-4">Open Ports</th>
                        <th class="pb-2 pr-4">Findings</th>
                        <th class="pb-2 pr-4">Completed</th>
                        <th class="pb-2">Result</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>`;
        }

        function closeSweepResultPanel() {
            document.getElementById('sweepResultPanel').classList.add('hidden');
            document.getElementById('sweepCancelJobsBtn').classList.add('hidden');
            activeSweepResultId = null;
        }

        let activeSweepResultId = null;

        async function cancelSweepJobs() {
            if (!activeSweepResultId) return;
            showConfirm(
                'Cancel all pending and running jobs from this sweep? This cannot be undone.',
                async () => {
                    const res = await apiFetch(`/sweeps/${activeSweepResultId}/cancel-jobs`, { method: 'POST' });
                    if (!res) return;
                    const data = await res.json();
                    document.getElementById('sweepCancelJobsBtn').classList.add('hidden');
                    // Refresh the panel to show updated statuses
                    viewSweepResults(activeSweepResultId);
                    loadJobs();
                },
                'Cancel All Jobs'
            );
        }

        async function deleteSweep(sweep_id) {
            showConfirm('Delete this sweep record?', async () => { await apiFetch(`/discover/${sweep_id}`, { method: 'DELETE' }); loadSweepHistory(); }, 'Delete');
        }
        async function clearAllSweeps() {
            showConfirm('Delete all sweep history records?', async () => { await apiFetch('/discover', { method: 'DELETE' }); loadSweepHistory(); }, 'Clear All');
        }

        // ── SCHEDULES ──────────────────────────────────────────────────────
        async function loadSchedules() {
            const res = await apiFetch('/schedules');
            if (!res) return;
            const data = await res.json();
            const el = document.getElementById("schedules");
            if (!data.length) { el.innerHTML = '<p class="text-gray-500 text-sm">No schedules yet.</p>'; return; }
            let html = `<table class="w-full text-sm">
            <thead><tr class="text-left text-gray-400 border-b border-gray-800">
            <th class="pb-2 pr-3">Name</th>
            <th class="pb-2 pr-3">Type</th>
            <th class="pb-2 pr-3">Target</th>
            <th class="pb-2 pr-3">Profile</th>
            <th class="pb-2 pr-3">Every</th>
            <th class="pb-2 pr-3">Status</th>
            <th class="pb-2 pr-3">Last Run</th>
            <th class="pb-2 pr-3">Next Run</th>
            <th class="pb-2">Actions</th>
            </tr></thead><tbody>`;
            
            data.forEach(s => {
                const badge = s.paused 
                ? '<span class="text-xs px-2 py-0.5 rounded-full bg-yellow-900 text-yellow-300 border border-yellow-700">paused</span>' 
                : '<span class="text-xs px-2 py-0.5 rounded-full bg-green-900 text-green-300 border border-green-700">active</span>';
                
                const toggle = s.paused 
                ? `<button onclick="resumeSchedule(${s.id})" class="text-xs text-blue-400 hover:text-blue-300 transition">Resume</button>` 
                : `<button onclick="pauseSchedule(${s.id})" class="text-xs text-yellow-400 hover:text-yellow-300 transition">Pause</button>`;
                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition">
                <td class="py-2 pr-3 font-medium text-sm">${s.name}</td>
                <td class="py-2 pr-3 text-xs text-blue-300">${scanTypeLabel(s.type)}</td>
                <td class="py-2 pr-3 font-mono text-xs">${s.target}${s.port ? '<span class="text-gray-600">:' + s.port + '</span>' : ''}</td>
                <td class="py-2 pr-3 text-xs text-gray-300">${s.profile}</td>
                <td class="py-2 pr-3 text-xs text-gray-300">${s.interval_hours}h</td>
                <td class="py-2 pr-3">${badge}</td>
                <td class="py-2 pr-3 text-xs text-gray-400">${formatTimestamp(s.last_run_at)}</td>
                <td class="py-2 pr-3 text-xs text-gray-400">${s.paused ? '—' : formatTimestamp(s.next_run_at)}</td>
                <td class="py-2 flex gap-3">
                ${toggle}
                <button onclick="deleteSchedule(${s.id})" class="text-xs text-red-400 hover:text-red-300 transition">Delete</button></td></tr>`;
            });
            html += '</tbody></table>';
            el.innerHTML = html;
        }
        function onSchedTypeChange() {
            const type = document.getElementById('sched_type').value;
            document.getElementById('schedPortField').style.display = type === 'nikto_scan' ? 'flex' : 'none';
            const targetInput = document.getElementById('sched_target');
            if (targetInput) targetInput.placeholder = type === 'nikto_scan' ? 'IP, hostname, or URL' : 'IP or hostname';
        }
        async function createSchedule() {
            const name = document.getElementById("sched_name").value.trim();
            const target = document.getElementById("sched_target").value.trim();
            const type = document.getElementById("sched_type").value;
            const profile = document.getElementById("sched_profile").value;
            const mode = document.getElementById("sched_mode").value;
            const priority = document.getElementById("sched_priority").value;
            const interval = document.getElementById("sched_interval").value.trim();
            const port = document.getElementById("sched_port")?.value.trim();

            if (!name || !target || !interval) { alert("Name, target, and interval are required."); return; }
            if (parseInt(interval) < 1) { alert("Interval must be at least 1 hour."); return; }

            const payload = { name, target, type, profile, mode, priority, interval_hours: parseInt(interval) };
            if (type === 'nikto_scan' && port) payload.port = parseInt(port);

            const res = await apiFetch('/schedules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
            });

            if (!res) return;

            if (res.status === 400) { const err = await res.json(); alert(`Failed: ${err.detail}`); return; }
            document.getElementById("sched_name").value = "";
            document.getElementById("sched_target").value = "";
            document.getElementById("sched_interval").value = "";
            if (document.getElementById("sched_port")) document.getElementById("sched_port").value = "";
            loadSchedules();
        }
        async function pauseSchedule(id) { await apiFetch(`/schedules/${id}/pause`, { method: 'POST' }); loadSchedules(); }
        async function resumeSchedule(id) { await apiFetch(`/schedules/${id}/resume`, { method: 'POST' }); loadSchedules(); }
        async function deleteSchedule(id) {
            showConfirm('Delete this schedule? Jobs already created are not affected.', async () => { await apiFetch(`/schedules/${id}`, { method: 'DELETE' }); loadSchedules(); }, 'Delete');
        }

        // ── INSIGHTS ───────────────────────────────────────────────────────
        let insightWindow = '7d';
        let insightHost = null;
        let chartActivity = null, chartRisk = null, chartTopHosts = null, chartScanHistory = null;
        let chartScanTypes = null, chartTopPorts = null, chartScanHealth = null;
        // Insight host table pagination (separate from main pageData since it's a sub-view)
        let insightHostsData = [];
        let insightHostPage  = 1;
        const INSIGHT_HOST_PAGE_SIZE = 15;

        function setInsightWindow(w) {
            insightWindow = w;
            document.querySelectorAll('.insight-win').forEach(b => {
                b.style.borderColor = '#374151';
                b.style.color = '#9ca3af';
                b.style.background = '';
            });
            const active = document.getElementById('iw-' + w);
            if (active) {
                active.style.borderColor = '#4ade80';
                active.style.color = '#4ade80';
                active.style.background = 'rgba(74,222,128,0.1)';
            }
            loadInsights();
        }

        function clearInsightHost() {
            insightHost = null;
            document.getElementById('insightHostBreadcrumb').classList.add('hidden');
            document.getElementById('insightScanHistory').classList.add('hidden');
            document.getElementById('insightHostTable').classList.remove('hidden');
            loadInsights();
        }

        function drillIntoHost(ip) {
            insightHost = ip;
            document.getElementById('insightHostLabel').textContent = ip;
            document.getElementById('insightHostBreadcrumb').classList.remove('hidden');
            document.getElementById('insightScanHistory').classList.remove('hidden');
            document.getElementById('insightHostTable').classList.add('hidden');
            loadInsights();
        }

        function riskColour(risk) {
            return {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#3b82f6',INFO:'#6b7280',UNANALYSED:'#374151'}[risk] || '#6b7280';
        }
        function riskBadgeHtml(risk) {
            const cls = {CRITICAL:'bg-red-900 text-red-300 border-red-700',HIGH:'bg-orange-900 text-orange-300 border-orange-700',MEDIUM:'bg-yellow-900 text-yellow-300 border-yellow-700',LOW:'bg-blue-900 text-blue-300 border-blue-700',INFO:'bg-gray-800 text-gray-400 border-gray-600',UNANALYSED:'bg-gray-900 text-gray-600 border-gray-700'}[risk] || 'bg-gray-900 text-gray-600 border-gray-700';
            return `<span class="text-xs px-2 py-0.5 rounded-full border font-semibold ${cls}">${risk}</span>`;
        }

        function destroyChart(ref) { if (ref) { ref.destroy(); } return null; }

        function goPage_insightHosts(n) { insightHostPage = n; renderInsightHostTable(); }

        function renderInsightHostTable() {
            const tbody  = document.getElementById('insightHostTableBody');
            const total  = insightHostsData.length;
            const size   = INSIGHT_HOST_PAGE_SIZE;
            const start  = (insightHostPage - 1) * size;
            const paged  = insightHostsData.slice(start, start + size);

            if (!total) {
                tbody.innerHTML = '<p class="text-xs text-gray-600">No hosts found in this window.</p>';
                return;
            }

            let hostRows = '';
            for (const h of paged) {
                const nameCell = h.hostname
                    ? '<span class="text-gray-300">' + h.hostname + '</span>'
                    : (h.agent_name
                        ? '<span class="text-blue-400">agent: ' + h.agent_name + '</span>'
                        : '<span class="text-gray-700 italic">unknown</span>');
                const macCell  = h.mac ? '<div class="text-gray-600 font-mono text-xs">' + h.mac + '</div>' : '';
                const osCell   = h.os  ? '<div class="text-gray-600 text-xs">' + h.os + '</div>' : '';
                const ipWarn   = h.ip_changed ? ' <span class="text-yellow-500" title="IP changed from ' + (h.previous_ip || '') + '">⚠</span>' : '';
                const lastScan = h.last_scan ? h.last_scan.split('T')[0] : '—';
                const actionCell = h.result_id
                    ? '<div class="flex gap-1.5 flex-wrap">'
                        + '<a href="/report/' + h.result_id + '" target="_blank" '
                        + 'class="text-xs px-2 py-1 rounded bg-cyan-900 hover:bg-cyan-800 text-cyan-300 border border-cyan-800 transition whitespace-nowrap">Report ↗</a>'
                        + '<button onclick="goToResult(' + h.result_id + ')" '
                        + 'class="text-xs px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-green-400 border border-gray-700 transition whitespace-nowrap">→ Result</button>'
                        + '</div>'
                    : '<span class="text-xs text-gray-700 italic">no result</span>';

                hostRows +=
                    '<tr class="border-b border-gray-800 hover:bg-gray-800 transition insight-host-row" data-ip="' + h.ip + '">'
                    + '<td class="py-2 pr-4 cursor-pointer">'
                    +     '<div class="font-mono text-green-400 text-xs">' + h.ip + ipWarn + '</div>' + osCell
                    + '</td>'
                    + '<td class="py-2 pr-4 cursor-pointer">'
                    +     '<div class="text-xs">' + nameCell + '</div>' + macCell
                    + '</td>'
                    + '<td class="py-2 pr-4 text-xs text-gray-300 cursor-pointer">' + h.scan_count + '</td>'
                    + '<td class="py-2 pr-4 text-xs text-gray-300 cursor-pointer">' + h.open_ports + '</td>'
                    + '<td class="py-2 pr-4 text-xs text-gray-300 cursor-pointer">' + h.findings   + '</td>'
                    + '<td class="py-2 pr-4 cursor-pointer">' + riskBadgeHtml(h.risk) + '</td>'
                    + '<td class="py-2 pr-4 text-xs text-gray-500 cursor-pointer">' + lastScan + '</td>'
                    + '<td class="py-2" onclick="event.stopPropagation()">' + actionCell + '</td>'
                    + '</tr>';
            }

            // Pagination bar for insights host table
            const numPages = Math.ceil(total / size);
            let pagBar = '';
            if (numPages > 1) {
                const cur  = insightHostPage;
                const prev = cur > 1 ? `<button onclick="goPage_insightHosts(${cur-1})" class="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition">‹</button>` : '<span class="px-2 py-1 text-xs text-gray-700">‹</span>';
                const next = cur < numPages ? `<button onclick="goPage_insightHosts(${cur+1})" class="px-2 py-1 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition">›</button>` : '<span class="px-2 py-1 text-xs text-gray-700">›</span>';
                const startN = start + 1, endN = Math.min(start + size, total);
                pagBar = `<div class="flex items-center justify-between mt-4 pt-3 border-t border-gray-800">
                    <span class="text-xs text-gray-600">${startN}–${endN} of ${total}</span>
                    <div class="flex items-center gap-1">${prev}
                        <span class="text-xs text-gray-500 px-2">Page ${cur} of ${numPages}</span>
                    ${next}</div></div>`;
            }

            tbody.innerHTML =
                '<table class="w-full text-sm">'
                + '<thead><tr class="text-left text-gray-500 border-b border-gray-800 text-xs">'
                + '<th class="pb-2 pr-4">Host</th>'
                + '<th class="pb-2 pr-4">Identity</th>'
                + '<th class="pb-2 pr-4">Scans</th>'
                + '<th class="pb-2 pr-4">Open Ports</th>'
                + '<th class="pb-2 pr-4">Findings</th>'
                + '<th class="pb-2 pr-4">Risk</th>'
                + '<th class="pb-2 pr-4">Last Scan</th>'
                + '<th class="pb-2">Actions</th>'
                + '</tr></thead>'
                + '<tbody>' + hostRows + '</tbody>'
                + '</table>' + pagBar;
        }

        // Delegated click handler for insight host table rows
        // (avoids inline onclick with escaped quotes which break in Firefox)
        document.addEventListener('click', function(e) {
            const row = e.target.closest('.insight-host-row');
            if (row && !e.target.closest('[onclick]') && !e.target.closest('button') && !e.target.closest('a')) {
                const ip = row.dataset.ip;
                if (ip) drillIntoHost(ip);
            }
        });

        async function loadInsights() {
            // Always sync the active window button styling
            document.querySelectorAll('.insight-win').forEach(b => {
                b.style.borderColor = '#374151';
                b.style.color = '#9ca3af';
                b.style.background = '';
            });
            const activeBtn = document.getElementById('iw-' + insightWindow);
            if (activeBtn) {
                activeBtn.style.borderColor = '#4ade80';
                activeBtn.style.color = '#4ade80';
                activeBtn.style.background = 'rgba(74,222,128,0.1)';
            }

            let url = `/insights?window=${insightWindow}`;
            if (insightHost) url += `&host=${encodeURIComponent(insightHost)}`;
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();

            const isEmpty = data.stats.total_scans === 0;
            document.getElementById('insightEmpty').classList.toggle('hidden', !isEmpty);

            // ── Stat cards ────────────────────────────────────────────────
            const riskSummary = ['CRITICAL','HIGH','MEDIUM','LOW'].map(r =>
                data.stats.risk_counts[r] > 0
                    ? `<span style="color:${riskColour(r)}" class="font-semibold">${data.stats.risk_counts[r]} ${r}</span>`
                    : null
            ).filter(Boolean).join(' · ') || '<span class="text-gray-600">None analysed</span>';

            document.getElementById('insightStats').innerHTML = [
                [insightHost ? 'Scans (this host)' : 'Total Scans', insightHost ? data.stats.total_scans : data.stats.total_scans, 'text-green-400'],
                [insightHost ? 'Host' : 'Unique Hosts', insightHost ? insightHost : data.stats.unique_hosts, 'text-blue-400'],
                ['Open Ports Found', data.stats.total_open_ports, 'text-orange-400'],
            ].map(([label, val, cls]) => `
                <div class="bg-gray-900 rounded-xl border border-gray-800 p-4 text-center">
                    <div class="text-2xl font-bold ${cls}">${val}</div>
                    <div class="text-xs text-gray-500 mt-1 uppercase tracking-wider">${label}</div>
                </div>
            `).join('') + `
                <div class="bg-gray-900 rounded-xl border border-gray-800 p-4 text-center">
                    <div class="text-xs mt-2 leading-relaxed">${riskSummary}</div>
                    <div class="text-xs text-gray-500 mt-1 uppercase tracking-wider">Risk Summary</div>
                </div>`;

            // ── Scan activity bar chart ───────────────────────────────────
            chartActivity = destroyChart(chartActivity);
            const actCtx = document.getElementById('chartActivity').getContext('2d');
            const labels = data.scan_activity.map(d => {
                const parts = d.date.split('-');
                return `${parts[1]}/${parts[2]}`;
            });
            chartActivity = new Chart(actCtx, {
                type: 'bar',
                data: {
                    labels,
                    datasets: [{
                        label: 'Scans',
                        data: data.scan_activity.map(d => d.count),
                        backgroundColor: 'rgba(74,222,128,0.5)',
                        borderColor: '#4ade80',
                        borderWidth: 1,
                        borderRadius: 3,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#6b7280', font: { size: 10 } }, grid: { color: '#1f2937' } },
                        y: { ticks: { color: '#6b7280', font: { size: 10 }, stepSize: 1 }, grid: { color: '#1f2937' }, beginAtZero: true }
                    }
                }
            });

            // ── Risk doughnut chart ───────────────────────────────────────
            chartRisk = destroyChart(chartRisk);
            const riskCtx = document.getElementById('chartRisk').getContext('2d');
            const riskKeys = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNANALYSED'];
            const riskVals = riskKeys.map(k => data.stats.risk_counts[k] || 0);
            const hasRiskData = riskVals.some(v => v > 0);
            chartRisk = new Chart(riskCtx, {
                type: 'doughnut',
                data: {
                    labels: riskKeys,
                    datasets: [{
                        data: hasRiskData ? riskVals : [1],
                        backgroundColor: hasRiskData ? riskKeys.map(riskColour) : ['#1f2937'],
                        borderWidth: 0,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 10 }, boxWidth: 12, padding: 8 } },
                        tooltip: { enabled: hasRiskData }
                    },
                    cutout: '65%'
                }
            });

            // ── Top hosts bar chart ───────────────────────────────────────
            chartTopHosts = destroyChart(chartTopHosts);
            const topCtx = document.getElementById('chartTopHosts').getContext('2d');
            const topHosts = data.hosts.slice(0, 8);
            chartTopHosts = new Chart(topCtx, {
                type: 'bar',
                data: {
                    labels: topHosts.map(h => h.ip),
                    datasets: [{
                        label: 'Findings',
                        data: topHosts.map(h => h.findings),
                        backgroundColor: topHosts.map(h => riskColour(h.risk) + '99'),
                        borderColor: topHosts.map(h => riskColour(h.risk)),
                        borderWidth: 1,
                        borderRadius: 3,
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#6b7280', font: { size: 10 }, stepSize: 1 }, grid: { color: '#1f2937' }, beginAtZero: true },
                        y: { ticks: { color: '#9ca3af', font: { size: 10 } }, grid: { display: false } }
                    }
                }
            });

            // ── Scan type breakdown chart ──────────────────────────────────
            chartScanTypes  = destroyChart(chartScanTypes);
            chartScanHealth = destroyChart(chartScanHealth);
            const stCtx = document.getElementById('chartScanTypes').getContext('2d');
            const stLabels = Object.keys(data.scan_type_counts || {});
            const stVals   = stLabels.map(k => data.scan_type_counts[k]);
            const stColors = ['rgba(74,222,128,0.7)', 'rgba(96,165,250,0.7)', 'rgba(251,146,60,0.7)'];
            chartScanTypes = new Chart(stCtx, {
                type: 'doughnut',
                data: {
                    labels: stLabels,
                    datasets: [{ data: stVals.length ? stVals : [1], backgroundColor: stVals.length ? stColors : ['#1f2937'], borderWidth: 0 }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 10 }, boxWidth: 12, padding: 8 } },
                        tooltip: { enabled: !!stVals.length }
                    },
                    cutout: '60%'
                }
            });

            // ── Port frequency chart ───────────────────────────────────────
            chartTopPorts = destroyChart(chartTopPorts);
            const portCtx  = document.getElementById('chartTopPorts').getContext('2d');
            const portData = (data.top_ports || []).slice(0, 12);
            chartTopPorts = new Chart(portCtx, {
                type: 'bar',
                data: {
                    labels: portData.map(p => p.port),
                    datasets: [{ label: 'Hosts', data: portData.map(p => p.host_count), backgroundColor: 'rgba(96,165,250,0.5)', borderColor: '#60a5fa', borderWidth: 1, borderRadius: 3 }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#6b7280', font: { size: 9 } }, grid: { color: '#1f2937' } },
                        y: { ticks: { color: '#6b7280', font: { size: 10 }, stepSize: 1 }, grid: { color: '#1f2937' }, beginAtZero: true }
                    }
                }
            });

            // ── Scan health chart ──────────────────────────────────────────
            chartScanHealth = destroyChart(chartScanHealth);
            const shCtx = document.getElementById('chartScanHealth').getContext('2d');
            const sh    = data.scan_health || {};
            const shLabels = ['Done', 'Failed', 'Cancelled', 'Pending'];
            const shVals   = [sh.done || 0, sh.failed || 0, sh.cancelled || 0, sh.pending || 0];
            const shColors = ['rgba(74,222,128,0.7)', 'rgba(239,68,68,0.7)', 'rgba(234,179,8,0.7)', 'rgba(96,165,250,0.4)'];
            const shTotal  = shVals.reduce((a, b) => a + b, 0);
            chartScanHealth = new Chart(shCtx, {
                type: 'doughnut',
                data: {
                    labels: shLabels,
                    datasets: [{ data: shTotal ? shVals : [1], backgroundColor: shTotal ? shColors : ['#1f2937'], borderWidth: 0 }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 10 }, boxWidth: 12, padding: 8 } },
                        tooltip: {
                            enabled: !!shTotal,
                            callbacks: {
                                label: ctx => {
                                    const pct = shTotal ? Math.round(ctx.parsed / shTotal * 100) : 0;
                                    return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
                                }
                            }
                        }
                    },
                    cutout: '60%'
                }
            });

            // ── Coverage gaps ──────────────────────────────────────────────
            const gapPanel = document.getElementById('insightCoverageGaps');
            const gapBody  = document.getElementById('insightCoverageGapsBody');
            const gaps = data.coverage_gaps || [];
            if (gaps.length && !insightHost) {
                gapPanel.classList.remove('hidden');
                const shown   = gaps.slice(0, 8);
                const overflow = gaps.length - shown.length;
                gapBody.innerHTML = shown.map(g => {
                    const label = g.days_ago !== null
                        ? `<span class="text-yellow-500">${g.ip}</span><span class="text-yellow-700 ml-1 text-xs">${g.days_ago}d ago</span>`
                        : `<span class="text-orange-400">${g.ip}</span><span class="text-orange-700 ml-1 text-xs">never</span>`;
                    return `<button onclick="drillIntoHost('${g.ip}')" class="flex items-center gap-1 text-xs px-2 py-1 rounded bg-yellow-950 border border-yellow-800 hover:bg-yellow-900 transition">${label}</button>`;
                }).join('')
                + (overflow > 0 ? `<span class="text-xs text-gray-600 self-center">+${overflow} more — run vuln scans to clear them</span>` : '');
            } else {
                gapPanel.classList.add('hidden');
            }

            // ── Host table (paginated) ─────────────────────────────────────
            if (!insightHost) {
                insightHostsData = data.hosts;
                insightHostPage  = 1;
                renderInsightHostTable();
            }

            if (insightHost && data.scan_history.length) {
                // Line chart: open ports over time
                chartScanHistory = destroyChart(chartScanHistory);
                const histCtx = document.getElementById('chartScanHistory').getContext('2d');
                const histLabels = data.scan_history.map(e => e.date || '?');
                chartScanHistory = new Chart(histCtx, {
                    type: 'line',
                    data: {
                        labels: histLabels,
                        datasets: [
                            {
                                label: 'Open Ports',
                                data: data.scan_history.map(e => e.open_ports),
                                borderColor: '#4ade80',
                                backgroundColor: 'rgba(74,222,128,0.1)',
                                tension: 0.3, fill: true, pointRadius: 4,
                            },
                            {
                                label: 'Findings',
                                data: data.scan_history.map(e => e.findings),
                                borderColor: '#f97316',
                                backgroundColor: 'rgba(249,115,22,0.05)',
                                tension: 0.3, fill: true, pointRadius: 4,
                            }
                        ]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#9ca3af', font: { size: 10 }, boxWidth: 12 } } },
                        scales: {
                            x: { ticks: { color: '#6b7280', font: { size: 10 } }, grid: { color: '#1f2937' } },
                            y: { ticks: { color: '#6b7280', font: { size: 10 }, stepSize: 1 }, grid: { color: '#1f2937' }, beginAtZero: true }
                        }
                    }
                });

                // History table — no backticks
                var histRows = '';
                for (var si = 0; si < data.scan_history.length; si++) {
                    var e = data.scan_history[si];
                    var histAction = e.result_id
                        ? '<div class="flex gap-1">'
                          + '<a href="/report/' + e.result_id + '" target="_blank" '
                          + 'class="text-xs px-1.5 py-0.5 rounded bg-cyan-900 hover:bg-cyan-800 text-cyan-300 border border-cyan-800 transition">↗</a>'
                          + '<button onclick="goToResult(' + e.result_id + ')" '
                          + 'class="text-xs px-1.5 py-0.5 rounded bg-gray-800 hover:bg-gray-700 text-green-400 border border-gray-700 transition">→</button>'
                          + '</div>'
                        : '';
                    histRows +=
                        '<tr class="border-b border-gray-800 text-xs">'
                        + '<td class="py-2 pr-4 text-gray-400">'       + (e.date || '—') + '</td>'
                        + '<td class="py-2 pr-4 font-mono text-blue-300">' + e.type           + '</td>'
                        + '<td class="py-2 pr-4 text-blue-300">'           + scanTypeLabel(e.type) + '</td>'
                        + '<td class="py-2 pr-4 text-gray-400">'       + e.profile            + '</td>'
                        + '<td class="py-2 pr-4 text-gray-300">'       + e.open_ports         + '</td>'
                        + '<td class="py-2 pr-4 text-gray-300">'       + e.findings           + '</td>'
                        + '<td class="py-2 pr-4">'                     + riskBadgeHtml(e.risk) + '</td>'
                        + '<td class="py-2">'                          + histAction            + '</td>'
                        + '</tr>';
                }
                document.getElementById('insightScanHistoryTable').innerHTML =
                    '<table class="w-full text-sm">'
                    + '<thead><tr class="text-left text-gray-500 border-b border-gray-800 text-xs">'
                    + '<th class="pb-2 pr-4">Date</th>'
                    + '<th class="pb-2 pr-4">Type</th>'
                    + '<th class="pb-2 pr-4">Profile</th>'
                    + '<th class="pb-2 pr-4">Open Ports</th>'
                    + '<th class="pb-2 pr-4">Findings</th>'
                    + '<th class="pb-2 pr-4">Risk</th>'
                    + '<th class="pb-2">Actions</th>'
                    + '</tr></thead>'
                    + '<tbody>' + histRows + '</tbody>'
                    + '</table>';
            } else if (insightHost) {
                document.getElementById('insightScanHistoryTable').innerHTML = '<p class="text-xs text-gray-600">No scan history for this host in the selected window.</p>';
                chartScanHistory = destroyChart(chartScanHistory);
            }
        }
        
        const RISK_COLOR = {
    CRITICAL:   '#ef4444',
    HIGH:       '#f97316',
    MEDIUM:     '#eab308',
    LOW:        '#3b82f6',
    INFO:       '#6b7280',
    UNANALYSED: '#4b5563',
    UNSCANNED:  '#4ade80',
};
 
const RISK_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNANALYSED', 'UNSCANNED'];
 
function riskColor(risk) {
    return RISK_COLOR[risk] || RISK_COLOR.UNANALYSED;
}
 
        // ── NETWORK MAP ────────────────────────────────────────────────────────

        function setMapFilter(f) {
            mapFilter = f;
            document.querySelectorAll('.map-filter-btn').forEach(b => {
                b.classList.remove('bg-gray-700', 'text-white');
                b.classList.add('text-gray-400');
            });
            const active = document.getElementById('mf-' + f);
            if (active) { active.classList.add('bg-gray-700', 'text-white'); active.classList.remove('text-gray-400'); }
            renderNetworkMap(topoData);
        }

        async function loadTopology() {
            const res = await apiFetch('/topology');
            if (!res) return;
            topoData = await res.json();
            renderNetworkMap(topoData);
        }

        function renderNetworkMap(data) {
            const mapBody  = document.getElementById('mapBody');
            const mapEmpty = document.getElementById('mapEmpty');
            const mapStats = document.getElementById('mapStats');

            if (!data || !data.nodes) return;

            const hosts = data.nodes.filter(n => n.type === 'host');

            // Stats row
            const rc = data.stats.risk_counts || {};
            const statItems = [
                { label: 'Hosts',    val: data.stats.total_hosts,   color: 'text-gray-300' },
                { label: 'Subnets',  val: data.stats.total_subnets, color: 'text-gray-300' },
                { label: 'Critical', val: rc.CRITICAL || 0,         color: 'text-red-400'    },
                { label: 'High',     val: rc.HIGH     || 0,         color: 'text-orange-400' },
                { label: 'Medium',   val: rc.MEDIUM   || 0,         color: 'text-yellow-400' },
            ];
            mapStats.innerHTML = statItems.map(s =>
                `<div class="bg-gray-900 border border-gray-800 rounded-lg px-4 py-2 text-center">
                    <div class="text-lg font-bold ${s.color}">${s.val}</div>
                    <div class="text-xs text-gray-600">${s.label}</div>
                </div>`
            ).join('');

            // Filter hosts
            const filtered = mapFilter === 'all' ? hosts : hosts.filter(h => h.risk === mapFilter);

            if (!filtered.length) {
                mapBody.innerHTML = '';
                mapEmpty.classList.remove('hidden');
                return;
            }
            mapEmpty.classList.add('hidden');

            // Group by subnet
            const bySubnet = {};
            filtered.forEach(h => {
                if (!bySubnet[h.subnet]) bySubnet[h.subnet] = [];
                bySubnet[h.subnet].push(h);
            });

            const riskColor = {
                CRITICAL:   'border-red-600    bg-red-950',
                HIGH:       'border-orange-600 bg-orange-950',
                MEDIUM:     'border-yellow-600 bg-yellow-950',
                LOW:        'border-blue-700   bg-blue-950',
                INFO:       'border-blue-800   bg-blue-950',
                UNANALYSED: 'border-gray-700   bg-gray-900',
                UNSCANNED:  'border-green-800  bg-green-950',
            };
            const riskDot = {
                CRITICAL:   'bg-red-500',
                HIGH:       'bg-orange-500',
                MEDIUM:     'bg-yellow-400',
                LOW:        'bg-blue-400',
                INFO:       'bg-blue-400',
                UNANALYSED: 'bg-gray-500',
                UNSCANNED:  'bg-green-500',
            };

            mapBody.innerHTML = Object.entries(bySubnet)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([subnet, subHosts]) => {
                    const cards = subHosts
                        .sort((a, b) => {
                            // Sort by risk severity then IP
                            const order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNANALYSED','UNSCANNED'];
                            return (order.indexOf(a.risk) - order.indexOf(b.risk)) || a.ip.localeCompare(b.ip);
                        })
                        .map(h => {
                            const borderBg   = riskColor[h.risk] || riskColor.UNANALYSED;
                            const dot        = riskDot[h.risk]   || 'bg-gray-500';
                            const agentRing  = h.is_agent ? 'ring-1 ring-cyan-400' : '';
                            const portList   = h.open_ports.slice(0, 5).map(p =>
                                `<span class="font-mono text-xs text-gray-500">${p.port}</span>`
                            ).join(' ');
                            const moreports  = h.open_ports.length > 5
                                ? `<span class="text-xs text-gray-700">+${h.open_ports.length - 5}</span>` : '';
                            const findings   = (h.nse_findings + h.nikto_findings);
                            const findBadge  = findings
                                ? `<span class="text-xs px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-900">${findings} finding${findings>1?'s':''}</span>` : '';
                            const scanDate   = h.last_scan_at ? h.last_scan_at.split('T')[0] : '—';
                            const resultBtn  = h.result_id
                                ? `<button onclick="goToResult(${h.result_id})" class="text-xs text-green-400 hover:text-green-300 transition">→ Result</button>` : '';
                            const scanBtn    = `<button onclick="createJobFromTopo('${h.ip}')" class="text-xs text-gray-500 hover:text-gray-300 transition">+ Scan</button>`;

                            return `<div class="border rounded-lg p-3 ${borderBg} ${agentRing} min-w-0">
                                <div class="flex items-start justify-between gap-2 mb-2">
                                    <div class="min-w-0">
                                        <div class="flex items-center gap-1.5">
                                            <span class="w-2 h-2 rounded-full flex-shrink-0 ${dot}"></span>
                                            <span class="font-mono text-xs font-semibold text-gray-200 truncate">${h.ip}</span>
                                            ${h.is_agent ? '<span class="text-xs text-cyan-500" title="Agent host">⬡</span>' : ''}
                                        </div>
                                        ${h.hostname ? `<div class="text-xs text-gray-500 truncate mt-0.5 pl-3.5">${h.hostname}</div>` : ''}
                                        ${h.os ? `<div class="text-xs text-gray-600 truncate pl-3.5">${h.os}</div>` : ''}
                                    </div>
                                    ${findBadge}
                                </div>
                                ${h.port_count ? `<div class="flex flex-wrap gap-1 mb-2">${portList}${moreports}</div>` : '<div class="text-xs text-gray-700 mb-2 italic">no open ports</div>'}
                                <div class="flex items-center justify-between">
                                    <span class="text-xs text-gray-700">${scanDate}</span>
                                    <div class="flex gap-2">${resultBtn}${scanBtn}</div>
                                </div>
                            </div>`;
                        }).join('');

                    return `<div class="bg-gray-900 border border-gray-800 rounded-xl p-4">
                        <div class="flex items-center gap-2 mb-4">
                            <span class="font-mono text-xs font-semibold text-cyan-400">${subnet}</span>
                            <span class="text-xs text-gray-600">${subHosts.length} host${subHosts.length!==1?'s':''}</span>
                        </div>
                        <div class="grid gap-3" style="grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));">
                            ${cards}
                        </div>
                    </div>`;
                }).join('');
        }

        function createJobFromTopo(ip) {
            switchTab('dashboard');
            document.getElementById('target').value = ip;
            document.getElementById('target').focus();
            document.getElementById('target').style.borderColor = '#4ade80';
            setTimeout(() => document.getElementById('target').style.borderColor = '', 1500);
        }


        initSettings();

        