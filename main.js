/*
 * Nmap Syntax Highlight Plugin for Obsidian
 * Highlights key elements of nmap scan output for CTF/pentesting workflows
 */

const { Plugin, PluginSettingTab, Setting } = require('obsidian');

const DEFAULT_SETTINGS = {
    highlightOpenPorts: true,
    highlightClosedPorts: true,
    highlightFilteredPorts: true,
    highlightServices: true,
    highlightVersions: true,
    highlightOsDetection: true,
    highlightScriptOutput: true,
    highlightVulnerabilities: true,
    highlightIpAddresses: true,
    highlightIPv6Addresses: true,
    highlightHostnames: true,
    highlightCriticalPorts: true,
    highlightTraceroute: true,
    highlightRdns: true,
    highlightCpe: true,
    highlightReasons: true,
    severityHighlighting: true,
    highlightWarnings: true,
    highlightTiming: true,
    showSummary: true,
    summaryPosition: 'after',
    showCopyButton: true,
    showLineNumbers: false,
    showFilterToolbar: true,
    colorBlindMode: false,
    customCriticalPorts: ''
};

// Critical ports commonly targeted in pentesting/CTFs
const CRITICAL_PORTS = [
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    88,    // Kerberos
    110,   // POP3
    111,   // RPCbind
    135,   // MSRPC
    139,   // NetBIOS
    143,   // IMAP
    389,   // LDAP
    443,   // HTTPS
    445,   // SMB
    465,   // SMTPS
    514,   // Syslog
    587,   // SMTP Submission
    636,   // LDAPS
    993,   // IMAPS
    995,   // POP3S
    1080,  // SOCKS
    1433,  // MSSQL
    1521,  // Oracle
    2049,  // NFS
    2121,  // FTP alternate
    3306,  // MySQL
    3389,  // RDP
    5432,  // PostgreSQL
    5900,  // VNC
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    6379,  // Redis
    8000,  // HTTP alternate
    8080,  // HTTP proxy
    8443,  // HTTPS alternate
    8888,  // HTTP alternate
    9200,  // Elasticsearch
    27017, // MongoDB
    27018, // MongoDB
    28017  // MongoDB Web
];

// IPv6 regex pattern - matches standard IPv6 formats
const IPV6_PATTERN = /(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))(?:%[0-9a-zA-Z]+)?/g;

// Validated IPv4 pattern (0-255 range)
const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

// Vulnerability patterns (CVE supports 4+ digit IDs for modern CVEs like CVE-2024-12345)
const VULN_PATTERN = /VULNERABLE|CRITICAL|HIGH|MEDIUM|LOW|CVE-\d{4}-\d{4,}|MS\d{2,4}-\d{3,4}|ADV\d{6}|CWE-\d+|EXPLOIT|\[\!\]|\[\+\]|CVSS/i;

// Host extraction patterns for /etc/hosts generation
const HOST_PATTERNS = {
    scanReportWithHostname: /^Nmap scan report for\s+([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9])\s+\(([0-9a-fA-F:.]+)\)$/i,
    scanReportIpOnly: /^Nmap scan report for\s+([0-9a-fA-F:.]+)$/i,
    rdnsRecord: /^rDNS record for\s+([0-9a-fA-F:.]+):\s+([a-zA-Z0-9][-a-zA-Z0-9.]+)$/i,
    serviceInfoHost: /Service Info:.*?Host:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    smbDomain: /\|\s*Domain name:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    fqdn: /\|\s*FQDN:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    sslCommonName: /\|\s*(?:Subject|commonName).*?CN[=:]([a-zA-Z0-9][-a-zA-Z0-9.*]+)/i,
    // SSL cert with commonName= format (nmap ssl-cert script)
    sslCommonNameAlt: /commonName=([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    dnsHostnames: /\|\s*DNS:([a-zA-Z0-9][-a-zA-Z0-9.]+)/gi,
    // NetBIOS/SMB hostname patterns
    netbiosName: /\|\s*NetBIOS name:\s*([a-zA-Z0-9][-a-zA-Z0-9]*)/i,
    computerName: /\|\s*Computer name:\s*([a-zA-Z0-9][-a-zA-Z0-9]*)/i,
    netbiosComputerName: /\|\s*NetBIOS computer name:\s*([a-zA-Z0-9][-a-zA-Z0-9]*)(?:\\x00)?/i,
    // RDP NTLM info patterns (rdp-ntlm-info script)
    rdpDnsComputerName: /\|\s*DNS_Computer_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    rdpDnsDomainName: /\|\s*DNS_Domain_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    rdpDnsTreeName: /\|\s*DNS_Tree_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    rdpNetbiosComputerName: /\|\s*NetBIOS_Computer_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9]*)/i,
    rdpNetbiosDomainName: /\|\s*NetBIOS_Domain_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9]*)/i,
    // Generic NTLM authentication patterns (http-ntlm-info, smtp-ntlm-info, etc.)
    ntlmTargetName: /\|\s*Target_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9]*)/i,
    ntlmDnsDomainName: /\|\s*DNS_Domain_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    ntlmDnsComputerName: /\|\s*DNS_Computer_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    ntlmDnsTreeName: /\|\s*DNS_Tree_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    ntlmNetbiosDomainName: /\|\s*NetBIOS_Domain_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9]*)/i,
    ntlmNetbiosComputerName: /\|\s*NetBIOS_Computer_Name:\s*([a-zA-Z0-9][-a-zA-Z0-9]*)/i,
    // Kerberos realm patterns
    kerberosRealm: /\|\s*(?:Kerberos\s+)?[Rr]ealm:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    kerberosDomain: /\|\s*krb5.*?:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+@)?([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    msKerberos: /\|\s*Kerberos:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+)/i,
    // Certificate Subject Alternative Name (SAN) patterns
    sanDns: /\|\s*(?:Subject Alternative Name|subjectAltName).*?DNS:([a-zA-Z0-9][-a-zA-Z0-9.*]+)/gi,
    sanDnsMultiple: /DNS:([a-zA-Z0-9][-a-zA-Z0-9.*]+)/gi,
    sslAltNames: /\|\s*(?:DNS|dns)=([a-zA-Z0-9][-a-zA-Z0-9.]+)/gi,
    // DNS TXT record patterns
    dnsTxtSpf: /\|\s*(?:SPF|spf).*?include:([a-zA-Z0-9][-a-zA-Z0-9.]+)/gi,
    dnsTxtDmarc: /\|\s*(?:DMARC|dmarc).*?(?:rua|ruf)=mailto:[^@]+@([a-zA-Z0-9][-a-zA-Z0-9.]+)/gi,
    dnsTxtGeneric: /\|\s*[Tt][Xx][Tt].*?(?:domain|host|server)[=:]([a-zA-Z0-9][-a-zA-Z0-9.]+)/gi
};

// Helper: validate hostname (allows single-label names like NetBIOS names)
function isValidHostname(hostname) {
    if (!hostname || hostname.length === 0 || hostname.length > 253) return false;
    // Reject if it looks like an IPv4 address (all digits and dots)
    if (/^[0-9.]+$/.test(hostname)) return false;
    // Reject if it looks like an IPv6 address (hex digits with colons - must have at least one colon)
    if (hostname.includes(':') && /^[0-9a-fA-F:]+$/.test(hostname)) return false;
    if (hostname.startsWith('*')) return false; // Skip wildcards
    // Allow single-label names (NetBIOS/computer names) and FQDNs
    return /^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$/.test(hostname) || /^[a-zA-Z0-9]+$/.test(hostname);
}

// Helper: validate IP address
function isValidIP(ip) {
    const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4.test(ip)) return true;
    // Simplified IPv6 check
    return ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip);
}

// Extract parent domain from FQDN (e.g., "dc01.htb.local" -> "htb.local")
function extractParentDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length >= 3) {
        return parts.slice(1).join('.');
    }
    return null;
}

class NmapSyntaxHighlightPlugin extends Plugin {
    async onload() {
        await this.loadSettings();

        // Register the nmap code block processor
        this.registerMarkdownCodeBlockProcessor('nmap', (source, el, ctx) => {
            this.processNmapBlock(source, el);
        });

        // Also register 'nmap-scan' as an alias
        this.registerMarkdownCodeBlockProcessor('nmap-scan', (source, el, ctx) => {
            this.processNmapBlock(source, el);
        });

        // Add settings tab
        this.addSettingTab(new NmapSettingTab(this.app, this));
    }

    /**
     * Called when the plugin is disabled.
     * DOM elements created by code block processors are automatically
     * removed by Obsidian when views are unloaded or plugin is disabled.
     */
    onunload() {
        console.log('Nmap Syntax Highlight: Plugin unloaded');
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    }

    async saveSettings() {
        await this.saveData(this.settings);
        // Refresh all markdown views to apply new settings
        this.refreshAllViews();
    }

    // Refresh all markdown views to re-render code blocks with new settings
    refreshAllViews() {
        // Get all markdown leaves and trigger a re-render
        this.app.workspace.iterateAllLeaves((leaf) => {
            if (leaf.view && leaf.view.getViewType() === 'markdown') {
                const view = leaf.view;
                // Try multiple refresh approaches for maximum compatibility

                // Method 1: Rerender the preview mode if available
                if (view.previewMode && view.previewMode.rerender) {
                    view.previewMode.rerender(true);
                }

                // Method 2: For reading view, try to refresh via state
                if (view.getState && view.setState) {
                    const state = view.getState();
                    if (state) {
                        view.setState(state, { history: false });
                    }
                }
            }
        });

        // Also trigger a layout change event as a fallback
        this.app.workspace.trigger('layout-change');
    }

    /**
     * Classifies a line by its type for filtering purposes.
     * @param {string} line - The line to classify
     * @returns {string} The line type (header, port-open, port-closed, etc.)
     */
    getLineType(line) {
        // Warning/Error/Note lines
        if (/^Warning:/i.test(line)) {
            return 'warning';
        }
        if (/^ERROR:|^RTTVAR/i.test(line)) {
            return 'error';
        }
        if (/^Note:/i.test(line) || /^#/.test(line)) {
            return 'note';
        }
        // Timing/Statistics lines
        if (/^Stats:|scanned in|hosts? up|elapsed|remaining/i.test(line)) {
            return 'timing';
        }
        // Header lines
        if (/^(Nmap scan report|Starting Nmap|Nmap done|Host is|PORT\s+STATE|Service detection|Not shown:)/i.test(line)) {
            return 'header';
        }
        // Traceroute
        if (/^TRACEROUTE/i.test(line)) {
            return 'traceroute';
        }
        // Tightened pattern: limit hop to 1-2 digits, timing samples to 1-3
        const tracerouteMatch = line.match(/^\s*(\d{1,2})\s+((?:[\d.]+\s*ms|--|\*)\s+){1,3}(.+)$/);
        if (tracerouteMatch) {
            return 'traceroute';
        }
        // rDNS
        if (/^(rDNS record for)/i.test(line)) {
            return 'rdns';
        }
        // Script output
        if (/^\|/.test(line)) {
            // Check for vulnerability in script output
            if (VULN_PATTERN.test(line)) {
                return 'vuln';
            }
            return 'script';
        }
        // Port lines - determine state
        const portMatch = line.match(/^(\d+)\/(tcp|udp|sctp)\s+(open|closed|filtered|open\|filtered|unfiltered|closed\|filtered)/i);
        if (portMatch) {
            const state = portMatch[3].toLowerCase();
            if (state === 'open') return 'port-open';
            if (state === 'closed') return 'port-closed';
            return 'port-filtered';
        }
        // OS detection
        if (/^(OS:|OS details:|Running:|Aggressive OS guesses:|Device type:)/i.test(line)) {
            return 'os';
        }
        // MAC Address
        if (/^MAC Address:/i.test(line)) {
            return 'mac';
        }
        // Service Info
        if (/^Service Info:/i.test(line)) {
            return 'service-info';
        }
        // Vulnerability indicators
        if (VULN_PATTERN.test(line)) {
            return 'vuln';
        }
        // Host script results header
        if (/^Host script results:/i.test(line)) {
            return 'script';
        }
        return 'other';
    }

    // Get combined critical ports (default + custom)
    getCriticalPorts() {
        const ports = [...CRITICAL_PORTS];
        if (this.settings.customCriticalPorts) {
            const customPorts = this.settings.customCriticalPorts
                .split(',')
                .map(p => parseInt(p.trim()))
                .filter(p => !isNaN(p) && p > 0 && p <= 65535);
            customPorts.forEach(p => {
                if (!ports.includes(p)) ports.push(p);
            });
        }
        return ports;
    }

    /**
     * Processes an nmap code block, applying syntax highlighting and UI elements.
     * @param {string} source - The raw nmap output text
     * @param {HTMLElement} el - The container element to render into
     */
    processNmapBlock(source, el) {
        // Apply colorblind class if enabled
        const containerClasses = this.settings.colorBlindMode ? 'nmap-output nmap-colorblind' : 'nmap-output';
        const container = el.createDiv({ cls: containerClasses });

        // Split lines once for reuse (avoids duplicate splits)
        const lines = source.split('\n');

        // Parse and collect summary data
        const summaryData = this.settings.showSummary ? this.collectSummaryData(lines) : null;

        // Show summary before if configured
        if (summaryData && this.settings.summaryPosition === 'before') {
            this.renderSummary(container, summaryData);
        }

        // Create the highlighted output
        const pre = container.createEl('pre', { cls: 'nmap-pre' });

        // Add copy button if enabled
        if (this.settings.showCopyButton) {
            const copyBtn = pre.createEl('button', {
                text: 'Copy',
                cls: 'nmap-copy-button'
            });
            copyBtn.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(source);
                    copyBtn.textContent = 'Copied!';
                    copyBtn.classList.add('copied');
                    setTimeout(() => {
                        copyBtn.textContent = 'Copy';
                        copyBtn.classList.remove('copied');
                    }, 2000);
                } catch (err) {
                    console.error('Nmap Syntax Highlight: Failed to copy to clipboard', err);
                    copyBtn.textContent = 'Failed';
                    setTimeout(() => {
                        copyBtn.textContent = 'Copy';
                    }, 2000);
                }
            });
        }

        // Analyze lines to determine which filter buttons to show (reusing cached lines)
        const lineTypes = lines.map(line => this.getLineType(line));
        const hasTypes = {
            script: lineTypes.includes('script'),
            'port-closed': lineTypes.includes('port-closed'),
            'port-filtered': lineTypes.includes('port-filtered'),
            os: lineTypes.includes('os'),
            traceroute: lineTypes.includes('traceroute'),
            vuln: lineTypes.includes('vuln')
        };

        // Track hidden types
        const hiddenTypes = new Set();

        // Add filter toolbar if enabled and there's something to filter
        if (this.settings.showFilterToolbar && Object.values(hasTypes).some(v => v)) {
            const toolbar = pre.createDiv({ cls: 'nmap-filter-toolbar' });

            const filterLabel = toolbar.createSpan({ text: 'Filter:', cls: 'nmap-filter-label' });

            const filters = [
                { type: 'script', label: 'Scripts', has: hasTypes.script },
                { type: 'port-closed', label: 'Closed', has: hasTypes['port-closed'] },
                { type: 'port-filtered', label: 'Filtered', has: hasTypes['port-filtered'] },
                { type: 'os', label: 'OS', has: hasTypes.os },
                { type: 'traceroute', label: 'Traceroute', has: hasTypes.traceroute },
                { type: 'vuln', label: 'Vulns', has: hasTypes.vuln }
            ];

            filters.forEach(filter => {
                if (!filter.has) return;

                const btn = toolbar.createEl('button', {
                    text: filter.label,
                    cls: 'nmap-filter-btn active'
                });
                btn.dataset.filterType = filter.type;

                btn.addEventListener('click', () => {
                    btn.classList.toggle('active');
                    const isActive = btn.classList.contains('active');

                    if (isActive) {
                        hiddenTypes.delete(filter.type);
                    } else {
                        hiddenTypes.add(filter.type);
                    }

                    // Update visibility of all lines with this type
                    const linesToToggle = pre.querySelectorAll(`[data-line-type="${filter.type}"]`);
                    linesToToggle.forEach(lineEl => {
                        if (isActive) {
                            lineEl.classList.remove('nmap-line-hidden');
                            // Also show the br after it if exists
                            if (lineEl.nextElementSibling?.tagName === 'BR') {
                                lineEl.nextElementSibling.classList.remove('nmap-line-hidden');
                            }
                        } else {
                            lineEl.classList.add('nmap-line-hidden');
                            if (lineEl.nextElementSibling?.tagName === 'BR') {
                                lineEl.nextElementSibling.classList.add('nmap-line-hidden');
                            }
                        }
                    });
                });
            });
        }

        const code = pre.createEl('code', { cls: 'nmap-code' });

        lines.forEach((line, index) => {
            const lineType = lineTypes[index];

            if (this.settings.showLineNumbers) {
                const lineContainer = code.createDiv({
                    cls: 'nmap-line-numbered',
                    attr: { 'data-line-type': lineType }
                });
                const lineNum = lineContainer.createSpan({
                    text: String(index + 1),
                    cls: 'nmap-line-number'
                });
                const lineEl = lineContainer.createSpan({ cls: 'nmap-line' });
                this.highlightLine(line, lineEl);
            } else {
                const lineEl = code.createDiv({
                    cls: 'nmap-line',
                    attr: { 'data-line-type': lineType }
                });
                this.highlightLine(line, lineEl);
            }
            if (index < lines.length - 1) {
                code.createEl('br');
            }
        });

        // Show summary after if configured
        if (summaryData && this.settings.summaryPosition === 'after') {
            this.renderSummary(container, summaryData);
        }
    }

    /**
     * Applies syntax highlighting to a single line of nmap output.
     * Dispatches to specific highlight handlers based on line content.
     * @param {string} line - The line to highlight
     * @param {HTMLElement} lineEl - The element to render highlighted content into
     */
    highlightLine(line, lineEl) {
        // Warning lines
        if (/^Warning:/i.test(line) && this.settings.highlightWarnings) {
            lineEl.createSpan({ text: line, cls: 'nmap-warning' });
            return;
        }

        // Error lines
        if (/^ERROR:|^RTTVAR/i.test(line) && this.settings.highlightWarnings) {
            lineEl.createSpan({ text: line, cls: 'nmap-error' });
            return;
        }

        // Note/comment lines
        if (/^Note:/i.test(line) || /^#/.test(line)) {
            lineEl.createSpan({ text: line, cls: 'nmap-note' });
            return;
        }

        // Timing/Statistics lines
        if (this.settings.highlightTiming) {
            // "Nmap done" with timing info
            const doneMatch = line.match(/^(Nmap done:?\s*)(.+?\s+scanned\s+in\s+)([\d.]+\s*(?:seconds?|s))(.*)$/i);
            if (doneMatch) {
                lineEl.createSpan({ text: doneMatch[1], cls: 'nmap-header' });
                lineEl.createSpan({ text: doneMatch[2] });
                lineEl.createSpan({ text: doneMatch[3], cls: 'nmap-timing' });
                if (doneMatch[4]) lineEl.createSpan({ text: doneMatch[4] });
                return;
            }

            // Stats lines
            if (/^Stats:/i.test(line)) {
                lineEl.createSpan({ text: line, cls: 'nmap-stats' });
                return;
            }
        }

        // Host is up/down with latency
        const hostUpMatch = line.match(/^(Host is\s+)(up|down)(\s*\(([^)]+)\))?(.*)$/i);
        if (hostUpMatch) {
            lineEl.createSpan({ text: hostUpMatch[1], cls: 'nmap-header' });
            const statusClass = hostUpMatch[2].toLowerCase() === 'up' ? 'nmap-host-up' : 'nmap-host-down';
            lineEl.createSpan({ text: hostUpMatch[2], cls: statusClass });
            if (hostUpMatch[3]) {
                lineEl.createSpan({ text: ' (' });
                lineEl.createSpan({ text: hostUpMatch[4], cls: 'nmap-latency' });
                lineEl.createSpan({ text: ')' });
            }
            if (hostUpMatch[5]) lineEl.createSpan({ text: hostUpMatch[5] });
            return;
        }

        // Header lines (Nmap scan report, Starting Nmap, etc.)
        if (/^(Nmap scan report|Starting Nmap|Nmap done|PORT\s+STATE|Service detection|Not shown:)/i.test(line)) {
            lineEl.createSpan({ text: line, cls: 'nmap-header' });
            return;
        }

        // Traceroute header
        if (/^TRACEROUTE/i.test(line) && this.settings.highlightTraceroute) {
            lineEl.createSpan({ text: line, cls: 'nmap-header' });
            return;
        }

        // Traceroute hop lines (limit hop to 1-2 digits, timing samples to 1-3)
        const tracerouteMatch = line.match(/^\s*(\d{1,2})\s+((?:[\d.]+\s*ms|--|\*)\s+){1,3}(.+)$/);
        if (tracerouteMatch && this.settings.highlightTraceroute) {
            this.highlightTracerouteLine(line, lineEl);
            return;
        }

        // rDNS lines
        const rdnsMatch = line.match(/^(rDNS record for)\s+(\S+):\s+(.+)$/i);
        if (rdnsMatch && this.settings.highlightRdns) {
            this.highlightRdnsLine(rdnsMatch, lineEl);
            return;
        }

        // Script output headers (NSE scripts)
        if (/^\|/.test(line)) {
            if (this.settings.highlightScriptOutput) {
                this.highlightScriptLine(line, lineEl);
            } else {
                lineEl.createSpan({ text: line, cls: 'nmap-script' });
            }
            return;
        }

        // Port lines with reason (e.g., "22/tcp open syn-ack ssh")
        const portWithReasonMatch = line.match(/^(\d+)\/(tcp|udp|sctp)\s+(open|closed|filtered|open\|filtered|unfiltered|closed\|filtered)\s+([\w-]+)\s+(.*)$/i);
        if (portWithReasonMatch) {
            this.highlightPortLineWithReason(portWithReasonMatch, lineEl);
            return;
        }

        // Port lines (e.g., "22/tcp open ssh OpenSSH 8.2p1")
        const portMatch = line.match(/^(\d+)\/(tcp|udp|sctp)\s+(open|closed|filtered|open\|filtered|unfiltered|closed\|filtered)(.*)$/i);
        if (portMatch) {
            this.highlightPortLine(portMatch, lineEl);
            return;
        }

        // OS detection lines
        if (/^(OS:|OS details:|Running:|Aggressive OS guesses:|Device type:)/i.test(line)) {
            if (this.settings.highlightOsDetection) {
                lineEl.createSpan({ text: line, cls: 'nmap-os' });
            } else {
                lineEl.createSpan({ text: line });
            }
            return;
        }

        // MAC Address lines
        if (/^MAC Address:/i.test(line)) {
            this.highlightMacLine(line, lineEl);
            return;
        }

        // Service Info lines
        if (/^Service Info:/i.test(line)) {
            lineEl.createSpan({ text: line, cls: 'nmap-service-info' });
            return;
        }

        // Vulnerability indicators
        if (this.settings.highlightVulnerabilities && VULN_PATTERN.test(line)) {
            this.highlightVulnerabilityLine(line, lineEl);
            return;
        }

        // Default: apply inline highlighting for IPs and hostnames
        this.highlightInlineElements(line, lineEl);
    }

    highlightPortLine(match, lineEl) {
        const [fullMatch, port, protocol, state, rest] = match;
        const portNum = parseInt(port);
        const isCritical = this.getCriticalPorts().includes(portNum);

        // Port number
        const portClass = isCritical && this.settings.highlightCriticalPorts ? 'nmap-port-critical' : 'nmap-port';
        lineEl.createSpan({ text: port, cls: portClass });
        lineEl.createSpan({ text: '/' });
        lineEl.createSpan({ text: protocol, cls: 'nmap-protocol' });
        lineEl.createSpan({ text: ' ' });

        // State
        const stateClass = this.getStateClass(state);
        lineEl.createSpan({ text: state, cls: stateClass });

        // Rest of the line (service, version, etc.)
        if (rest) {
            this.highlightServiceVersion(rest.trim(), lineEl);
        }
    }

    highlightPortLineWithReason(match, lineEl) {
        const [fullMatch, port, protocol, state, reason, rest] = match;
        const portNum = parseInt(port);
        const isCritical = this.getCriticalPorts().includes(portNum);

        // Port number
        const portClass = isCritical && this.settings.highlightCriticalPorts ? 'nmap-port-critical' : 'nmap-port';
        lineEl.createSpan({ text: port, cls: portClass });
        lineEl.createSpan({ text: '/' });
        lineEl.createSpan({ text: protocol, cls: 'nmap-protocol' });
        lineEl.createSpan({ text: ' ' });

        // State
        const stateClass = this.getStateClass(state);
        lineEl.createSpan({ text: state, cls: stateClass });
        lineEl.createSpan({ text: ' ' });

        // Reason
        if (this.settings.highlightReasons) {
            lineEl.createSpan({ text: reason, cls: 'nmap-reason' });
        } else {
            lineEl.createSpan({ text: reason });
        }

        // Rest of the line (service, version, etc.)
        if (rest) {
            this.highlightServiceVersion(rest.trim(), lineEl);
        }
    }

    getStateClass(state) {
        const stateLower = state.toLowerCase();
        if (stateLower === 'open' && this.settings.highlightOpenPorts) {
            return 'nmap-state-open';
        } else if (stateLower === 'closed' && this.settings.highlightClosedPorts) {
            return 'nmap-state-closed';
        } else if ((stateLower === 'filtered' || stateLower === 'open|filtered' || stateLower === 'closed|filtered') && this.settings.highlightFilteredPorts) {
            return 'nmap-state-filtered';
        } else if (stateLower === 'unfiltered') {
            return 'nmap-state-filtered'; // Use filtered style for unfiltered too
        }
        return 'nmap-state';
    }

    highlightServiceVersion(text, lineEl) {
        if (!text) return;

        lineEl.createSpan({ text: ' ' });

        // Check for CPE identifiers
        const cpePattern = /(cpe:\/[aho]:[^\s]+)/gi;
        const cpeMatches = [];
        let cpeResult;

        while ((cpeResult = cpePattern.exec(text)) !== null) {
            cpeMatches.push({
                start: cpeResult.index,
                end: cpePattern.lastIndex,
                text: cpeResult[1]
            });
        }

        if (cpeMatches.length > 0 && this.settings.highlightCpe) {
            let lastIndex = 0;
            cpeMatches.forEach(cpe => {
                if (cpe.start > lastIndex) {
                    const beforeCpe = text.substring(lastIndex, cpe.start);
                    this.highlightServiceVersionText(beforeCpe, lineEl);
                }
                lineEl.createSpan({ text: cpe.text, cls: 'nmap-cpe' });
                lastIndex = cpe.end;
            });

            if (lastIndex < text.length) {
                this.highlightServiceVersionText(text.substring(lastIndex), lineEl);
            }
        } else {
            this.highlightServiceVersionText(text, lineEl);
        }
    }

    highlightServiceVersionText(text, lineEl) {
        if (!text || !text.trim()) return;

        const trimmed = text.trim();
        const parts = trimmed.split(/\s+/);

        if (parts.length > 0) {
            // Check if first part looks like a service name (not a version number)
            const firstPart = parts[0];
            const isServiceName = !/^\d/.test(firstPart) && !/^v?\d+\.\d+/.test(firstPart);

            if (isServiceName) {
                if (this.settings.highlightServices) {
                    lineEl.createSpan({ text: firstPart, cls: 'nmap-service' });
                } else {
                    lineEl.createSpan({ text: firstPart });
                }

                if (parts.length > 1) {
                    const versionInfo = ' ' + parts.slice(1).join(' ');
                    if (this.settings.highlightVersions) {
                        lineEl.createSpan({ text: versionInfo, cls: 'nmap-version' });
                    } else {
                        lineEl.createSpan({ text: versionInfo });
                    }
                }
            } else {
                // Entire text is version info
                if (this.settings.highlightVersions) {
                    lineEl.createSpan({ text: ' ' + trimmed, cls: 'nmap-version' });
                } else {
                    lineEl.createSpan({ text: ' ' + trimmed });
                }
            }
        }
    }

    highlightScriptLine(line, lineEl) {
        // Check for vulnerability indicators with severity
        if (this.settings.highlightVulnerabilities && VULN_PATTERN.test(line)) {
            this.highlightVulnerabilityLine(line, lineEl);
            return;
        }

        // Check for interesting findings
        if (/anonymous|default|password|credentials|login|authentication/i.test(line)) {
            lineEl.createSpan({ text: line, cls: 'nmap-script-interesting' });
            return;
        }

        // Regular script output
        lineEl.createSpan({ text: line, cls: 'nmap-script' });
    }

    highlightVulnerabilityLine(line, lineEl) {
        if (!this.settings.severityHighlighting) {
            lineEl.createSpan({ text: line, cls: 'nmap-vuln' });
            return;
        }

        // Patterns for different severity levels
        const patterns = [
            { regex: /\bCRITICAL\b/gi, cls: 'nmap-severity-critical' },
            { regex: /\bHIGH\b/gi, cls: 'nmap-severity-high' },
            { regex: /\bMEDIUM\b/gi, cls: 'nmap-severity-medium' },
            { regex: /\bLOW\b/gi, cls: 'nmap-severity-low' },
            { regex: /\bVULNERABLE\b/gi, cls: 'nmap-vuln' },
            { regex: /CVE-\d{4}-\d{4,}/gi, cls: 'nmap-cve' },
            { regex: /MS\d{2,4}-\d{3,4}/gi, cls: 'nmap-cve' },
            { regex: /ADV\d{6}/gi, cls: 'nmap-cve' },
            { regex: /CWE-\d+/gi, cls: 'nmap-cve' },
            { regex: /\bEXPLOIT\b/gi, cls: 'nmap-vuln' },
            { regex: /\[\!\]/g, cls: 'nmap-vuln' },
            { regex: /\[\+\]/g, cls: 'nmap-script-interesting' },
            { regex: /CVSS(?:\s+Score)?:\s*[\d.]+/gi, cls: 'nmap-vuln' }
        ];

        // Collect all matches
        const matches = [];
        patterns.forEach(pattern => {
            let result;
            const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
            while ((result = regex.exec(line)) !== null) {
                matches.push({
                    start: result.index,
                    end: regex.lastIndex,
                    text: result[0],
                    cls: pattern.cls
                });
            }
        });

        if (matches.length === 0) {
            lineEl.createSpan({ text: line, cls: 'nmap-vuln' });
            return;
        }

        // Sort by position
        matches.sort((a, b) => a.start - b.start);

        // Remove overlapping matches
        const nonOverlapping = [];
        let lastEnd = -1;
        matches.forEach(match => {
            if (match.start >= lastEnd) {
                nonOverlapping.push(match);
                lastEnd = match.end;
            }
        });

        // Render with specific highlighting
        let lastIndex = 0;
        nonOverlapping.forEach(match => {
            if (match.start > lastIndex) {
                lineEl.createSpan({ text: line.substring(lastIndex, match.start) });
            }
            lineEl.createSpan({ text: match.text, cls: match.cls });
            lastIndex = match.end;
        });

        if (lastIndex < line.length) {
            lineEl.createSpan({ text: line.substring(lastIndex) });
        }
    }

    highlightTracerouteLine(line, lineEl) {
        // Parse traceroute line: "1  0.50 ms  router.local (192.168.1.1)"
        const parts = line.split(/\s+/);

        if (parts.length > 0) {
            // Hop number
            lineEl.createSpan({ text: parts[0], cls: 'nmap-traceroute-hop' });
            lineEl.createSpan({ text: '  ' });

            // Rest of line - look for RTT values and addresses
            const rest = parts.slice(1).join(' ');
            const rttPattern = /([\d.]+\s*ms|--|\*)/g;
            let lastIndex = 0;
            let match;

            while ((match = rttPattern.exec(rest)) !== null) {
                if (match.index > lastIndex) {
                    const segment = rest.substring(lastIndex, match.index);
                    this.highlightInlineElements(segment, lineEl);
                }
                lineEl.createSpan({ text: match[0], cls: 'nmap-traceroute-rtt' });
                lastIndex = rttPattern.lastIndex;
            }

            if (lastIndex < rest.length) {
                this.highlightInlineElements(rest.substring(lastIndex), lineEl);
            }
        }
    }

    highlightRdnsLine(match, lineEl) {
        const [, label, ip, hostname] = match;

        lineEl.createSpan({ text: label + ' ', cls: 'nmap-label' });

        // Determine if IPv4 or IPv6
        const isIPv6 = ip.includes(':');
        if (this.settings.highlightIpAddresses || (isIPv6 && this.settings.highlightIPv6Addresses)) {
            lineEl.createSpan({ text: ip, cls: isIPv6 ? 'nmap-ipv6' : 'nmap-ip' });
        } else {
            lineEl.createSpan({ text: ip });
        }

        lineEl.createSpan({ text: ': ' });

        if (this.settings.highlightHostnames) {
            lineEl.createSpan({ text: hostname, cls: 'nmap-hostname' });
        } else {
            lineEl.createSpan({ text: hostname });
        }
    }

    highlightMacLine(line, lineEl) {
        const macMatch = line.match(/^(MAC Address:)\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s*(.*)$/i);
        if (macMatch) {
            lineEl.createSpan({ text: macMatch[1] + ' ', cls: 'nmap-label' });
            lineEl.createSpan({ text: macMatch[2], cls: 'nmap-mac' });
            if (macMatch[3]) {
                lineEl.createSpan({ text: ' ' + macMatch[3], cls: 'nmap-vendor' });
            }
        } else {
            lineEl.createSpan({ text: line });
        }
    }

    highlightInlineElements(line, lineEl) {
        const matches = [];

        // Find IPv4 addresses (with validation)
        if (this.settings.highlightIpAddresses) {
            const ipv4Pattern = new RegExp(IPV4_PATTERN.source, 'g');
            let result;
            while ((result = ipv4Pattern.exec(line)) !== null) {
                matches.push({
                    start: result.index,
                    end: ipv4Pattern.lastIndex,
                    text: result[0],
                    cls: 'nmap-ip'
                });
            }
        }

        // Find IPv6 addresses
        if (this.settings.highlightIPv6Addresses) {
            const ipv6Pattern = new RegExp(IPV6_PATTERN.source, 'g');
            let result;
            while ((result = ipv6Pattern.exec(line)) !== null) {
                const matchStart = result.index;
                const matchEnd = matchStart + result[0].length;

                // Avoid overlap with IPv4 matches (comprehensive overlap check)
                const overlaps = matches.some(m =>
                    // New match starts inside existing match
                    (matchStart >= m.start && matchStart < m.end) ||
                    // New match ends inside existing match
                    (matchEnd > m.start && matchEnd <= m.end) ||
                    // New match completely contains existing match
                    (matchStart <= m.start && matchEnd >= m.end)
                );
                if (!overlaps) {
                    matches.push({
                        start: matchStart,
                        end: matchEnd,
                        text: result[0],
                        cls: 'nmap-ipv6'
                    });
                }
            }
        }

        // Find hostnames in parentheses
        if (this.settings.highlightHostnames) {
            const hostnamePattern = /\(([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)\)/g;
            let result;
            while ((result = hostnamePattern.exec(line)) !== null) {
                const matchStart = result.index;
                const matchEnd = matchStart + result[0].length;

                // Check for overlap with IP matches (comprehensive overlap check)
                const overlaps = matches.some(m =>
                    // New match starts inside existing match
                    (matchStart >= m.start && matchStart < m.end) ||
                    // New match ends inside existing match
                    (matchEnd > m.start && matchEnd <= m.end) ||
                    // New match completely contains existing match
                    (matchStart <= m.start && matchEnd >= m.end)
                );
                if (!overlaps) {
                    matches.push({
                        start: matchStart + 1, // Skip opening paren
                        end: matchEnd - 1, // Skip closing paren
                        text: result[1],
                        cls: 'nmap-hostname',
                        prefix: '(',
                        suffix: ')'
                    });
                }
            }
        }

        if (matches.length === 0) {
            lineEl.createSpan({ text: line });
            return;
        }

        // Sort by position
        matches.sort((a, b) => a.start - b.start);

        // Render segments
        let lastIndex = 0;
        matches.forEach(match => {
            // Text before this match
            const actualStart = match.prefix ? match.start - 1 : match.start;
            if (actualStart > lastIndex) {
                lineEl.createSpan({ text: line.substring(lastIndex, actualStart) });
            }

            // The matched element
            if (match.prefix) {
                lineEl.createSpan({ text: match.prefix });
            }
            lineEl.createSpan({ text: match.text, cls: match.cls });
            if (match.suffix) {
                lineEl.createSpan({ text: match.suffix });
            }

            lastIndex = match.suffix ? match.end + 1 : match.end;
        });

        // Remaining text
        if (lastIndex < line.length) {
            lineEl.createSpan({ text: line.substring(lastIndex) });
        }
    }

    /**
     * Collects summary data from nmap output lines.
     * @param {string[]} lines - Array of lines from the nmap output
     * @returns {Object} Summary data containing hosts, ports, services, OS, and vulnerabilities
     */
    collectSummaryData(lines) {
        const summary = {
            hosts: [],
            hostMappings: new Map(), // IP -> Set of hostnames
            perHostData: new Map(), // IP -> { openPorts, closedPorts, filteredPorts, services, criticalPorts, os, vulns }
            totalOpenPorts: 0,
            totalClosedPorts: 0,
            totalFilteredPorts: 0
        };

        let currentIP = null;

        // Initialize per-host data helper
        const initHostData = (ip) => {
            if (!summary.perHostData.has(ip)) {
                summary.perHostData.set(ip, {
                    openPorts: [],
                    closedPorts: 0,
                    filteredPorts: 0,
                    services: new Set(),
                    criticalPorts: [],
                    osGuesses: [],
                    vulnerabilities: []
                });
            }
        };

        // Pre-compile regex patterns used in the loop (performance optimization)
        const sanRegex = new RegExp(HOST_PATTERNS.sanDnsMultiple.source, 'gi');
        const sslAltRegex = new RegExp(HOST_PATTERNS.sslAltNames.source, 'gi');
        const spfRegex = new RegExp(HOST_PATTERNS.dnsTxtSpf.source, 'gi');
        const dmarcRegex = new RegExp(HOST_PATTERNS.dnsTxtDmarc.source, 'gi');
        const txtRegex = new RegExp(HOST_PATTERNS.dnsTxtGeneric.source, 'gi');

        lines.forEach(line => {
            const trimmed = line.trim();

            // Extract host info with hostname-IP mapping
            // Pattern: "Nmap scan report for hostname (IP)"
            const scanWithHostMatch = trimmed.match(HOST_PATTERNS.scanReportWithHostname);
            if (scanWithHostMatch) {
                const hostname = scanWithHostMatch[1];
                const ip = scanWithHostMatch[2];
                // Only add to hosts array if this IP hasn't been seen before
                const existingHost = summary.hosts.find(h => h.ip === ip);
                if (!existingHost) {
                    summary.hosts.push({ raw: `${hostname} (${ip})`, hostname, ip });
                } else if (!existingHost.hostname && hostname) {
                    // Update existing entry if we now have a hostname
                    existingHost.hostname = hostname;
                    existingHost.raw = `${hostname} (${ip})`;
                }
                currentIP = ip;
                initHostData(ip);
                if (isValidIP(ip) && isValidHostname(hostname)) {
                    if (!summary.hostMappings.has(ip)) {
                        summary.hostMappings.set(ip, new Set());
                    }
                    summary.hostMappings.get(ip).add(hostname.toLowerCase());
                    // Also add parent domain if applicable
                    const parent = extractParentDomain(hostname);
                    if (parent && isValidHostname(parent)) {
                        summary.hostMappings.get(ip).add(parent.toLowerCase());
                    }
                }
            } else {
                // Pattern: "Nmap scan report for IP"
                const scanIpMatch = trimmed.match(HOST_PATTERNS.scanReportIpOnly);
                if (scanIpMatch) {
                    const ip = scanIpMatch[1];
                    // Only add to hosts array if this IP hasn't been seen before
                    if (!summary.hosts.find(h => h.ip === ip)) {
                        summary.hosts.push({ raw: ip, hostname: null, ip });
                    }
                    currentIP = ip;
                    initHostData(ip);
                    if (isValidIP(ip) && !summary.hostMappings.has(ip)) {
                        summary.hostMappings.set(ip, new Set());
                    }
                }
            }

            // Pattern: "rDNS record for IP: hostname"
            const rdnsMatch = trimmed.match(HOST_PATTERNS.rdnsRecord);
            if (rdnsMatch) {
                const ip = rdnsMatch[1];
                const hostname = rdnsMatch[2];
                if (isValidIP(ip) && isValidHostname(hostname)) {
                    if (!summary.hostMappings.has(ip)) {
                        summary.hostMappings.set(ip, new Set());
                    }
                    summary.hostMappings.get(ip).add(hostname.toLowerCase());
                }
            }

            // Extract additional hostnames for current IP
            if (currentIP && summary.hostMappings.has(currentIP)) {
                const hostSet = summary.hostMappings.get(currentIP);

                // Service Info Host
                const serviceMatch = trimmed.match(HOST_PATTERNS.serviceInfoHost);
                if (serviceMatch && isValidHostname(serviceMatch[1])) {
                    hostSet.add(serviceMatch[1]);
                }

                // SMB Domain
                const smbMatch = trimmed.match(HOST_PATTERNS.smbDomain);
                if (smbMatch && isValidHostname(smbMatch[1])) {
                    hostSet.add(smbMatch[1]);
                }

                // FQDN from scripts
                const fqdnMatch = trimmed.match(HOST_PATTERNS.fqdn);
                if (fqdnMatch && isValidHostname(fqdnMatch[1])) {
                    hostSet.add(fqdnMatch[1]);
                    const parent = extractParentDomain(fqdnMatch[1]);
                    if (parent && isValidHostname(parent)) {
                        hostSet.add(parent);
                    }
                }

                // SSL Common Name
                const sslMatch = trimmed.match(HOST_PATTERNS.sslCommonName);
                if (sslMatch && isValidHostname(sslMatch[1])) {
                    hostSet.add(sslMatch[1]);
                }

                // NetBIOS name (from nbstat script)
                const netbiosMatch = trimmed.match(HOST_PATTERNS.netbiosName);
                if (netbiosMatch && isValidHostname(netbiosMatch[1])) {
                    hostSet.add(netbiosMatch[1].toLowerCase());
                }

                // Computer name (from smb-os-discovery)
                const computerMatch = trimmed.match(HOST_PATTERNS.computerName);
                if (computerMatch && isValidHostname(computerMatch[1])) {
                    hostSet.add(computerMatch[1].toLowerCase());
                }

                // NetBIOS computer name
                const nbComputerMatch = trimmed.match(HOST_PATTERNS.netbiosComputerName);
                if (nbComputerMatch && isValidHostname(nbComputerMatch[1])) {
                    hostSet.add(nbComputerMatch[1].toLowerCase());
                }

                // RDP NTLM info - DNS Computer Name (FQDN)
                const rdpDnsComputerMatch = trimmed.match(HOST_PATTERNS.rdpDnsComputerName);
                if (rdpDnsComputerMatch && isValidHostname(rdpDnsComputerMatch[1])) {
                    hostSet.add(rdpDnsComputerMatch[1].toLowerCase());
                    const parent = extractParentDomain(rdpDnsComputerMatch[1]);
                    if (parent && isValidHostname(parent)) {
                        hostSet.add(parent.toLowerCase());
                    }
                }

                // RDP NTLM info - DNS Domain Name
                const rdpDnsDomainMatch = trimmed.match(HOST_PATTERNS.rdpDnsDomainName);
                if (rdpDnsDomainMatch && isValidHostname(rdpDnsDomainMatch[1])) {
                    hostSet.add(rdpDnsDomainMatch[1].toLowerCase());
                }

                // RDP NTLM info - DNS Tree Name
                const rdpDnsTreeMatch = trimmed.match(HOST_PATTERNS.rdpDnsTreeName);
                if (rdpDnsTreeMatch && isValidHostname(rdpDnsTreeMatch[1])) {
                    hostSet.add(rdpDnsTreeMatch[1].toLowerCase());
                }

                // RDP NTLM info - NetBIOS Computer Name
                const rdpNbComputerMatch = trimmed.match(HOST_PATTERNS.rdpNetbiosComputerName);
                if (rdpNbComputerMatch && isValidHostname(rdpNbComputerMatch[1])) {
                    hostSet.add(rdpNbComputerMatch[1].toLowerCase());
                }

                // SSL cert commonName= format (skip Issuer lines - those are CA names, not hostnames)
                if (!/\bIssuer:/i.test(trimmed)) {
                    const sslCnAltMatch = trimmed.match(HOST_PATTERNS.sslCommonNameAlt);
                    if (sslCnAltMatch && isValidHostname(sslCnAltMatch[1])) {
                        hostSet.add(sslCnAltMatch[1].toLowerCase());
                        const parent = extractParentDomain(sslCnAltMatch[1]);
                        if (parent && isValidHostname(parent)) {
                            hostSet.add(parent.toLowerCase());
                        }
                    }
                }

                // Generic NTLM authentication patterns (http-ntlm-info, smtp-ntlm-info, etc.)
                const ntlmTargetMatch = trimmed.match(HOST_PATTERNS.ntlmTargetName);
                if (ntlmTargetMatch && isValidHostname(ntlmTargetMatch[1])) {
                    hostSet.add(ntlmTargetMatch[1].toLowerCase());
                }

                const ntlmDnsDomainMatch = trimmed.match(HOST_PATTERNS.ntlmDnsDomainName);
                if (ntlmDnsDomainMatch && isValidHostname(ntlmDnsDomainMatch[1])) {
                    hostSet.add(ntlmDnsDomainMatch[1].toLowerCase());
                }

                const ntlmDnsComputerMatch = trimmed.match(HOST_PATTERNS.ntlmDnsComputerName);
                if (ntlmDnsComputerMatch && isValidHostname(ntlmDnsComputerMatch[1])) {
                    hostSet.add(ntlmDnsComputerMatch[1].toLowerCase());
                    const parent = extractParentDomain(ntlmDnsComputerMatch[1]);
                    if (parent && isValidHostname(parent)) {
                        hostSet.add(parent.toLowerCase());
                    }
                }

                const ntlmDnsTreeMatch = trimmed.match(HOST_PATTERNS.ntlmDnsTreeName);
                if (ntlmDnsTreeMatch && isValidHostname(ntlmDnsTreeMatch[1])) {
                    hostSet.add(ntlmDnsTreeMatch[1].toLowerCase());
                }

                const ntlmNbDomainMatch = trimmed.match(HOST_PATTERNS.ntlmNetbiosDomainName);
                if (ntlmNbDomainMatch && isValidHostname(ntlmNbDomainMatch[1])) {
                    hostSet.add(ntlmNbDomainMatch[1].toLowerCase());
                }

                const ntlmNbComputerMatch = trimmed.match(HOST_PATTERNS.ntlmNetbiosComputerName);
                if (ntlmNbComputerMatch && isValidHostname(ntlmNbComputerMatch[1])) {
                    hostSet.add(ntlmNbComputerMatch[1].toLowerCase());
                }

                // Kerberos realm patterns
                const kerbRealmMatch = trimmed.match(HOST_PATTERNS.kerberosRealm);
                if (kerbRealmMatch && isValidHostname(kerbRealmMatch[1])) {
                    hostSet.add(kerbRealmMatch[1].toLowerCase());
                }

                const kerbDomainMatch = trimmed.match(HOST_PATTERNS.kerberosDomain);
                if (kerbDomainMatch) {
                    // Capture group 2 contains the domain (group 1 is optional user@)
                    const domain = kerbDomainMatch[2];
                    if (domain && isValidHostname(domain)) {
                        hostSet.add(domain.toLowerCase());
                    }
                }

                const msKerbMatch = trimmed.match(HOST_PATTERNS.msKerberos);
                if (msKerbMatch && isValidHostname(msKerbMatch[1])) {
                    hostSet.add(msKerbMatch[1].toLowerCase());
                }

                // Certificate Subject Alternative Name (SAN) patterns - extract all DNS names
                let sanMatch;
                sanRegex.lastIndex = 0; // Reset for reuse
                while ((sanMatch = sanRegex.exec(trimmed)) !== null) {
                    const hostname = sanMatch[1];
                    // Skip wildcards but keep the base domain
                    if (hostname.startsWith('*.')) {
                        const baseDomain = hostname.substring(2);
                        if (isValidHostname(baseDomain)) {
                            hostSet.add(baseDomain.toLowerCase());
                        }
                    } else if (isValidHostname(hostname)) {
                        hostSet.add(hostname.toLowerCase());
                        const parent = extractParentDomain(hostname);
                        if (parent && isValidHostname(parent)) {
                            hostSet.add(parent.toLowerCase());
                        }
                    }
                }

                // SSL alt names in dns= format
                let sslAltMatch;
                sslAltRegex.lastIndex = 0; // Reset for reuse
                while ((sslAltMatch = sslAltRegex.exec(trimmed)) !== null) {
                    if (isValidHostname(sslAltMatch[1])) {
                        hostSet.add(sslAltMatch[1].toLowerCase());
                    }
                }

                // DNS TXT record patterns - SPF includes
                let spfMatch;
                spfRegex.lastIndex = 0; // Reset for reuse
                while ((spfMatch = spfRegex.exec(trimmed)) !== null) {
                    if (isValidHostname(spfMatch[1])) {
                        hostSet.add(spfMatch[1].toLowerCase());
                    }
                }

                // DNS TXT record patterns - DMARC addresses
                let dmarcMatch;
                dmarcRegex.lastIndex = 0; // Reset for reuse
                while ((dmarcMatch = dmarcRegex.exec(trimmed)) !== null) {
                    if (isValidHostname(dmarcMatch[1])) {
                        hostSet.add(dmarcMatch[1].toLowerCase());
                    }
                }

                // DNS TXT record patterns - generic domain references
                let txtMatch;
                txtRegex.lastIndex = 0; // Reset for reuse
                while ((txtMatch = txtRegex.exec(trimmed)) !== null) {
                    if (isValidHostname(txtMatch[1])) {
                        hostSet.add(txtMatch[1].toLowerCase());
                    }
                }
            }

            // Extract port info (including sctp and additional states)
            const portMatch = trimmed.match(/^(\d+)\/(tcp|udp|sctp)\s+(open|closed|filtered|open\|filtered|unfiltered|closed\|filtered)\s*(\S*)/i);
            if (portMatch && currentIP) {
                const [, port, protocol, state, service] = portMatch;
                const portNum = parseInt(port);
                const stateLower = state.toLowerCase();
                const hostData = summary.perHostData.get(currentIP);

                // Defensive null check for hostData (use 'return' not 'continue' in forEach)
                if (!hostData) return;

                if (stateLower === 'open') {
                    hostData.openPorts.push({ port: portNum, protocol, service: service || 'unknown' });
                    summary.totalOpenPorts++;
                    if (this.getCriticalPorts().includes(portNum)) {
                        hostData.criticalPorts.push({ port: portNum, protocol, service: service || 'unknown' });
                    }
                    if (service) {
                        hostData.services.add(service);
                    }
                } else if (stateLower === 'closed') {
                    hostData.closedPorts++;
                    summary.totalClosedPorts++;
                } else if (stateLower.includes('filtered')) {
                    hostData.filteredPorts++;
                    summary.totalFilteredPorts++;
                }
            }

            // Extract OS info
            const osMatch = trimmed.match(/^(?:OS details?:|Running:|Aggressive OS guesses?:)\s*(.+)$/i);
            if (osMatch && currentIP) {
                const hostData = summary.perHostData.get(currentIP);
                if (hostData) {
                    hostData.osGuesses.push(osMatch[1]);
                }
            }

            // Extract vulnerabilities (expanded patterns with modern CVE/MS support)
            const vulnPatterns = [
                /VULNERABLE/i,
                /CVE-\d{4}-\d{4,}/i,
                /MS\d{2,4}-\d{3,4}/i,
                /ADV\d{6}/i,
                /CWE-\d+/i
            ];

            if (currentIP) {
                const hostData = summary.perHostData.get(currentIP);
                if (hostData) {
                    vulnPatterns.forEach(pattern => {
                        // Use global flag to capture all matches on the line
                        const globalPattern = new RegExp(pattern.source, 'gi');
                        let vulnMatch;
                        while ((vulnMatch = globalPattern.exec(trimmed)) !== null) {
                            if (!hostData.vulnerabilities.includes(vulnMatch[0])) {
                                hostData.vulnerabilities.push(vulnMatch[0]);
                            }
                        }
                    });
                }
            }
        });

        return summary;
    }

    /**
     * Renders the scan summary section with host details and /etc/hosts entries.
     * @param {HTMLElement} container - The container to render the summary into
     * @param {Object} summary - The summary data from collectSummaryData()
     */
    renderSummary(container, summary) {
        const summaryEl = container.createDiv({ cls: 'nmap-summary' });

        // Title
        summaryEl.createEl('div', { text: 'Scan Summary', cls: 'nmap-summary-title' });

        const content = summaryEl.createDiv({ cls: 'nmap-summary-content' });

        // Global summary line
        const globalSummary = content.createDiv({ cls: 'nmap-summary-global' });
        globalSummary.createSpan({ text: 'Hosts Scanned: ', cls: 'nmap-summary-label' });
        globalSummary.createSpan({ text: `${summary.hosts.length}`, cls: 'nmap-summary-value' });
        globalSummary.createSpan({ text: ' | Total Open Ports: ' });
        globalSummary.createSpan({ text: `${summary.totalOpenPorts}`, cls: 'nmap-summary-value nmap-summary-open' });

        // Divider
        content.createDiv({ cls: 'nmap-summary-divider' });

        // Per-host sections
        summary.hosts.forEach((host, index) => {
            const hostData = summary.perHostData.get(host.ip);
            if (!hostData) return;

            const hostSection = content.createDiv({ cls: 'nmap-host-section' });

            // Host header (collapsible trigger)
            const hostHeader = hostSection.createDiv({ cls: 'nmap-host-header' });
            const expandIcon = hostHeader.createSpan({ text: '\u25B8 ', cls: 'nmap-expand-icon' }); // ▸

            // Hostname and IP
            if (host.hostname && host.ip) {
                hostHeader.createSpan({ text: host.hostname, cls: 'nmap-hostname' });
                hostHeader.createSpan({ text: ' (' });
                const isIPv6 = host.ip.includes(':');
                hostHeader.createSpan({ text: host.ip, cls: isIPv6 ? 'nmap-ipv6' : 'nmap-ip' });
                hostHeader.createSpan({ text: ')' });
            } else if (host.ip) {
                const isIPv6 = host.ip.includes(':');
                hostHeader.createSpan({ text: host.ip, cls: isIPv6 ? 'nmap-ipv6' : 'nmap-ip' });
            }

            // Host details (initially hidden)
            const hostDetails = hostSection.createDiv({ cls: 'nmap-host-details' });
            hostDetails.style.display = 'none';

            // Port stats line
            const portsLine = hostDetails.createDiv({ cls: 'nmap-host-line' });
            portsLine.createSpan({ text: '  Open: ', cls: 'nmap-summary-label-indent' });
            portsLine.createSpan({ text: `${hostData.openPorts.length}`, cls: 'nmap-summary-open' });

            if (hostData.closedPorts > 0) {
                portsLine.createSpan({ text: ' | Closed: ' });
                portsLine.createSpan({ text: `${hostData.closedPorts}`, cls: 'nmap-summary-closed' });
            }
            if (hostData.filteredPorts > 0) {
                portsLine.createSpan({ text: ' | Filtered: ' });
                portsLine.createSpan({ text: `${hostData.filteredPorts}`, cls: 'nmap-summary-filtered' });
            }

            // Critical ports
            if (hostData.criticalPorts.length > 0) {
                const critLine = hostDetails.createDiv({ cls: 'nmap-host-line' });
                critLine.createSpan({ text: '  Critical: ', cls: 'nmap-summary-label-indent' });
                const critPorts = hostData.criticalPorts.map(p => `${p.port}/${p.protocol}`).join(', ');
                critLine.createSpan({ text: critPorts, cls: 'nmap-port-critical' });
            }

            // Services
            if (hostData.services.size > 0) {
                const svcLine = hostDetails.createDiv({ cls: 'nmap-host-line' });
                svcLine.createSpan({ text: '  Services: ', cls: 'nmap-summary-label-indent' });
                svcLine.createSpan({ text: Array.from(hostData.services).join(', '), cls: 'nmap-service' });
            }

            // OS detection
            if (hostData.osGuesses.length > 0) {
                const osLine = hostDetails.createDiv({ cls: 'nmap-host-line' });
                osLine.createSpan({ text: '  OS: ', cls: 'nmap-summary-label-indent' });
                osLine.createSpan({ text: hostData.osGuesses[0], cls: 'nmap-summary-value' });
            }

            // Vulnerabilities
            if (hostData.vulnerabilities.length > 0) {
                const vulnLine = hostDetails.createDiv({ cls: 'nmap-host-line nmap-host-vuln' });
                vulnLine.createSpan({ text: '  Vulns: ', cls: 'nmap-summary-label-indent' });
                // Render each vulnerability with appropriate class
                hostData.vulnerabilities.forEach((vuln, idx) => {
                    const isCve = /^(CVE-|MS\d|ADV\d|CWE-)/i.test(vuln);
                    vulnLine.createSpan({ text: vuln, cls: isCve ? 'nmap-cve' : 'nmap-vuln' });
                    if (idx < hostData.vulnerabilities.length - 1) {
                        vulnLine.createSpan({ text: ', ' });
                    }
                });
            }

            // Toggle collapse/expand
            let isExpanded = false;
            hostHeader.addEventListener('click', () => {
                isExpanded = !isExpanded;
                hostDetails.style.display = isExpanded ? 'block' : 'none';
                expandIcon.textContent = isExpanded ? '\u25BE ' : '\u25B8 '; // ▾ or ▸
                hostHeader.classList.toggle('expanded', isExpanded);
            });
            hostHeader.style.cursor = 'pointer';
        });

        // Divider before /etc/hosts
        const hostsWithNames = Array.from(summary.hostMappings.entries())
            .filter(([ip, hostnames]) => hostnames.size > 0);

        if (hostsWithNames.length > 0) {
            content.createDiv({ cls: 'nmap-summary-divider' });

            const etcHostsSection = content.createDiv({ cls: 'nmap-etc-hosts-section' });

            // Header with copy button
            const etcHeader = etcHostsSection.createDiv({ cls: 'nmap-etc-hosts-header' });
            etcHeader.createSpan({ text: '/etc/hosts', cls: 'nmap-etc-hosts-title' });

            // Generate hosts file content
            const hostsLines = [];
            hostsWithNames.forEach(([ip, hostnames]) => {
                const sortedHosts = Array.from(hostnames).sort((a, b) => {
                    // Sort by specificity (more dots = more specific = first)
                    const dotsA = (a.match(/\./g) || []).length;
                    const dotsB = (b.match(/\./g) || []).length;
                    if (dotsA !== dotsB) return dotsB - dotsA;
                    return a.localeCompare(b);
                });
                hostsLines.push(`${ip}\t${sortedHosts.join(' ')}`);
            });
            const hostsFileContent = hostsLines.join('\n');

            const copyBtn = etcHeader.createEl('button', {
                text: 'Copy',
                cls: 'nmap-etc-hosts-copy'
            });
            copyBtn.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(hostsFileContent);
                    copyBtn.textContent = 'Copied!';
                    copyBtn.classList.add('copied');
                    setTimeout(() => {
                        copyBtn.textContent = 'Copy';
                        copyBtn.classList.remove('copied');
                    }, 2000);
                } catch (err) {
                    console.error('Nmap Syntax Highlight: Failed to copy /etc/hosts to clipboard', err);
                    copyBtn.textContent = 'Failed';
                    setTimeout(() => {
                        copyBtn.textContent = 'Copy';
                    }, 2000);
                }
            });

            // Code block with highlighted entries
            const codeBlock = etcHostsSection.createDiv({ cls: 'nmap-etc-hosts-code' });
            hostsWithNames.forEach(([ip, hostnames]) => {
                const line = codeBlock.createDiv({ cls: 'nmap-etc-hosts-line' });
                const isIPv6 = ip.includes(':');
                line.createSpan({ text: ip, cls: isIPv6 ? 'nmap-ipv6' : 'nmap-ip' });
                line.createSpan({ text: '\t' });

                const sortedHosts = Array.from(hostnames).sort((a, b) => {
                    const dotsA = (a.match(/\./g) || []).length;
                    const dotsB = (b.match(/\./g) || []).length;
                    if (dotsA !== dotsB) return dotsB - dotsA;
                    return a.localeCompare(b);
                });

                sortedHosts.forEach((hostname, idx) => {
                    if (idx > 0) line.createSpan({ text: ' ' });
                    line.createSpan({ text: hostname, cls: 'nmap-hostname' });
                });
            });
        }
    }
}

class NmapSettingTab extends PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display() {
        const { containerEl } = this;
        containerEl.empty();

        containerEl.createEl('h2', { text: 'Nmap Syntax Highlight Settings' });

        // Port state highlighting
        containerEl.createEl('h3', { text: 'Port State Highlighting' });

        new Setting(containerEl)
            .setName('Highlight open ports')
            .setDesc('Highlight ports with "open" state in green')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightOpenPorts)
                .onChange(async (value) => {
                    this.plugin.settings.highlightOpenPorts = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight closed ports')
            .setDesc('Highlight ports with "closed" state in red')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightClosedPorts)
                .onChange(async (value) => {
                    this.plugin.settings.highlightClosedPorts = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight filtered ports')
            .setDesc('Highlight ports with "filtered" state in orange')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightFilteredPorts)
                .onChange(async (value) => {
                    this.plugin.settings.highlightFilteredPorts = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight critical ports')
            .setDesc('Extra emphasis on commonly targeted ports (21, 22, 80, 443, 445, 3389, etc.)')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightCriticalPorts)
                .onChange(async (value) => {
                    this.plugin.settings.highlightCriticalPorts = value;
                    await this.plugin.saveSettings();
                }));

        // Service & Version highlighting
        containerEl.createEl('h3', { text: 'Service & Version Highlighting' });

        new Setting(containerEl)
            .setName('Highlight services')
            .setDesc('Highlight service names (ssh, http, smb, etc.)')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightServices)
                .onChange(async (value) => {
                    this.plugin.settings.highlightServices = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight versions')
            .setDesc('Highlight version information for enumeration')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightVersions)
                .onChange(async (value) => {
                    this.plugin.settings.highlightVersions = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight CPE')
            .setDesc('Highlight Common Platform Enumeration identifiers')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightCpe)
                .onChange(async (value) => {
                    this.plugin.settings.highlightCpe = value;
                    await this.plugin.saveSettings();
                }));

        // Additional highlighting
        containerEl.createEl('h3', { text: 'Additional Highlighting' });

        new Setting(containerEl)
            .setName('Highlight OS detection')
            .setDesc('Highlight operating system detection results')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightOsDetection)
                .onChange(async (value) => {
                    this.plugin.settings.highlightOsDetection = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight script output')
            .setDesc('Highlight NSE script output sections')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightScriptOutput)
                .onChange(async (value) => {
                    this.plugin.settings.highlightScriptOutput = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight vulnerabilities')
            .setDesc('Emphasize VULNERABLE findings and CVE references')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightVulnerabilities)
                .onChange(async (value) => {
                    this.plugin.settings.highlightVulnerabilities = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Severity highlighting')
            .setDesc('Color-code severity levels (CRITICAL, HIGH, MEDIUM, LOW)')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.severityHighlighting)
                .onChange(async (value) => {
                    this.plugin.settings.severityHighlighting = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight IP addresses')
            .setDesc('Highlight IPv4 addresses in the output')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightIpAddresses)
                .onChange(async (value) => {
                    this.plugin.settings.highlightIpAddresses = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight IPv6 addresses')
            .setDesc('Highlight IPv6 addresses in the output')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightIPv6Addresses)
                .onChange(async (value) => {
                    this.plugin.settings.highlightIPv6Addresses = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight hostnames')
            .setDesc('Highlight hostnames in the output')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightHostnames)
                .onChange(async (value) => {
                    this.plugin.settings.highlightHostnames = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight traceroute')
            .setDesc('Highlight traceroute hop information')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightTraceroute)
                .onChange(async (value) => {
                    this.plugin.settings.highlightTraceroute = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight reverse DNS')
            .setDesc('Highlight reverse DNS resolution results')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightRdns)
                .onChange(async (value) => {
                    this.plugin.settings.highlightRdns = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight port reasons')
            .setDesc('Highlight reason information from --reason flag (e.g., syn-ack, reset)')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightReasons)
                .onChange(async (value) => {
                    this.plugin.settings.highlightReasons = value;
                    await this.plugin.saveSettings();
                }));

        // Summary settings
        containerEl.createEl('h3', { text: 'Summary' });

        new Setting(containerEl)
            .setName('Show summary')
            .setDesc('Display a summary of key findings')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.showSummary)
                .onChange(async (value) => {
                    this.plugin.settings.showSummary = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Summary position')
            .setDesc('Where to display the summary')
            .addDropdown(dropdown => dropdown
                .addOption('before', 'Before scan output')
                .addOption('after', 'After scan output')
                .setValue(this.plugin.settings.summaryPosition)
                .onChange(async (value) => {
                    this.plugin.settings.summaryPosition = value;
                    await this.plugin.saveSettings();
                }));

        // Display options
        containerEl.createEl('h3', { text: 'Display Options' });

        new Setting(containerEl)
            .setName('Show copy button')
            .setDesc('Display a button to copy scan output to clipboard')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.showCopyButton)
                .onChange(async (value) => {
                    this.plugin.settings.showCopyButton = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Show line numbers')
            .setDesc('Display line numbers for each line of output')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.showLineNumbers)
                .onChange(async (value) => {
                    this.plugin.settings.showLineNumbers = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Show filter toolbar')
            .setDesc('Display a toolbar to show/hide line categories (scripts, closed ports, OS detection, etc.)')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.showFilterToolbar)
                .onChange(async (value) => {
                    this.plugin.settings.showFilterToolbar = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight warnings and errors')
            .setDesc('Highlight warning and error messages from nmap')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightWarnings)
                .onChange(async (value) => {
                    this.plugin.settings.highlightWarnings = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Highlight timing information')
            .setDesc('Highlight scan duration and statistics')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.highlightTiming)
                .onChange(async (value) => {
                    this.plugin.settings.highlightTiming = value;
                    await this.plugin.saveSettings();
                }));

        // Accessibility settings
        containerEl.createEl('h3', { text: 'Accessibility' });

        new Setting(containerEl)
            .setName('Color-blind friendly mode')
            .setDesc('Add symbols alongside colors (✓ open, ✗ closed, ― filtered, ⚠ vuln)')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.colorBlindMode)
                .onChange(async (value) => {
                    this.plugin.settings.colorBlindMode = value;
                    await this.plugin.saveSettings();
                }));

        // Advanced settings
        containerEl.createEl('h3', { text: 'Advanced' });

        new Setting(containerEl)
            .setName('Custom critical ports')
            .setDesc('Additional ports to highlight as critical (comma-separated, e.g., "8888,9090,4444")')
            .addText(text => text
                .setPlaceholder('8888, 9090, 4444')
                .setValue(this.plugin.settings.customCriticalPorts)
                .onChange(async (value) => {
                    this.plugin.settings.customCriticalPorts = value;
                    await this.plugin.saveSettings();
                }));
    }
}

module.exports = NmapSyntaxHighlightPlugin;
