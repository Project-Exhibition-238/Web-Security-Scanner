document.addEventListener('DOMContentLoaded', function() {
    const scanButton = document.getElementById('scan-button');
    const targetUrl = document.getElementById('target-url');
    const resultsContainer = document.getElementById('results-container');
    const resultsSection = document.getElementById('results');
    const progressBar = document.getElementById('progress-bar');
    const spinner = document.getElementById('spinner');
    const tabButtons = document.querySelectorAll('.tab-button');
    
    // Severity counters
    const criticalCount = document.getElementById('critical-count');
    const highCount = document.getElementById('high-count');
    const mediumCount = document.getElementById('medium-count');
    const lowCount = document.getElementById('low-count');
    
    // Current active tab
    let activeTab = 'headers';
    
    // Tab switching functionality
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Update active tab
            tabButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            activeTab = this.dataset.tab;
            
            // Show appropriate content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`tab-${activeTab}`).classList.add('active');
        });
    });
    
    scanButton.addEventListener('click', function() {
        // Reset counters
        criticalCount.textContent = '0';
        highCount.textContent = '0';
        mediumCount.textContent = '0';
        lowCount.textContent = '0';
        
        // Validate URL
        const url = targetUrl.value.trim();
        if (!url) {
            alert('Please enter a valid URL');
            return;
        }
        
        // Show loading state
        spinner.style.display = 'block';
        resultsSection.style.display = 'none';
        progressBar.style.width = '0%';
        
        // Clear previous results
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.innerHTML = '';
        });
        
        // Get selected options
        const options = {
            headers: document.getElementById('option-headers').checked,
            tls: document.getElementById('option-tls').checked,
            vulnerabilities: document.getElementById('option-vulnerabilities').checked,
            content: document.getElementById('option-content').checked,
            ports: document.getElementById('option-ports').checked,
            advanced: document.getElementById('option-advanced').checked
        };
        
        // Start scanning with progress updates
        scanWebsite(url, options);
    });
    
    function updateProgress(percent) {
        progressBar.style.width = percent + '%';
    }
    
    function incrementCounter(severity) {
        const counter = document.getElementById(`${severity}-count`);
        counter.textContent = parseInt(counter.textContent) + 1;
    }
    
    function addResult(title, description, severity, details = null, tab = 'general') {
        incrementCounter(severity);
        
        // Ensure the tab exists
        if (!document.getElementById(`tab-${tab}`)) {
            const tabContent = document.createElement('div');
            tabContent.id = `tab-${tab}`;
            tabContent.className = 'tab-content';
            if (tab === activeTab) tabContent.classList.add('active');
            resultsContainer.appendChild(tabContent);
        }
        
        const resultItem = document.createElement('div');
        resultItem.className = `result-item ${severity}`;
        
        let detailsHtml = '';
        if (details) {
            if (typeof details === 'string') {
                detailsHtml = `<p>${details}</p>`;
            } else if (Array.isArray(details)) {
                detailsHtml = '<ul>';
                details.forEach(item => {
                    if (typeof item === 'object') {
                        detailsHtml += `<li>${JSON.stringify(item)}</li>`;
                    } else {
                        detailsHtml += `<li>${item}</li>`;
                    }
                });
                detailsHtml += '</ul>';
            } else if (typeof details === 'object') {
                detailsHtml = '<pre>' + JSON.stringify(details, null, 2) + '</pre>';
            }
        }
        
        resultItem.innerHTML = `
            <div class="result-header">
                <div class="result-title">${title}</div>
                <div class="result-severity severity-${severity}">${severity.toUpperCase()}</div>
            </div>
            <div class="result-description">${description}</div>
            ${detailsHtml}
        `;
        
        document.getElementById(`tab-${tab}`).appendChild(resultItem);
    }
    
    async function scanWebsite(url, options) {
        try {
            updateProgress(10);
            
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });
            
            updateProgress(70);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const results = await response.json();
            
            updateProgress(90);
            
            // Process results based on options
            if (options.headers && results.security_headers) {
                processSecurityHeaders(results.security_headers);
            }
            
            if (options.tls && results.tls_configuration) {
                processTlsResults(results.tls_configuration);
            }
            
            if (options.vulnerabilities && results.vulnerabilities) {
                processVulnerabilityResults(results.vulnerabilities);
            }
            
            if (options.content && results.content_analysis) {
                processContentResults(results.content_analysis);
            }
            
            if (options.ports && results.port_scan) {
                processPortScanResults(results.port_scan);
            }
            
            if (options.advanced && results.advanced_scan) {
                processAdvancedScanResults(results.advanced_scan);
            }
            
            updateProgress(100);
            
            // Show results
            setTimeout(() => {
                spinner.style.display = 'none';
                resultsSection.style.display = 'block';
            }, 500);
            
        } catch (error) {
            console.error('Scan error:', error);
            spinner.style.display = 'none';
            
            addResult(
                'Scan Failed', 
                `The scanner encountered an error: ${error.message}`, 
                'high'
            );
            
            resultsSection.style.display = 'block';
        }
    }
    
    function processSecurityHeaders(headers) {
        if (headers.error) {
            addResult(
                'Security Headers Check Failed',
                headers.error,
                'medium',
                null,
                'headers'
            );
            return;
        }
        
        // Check for missing security headers
        const missingHeaders = [];
        for (const [header, data] of Object.entries(headers)) {
            if (header !== 'analysis' && !data.present) {
                missingHeaders.push(header);
            }
        }
        
        if (missingHeaders.length > 0) {
            addResult(
                'Missing Security Headers',
                'The website is missing important security headers that help protect against various attacks.',
                missingHeaders.includes('Strict-Transport-Security') ? 'high' : 'medium',
                missingHeaders,
                'headers'
            );
        }
        
        // Process analysis results
        if (headers.analysis) {
            headers.analysis.issues.forEach(issue => {
                addResult(
                    'Security Header Issue',
                    issue,
                    'medium',
                    null,
                    'headers'
                );
            });
            
            if (headers.analysis.score < 70) {
                addResult(
                    'Security Headers Score',
                    `The security headers score is ${headers.analysis.score}/100. Consider implementing the recommendations below.`,
                    headers.analysis.score < 50 ? 'high' : 'medium',
                    headers.analysis.recommendations,
                    'headers'
                );
            } else {
                addResult(
                    'Security Headers Score',
                    `The security headers score is ${headers.analysis.score}/100. Good job!`,
                    'low',
                    null,
                    'headers'
                );
            }
        }
    }
    
    function processTlsResults(tls) {
        if (tls.error) {
            addResult(
                'TLS/SSL Check Failed',
                tls.error,
                'medium',
                null,
                'tls'
            );
            return;
        }
        
        // Check certificate validity
        if (!tls.certificate.valid) {
            addResult(
                'SSL Certificate Expired',
                'The SSL certificate has expired, which will cause browser security warnings.',
                'critical',
                `Expired on: ${tls.certificate.expiration}`,
                'tls'
            );
        } else if (tls.certificate.days_until_expiry < 30) {
            addResult(
                'SSL Certificate Expiring Soon',
                'The SSL certificate will expire soon, which may cause service disruption.',
                'medium',
                `Expires on: ${tls.certificate.expiration} (${tls.certificate.days_until_expiry} days)`,
                'tls'
            );
        }
        
        // Check protocol support
        if (tls.protocol_support['SSLv2'] || tls.protocol_support['SSLv3']) {
            addResult(
                'Insecure SSL Protocols Enabled',
                'The server supports outdated and insecure SSL protocols that have known vulnerabilities.',
                'high',
                `Supported protocols: ${Object.keys(tls.protocol_support).filter(p => tls.protocol_support[p]).join(', ')}`,
                'tls'
            );
        }
        
        // Process analysis results
        if (tls.analysis) {
            tls.analysis.issues.forEach(issue => {
                addResult(
                    'TLS Configuration Issue',
                    issue,
                    'medium',
                    null,
                    'tls'
                );
            });
            
            if (tls.analysis.score < 70) {
                addResult(
                    'TLS Configuration Score',
                    `The TLS configuration score is ${tls.analysis.score}/100. Consider implementing the recommendations below.`,
                    tls.analysis.score < 50 ? 'high' : 'medium',
                    tls.analysis.recommendations,
                    'tls'
                );
            } else {
                addResult(
                    'TLS Configuration Score',
                    `The TLS configuration score is ${tls.analysis.score}/100. Good job!`,
                    'low',
                    null,
                    'tls'
                );
            }
        }
    }
    
    function processVulnerabilityResults(vulnerabilities) {
        if (vulnerabilities.error) {
            addResult(
                'Vulnerability Check Failed',
                vulnerabilities.error,
                'medium',
                null,
                'vulnerabilities'
            );
            return;
        }
        
        // Process common vulnerabilities
        vulnerabilities.common_vulnerabilities.forEach(vuln => {
            addResult(
                vuln.type,
                `Found potential vulnerability: ${vuln.type}`,
                vuln.severity,
                vuln,
                'vulnerabilities'
            );
        });
        
        // Process sensitive files
        vulnerabilities.sensitive_files.forEach(file => {
            addResult(
                'Sensitive File Exposed',
                `A sensitive file was found accessible: ${file.file}`,
                'medium',
                file,
                'vulnerabilities'
            );
        });
        
        // Process information disclosure
        vulnerabilities.information_disclosure.forEach(disclosure => {
            addResult(
                'Information Disclosure',
                `Potential information disclosure: ${disclosure.type}`,
                'low',
                disclosure.details,
                'vulnerabilities'
            );
        });
        
        // Process SQL injection results
        if (vulnerabilities.sql_injection_test && vulnerabilities.sql_injection_test.length > 0) {
            vulnerabilities.sql_injection_test.forEach(vuln => {
                addResult(
                    'SQL Injection Vulnerability',
                    `Potential SQL injection vulnerability detected with payload: ${vuln.payload}`,
                    vuln.severity,
                    vuln,
                    'vulnerabilities'
                );
            });
        }
        
        // Process XSS results
        if (vulnerabilities.xss_test && vulnerabilities.xss_test.length > 0) {
            vulnerabilities.xss_test.forEach(vuln => {
                addResult(
                    'XSS Vulnerability',
                    `Potential XSS vulnerability detected with payload: ${vuln.payload}`,
                    vuln.severity,
                    vuln,
                    'vulnerabilities'
                );
            });
        }
    }
    
    function processContentResults(content) {
        if (content.error) {
            addResult(
                'Content Analysis Failed',
                content.error,
                'medium',
                null,
                'content'
            );
            return;
        }
        
        // Process forms
        content.forms.forEach(form => {
            if (form.issues && form.issues.length > 0) {
                addResult(
                    'Form Security Issues',
                    `Form with action "${form.action}" has security considerations`,
                    'low',
                    form.issues,
                    'content'
                );
            }
        });
        
        // Process scripts
        content.scripts.forEach(script => {
            if (script.issues && script.issues.length > 0) {
                addResult(
                    'Script Security Issues',
                    `Script from "${script.src || 'inline'}" has security considerations`,
                    'low',
                    script.issues,
                    'content'
                );
            }
        });
        
        // Process comments
        if (content.comments && content.comments.length > 0) {
            addResult(
                'Sensitive Comments Found',
                'The HTML contains comments with potentially sensitive information',
                'low',
                content.comments,
                'content'
            );
        }
        
        // Process inputs
        if (content.inputs && content.inputs.length > 0) {
            const inputsWithIssues = content.inputs.filter(input => input.issues && input.issues.length > 0);
            if (inputsWithIssues.length > 0) {
                addResult(
                    'Input Security Issues',
                    'Some form inputs have security considerations',
                    'low',
                    inputsWithIssues,
                    'content'
                );
            }
        }
    }
    
    function processPortScanResults(portScan) {
        if (portScan.error) {
            addResult(
                'Port Scan Failed',
                portScan.error,
                'medium',
                null,
                'ports'
            );
            return;
        }
        
        // Display open ports
        if (portScan.open_ports && portScan.open_ports.length > 0) {
            addResult(
                'Open Ports Found',
                `Found ${portScan.open_ports.length} open ports on ${portScan.ip}`,
                'low',
                null,
                'ports'
            );
            
            // Create a visual representation of open ports
            const portsContainer = document.createElement('div');
            portsContainer.className = 'port-list';
            
            portScan.open_ports.forEach(port => {
                const portElement = document.createElement('div');
                portElement.className = 'port-item open';
                portElement.textContent = port;
                portsContainer.appendChild(portElement);
            });
            
            document.getElementById('tab-ports').appendChild(portsContainer);
        } else {
            addResult(
                'No Open Ports Found',
                'No common open ports found.',
                'low',
                null,
                'ports'
            );
        }
        
        // Process analysis results
        if (portScan.analysis) {
            portScan.analysis.issues.forEach(issue => {
                addResult(
                    'Port Security Issue',
                    issue,
                    'medium',
                    null,
                    'ports'
                );
            });
            
            if (portScan.analysis.recommendations && portScan.analysis.recommendations.length > 0) {
                addResult(
                    'Port Security Recommendations',
                    'Recommendations for improving port security:',
                    'low',
                    portScan.analysis.recommendations,
                    'ports'
                );
            }
        }
    }
    
    function processAdvancedScanResults(advancedScan) {
        if (advancedScan.error) {
            addResult(
                'Advanced Scan Failed',
                advancedScan.error,
                'medium',
                null,
                'advanced'
            );
            return;
        }
        
        // Process CSRF test results
        if (advancedScan.csrf_test) {
            addResult(
                'CSRF Protection Test',
                advancedScan.csrf_test.details,
                advancedScan.csrf_test.status === 'Potential issue' ? 'medium' : 'low',
                null,
                'advanced'
            );
        }
        
        // Process clickjacking test results
        if (advancedScan.clickjacking_test) {
            addResult(
                'Clickjacking Protection Test',
                advancedScan.clickjacking_test.details,
                advancedScan.clickjacking_test.status === 'Vulnerable' ? 'high' : 'low',
                null,
                'advanced'
            );
        }
        
        // Process CORS test results
        if (advancedScan.cors_test) {
            addResult(
                'CORS Configuration Test',
                advancedScan.cors_test.details,
                advancedScan.cors_test.status === 'Misconfigured' ? 'high' : 'low',
                null,
                'advanced'
            );
        }
        
        // Process HTTP methods test results
        if (advancedScan.http_methods_test) {
            addResult(
                'HTTP Methods Test',
                advancedScan.http_methods_test.details,
                advancedScan.http_methods_test.status === 'Potential issue' ? 'medium' : 'low',
                null,
                'advanced'
            );
        }
        
        // Process subdomain enumeration results
        if (advancedScan.subdomain_enumeration) {
            if (advancedScan.subdomain_enumeration.found && advancedScan.subdomain_enumeration.found.length > 0) {
                addResult(
                    'Subdomain Enumeration',
                    `Found ${advancedScan.subdomain_enumeration.found.length} subdomains out of ${advancedScan.subdomain_enumeration.total_checked} checked`,
                    'low',
                    advancedScan.subdomain_enumeration.found,
                    'advanced'
                );
            } else {
                addResult(
                    'Subdomain Enumeration',
                    `No subdomains found out of ${advancedScan.subdomain_enumeration.total_checked} checked`,
                    'low',
                    null,
                    'advanced'
                );
            }
        }
    }
});
